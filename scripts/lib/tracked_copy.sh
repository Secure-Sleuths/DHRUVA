#!/usr/bin/env bash
# =============================================================================
# tracked_copy.sh — copy a path into a staging tree, TRACKED FILES ONLY.
#
# WO-H132 (second half). WHY THIS EXISTS
# ======================================
#
# Every shipping lane composed its tree with ``cp -r``:
#
#     cp -r "${PROJECT_DIR}/src"    "${BUILD_DIR}/"      # source + Cython lanes
#     cp -r "${PROJECT_DIR}/config" "${BUILD_DIR}/"
#     cp -r "$PRIV/web/src" "$PRIV/web/public" web/      # public-repo publish
#
# ``cp`` does not know what ``.gitignore`` is. It copies whatever is sitting on
# that disk. Measured on the real working repo, the composed public tree held
# four files that git ignores, one of which — ``web/src/app/shotharness/h86/
# page.tsx`` — carried a live client's hostname in an ``agent_name:`` slot. It
# was never committed, so no branch, no CI run and no fresh worktree could ever
# have shown it: CI checks out the tracked tree, and there was nothing there to
# copy. The bug is only reproducible on a tree that has actually been worked in.
#
# That is a CLASS, not one file. The same ``cp`` would have published an editor
# backup of a module, a ``.env`` a colleague dropped in ``config/``, a key
# downloaded into ``src/`` for a five-minute test, a scratch note, a customer
# CSV. The blocklist in ``check_no_client_names.py`` catches names somebody
# already wrote down; the allowlist catches unknown names in identity slots on
# three surfaces. Neither can catch "a file that should not be in the build at
# all". Only asking git what belongs to the project can.
#
# THE SEMANTIC, AND WHY THIS ONE
# ==============================
#
# ``tracked_copy`` copies the WORKING-TREE CONTENT of files git has under
# version control. Not ``git archive HEAD``, which was the other candidate:
#
#   * ``git archive HEAD`` ships the last commit. In a release that is arguably
#     the more correct thing — but these same builders are run by hand on dirty
#     trees, and by the test-suite on a scratch repo, and a builder that
#     silently drops uncommitted edits to a TRACKED file is its own quiet
#     failure mode. Someone would fix a bug, build, and ship the old bug.
#   * ``ls-files`` + working tree drops exactly the files that caused this work
#     order (untracked and ignored) and nothing else. It is the narrowest change
#     that closes the class.
#
# The trade is stated rather than hidden: a BRAND-NEW file that has not been
# ``git add``ed yet will not be packaged. That is loud, not silent — every call
# prints the count of files it skipped and, when the caller asks, their names.
#
# FAIL CLOSED
# ===========
#
# If the source is not a git work tree the function FAILS. It does not fall
# back to ``cp -r``. "I cannot tell what belongs to this project" and "ship
# everything on the disk" must not be the same outcome — the same reasoning
# that made ``check_no_client_names.py`` raise ``UnreadableFile`` instead of
# counting an unreadable file as a clean one.
#
# USAGE
#   source "$(dirname "$0")/lib/tracked_copy.sh"
#   tracked_copy <repo-root> <dest-root> <repo-relative-path>...
#
# Paths keep their repo-relative shape under <dest-root>: copying ``src`` and
# ``web/src`` into ``/stage`` yields ``/stage/src`` and ``/stage/web/src``.
# =============================================================================

# How many skipped paths to NAME before switching to a count. `web` alone has
# ~27,600 ignored files (node_modules), and an earlier draft listed every one
# of them: a 2 MB build log in which the one line that mattered was invisible.
# Counts are always printed; names are printed while they are still readable.
TRACKED_COPY_LIST_LIMIT="${TRACKED_COPY_LIST_LIMIT:-25}"

# Print, on stderr, what tracked_copy will leave behind for these paths.
# Separated from the copy so a caller can report it before doing work, and so
# the numbers in a build log are the numbers this function actually used.
tracked_copy_skipped() {
    local repo="$1"; shift
    local untracked ignored
    untracked="$( { git -C "$repo" ls-files --others --exclude-standard -- "$@" 2>/dev/null || true; } | wc -l)"
    ignored="$( { git -C "$repo" ls-files --others --ignored --exclude-standard -- "$@" 2>/dev/null || true; } | wc -l)"
    if [ "${untracked:-0}" -gt 0 ] || [ "${ignored:-0}" -gt 0 ]; then
        echo "  tracked_copy: NOT packaging ${untracked} untracked + ${ignored} git-ignored file(s) under: $*" >&2
        _tracked_copy_name_some "untracked" "${untracked}" "$repo" \
            --others --exclude-standard -- "$@"
        _tracked_copy_name_some "ignored  " "${ignored}" "$repo" \
            --others --ignored --exclude-standard -- "$@"
    fi
}

_tracked_copy_name_some() {
    local label="$1" total="$2" repo="$3"; shift 3
    [ "${total:-0}" -gt 0 ] || return 0
    if [ "$total" -le "$TRACKED_COPY_LIST_LIMIT" ]; then
        { git -C "$repo" ls-files "$@" 2>/dev/null || true; } \
            | sed "s|^|    ${label}: |" >&2
    else
        { git -C "$repo" ls-files "$@" 2>/dev/null || true; } \
            | head -n "$TRACKED_COPY_LIST_LIMIT" \
            | sed "s|^|    ${label}: |" >&2
        echo "    ${label}: ... and $((total - TRACKED_COPY_LIST_LIMIT)) more (not listed)" >&2
    fi
}

tracked_copy() {
    local repo="$1"; shift
    local dest="$1"; shift

    if [ "$#" -eq 0 ]; then
        echo "tracked_copy: no paths given" >&2
        return 2
    fi
    if ! git -C "$repo" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        echo "tracked_copy: '$repo' is not a git work tree — refusing to copy." >&2
        echo "  A shipping lane must be able to ask git what belongs to the" >&2
        echo "  project. Falling back to cp -r here would reopen WO-H132." >&2
        return 1
    fi

    local list present missing
    list="$(mktemp)" || return 1
    present="$(mktemp)" || { rm -f "$list"; return 1; }

    if ! git -C "$repo" ls-files -z --cached -- "$@" > "$list"; then
        rm -f "$list" "$present"
        return 1
    fi
    if [ ! -s "$list" ]; then
        echo "tracked_copy: no tracked files under: $*" >&2
        echo "  Refusing to produce an empty/partial package silently." >&2
        rm -f "$list" "$present"
        return 1
    fi

    # A file can be tracked and deleted from the working tree. tar would abort
    # on it; dropping it matches the working tree, which is what we are
    # copying. Say how many rather than doing it quietly.
    missing=0
    while IFS= read -r -d '' f; do
        if [ -e "${repo}/${f}" ] || [ -L "${repo}/${f}" ]; then
            printf '%s\0' "$f" >> "$present"
        else
            missing=$((missing + 1))
        fi
    done < "$list"
    [ "$missing" -eq 0 ] || \
        echo "  tracked_copy: ${missing} tracked file(s) are deleted in the working tree — not packaged" >&2

    if [ ! -s "$present" ]; then
        echo "tracked_copy: every tracked file under '$*' is missing from the working tree" >&2
        rm -f "$list" "$present"
        return 1
    fi

    mkdir -p "$dest" || { rm -f "$list" "$present"; return 1; }
    # Both halves of the pipe are checked. An earlier draft read $? after a
    # `local` assignment, which had already overwritten it — the copy could
    # fail and the function still return 0.
    tar -C "$repo" --null -T "$present" -cf - | tar -C "$dest" -xf -
    local st=("${PIPESTATUS[@]}")
    rm -f "$list" "$present"
    [ "${st[0]}" -eq 0 ] && [ "${st[1]}" -eq 0 ]
}
