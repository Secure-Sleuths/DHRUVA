"use client";

/**
 * KnowledgeTab (WO-U9c read + Knowledge-write wiring) — the knowledge base:
 * recent docs, a type breakdown, a full-text search box, and the CRUD writes.
 *
 * Reads: `GET /api/kb/documents` (`getKbDocuments`), `GET /api/kb/stats`
 * (`getKbStats`), `GET /api/kb/search?q=` (`searchKb`) — all `verify_jwt` +
 * `require_license_feature("knowledge_base")` and available to ALL roles per the
 * shell ACL. The search box hits the GET search endpoint (a READ).
 *
 * Writes (each mirrors src/api/routes/knowledge_base.py EXACTLY; server re-checks):
 *   - Add    → `POST /api/kb/documents` (ANALYST+; read_only excluded). Requires
 *     title+content and a valid doc_type. The form offers the two human-authored
 *     types (analyst_note, investigation_pattern); the system self-indexes the rest.
 *   - Edit   → `PUT /api/kb/documents/{id}` (SENIOR_ANALYST+ — a plain analyst may
 *     add but NOT edit). doc_type is not editable server-side, shown read-only.
 *   - Delete → `DELETE /api/kb/documents/{id}` (SENIOR_ANALYST+). Hard delete →
 *     behind an explicit confirm dialog.
 *
 * RBAC is mirrored via `knowledgeActionGate` (@/lib/rbac), fail-closed, NEVER wider
 * than the server (note the create-vs-edit asymmetry). `created_by` is set
 * server-side from the JWT — never sent by the client.
 *
 * ANONYMIZATION BOUNDARY preserved: KB content is operational free-text; these
 * forms carry title/content/tags/techniques only. This surface adds NO raw-
 * identifier reverse-lookup (that risky Admin affordance is deliberately absent
 * from the redesign) — nothing here resolves a token to PII.
 *
 * HONEST STUB: there is NO re-index / rebuild endpoint on this server — indexing is
 * automatic on write. No "rebuild index" control is offered.
 *
 * TIER GATE: a runtime 402/403 from the `knowledge_base` gate degrades the whole
 * surface to FeatureLockedState. Typed action errors: 402/403 → locked, 404 →
 * "changed, refreshing", 400/503 → typed, else typed. States: loading / empty /
 * error+retry / locked; PollingStatus (30s, aborts on unmount). Fixtures gate
 * behind NEXT_PUBLIC_DHRUVA_FIXTURES (writes short-circuit to a synthetic success
 * with NO real mutation).
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { Search } from "lucide-react";
import {
  Chip,
  Dialog,
  Panel,
  PollingStatus,
  StatusState,
  FeatureLockedState,
} from "@/components";
import { PageHeading } from "../PageHeading";
import {
  ApiError,
  createKbDocument,
  deleteKbDocument,
  getKbDocuments,
  getKbStats,
  searchKb,
  updateKbDocument,
} from "@/lib/api";
import { knowledgeActionGate, type KnowledgeActionGate } from "@/lib/rbac";
import { useAuth } from "@/lib/auth";
import { docTypeLabel, kbPreview, parseKbList } from "@/lib/knowledge";
import { fmtDate, fmtInt } from "@/lib/format";
import { cn, focusRing } from "@/lib/ui";
import type { TabProps } from "../tabRegistry";
import type {
  KbAuthorableDocType,
  KbDocument,
  KbSearchResult,
  KbStats,
} from "@/lib/types";

const POLL_MS = 30_000;

/** The two human-authored doc types the create form offers (mirrors legacy). */
const AUTHORABLE_TYPES: { value: KbAuthorableDocType; label: string }[] = [
  { value: "analyst_note", label: "Analyst note" },
  { value: "investigation_pattern", label: "Investigation pattern" },
];

function isLockError(e: unknown): boolean {
  return e instanceof ApiError && (e.status === 402 || e.status === 403);
}
function errMessage(e: unknown): string {
  return e instanceof Error ? e.message : "Unknown error";
}
/** comma-separated input → trimmed, de-blanked string[] */
function parseCsv(v: string): string[] {
  return v
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

interface State {
  docs: KbDocument[] | null;
  stats: KbStats | null;
  error: string | null;
  locked: boolean;
  loading: boolean;
}

interface SearchState {
  query: string; // the submitted query (drives the results view)
  results: KbSearchResult[] | null;
  loading: boolean;
  error: string | null;
}

/** The doc-editor dialog target: a fresh create, or editing an existing doc. */
type Editor = { mode: "create" } | { mode: "edit"; doc: KbDocument } | null;
/** A transient result banner. */
type Flash = { tone: "ok" | "warn"; msg: string };

export function KnowledgeTab(_props: TabProps) {
  const { role } = useAuth();
  const gate = knowledgeActionGate(role);

  const [state, setState] = useState<State>({
    docs: null,
    stats: null,
    error: null,
    locked: false,
    loading: true,
  });
  const [input, setInput] = useState("");
  // OPTIONAL type filter (restores legacy `kbFilterType`). SERVER-SIDE: the value
  // is passed to `GET /api/kb/documents?type=…` (WHERE doc_type=), so it narrows
  // the whole KB for that tenant, not just the loaded page. "all" = no filter =
  // default browse behaviour (unchanged). It refines browse only — search is a
  // separate read.
  const [typeFilter, setTypeFilter] = useState<string>("all");
  const [search, setSearch] = useState<SearchState>({
    query: "",
    results: null,
    loading: false,
    error: null,
  });
  const [secondsAgo, setSecondsAgo] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const abortRef = useRef<AbortController | null>(null);
  const searchAbortRef = useRef<AbortController | null>(null);

  // ---- write state (create / edit / delete) --------------------------------
  const [editor, setEditor] = useState<Editor>(null);
  const [deleting, setDeleting] = useState<KbDocument | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [flash, setFlash] = useState<Flash | null>(null);

  const load = useCallback(async (manual: boolean) => {
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    if (manual) setRefreshing(true);
    try {
      const [docs, stats] = await Promise.all([
        getKbDocuments(
          { limit: 100, type: typeFilter === "all" ? undefined : typeFilter },
          ac.signal,
        ),
        getKbStats(ac.signal),
      ]);
      if (ac.signal.aborted) return;
      setState({ docs: docs.documents, stats, error: null, locked: false, loading: false });
      setSecondsAgo(0);
    } catch (e) {
      if (ac.signal.aborted) return;
      if (isLockError(e)) {
        setState({ docs: null, stats: null, error: null, locked: true, loading: false });
        return;
      }
      const msg = errMessage(e);
      setState((prev) =>
        prev.docs
          ? { ...prev, loading: false }
          : { docs: null, stats: null, error: msg, locked: false, loading: false },
      );
    } finally {
      if (!ac.signal.aborted) setRefreshing(false);
    }
  }, [typeFilter]);

  useEffect(() => {
    load(false);
    const poll = setInterval(() => load(false), POLL_MS);
    return () => {
      clearInterval(poll);
      abortRef.current?.abort();
      searchAbortRef.current?.abort();
    };
  }, [load]);

  useEffect(() => {
    const t = setInterval(() => setSecondsAgo((s) => s + 1), 1000);
    return () => clearInterval(t);
  }, []);

  const runSearch = useCallback(async (q: string) => {
    const query = q.trim();
    if (query.length < 2) return; // server requires q ≥ 2 chars
    searchAbortRef.current?.abort();
    const ac = new AbortController();
    searchAbortRef.current = ac;
    setSearch({ query, results: null, loading: true, error: null });
    try {
      const res = await searchKb({ q: query, limit: 25 }, ac.signal);
      if (ac.signal.aborted) return;
      setSearch({ query, results: res.results, loading: false, error: null });
    } catch (e) {
      if (ac.signal.aborted) return;
      setSearch({ query, results: null, loading: false, error: errMessage(e) });
    }
  }, []);

  const clearSearch = useCallback(() => {
    searchAbortRef.current?.abort();
    setInput("");
    setSearch({ query: "", results: null, loading: false, error: null });
  }, []);

  const onUpgrade = useCallback(() => {
    if (typeof window !== "undefined") {
      window.open("https://securesleuths.in/pricing", "_blank", "noreferrer");
    }
  }, []);

  // ---- write handlers ------------------------------------------------------
  const openCreate = useCallback(() => {
    setActionError(null);
    setEditor({ mode: "create" });
  }, []);
  const openEdit = useCallback((doc: KbDocument) => {
    setActionError(null);
    setEditor({ mode: "edit", doc });
  }, []);
  const closeEditor = useCallback(() => {
    if (submitting) return;
    setEditor(null);
    setActionError(null);
  }, [submitting]);
  const openDelete = useCallback((doc: KbDocument) => {
    setActionError(null);
    setDeleting(doc);
  }, []);
  const closeDelete = useCallback(() => {
    if (submitting) return;
    setDeleting(null);
    setActionError(null);
  }, [submitting]);

  /** Map a caught write error to a typed action message; self-heal on 404. */
  const applyWriteError = useCallback(
    async (e: unknown, verb: string): Promise<void> => {
      if (isLockError(e)) {
        setActionError(
          "Your role or license tier does not permit this action — the server denied it (this control mirrors the server and stays locked). Nothing changed.",
        );
      } else if (e instanceof ApiError && e.status === 404) {
        setActionError(
          "This document changed since you loaded it — it may already be gone. Refreshing the list.",
        );
        setEditor(null);
        setDeleting(null);
        await load(true);
      } else if (e instanceof ApiError && e.status === 400) {
        setActionError(`The document was rejected: ${errMessage(e)}.`);
      } else if (e instanceof ApiError && e.status === 503) {
        setActionError(
          `The knowledge base is disabled on the server right now, so the ${verb} did not complete.`,
        );
      } else {
        setActionError(errMessage(e));
      }
    },
    [load],
  );

  const submitEditor = useCallback(
    async (values: EditorValues) => {
      if (!editor) return;
      setSubmitting(true);
      setActionError(null);
      try {
        if (editor.mode === "create") {
          await createKbDocument({
            title: values.title.trim(),
            content: values.content.trim(),
            doc_type: values.doc_type,
            tags: parseCsv(values.tags),
            mitre_techniques: parseCsv(values.mitre),
          });
          setFlash({ tone: "ok", msg: `Added “${values.title.trim()}” to the knowledge base.` });
          // Clear any active type filter so the just-added document is visible in
          // browse (the create form only authors analyst_note / investigation_pattern).
          setTypeFilter("all");
        } else {
          await updateKbDocument(editor.doc.id, {
            title: values.title.trim(),
            content: values.content.trim(),
            tags: parseCsv(values.tags),
            mitre_techniques: parseCsv(values.mitre),
          });
          setFlash({ tone: "ok", msg: `Saved changes to “${values.title.trim()}”.` });
        }
        setEditor(null);
        await load(true);
      } catch (e) {
        await applyWriteError(e, editor.mode === "create" ? "create" : "update");
      } finally {
        setSubmitting(false);
      }
    },
    [editor, load, applyWriteError],
  );

  const submitDelete = useCallback(async () => {
    if (!deleting) return;
    setSubmitting(true);
    setActionError(null);
    try {
      await deleteKbDocument(deleting.id);
      setFlash({ tone: "ok", msg: `Deleted “${deleting.title}”.` });
      setDeleting(null);
      await load(true);
    } catch (e) {
      await applyWriteError(e, "delete");
    } finally {
      setSubmitting(false);
    }
  }, [deleting, load, applyWriteError]);

  const { docs, stats, error, locked, loading } = state;
  const searching = search.query.length > 0;

  return (
    <>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <PageHeading
          title="Knowledge base"
          sub="Playbooks, analyst notes, runbooks and hunt records the SOC has captured — search it, or browse the most recent. Add and curate what the team has learned."
        />
        <div className="mt-1 flex items-center gap-2">
          {!locked && (
            <PollingStatus
              secondsAgo={secondsAgo}
              refreshing={refreshing}
              onRefresh={() => load(true)}
            />
          )}
          {!locked && docs && gate.canCreate && (
            <ActionButton tone="ok" onClick={openCreate}>
              Add document…
            </ActionButton>
          )}
        </div>
      </div>

      {locked ? (
        <FeatureLockedState feature="Knowledge base" tier="current" onUpgrade={onUpgrade} />
      ) : loading && !docs ? (
        <StatusState variant="loading" title="Loading knowledge base…" />
      ) : error && !docs ? (
        <StatusState
          variant="error"
          title="Couldn't load the knowledge base"
          description={error}
          action={<Chip onClick={() => load(true)}>Retry</Chip>}
        />
      ) : docs ? (
        <div className="flex flex-col gap-3">
          {flash && <FlashBanner flash={flash} onDismiss={() => setFlash(null)} />}
          <SearchBar
            input={input}
            setInput={setInput}
            onSubmit={() => runSearch(input)}
            onClear={clearSearch}
            searching={searching}
          />
          {stats && !searching && (
            <StatsRow stats={stats} value={typeFilter} onChange={setTypeFilter} />
          )}
          {searching ? (
            <SearchResults
              search={search}
              gate={gate}
              onEdit={openEdit}
              onDelete={openDelete}
              onClear={clearSearch}
            />
          ) : (
            <DocsPanel
              docs={docs}
              gate={gate}
              typeFilter={typeFilter}
              onClearFilter={() => setTypeFilter("all")}
              onEdit={openEdit}
              onDelete={openDelete}
            />
          )}
        </div>
      ) : null}

      <EditorDialog
        editor={editor}
        submitting={submitting}
        error={actionError}
        onSubmit={submitEditor}
        onClose={closeEditor}
      />

      <DeleteDialog
        doc={deleting}
        submitting={submitting}
        error={actionError}
        onConfirm={submitDelete}
        onClose={closeDelete}
      />
    </>
  );
}

function FlashBanner({ flash, onDismiss }: { flash: Flash; onDismiss: () => void }) {
  const tone =
    flash.tone === "ok"
      ? "border-grounded-border text-grounded-ink"
      : "border-gated-border text-gated-ink";
  return (
    <div
      role="status"
      aria-live="polite"
      className={cn(
        "flex items-start gap-3 rounded-lg border bg-panel2 px-3.5 py-2.5 text-data",
        tone,
      )}
    >
      <span className="flex-1">{flash.msg}</span>
      <button
        type="button"
        onClick={onDismiss}
        className={cn("shrink-0 text-kbd text-dim hover:text-ink", focusRing)}
      >
        Dismiss
      </button>
    </div>
  );
}

function SearchBar({
  input,
  setInput,
  onSubmit,
  onClear,
  searching,
}: {
  input: string;
  setInput: (v: string) => void;
  onSubmit: () => void;
  onClear: () => void;
  searching: boolean;
}) {
  return (
    <form
      role="search"
      onSubmit={(e) => {
        e.preventDefault();
        onSubmit();
      }}
      className="flex flex-wrap items-center gap-2"
    >
      <div className="relative min-w-[260px] flex-1">
        <Search
          className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-dim2"
          aria-hidden="true"
        />
        <input
          type="search"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Search the knowledge base…"
          aria-label="Search the knowledge base"
          className={`w-full rounded-lg border border-line bg-panel2 py-2 pl-8 pr-3 text-data text-ink placeholder:text-dim2 ${focusRing}`}
        />
      </div>
      <Chip variant="cite" onClick={onSubmit} aria-label="Run search">
        Search
      </Chip>
      {searching && (
        <Chip onClick={onClear} aria-label="Clear search and browse">
          Clear
        </Chip>
      )}
    </form>
  );
}

/**
 * The KB-wide total + a per-type filter control (restores legacy `kbFilterType`).
 * The counts are the tenant's KB-wide `by_type` totals (from `GET /api/kb/stats`),
 * and clicking a type narrows the browse list SERVER-SIDE via `?type=` — so it is
 * an honest, complete filter, not a page-local one. "All" clears it (default
 * browse). Selecting a type is an optional refinement; the recency order is
 * unchanged.
 */
function StatsRow({
  stats,
  value,
  onChange,
}: {
  stats: KbStats;
  value: string;
  onChange: (v: string) => void;
}) {
  const types = Object.entries(stats.by_type ?? {}).sort((a, b) => b[1] - a[1]);
  return (
    <Panel className="px-4 py-3">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <div className="text-data text-ink">
          <span className="text-kpi tabular">{fmtInt(stats.total)}</span>{" "}
          <span className="text-kbd text-dim2">documents</span>
        </div>
        {types.length > 0 ? (
          <div
            className="flex flex-wrap items-center gap-1.5"
            role="group"
            aria-label="Filter documents by type"
          >
            <span className="text-kbd uppercase tracking-wider text-dim2">Type</span>
            <Chip
              variant={value === "all" ? "cite" : "default"}
              onClick={() => onChange("all")}
              aria-label={`All types${value === "all" ? " (selected)" : ""}`}
            >
              All · {fmtInt(stats.total)}
            </Chip>
            {types.map(([type, count]) => (
              <Chip
                key={type}
                variant={value === type ? "cite" : "default"}
                onClick={() => onChange(type)}
                aria-label={`Filter to ${docTypeLabel(type)}${value === type ? " (selected)" : ""}`}
              >
                {docTypeLabel(type)} · {fmtInt(count)}
              </Chip>
            ))}
          </div>
        ) : (
          <span className="text-kbd text-dim2">No documents yet</span>
        )}
      </div>
    </Panel>
  );
}

function DocCard({
  doc,
  rank,
  gate,
  onEdit,
  onDelete,
}: {
  doc: KbDocument;
  rank?: number;
  gate: KnowledgeActionGate;
  onEdit: (d: KbDocument) => void;
  onDelete: (d: KbDocument) => void;
}) {
  const tags = parseKbList(doc.tags);
  const techniques = parseKbList(doc.mitre_techniques);
  const preview = kbPreview(doc);
  return (
    <Panel className="p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="text-title text-ink">{doc.title}</div>
        <Chip>{docTypeLabel(doc.doc_type)}</Chip>
      </div>
      {preview && <div className="mt-1 text-data text-dim">{preview}</div>}
      <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-kbd text-dim2">
        <span>Updated {fmtDate(doc.updated_at ?? doc.created_at)}</span>
        {doc.created_by && <span>· by {doc.created_by}</span>}
        {typeof rank === "number" && <span>· relevance {rank.toFixed(2)}</span>}
      </div>
      {(tags.length > 0 || techniques.length > 0) && (
        <div className="mt-2 flex flex-wrap gap-1">
          {techniques.map((t) => (
            <span key={t} className="font-mono text-kbd text-acc">
              {t}
            </span>
          ))}
          {tags.map((t) => (
            <Chip key={t}>{t}</Chip>
          ))}
        </div>
      )}
      {(gate.canEdit || gate.canDelete) && (
        <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-line pt-2.5">
          {gate.canEdit ? (
            <ActionButton tone="neutral" onClick={() => onEdit(doc)}>
              Edit…
            </ActionButton>
          ) : null}
          {gate.canDelete ? (
            <ActionButton tone="warn" onClick={() => onDelete(doc)}>
              Delete…
            </ActionButton>
          ) : null}
        </div>
      )}
    </Panel>
  );
}

function DocsPanel({
  docs,
  gate,
  typeFilter,
  onClearFilter,
  onEdit,
  onDelete,
}: {
  docs: KbDocument[];
  gate: KnowledgeActionGate;
  typeFilter: string;
  onClearFilter: () => void;
  onEdit: (d: KbDocument) => void;
  onDelete: (d: KbDocument) => void;
}) {
  const filtered = typeFilter !== "all";
  if (docs.length === 0) {
    // Honest empty state: distinguish "nothing here yet" from "the active type
    // filter matched nothing" (server returned no rows for this doc_type).
    return filtered ? (
      <StatusState
        variant="empty"
        title={`No ${docTypeLabel(typeFilter)} documents`}
        description="No documents of this type are in the knowledge base for this tenant. Clear the filter to browse all recent documents."
        action={<Chip onClick={onClearFilter}>Clear filter</Chip>}
      />
    ) : (
      <StatusState
        variant="empty"
        title="No knowledge-base documents yet"
        description="Playbooks, analyst notes and confirmed hunt findings are captured here as the SOC operates."
      />
    );
  }
  return (
    <div className="flex flex-col gap-2">
      <div className="text-kbd uppercase tracking-wider text-dim2">
        {filtered ? `${docTypeLabel(typeFilter)} · ` : "Recent documents · "}
        {docs.length} shown
      </div>
      {docs.map((d) => (
        <DocCard key={d.id} doc={d} gate={gate} onEdit={onEdit} onDelete={onDelete} />
      ))}
    </div>
  );
}

function SearchResults({
  search,
  gate,
  onEdit,
  onDelete,
  onClear,
}: {
  search: SearchState;
  gate: KnowledgeActionGate;
  onEdit: (d: KbDocument) => void;
  onDelete: (d: KbDocument) => void;
  onClear: () => void;
}) {
  if (search.loading) {
    return <StatusState variant="loading" title={`Searching for “${search.query}”…`} />;
  }
  if (search.error) {
    return (
      <StatusState
        variant="error"
        title="Search failed"
        description={search.error}
        action={<Chip onClick={onClear}>Back to browse</Chip>}
      />
    );
  }
  const results = search.results ?? [];
  if (results.length === 0) {
    return (
      <StatusState
        variant="empty"
        title={`No matches for “${search.query}”`}
        description="Try broader terms, or clear the search to browse recent documents."
        action={<Chip onClick={onClear}>Back to browse</Chip>}
      />
    );
  }
  return (
    <div className="flex flex-col gap-2">
      {/* announce the outcome of a user-initiated search to assistive tech */}
      <div role="status" aria-live="polite" className="text-kbd uppercase tracking-wider text-dim2">
        {results.length} result{results.length === 1 ? "" : "s"} for “{search.query}”
      </div>
      {results.map((r) => (
        <DocCard
          key={r.id}
          doc={r}
          rank={r.rank}
          gate={gate}
          onEdit={onEdit}
          onDelete={onDelete}
        />
      ))}
    </div>
  );
}

// ---- write UI ---------------------------------------------------------------

function ActionButton({
  tone,
  onClick,
  disabled,
  children,
}: {
  tone: "ok" | "warn" | "neutral";
  onClick: () => void;
  disabled?: boolean;
  children: React.ReactNode;
}) {
  const cls =
    tone === "ok"
      ? "border-grounded-border bg-grounded-border/40 text-grounded-ink hover:brightness-125"
      : tone === "warn"
        ? "border-gated-border bg-field text-gated-ink hover:brightness-125"
        : "border-line bg-field text-ink hover:bg-hover";
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={cn(
        "rounded-md border px-2.5 py-1 text-meta",
        disabled ? "cursor-not-allowed opacity-60" : "cursor-pointer",
        cls,
        focusRing,
      )}
    >
      {children}
    </button>
  );
}

interface EditorValues {
  title: string;
  content: string;
  doc_type: KbAuthorableDocType;
  tags: string;
  mitre: string;
}

const inputCls =
  "w-full rounded-md border border-line bg-field px-3 py-2 text-data text-ink placeholder:text-dim2";

/**
 * The create/edit dialog. Create offers the doc_type dropdown; edit shows the
 * (non-editable server-side) doc_type read-only and pre-fills the mutable fields.
 * Submit is disabled until title AND content are present (the server requires
 * both — the client never fires a request it will 400). The primary button is the
 * only path that fires the write.
 */
function EditorDialog({
  editor,
  submitting,
  error,
  onSubmit,
  onClose,
}: {
  editor: Editor;
  submitting: boolean;
  error: string | null;
  onSubmit: (values: EditorValues) => void;
  onClose: () => void;
}) {
  const isEdit = editor?.mode === "edit";
  const doc = isEdit ? editor.doc : null;

  const [values, setValues] = useState<EditorValues>({
    title: "",
    content: "",
    doc_type: "analyst_note",
    tags: "",
    mitre: "",
  });

  // Re-seed the form whenever the dialog target changes (open create vs edit).
  useEffect(() => {
    if (!editor) return;
    if (editor.mode === "edit") {
      const d = editor.doc;
      setValues({
        title: d.title ?? "",
        content: d.content ?? "",
        doc_type: "analyst_note", // unused in edit (doc_type not editable)
        tags: parseKbList(d.tags).join(", "),
        mitre: parseKbList(d.mitre_techniques).join(", "),
      });
    } else {
      setValues({ title: "", content: "", doc_type: "analyst_note", tags: "", mitre: "" });
    }
  }, [editor]);

  if (!editor) return null;

  const canSubmit =
    values.title.trim().length > 0 && values.content.trim().length > 0 && !submitting;
  const cta = isEdit
    ? submitting
      ? "Saving…"
      : "Save changes"
    : submitting
      ? "Adding…"
      : "Add document";

  return (
    <Dialog
      open
      onClose={onClose}
      maxWidth={600}
      title={isEdit ? "Edit knowledge" : "Add knowledge"}
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (canSubmit) onSubmit(values);
        }}
        className="flex flex-col gap-3"
      >
        {isEdit ? (
          <div className="rounded-md border border-line bg-panel2 px-3 py-2 text-kbd text-dim2">
            Type: <b className="text-dim">{docTypeLabel(doc?.doc_type)}</b> · cannot be
            changed
          </div>
        ) : (
          <div>
            <label htmlFor="kb-type" className="mb-1 block text-kbd text-dim2">
              Type
            </label>
            <select
              id="kb-type"
              value={values.doc_type}
              disabled={submitting}
              onChange={(e) =>
                setValues((v) => ({
                  ...v,
                  doc_type: e.target.value as KbAuthorableDocType,
                }))
              }
              className={cn(inputCls, focusRing)}
            >
              {AUTHORABLE_TYPES.map((t) => (
                <option key={t.value} value={t.value}>
                  {t.label}
                </option>
              ))}
            </select>
          </div>
        )}

        <div>
          <label htmlFor="kb-title" className="mb-1 block text-kbd text-dim2">
            Title <span className="text-sev-crit">*</span>
          </label>
          <input
            id="kb-title"
            type="text"
            value={values.title}
            disabled={submitting}
            onChange={(e) => setValues((v) => ({ ...v, title: e.target.value }))}
            placeholder="Brief descriptive title"
            className={cn(inputCls, focusRing)}
          />
        </div>

        <div>
          <label htmlFor="kb-content" className="mb-1 block text-kbd text-dim2">
            Content <span className="text-sev-crit">*</span>
          </label>
          <textarea
            id="kb-content"
            rows={8}
            value={values.content}
            disabled={submitting}
            onChange={(e) => setValues((v) => ({ ...v, content: e.target.value }))}
            placeholder="Describe the pattern, investigation steps, or knowledge…"
            className={cn("resize-y", inputCls, focusRing)}
          />
        </div>

        <div>
          <label htmlFor="kb-tags" className="mb-1 block text-kbd text-dim2">
            Tags (comma-separated)
          </label>
          <input
            id="kb-tags"
            type="text"
            value={values.tags}
            disabled={submitting}
            onChange={(e) => setValues((v) => ({ ...v, tags: e.target.value }))}
            placeholder="e.g. lateral_movement, false_positive"
            className={cn(inputCls, focusRing)}
          />
        </div>

        <div>
          <label htmlFor="kb-mitre" className="mb-1 block text-kbd text-dim2">
            MITRE techniques (comma-separated, e.g. T1078, T1059)
          </label>
          <input
            id="kb-mitre"
            type="text"
            value={values.mitre}
            disabled={submitting}
            onChange={(e) => setValues((v) => ({ ...v, mitre: e.target.value }))}
            placeholder="e.g. T1053.005, T1003.001"
            className={cn(inputCls, focusRing)}
          />
        </div>

        {error && (
          <p className="text-data text-sev-crit" role="alert">
            {error}
          </p>
        )}

        <div className="flex items-center gap-2">
          <button
            type="submit"
            disabled={!canSubmit}
            className={cn(
              "rounded-md border px-3 py-1.5 text-data",
              focusRing,
              canSubmit
                ? "cursor-pointer border-grounded-border bg-grounded-border/40 text-grounded-ink hover:brightness-125"
                : "cursor-not-allowed border-line bg-field text-dim opacity-60",
            )}
          >
            {cta}
          </button>
          <button
            type="button"
            onClick={onClose}
            disabled={submitting}
            className={cn(
              "rounded-md border border-line bg-field px-3 py-1.5 text-data text-ink hover:bg-hover",
              focusRing,
              submitting && "cursor-not-allowed opacity-60",
            )}
          >
            Cancel
          </button>
        </div>
      </form>
    </Dialog>
  );
}

/**
 * The delete confirm dialog. A KB delete is a HARD, irreversible removal — the
 * primary button is the only path that fires it, and the copy names the doc.
 */
function DeleteDialog({
  doc,
  submitting,
  error,
  onConfirm,
  onClose,
}: {
  doc: KbDocument | null;
  submitting: boolean;
  error: string | null;
  onConfirm: () => void;
  onClose: () => void;
}) {
  if (!doc) return null;
  return (
    <Dialog open onClose={onClose} maxWidth={520} title="Delete document">
      <p className="text-data text-dim">
        This <b>permanently deletes</b>{" "}
        <span className="text-ink">“{doc.title}”</span> ({docTypeLabel(doc.doc_type)})
        from the knowledge base. It cannot be undone from here. Nothing is removed
        until you confirm.
      </p>

      {error && (
        <p className="mt-3 text-data text-sev-crit" role="alert">
          {error}
        </p>
      )}

      <div className="mt-4 flex items-center gap-2">
        <button
          type="button"
          onClick={onConfirm}
          disabled={submitting}
          className={cn(
            "rounded-md border px-3 py-1.5 text-data",
            focusRing,
            submitting
              ? "cursor-not-allowed border-line bg-field text-dim opacity-60"
              : "cursor-pointer border-gated-border bg-field text-gated-ink hover:brightness-125",
          )}
        >
          {submitting ? "Deleting…" : "Delete now"}
        </button>
        <button
          type="button"
          onClick={onClose}
          disabled={submitting}
          className={cn(
            "rounded-md border border-line bg-field px-3 py-1.5 text-data text-ink hover:bg-hover",
            focusRing,
            submitting && "cursor-not-allowed opacity-60",
          )}
        >
          Cancel
        </button>
      </div>
    </Dialog>
  );
}
