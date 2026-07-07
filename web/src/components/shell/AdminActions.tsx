"use client";

/**
 * AdminActions — the WRITE rail for the Admin tab (mirrors IncidentActions.tsx).
 *
 * Turns the read-only Admin surface into an operational one: user create/edit/
 * role/deactivate/password-reset, tenant create/rename/activate + agent-mapping
 * (mssp_admin), assets/identities/local-IOC CRUD, guidance + enricher reload, and
 * shift handoff — each wired to its real endpoint in `@/lib/api`.
 *
 * DISCIPLINE (mirrors the server, never widens):
 *   - RBAC per action is mirrored from `rbac.ts::adminActionGate`. The Admin TAB
 *     is already admin+; the one split that matters IN-tab is mssp_admin-only
 *     tenant management, so those controls are HIDDEN for a plain admin (a dead
 *     control the server would 403). The server always re-checks.
 *   - Assignable ROLES for user create/edit come from `rbac.ts::assignableRoles`
 *     (an admin can't mint an admin; community restricts to analyst/read_only) —
 *     the dropdown never offers a role the server's `_validate_role_assignment`
 *     would reject.
 *   - CREDENTIALS: user create/reset takes an admin-TYPED password (server rules:
 *     ≥12 + upper/lower/digit/special). It is sent once and NEVER logged, echoed,
 *     or displayed — the server hashes it and returns no secret. There is no
 *     generated-password or reset-link flow (the server has none), so we mirror
 *     exactly: an admin sets the password.
 *   - DESTRUCTIVE actions (deactivate user, deactivate tenant, delete asset/
 *     identity/IOC, remove agent-mapping) go behind a confirm Dialog.
 *   - Every panel has explicit submitting / typed-error / success states and
 *     refetches via `onChanged`. No optimistic fabrication.
 *   - Anonymization token REVERSE-LOOKUP is deliberately NOT wired (safety by
 *     omission — see AdminTab's note); this file exposes no path to raw PII.
 */

import {
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { Chip, Dialog, Panel, StatusState, Table, TBody, TD, TH, THead, TR } from "@/components";
import {
  ApiError,
  assignTenantAgents,
  createAdminAsset,
  createAdminIdentity,
  createAdminLocalIoc,
  createAdminTenant,
  createAdminUser,
  deleteAdminAsset,
  deleteAdminIdentity,
  deleteAdminLocalIoc,
  getAdminAssets,
  getAdminIdentities,
  getAdminLocalIocs,
  getTenantAgents,
  reloadEnrichers,
  reloadGuidance,
  removeTenantAgent,
  saveShiftHandoff,
  updateAdminTenant,
  updateAdminUser,
} from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { adminActionGate, assignableRoles } from "@/lib/rbac";
import { cn, focusRing } from "@/lib/ui";
import { DASH, fmtDateTime } from "@/lib/format";
import type {
  AdminAsset,
  AdminIdentity,
  AdminLocalIoc,
  AdminTenant,
  AdminUser,
  Role,
  TenantAgentRow,
} from "@/lib/types";

// ---- shared styling (matches IncidentActions form controls) -----------------

const FIELD_CLS =
  "mt-1 w-full rounded-lg border border-line bg-field px-2.5 py-2 text-data text-ink placeholder:text-dim2";
const BTN_PRIMARY =
  "rounded-md border-none bg-[#25406a] px-3 py-1.5 text-data text-white hover:brightness-110";
const BTN_NEUTRAL =
  "rounded-md border border-line bg-field px-2.5 py-1 text-meta text-ink hover:bg-hover";
const BTN_DANGER =
  "rounded-md border border-sev-crit/40 bg-field px-2.5 py-1 text-meta text-sev-crit hover:bg-hover";

function disabledCls(disabled: boolean): string {
  return disabled ? "cursor-not-allowed opacity-50" : "";
}

function errMessage(e: unknown): string {
  return e instanceof Error ? e.message : "Unknown error";
}

// ---- per-action write state hook (DRY) --------------------------------------

type WriteResult =
  | { ok: true; message?: string }
  | { ok: false; message: string }
  | null;

function useWrite(onChanged?: () => void) {
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<WriteResult>(null);

  const run = useCallback(
    async (fn: () => Promise<void>, successMsg?: string): Promise<boolean> => {
      setSubmitting(true);
      setResult(null);
      try {
        await fn();
        setResult({ ok: true, message: successMsg });
        onChanged?.();
        return true;
      } catch (e) {
        setResult({ ok: false, message: errMessage(e) });
        return false;
      } finally {
        setSubmitting(false);
      }
    },
    [onChanged],
  );

  return { submitting, result, run, setResult };
}

function ResultLine({ result }: { result: WriteResult }) {
  if (!result) return null;
  return result.ok ? (
    <span className="text-kbd text-grounded-ink" role="status">
      ✓ {result.message ?? "Saved."}
    </span>
  ) : (
    <span className="text-kbd text-sev-crit" role="alert">
      {result.message}
    </span>
  );
}

/** Small confirm dialog for destructive actions. */
function ConfirmDialog({
  open,
  title,
  body,
  confirmLabel,
  onConfirm,
  onCancel,
}: {
  open: boolean;
  title: string;
  body: ReactNode;
  confirmLabel: string;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  return (
    <Dialog open={open} onClose={onCancel} title={title} maxWidth={420}>
      <div className="text-data text-ink">{body}</div>
      <div className="mt-3 flex justify-end gap-2">
        <button type="button" onClick={onCancel} className={cn(BTN_NEUTRAL, focusRing)}>
          Cancel
        </button>
        <button
          type="button"
          onClick={onConfirm}
          className={cn(BTN_PRIMARY, focusRing)}
        >
          {confirmLabel}
        </button>
      </div>
    </Dialog>
  );
}

function LabeledField({
  label,
  required,
  children,
}: {
  label: string;
  required?: boolean;
  children: ReactNode;
}) {
  return (
    <div>
      <label className="text-kbd text-dim">
        {label}
        {required && <span className="ml-1 text-sev-crit">*</span>}
      </label>
      {children}
    </div>
  );
}

// ---- password policy (mirrors CreateUserRequest.validate_password) ----------
// Used ONLY to pre-disable submit + explain the rule; NEVER logs the value.
function passwordIssue(pw: string): string | null {
  if (pw.length < 12) return "at least 12 characters";
  if (!/[A-Z]/.test(pw)) return "an uppercase letter";
  if (!/[a-z]/.test(pw)) return "a lowercase letter";
  if (!/[0-9]/.test(pw)) return "a digit";
  if (!/[!@#$%^&*()\-_=+[\]{}|;:',.<>?/`~]/.test(pw)) return "a special character";
  return null;
}

const ROLE_LABEL: Record<string, string> = {
  mssp_admin: "MSSP admin",
  admin: "Admin",
  senior_analyst: "Senior analyst",
  analyst: "Analyst",
  read_only: "Read-only",
};

// =============================================================================
// USERS — create + edit (role / active / password reset)
// =============================================================================

function CreateUserForm({
  assignable,
  onDone,
}: {
  assignable: Role[];
  onDone: () => void;
}) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<string>(
    assignable.includes("analyst") ? "analyst" : (assignable[0] ?? "read_only"),
  );
  const { submitting, result, run } = useWrite();

  const pwIssue = password ? passwordIssue(password) : "at least 12 characters";
  const usernameOk = /^[a-z0-9._-]{2,50}$/.test(username.trim().toLowerCase());
  const canSubmit =
    !submitting && usernameOk && pwIssue === null && assignable.length > 0;

  const submit = async () => {
    if (!canSubmit) return;
    const ok = await run(
      () =>
        createAdminUser({
          username: username.trim().toLowerCase(),
          password, // sent once; never logged/echoed
          display_name: displayName.trim() || undefined,
          email: email.trim() || undefined,
          role,
        }).then(() => undefined),
      `User “${username.trim().toLowerCase()}” created.`,
    );
    if (ok) {
      setUsername("");
      setPassword("");
      setDisplayName("");
      setEmail("");
      onDone();
    }
  };

  return (
    <div className="flex flex-col gap-2">
      <LabeledField label="Username" required>
        <input
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          placeholder="lowercase, 2-50 chars (a-z 0-9 . _ -)"
          className={cn(FIELD_CLS, focusRing)}
          autoComplete="off"
        />
      </LabeledField>
      <LabeledField label="Initial password" required>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="≥12 chars · upper · lower · digit · special"
          className={cn(FIELD_CLS, focusRing)}
          autoComplete="new-password"
        />
        {pwIssue && (
          <div className="mt-1 text-kbd text-sev-med">
            Password needs {pwIssue}. The server enforces this (422 otherwise).
          </div>
        )}
      </LabeledField>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        <LabeledField label="Display name">
          <input
            type="text"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            className={cn(FIELD_CLS, focusRing)}
          />
        </LabeledField>
        <LabeledField label="Email">
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className={cn(FIELD_CLS, focusRing)}
          />
        </LabeledField>
      </div>
      <LabeledField label="Role" required>
        <select
          value={role}
          onChange={(e) => setRole(e.target.value)}
          className={cn(FIELD_CLS, focusRing)}
        >
          {assignable.map((r) => (
            <option key={r} value={r}>
              {ROLE_LABEL[r] ?? r}
            </option>
          ))}
        </select>
        <div className="mt-1 text-kbd text-dim2">
          Only roles you may assign are listed — the server rejects anything
          above your tier (and community licenses allow only analyst / read-only).
        </div>
      </LabeledField>
      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={submit}
          disabled={!canSubmit}
          className={cn(BTN_PRIMARY, disabledCls(!canSubmit), focusRing)}
        >
          {submitting ? "Creating…" : "Create user"}
        </button>
        <ResultLine result={result} />
      </div>
    </div>
  );
}

function EditUserDialog({
  user,
  assignable,
  onChanged,
  onClose,
}: {
  user: AdminUser;
  assignable: Role[];
  onChanged: () => void;
  onClose: () => void;
}) {
  const active = user.is_active === 1 || user.is_active === true;
  const [displayName, setDisplayName] = useState(user.display_name ?? "");
  const [email, setEmail] = useState(user.email ?? "");
  const [role, setRole] = useState<string>(String(user.role));
  const [newPw, setNewPw] = useState("");
  const [confirmDeactivate, setConfirmDeactivate] = useState(false);
  const profile = useWrite(onChanged);
  const pw = useWrite(onChanged);
  const activeState = useWrite(onChanged);

  const roleOptions = assignable.includes(role as Role)
    ? assignable
    : [role as Role, ...assignable]; // keep the current (non-assignable) role visible, read-only-ish

  const saveProfile = () =>
    profile.run(
      () =>
        updateAdminUser(user.id, {
          display_name: displayName.trim(),
          email: email.trim(),
          role: assignable.includes(role as Role) ? role : undefined,
        }).then(() => undefined),
      "Profile updated.",
    );

  const pwIssue = newPw ? passwordIssue(newPw) : "at least 12 characters";
  const resetPw = async () => {
    if (pwIssue) return;
    const ok = await pw.run(
      () => updateAdminUser(user.id, { password: newPw }).then(() => undefined),
      "Password reset.",
    );
    if (ok) setNewPw("");
  };

  const setActive = (next: boolean) =>
    activeState.run(
      () => updateAdminUser(user.id, { is_active: next }).then(() => undefined),
      next ? "User reactivated." : "User deactivated.",
    );

  return (
    <Dialog
      open
      onClose={onClose}
      title={`Edit ${user.display_name || user.username}`}
      maxWidth={520}
    >
      <div className="flex flex-col gap-3">
        <div className="text-kbd text-dim2">
          <span className="font-mono">{user.username}</span> ·{" "}
          {active ? "active" : "inactive"}
        </div>

        {/* profile + role */}
        <div className="flex flex-col gap-2 rounded-lg border border-line p-3">
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            <LabeledField label="Display name">
              <input
                type="text"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                className={cn(FIELD_CLS, focusRing)}
              />
            </LabeledField>
            <LabeledField label="Email">
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className={cn(FIELD_CLS, focusRing)}
              />
            </LabeledField>
          </div>
          <LabeledField label="Role">
            <select
              value={role}
              onChange={(e) => setRole(e.target.value)}
              className={cn(FIELD_CLS, focusRing)}
            >
              {roleOptions.map((r) => (
                <option key={r} value={r}>
                  {ROLE_LABEL[r] ?? r}
                </option>
              ))}
            </select>
            {!assignable.includes(role as Role) && (
              <div className="mt-1 text-kbd text-sev-med">
                You can’t assign this role — the server would reject it. Pick one
                you’re allowed to grant to change it.
              </div>
            )}
          </LabeledField>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={saveProfile}
              disabled={profile.submitting}
              className={cn(BTN_PRIMARY, disabledCls(profile.submitting), focusRing)}
            >
              {profile.submitting ? "Saving…" : "Save profile"}
            </button>
            <ResultLine result={profile.result} />
          </div>
        </div>

        {/* password reset */}
        <div className="flex flex-col gap-2 rounded-lg border border-line p-3">
          <LabeledField label="Reset password">
            <input
              type="password"
              value={newPw}
              onChange={(e) => setNewPw(e.target.value)}
              placeholder="≥12 chars · upper · lower · digit · special"
              className={cn(FIELD_CLS, focusRing)}
              autoComplete="new-password"
            />
            {newPw && pwIssue && (
              <div className="mt-1 text-kbd text-sev-med">
                Password needs {pwIssue}.
              </div>
            )}
          </LabeledField>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={resetPw}
              disabled={pw.submitting || !newPw || pwIssue !== null}
              className={cn(
                BTN_PRIMARY,
                disabledCls(pw.submitting || !newPw || pwIssue !== null),
                focusRing,
              )}
            >
              {pw.submitting ? "Resetting…" : "Reset password"}
            </button>
            <span className="text-kbd text-dim2">
              The new password is set directly (no reset link exists). It is never
              displayed or logged.
            </span>
            <ResultLine result={pw.result} />
          </div>
        </div>

        {/* active status (deactivate = destructive → confirm) */}
        <div className="flex flex-wrap items-center gap-2 rounded-lg border border-line p-3">
          <span className="text-kbd text-dim">
            Account is <b>{active ? "active" : "inactive"}</b>
          </span>
          {active ? (
            <button
              type="button"
              onClick={() => setConfirmDeactivate(true)}
              disabled={activeState.submitting}
              className={cn(BTN_DANGER, disabledCls(activeState.submitting), focusRing)}
            >
              Deactivate
            </button>
          ) : (
            <button
              type="button"
              onClick={() => setActive(true)}
              disabled={activeState.submitting}
              className={cn(BTN_NEUTRAL, disabledCls(activeState.submitting), focusRing)}
            >
              Reactivate
            </button>
          )}
          <ResultLine result={activeState.result} />
        </div>
      </div>

      <ConfirmDialog
        open={confirmDeactivate}
        title="Deactivate user?"
        body={
          <>
            Deactivate <b>{user.username}</b>? They will be unable to sign in.
            This is reversible (reactivate later). There is no hard-delete.
          </>
        }
        confirmLabel="Deactivate"
        onConfirm={() => {
          setConfirmDeactivate(false);
          setActive(false);
        }}
        onCancel={() => setConfirmDeactivate(false)}
      />
    </Dialog>
  );
}

/** The Users write controls: a "Create user" launcher + per-row Edit buttons. */
export function UserWriteControls({ onChanged }: { onChanged: () => void }) {
  const { role, tier } = useAuth();
  const gate = adminActionGate(role, "user_manage");
  const [createOpen, setCreateOpen] = useState(false);
  const assignable = assignableRoles(role, tier);

  if (!gate.visible) return null;

  return (
    <>
      <button
        type="button"
        onClick={() => setCreateOpen(true)}
        className={cn(BTN_PRIMARY, focusRing)}
      >
        + Create user
      </button>
      <Dialog
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title="Create user"
        maxWidth={520}
      >
        <CreateUserForm assignable={assignable} onDone={() => setCreateOpen(false)} />
      </Dialog>
    </>
  );
}

/** A per-row "Edit" button that opens the user-edit dialog. */
export function UserRowEdit({
  user,
  onChanged,
}: {
  user: AdminUser;
  onChanged: () => void;
}) {
  const { role, tier } = useAuth();
  const gate = adminActionGate(role, "user_manage");
  const [open, setOpen] = useState(false);
  if (!gate.visible) return null;
  const assignable = assignableRoles(role, tier);
  return (
    <>
      <button type="button" onClick={() => setOpen(true)} className={cn(BTN_NEUTRAL, focusRing)}>
        Edit
      </button>
      {open && (
        <EditUserDialog
          user={user}
          assignable={assignable}
          onChanged={onChanged}
          onClose={() => setOpen(false)}
        />
      )}
    </>
  );
}

// =============================================================================
// TENANTS (mssp_admin only) — create + rename/activate + agent mapping
// =============================================================================

function CreateTenantForm({ onDone }: { onDone: () => void }) {
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const { submitting, result, run } = useWrite();

  const slugOk = /^[a-z0-9][a-z0-9_-]{1,48}[a-z0-9]$/.test(slug.trim().toLowerCase());
  const canSubmit = !submitting && name.trim().length > 0 && slugOk;

  const submit = async () => {
    if (!canSubmit) return;
    const ok = await run(
      () =>
        createAdminTenant({
          name: name.trim(),
          slug: slug.trim().toLowerCase(),
        }).then(() => undefined),
      `Tenant “${name.trim()}” created.`,
    );
    if (ok) {
      setName("");
      setSlug("");
      onDone();
    }
  };

  return (
    <div className="flex flex-col gap-2">
      <LabeledField label="Tenant name" required>
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          className={cn(FIELD_CLS, focusRing)}
        />
      </LabeledField>
      <LabeledField label="Slug" required>
        <input
          type="text"
          value={slug}
          onChange={(e) => setSlug(e.target.value)}
          placeholder="3-50 lowercase · a-z 0-9 - _"
          className={cn(FIELD_CLS, "font-mono", focusRing)}
        />
        {slug && !slugOk && (
          <div className="mt-1 text-kbd text-sev-med">
            Slug must be 3-50 lowercase alphanumeric (hyphens/underscores).
          </div>
        )}
      </LabeledField>
      <div className="text-kbd text-dim2">
        Secrets (Wazuh, LLM keys) are configured out-of-band — this form never
        handles credentials. Requires multi-tenant mode to be enabled server-side.
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={submit}
          disabled={!canSubmit}
          className={cn(BTN_PRIMARY, disabledCls(!canSubmit), focusRing)}
        >
          {submitting ? "Creating…" : "Create tenant"}
        </button>
        <ResultLine result={result} />
      </div>
    </div>
  );
}

function TenantAgentsDialog({
  tenant,
  onClose,
}: {
  tenant: AdminTenant;
  onClose: () => void;
}) {
  const [agents, setAgents] = useState<TenantAgentRow[] | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [raw, setRaw] = useState("");
  const [confirmRemove, setConfirmRemove] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setLoadErr(null);
    try {
      const res = await getTenantAgents(tenant.id, ac.signal);
      if (!ac.signal.aborted) setAgents(res.agents);
    } catch (e) {
      if (!ac.signal.aborted) setLoadErr(errMessage(e));
    }
  }, [tenant.id]);

  useEffect(() => {
    load();
    return () => abortRef.current?.abort();
  }, [load]);

  const add = useWrite(load);
  const remove = useWrite(load);

  const ids = raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const idsOk = ids.length > 0 && ids.every((i) => /^\d{1,5}$/.test(i));

  const doAdd = async () => {
    if (!idsOk) return;
    const ok = await add.run(
      () => assignTenantAgents(tenant.id, ids).then(() => undefined),
      `Assigned ${ids.length} agent(s).`,
    );
    if (ok) setRaw("");
  };

  return (
    <Dialog
      open
      onClose={onClose}
      title={`Agent mapping — ${tenant.name}`}
      maxWidth={520}
    >
      <div className="flex flex-col gap-3">
        {loadErr ? (
          <StatusState
            variant="error"
            title="Couldn't load agent mappings"
            description={loadErr}
          />
        ) : agents === null ? (
          <StatusState variant="loading" title="Loading agents…" />
        ) : agents.length === 0 ? (
          <div className="text-data text-dim2">No agents mapped to this tenant.</div>
        ) : (
          <div className="overflow-hidden rounded-lg border border-line">
            <Table>
              <THead>
                <TR>
                  <TH>Agent ID</TH>
                  <TH>Added</TH>
                  <TH className="text-right">Action</TH>
                </TR>
              </THead>
              <TBody>
                {agents.map((a) => (
                  <TR key={a.agent_id}>
                    <TD mono>{a.agent_id}</TD>
                    <TD>{a.added_at ? fmtDateTime(a.added_at) : DASH}</TD>
                    <TD className="text-right">
                      <button
                        type="button"
                        onClick={() => setConfirmRemove(a.agent_id)}
                        className={cn(BTN_DANGER, focusRing)}
                      >
                        Remove
                      </button>
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          </div>
        )}

        <div className="flex flex-col gap-1 rounded-lg border border-line p-3">
          <LabeledField label="Assign agent IDs (numeric, comma-separated)">
            <input
              type="text"
              value={raw}
              onChange={(e) => setRaw(e.target.value)}
              placeholder="001, 002, 010"
              className={cn(FIELD_CLS, "font-mono", focusRing)}
            />
          </LabeledField>
          {raw && !idsOk && (
            <div className="text-kbd text-sev-med">
              Agent IDs must be 1-5 digit numbers (Wazuh format).
            </div>
          )}
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={doAdd}
              disabled={add.submitting || !idsOk}
              className={cn(BTN_PRIMARY, disabledCls(add.submitting || !idsOk), focusRing)}
            >
              {add.submitting ? "Assigning…" : "Assign"}
            </button>
            <span className="text-kbd text-dim2">
              Agents already mapped elsewhere are reported as conflicts.
            </span>
            <ResultLine result={add.result} />
          </div>
          <ResultLine result={remove.result} />
        </div>
      </div>

      <ConfirmDialog
        open={confirmRemove !== null}
        title="Remove agent mapping?"
        body={
          <>
            Unmap agent <b className="font-mono">{confirmRemove}</b> from{" "}
            <b>{tenant.name}</b>?
          </>
        }
        confirmLabel="Remove"
        onConfirm={() => {
          const aid = confirmRemove;
          setConfirmRemove(null);
          if (aid)
            remove.run(
              () => removeTenantAgent(tenant.id, aid).then(() => undefined),
              `Removed agent ${aid}.`,
            );
        }}
        onCancel={() => setConfirmRemove(null)}
      />
    </Dialog>
  );
}

/** Tenant write controls: a "Create tenant" launcher (mssp_admin only). */
export function TenantWriteControls({ onChanged }: { onChanged: () => void }) {
  const { role } = useAuth();
  const gate = adminActionGate(role, "tenant_manage");
  const [open, setOpen] = useState(false);
  if (!gate.visible) return null;
  return (
    <>
      <button type="button" onClick={() => setOpen(true)} className={cn(BTN_PRIMARY, focusRing)}>
        + Create tenant
      </button>
      <Dialog open={open} onClose={() => setOpen(false)} title="Create tenant" maxWidth={520}>
        <CreateTenantForm
          onDone={() => {
            setOpen(false);
            onChanged();
          }}
        />
      </Dialog>
    </>
  );
}

/** Per-row tenant actions: rename / activate-deactivate / manage agents. */
export function TenantRowActions({
  tenant,
  onChanged,
}: {
  tenant: AdminTenant;
  onChanged: () => void;
}) {
  const { role } = useAuth();
  const gate = adminActionGate(role, "tenant_manage");
  const [renameOpen, setRenameOpen] = useState(false);
  const [agentsOpen, setAgentsOpen] = useState(false);
  const [confirmToggle, setConfirmToggle] = useState(false);
  const [name, setName] = useState(tenant.name);
  const rename = useWrite(onChanged);
  const toggle = useWrite(onChanged);
  if (!gate.visible) return null;

  const doRename = async () => {
    if (!name.trim()) return;
    const ok = await rename.run(
      () => updateAdminTenant(tenant.id, { name: name.trim() }).then(() => undefined),
      "Tenant renamed.",
    );
    if (ok) setRenameOpen(false);
  };

  const setActive = (next: boolean) =>
    toggle.run(
      () => updateAdminTenant(tenant.id, { active: next }).then(() => undefined),
      next ? "Tenant activated." : "Tenant deactivated.",
    );

  return (
    <div className="flex flex-wrap items-center justify-end gap-1.5">
      <button type="button" onClick={() => setAgentsOpen(true)} className={cn(BTN_NEUTRAL, focusRing)}>
        Agents
      </button>
      <button type="button" onClick={() => setRenameOpen(true)} className={cn(BTN_NEUTRAL, focusRing)}>
        Rename
      </button>
      {tenant.active ? (
        <button
          type="button"
          onClick={() => setConfirmToggle(true)}
          disabled={toggle.submitting}
          className={cn(BTN_DANGER, disabledCls(toggle.submitting), focusRing)}
        >
          Deactivate
        </button>
      ) : (
        <button
          type="button"
          onClick={() => setActive(true)}
          disabled={toggle.submitting}
          className={cn(BTN_NEUTRAL, disabledCls(toggle.submitting), focusRing)}
        >
          Activate
        </button>
      )}
      <ResultLine result={toggle.result} />

      <Dialog open={renameOpen} onClose={() => setRenameOpen(false)} title="Rename tenant" maxWidth={420}>
        <LabeledField label="Tenant name" required>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className={cn(FIELD_CLS, focusRing)}
          />
        </LabeledField>
        <div className="mt-2 flex items-center gap-2">
          <button
            type="button"
            onClick={doRename}
            disabled={rename.submitting || !name.trim()}
            className={cn(BTN_PRIMARY, disabledCls(rename.submitting || !name.trim()), focusRing)}
          >
            {rename.submitting ? "Saving…" : "Save"}
          </button>
          <ResultLine result={rename.result} />
        </div>
      </Dialog>

      {agentsOpen && (
        <TenantAgentsDialog tenant={tenant} onClose={() => setAgentsOpen(false)} />
      )}

      <ConfirmDialog
        open={confirmToggle}
        title="Deactivate tenant?"
        body={
          <>
            Deactivate <b>{tenant.name}</b>? Its services stop processing until
            reactivated. This also recomputes multi-tenant mode.
          </>
        }
        confirmLabel="Deactivate"
        onConfirm={() => {
          setConfirmToggle(false);
          setActive(false);
        }}
        onCancel={() => setConfirmToggle(false)}
      />
    </div>
  );
}

// =============================================================================
// SETTINGS — assets / identities / local IOCs (admin+)
// =============================================================================

const ASSET_TIERS = [
  "tier_1_critical",
  "tier_2_important",
  "tier_3_standard",
  "tier_4_low",
  "unknown",
] as const;
const ENVIRONMENTS = ["production", "staging", "development", "testing", "unknown"] as const;
const RISK_LEVELS = ["critical", "high_risk", "elevated", "standard", "low_risk"] as const;
const IOC_TYPES = ["ip", "domain", "hash"] as const;
const IOC_SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

function csv(v: string): string[] {
  return v
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

/** A generic self-fetching settings section shell. */
function useSettingsList<T>(fetcher: (s: AbortSignal) => Promise<T>) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const abortRef = useRef<AbortController | null>(null);
  const load = useCallback(async () => {
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setLoading(true);
    setError(null);
    try {
      const res = await fetcher(ac.signal);
      if (!ac.signal.aborted) setData(res);
    } catch (e) {
      if (!ac.signal.aborted) setError(errMessage(e));
    } finally {
      if (!ac.signal.aborted) setLoading(false);
    }
    // fetcher is a stable module-level api fn
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  useEffect(() => {
    load();
    return () => abortRef.current?.abort();
  }, [load]);
  return { data, error, loading, reload: load };
}

export function AssetsSection() {
  const { role } = useAuth();
  const gate = adminActionGate(role, "settings_crud");
  const { data, error, loading, reload } = useSettingsList((s) => getAdminAssets(s));
  const [confirmDel, setConfirmDel] = useState<AdminAsset | null>(null);
  const create = useWrite(reload);
  const del = useWrite(reload);

  const [hostname, setHostname] = useState("");
  const [tier, setTier] = useState<string>("unknown");
  const [owner, setOwner] = useState("");
  const [environment, setEnvironment] = useState<string>("unknown");
  const [mult, setMult] = useState("1.0");
  const [tags, setTags] = useState("");
  const [services, setServices] = useState("");

  const canCreate = gate.canSubmit && hostname.trim().length > 0 && !create.submitting;
  const submitCreate = async () => {
    if (!canCreate) return;
    const ok = await create.run(
      () =>
        createAdminAsset({
          hostname: hostname.trim(),
          tier,
          owner: owner.trim() || undefined,
          environment,
          criticality_multiplier: Number(mult) || 1.0,
          tags: csv(tags),
          services: csv(services),
        }).then(() => undefined),
      `Asset “${hostname.trim()}” added.`,
    );
    if (ok) {
      setHostname("");
      setOwner("");
      setTags("");
      setServices("");
      setMult("1.0");
    }
  };

  const assets = data?.assets ?? [];

  return (
    <Panel className="p-4">
      <div className="mb-2 text-title text-ink">Assets</div>
      {gate.visible && (
        <div className="mb-3 flex flex-col gap-2 rounded-lg border border-line p-3">
          <div className="text-kbd uppercase tracking-wider text-dim2">Add asset</div>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            <LabeledField label="Hostname" required>
              <input type="text" value={hostname} onChange={(e) => setHostname(e.target.value)} className={cn(FIELD_CLS, focusRing)} />
            </LabeledField>
            <LabeledField label="Owner">
              <input type="text" value={owner} onChange={(e) => setOwner(e.target.value)} className={cn(FIELD_CLS, focusRing)} />
            </LabeledField>
            <LabeledField label="Tier">
              <select value={tier} onChange={(e) => setTier(e.target.value)} className={cn(FIELD_CLS, focusRing)}>
                {ASSET_TIERS.map((t) => (
                  <option key={t} value={t}>{t.replace(/_/g, " ")}</option>
                ))}
              </select>
            </LabeledField>
            <LabeledField label="Environment">
              <select value={environment} onChange={(e) => setEnvironment(e.target.value)} className={cn(FIELD_CLS, focusRing)}>
                {ENVIRONMENTS.map((e2) => (
                  <option key={e2} value={e2}>{e2}</option>
                ))}
              </select>
            </LabeledField>
            <LabeledField label="Criticality × (0.1–10)">
              <input type="number" step="0.1" min="0.1" max="10" value={mult} onChange={(e) => setMult(e.target.value)} className={cn(FIELD_CLS, focusRing)} />
            </LabeledField>
            <LabeledField label="Tags (comma-sep)">
              <input type="text" value={tags} onChange={(e) => setTags(e.target.value)} className={cn(FIELD_CLS, focusRing)} />
            </LabeledField>
            <LabeledField label="Services (comma-sep)">
              <input type="text" value={services} onChange={(e) => setServices(e.target.value)} className={cn(FIELD_CLS, focusRing)} />
            </LabeledField>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button type="button" onClick={submitCreate} disabled={!canCreate} className={cn(BTN_PRIMARY, disabledCls(!canCreate), focusRing)}>
              {create.submitting ? "Adding…" : "Add asset"}
            </button>
            <ResultLine result={create.result} />
          </div>
        </div>
      )}

      {loading && !data ? (
        <StatusState variant="loading" title="Loading assets…" />
      ) : error && !data ? (
        <StatusState variant="error" title="Couldn't load assets" description={error} action={<Chip onClick={reload}>Retry</Chip>} />
      ) : assets.length === 0 ? (
        <StatusState variant="empty" title="No assets" description="No asset criticality overrides are configured." />
      ) : (
        <div className="overflow-hidden rounded-lg border border-line">
          <Table>
            <THead>
              <TR>
                <TH>Hostname</TH>
                <TH>Tier</TH>
                <TH>Env</TH>
                <TH>Owner</TH>
                <TH className="text-right">×</TH>
                <TH className="text-right">Action</TH>
              </TR>
            </THead>
            <TBody>
              {assets.map((a) => (
                <TR key={a.id}>
                  <TD mono>{a.hostname}</TD>
                  <TD>{(a.tier ?? DASH).replace(/_/g, " ")}</TD>
                  <TD>{a.environment ?? DASH}</TD>
                  <TD>{a.owner ?? DASH}</TD>
                  <TD mono className="text-right">{a.criticality_multiplier ?? DASH}</TD>
                  <TD className="text-right">
                    {gate.visible && (
                      <button type="button" onClick={() => setConfirmDel(a)} className={cn(BTN_DANGER, focusRing)}>
                        Delete
                      </button>
                    )}
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        </div>
      )}
      <ResultLine result={del.result} />

      <ConfirmDialog
        open={confirmDel !== null}
        title="Delete asset?"
        body={<>Delete asset <b className="font-mono">{confirmDel?.hostname}</b>? Its criticality override is removed.</>}
        confirmLabel="Delete"
        onConfirm={() => {
          const a = confirmDel;
          setConfirmDel(null);
          if (a) del.run(() => deleteAdminAsset(a.id).then(() => undefined), "Asset deleted.");
        }}
        onCancel={() => setConfirmDel(null)}
      />
    </Panel>
  );
}

export function IdentitiesSection() {
  const { role } = useAuth();
  const gate = adminActionGate(role, "settings_crud");
  const { data, error, loading, reload } = useSettingsList((s) => getAdminIdentities(s));
  const [confirmDel, setConfirmDel] = useState<AdminIdentity | null>(null);
  const create = useWrite(reload);
  const del = useWrite(reload);

  const [username, setUsername] = useState("");
  const [riskLevel, setRiskLevel] = useState<string>("standard");
  const [mult, setMult] = useState("1.0");
  const [isAdmin, setIsAdmin] = useState(false);
  const [isSvc, setIsSvc] = useState(false);
  const [department, setDepartment] = useState("");

  const canCreate = gate.canSubmit && username.trim().length > 0 && !create.submitting;
  const submitCreate = async () => {
    if (!canCreate) return;
    const ok = await create.run(
      () =>
        createAdminIdentity({
          username: username.trim(),
          risk_level: riskLevel,
          risk_multiplier: Number(mult) || 1.0,
          is_admin: isAdmin,
          is_service_account: isSvc,
          department: department.trim() || undefined,
        }).then(() => undefined),
      `Identity “${username.trim()}” added.`,
    );
    if (ok) {
      setUsername("");
      setDepartment("");
      setIsAdmin(false);
      setIsSvc(false);
      setMult("1.0");
    }
  };

  const identities = data?.identities ?? [];

  return (
    <Panel className="p-4">
      <div className="mb-2 text-title text-ink">Identities</div>
      {gate.visible && (
        <div className="mb-3 flex flex-col gap-2 rounded-lg border border-line p-3">
          <div className="text-kbd uppercase tracking-wider text-dim2">Add identity</div>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            <LabeledField label="Username" required>
              <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} className={cn(FIELD_CLS, focusRing)} />
            </LabeledField>
            <LabeledField label="Department">
              <input type="text" value={department} onChange={(e) => setDepartment(e.target.value)} className={cn(FIELD_CLS, focusRing)} />
            </LabeledField>
            <LabeledField label="Risk level">
              <select value={riskLevel} onChange={(e) => setRiskLevel(e.target.value)} className={cn(FIELD_CLS, focusRing)}>
                {RISK_LEVELS.map((r) => (
                  <option key={r} value={r}>{r.replace(/_/g, " ")}</option>
                ))}
              </select>
            </LabeledField>
            <LabeledField label="Risk × (0.1–10)">
              <input type="number" step="0.1" min="0.1" max="10" value={mult} onChange={(e) => setMult(e.target.value)} className={cn(FIELD_CLS, focusRing)} />
            </LabeledField>
          </div>
          <div className="flex flex-wrap gap-4">
            <label className="flex items-center gap-1.5 text-data text-ink">
              <input type="checkbox" checked={isAdmin} onChange={(e) => setIsAdmin(e.target.checked)} /> Privileged
            </label>
            <label className="flex items-center gap-1.5 text-data text-ink">
              <input type="checkbox" checked={isSvc} onChange={(e) => setIsSvc(e.target.checked)} /> Service account
            </label>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button type="button" onClick={submitCreate} disabled={!canCreate} className={cn(BTN_PRIMARY, disabledCls(!canCreate), focusRing)}>
              {create.submitting ? "Adding…" : "Add identity"}
            </button>
            <ResultLine result={create.result} />
          </div>
        </div>
      )}

      {loading && !data ? (
        <StatusState variant="loading" title="Loading identities…" />
      ) : error && !data ? (
        <StatusState variant="error" title="Couldn't load identities" description={error} action={<Chip onClick={reload}>Retry</Chip>} />
      ) : identities.length === 0 ? (
        <StatusState variant="empty" title="No identities" description="No identity risk overrides are configured." />
      ) : (
        <div className="overflow-hidden rounded-lg border border-line">
          <Table>
            <THead>
              <TR>
                <TH>Username</TH>
                <TH>Risk</TH>
                <TH>Dept</TH>
                <TH>Flags</TH>
                <TH className="text-right">×</TH>
                <TH className="text-right">Action</TH>
              </TR>
            </THead>
            <TBody>
              {identities.map((i) => (
                <TR key={i.id}>
                  <TD mono>{i.username}</TD>
                  <TD>{(i.risk_level ?? DASH).replace(/_/g, " ")}</TD>
                  <TD>{i.department ?? DASH}</TD>
                  <TD>
                    <div className="flex flex-wrap gap-1">
                      {i.is_admin && <Chip>privileged</Chip>}
                      {i.is_service_account && <Chip>service</Chip>}
                    </div>
                  </TD>
                  <TD mono className="text-right">{i.risk_multiplier ?? DASH}</TD>
                  <TD className="text-right">
                    {gate.visible && (
                      <button type="button" onClick={() => setConfirmDel(i)} className={cn(BTN_DANGER, focusRing)}>
                        Delete
                      </button>
                    )}
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        </div>
      )}
      <ResultLine result={del.result} />

      <ConfirmDialog
        open={confirmDel !== null}
        title="Delete identity?"
        body={<>Delete identity <b className="font-mono">{confirmDel?.username}</b>? Its risk override is removed.</>}
        confirmLabel="Delete"
        onConfirm={() => {
          const i = confirmDel;
          setConfirmDel(null);
          if (i) del.run(() => deleteAdminIdentity(i.id).then(() => undefined), "Identity deleted.");
        }}
        onCancel={() => setConfirmDel(null)}
      />
    </Panel>
  );
}

export function LocalIocsSection() {
  const { role } = useAuth();
  const gate = adminActionGate(role, "settings_crud");
  const { data, error, loading, reload } = useSettingsList((s) => getAdminLocalIocs(s));
  const [confirmDel, setConfirmDel] = useState<AdminLocalIoc | null>(null);
  const create = useWrite(reload);
  const del = useWrite(reload);

  const [iocType, setIocType] = useState<string>("ip");
  const [value, setValue] = useState("");
  const [severity, setSeverity] = useState<string>("medium");
  const [description, setDescription] = useState("");

  const canCreate = gate.canSubmit && value.trim().length > 0 && !create.submitting;
  const submitCreate = async () => {
    if (!canCreate) return;
    const ok = await create.run(
      () =>
        createAdminLocalIoc({
          ioc_type: iocType,
          value: value.trim(),
          severity,
          description: description.trim() || undefined,
        }).then(() => undefined),
      "Local IOC added.",
    );
    if (ok) {
      setValue("");
      setDescription("");
    }
  };

  const iocs = data?.iocs ?? [];

  return (
    <Panel className="p-4">
      <div className="mb-2 text-title text-ink">Local IOCs</div>
      {gate.visible && (
        <div className="mb-3 flex flex-col gap-2 rounded-lg border border-line p-3">
          <div className="text-kbd uppercase tracking-wider text-dim2">Add IOC (create + delete only — no edit endpoint)</div>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            <LabeledField label="Type">
              <select value={iocType} onChange={(e) => setIocType(e.target.value)} className={cn(FIELD_CLS, focusRing)}>
                {IOC_TYPES.map((t) => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
            </LabeledField>
            <LabeledField label="Severity">
              <select value={severity} onChange={(e) => setSeverity(e.target.value)} className={cn(FIELD_CLS, focusRing)}>
                {IOC_SEVERITIES.map((s) => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
            </LabeledField>
            <LabeledField label="Value" required>
              <input type="text" value={value} onChange={(e) => setValue(e.target.value)} placeholder="ip / domain / hash" className={cn(FIELD_CLS, "font-mono", focusRing)} />
            </LabeledField>
            <LabeledField label="Description">
              <input type="text" value={description} onChange={(e) => setDescription(e.target.value)} className={cn(FIELD_CLS, focusRing)} />
            </LabeledField>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button type="button" onClick={submitCreate} disabled={!canCreate} className={cn(BTN_PRIMARY, disabledCls(!canCreate), focusRing)}>
              {create.submitting ? "Adding…" : "Add IOC"}
            </button>
            <ResultLine result={create.result} />
          </div>
        </div>
      )}

      {loading && !data ? (
        <StatusState variant="loading" title="Loading local IOCs…" />
      ) : error && !data ? (
        <StatusState variant="error" title="Couldn't load local IOCs" description={error} action={<Chip onClick={reload}>Retry</Chip>} />
      ) : iocs.length === 0 ? (
        <StatusState variant="empty" title="No local IOCs" description="No tenant-local indicators are configured." />
      ) : (
        <div className="overflow-hidden rounded-lg border border-line">
          <Table>
            <THead>
              <TR>
                <TH>Type</TH>
                <TH>Value</TH>
                <TH>Severity</TH>
                <TH>Description</TH>
                <TH className="text-right">Action</TH>
              </TR>
            </THead>
            <TBody>
              {iocs.map((i) => (
                <TR key={i.id}>
                  <TD><Chip mono>{i.ioc_type}</Chip></TD>
                  <TD mono>{i.value}</TD>
                  <TD>{i.severity ?? DASH}</TD>
                  <TD>{i.description || DASH}</TD>
                  <TD className="text-right">
                    {gate.visible && (
                      <button type="button" onClick={() => setConfirmDel(i)} className={cn(BTN_DANGER, focusRing)}>
                        Delete
                      </button>
                    )}
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        </div>
      )}
      <ResultLine result={del.result} />

      <ConfirmDialog
        open={confirmDel !== null}
        title="Delete local IOC?"
        body={<>Delete the {confirmDel?.ioc_type} indicator <b className="font-mono">{confirmDel?.value}</b>?</>}
        confirmLabel="Delete"
        onConfirm={() => {
          const i = confirmDel;
          setConfirmDel(null);
          if (i) del.run(() => deleteAdminLocalIoc(i.id).then(() => undefined), "Local IOC deleted.");
        }}
        onCancel={() => setConfirmDel(null)}
      />
    </Panel>
  );
}

// =============================================================================
// OPERATIONS — reload guidance / enrichers (confirm→POST→toast) + shift handoff
// =============================================================================

export function OperationsSection() {
  const { role } = useAuth();
  const reloadGate = adminActionGate(role, "reload");
  const handoffGate = adminActionGate(role, "handoff");
  const guidance = useWrite();
  const enrichers = useWrite();
  const handoff = useWrite();
  const [confirmGuidance, setConfirmGuidance] = useState(false);
  const [confirmEnrichers, setConfirmEnrichers] = useState(false);
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");

  const doHandoff = async () => {
    if (!from.trim() || !to.trim()) return;
    const ok = await handoff.run(
      () =>
        saveShiftHandoff({ shift_from: from.trim(), shift_to: to.trim() })
          .then(() => undefined)
          .catch((e) => {
            // Shift management is a paid (SLA) feature. The Admin tab is always
            // accessible, so a Community senior_analyst/admin can reach this
            // form. In Community the route module is tier-stripped → 404 (vs a
            // 402/403 license gate on a paid tier). Translate all three into one
            // clear "not on this tier" line instead of a raw "Not Found".
            if (
              e instanceof ApiError &&
              (e.status === 402 || e.status === 403 || e.status === 404)
            ) {
              throw new ApiError(
                e.status,
                "Shift handoff requires the SLA (shift management) license feature — not available on this tier.",
              );
            }
            throw e;
          }),
      "Shift handoff saved.",
    );
    if (ok) {
      setFrom("");
      setTo("");
    }
  };

  return (
    <div className="flex flex-col gap-3">
      {reloadGate.visible && (
        <Panel className="p-4">
          <div className="mb-1 text-title text-ink">Runtime reloads</div>
          <div className="mb-3 text-kbd text-dim2">
            Hot-reload the institutional-knowledge YAMLs and enrichment tables the
            agents read at runtime — no restart. Both are audit-logged.
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <button
              type="button"
              onClick={() => setConfirmGuidance(true)}
              disabled={guidance.submitting}
              className={cn(BTN_PRIMARY, disabledCls(guidance.submitting), focusRing)}
            >
              {guidance.submitting ? "Reloading…" : "Reload guidance"}
            </button>
            <ResultLine result={guidance.result} />
          </div>
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <button
              type="button"
              onClick={() => setConfirmEnrichers(true)}
              disabled={enrichers.submitting}
              className={cn(BTN_NEUTRAL, disabledCls(enrichers.submitting), focusRing)}
            >
              {enrichers.submitting ? "Reloading…" : "Reload enrichers"}
            </button>
            <ResultLine result={enrichers.result} />
          </div>
          <div className="mt-2 text-kbd text-dim2">
            Guidance reload is rate-limited to 2/min server-side.
          </div>

          <ConfirmDialog
            open={confirmGuidance}
            title="Reload guidance?"
            body="Reload risk criteria, escalation logic, and playbook YAMLs from disk. Takes effect immediately for new triage."
            confirmLabel="Reload"
            onConfirm={() => {
              setConfirmGuidance(false);
              guidance.run(() => reloadGuidance().then(() => undefined), "Guidance reloaded.");
            }}
            onCancel={() => setConfirmGuidance(false)}
          />
          <ConfirmDialog
            open={confirmEnrichers}
            title="Reload enrichers?"
            body="Reload the asset / identity / local-IOC enrichment tables into the running enrichment service."
            confirmLabel="Reload"
            onConfirm={() => {
              setConfirmEnrichers(false);
              enrichers.run(() => reloadEnrichers().then(() => undefined), "Enrichers reloaded.");
            }}
            onCancel={() => setConfirmEnrichers(false)}
          />
        </Panel>
      )}

      {handoffGate.visible && (
        <Panel className="p-4">
          <div className="mb-1 text-title text-ink">Shift handoff</div>
          <div className="mb-3 text-kbd text-dim2">
            Snapshot the current shift report and record who is handing off to
            whom. Requires the SLA (shift management) license feature server-side.
          </div>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            <LabeledField label="Shift from" required>
              <input type="text" value={from} onChange={(e) => setFrom(e.target.value)} placeholder="e.g. day" className={cn(FIELD_CLS, focusRing)} />
            </LabeledField>
            <LabeledField label="Shift to" required>
              <input type="text" value={to} onChange={(e) => setTo(e.target.value)} placeholder="e.g. night" className={cn(FIELD_CLS, focusRing)} />
            </LabeledField>
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={doHandoff}
              disabled={handoff.submitting || !from.trim() || !to.trim()}
              className={cn(BTN_PRIMARY, disabledCls(handoff.submitting || !from.trim() || !to.trim()), focusRing)}
            >
              {handoff.submitting ? "Saving…" : "Save handoff"}
            </button>
            <ResultLine result={handoff.result} />
          </div>
        </Panel>
      )}
    </div>
  );
}
