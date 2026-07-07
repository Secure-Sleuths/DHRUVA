/**
 * RBAC + license-tier gating — the client-side MIRROR of the server.
 *
 * ============================ INVARIANT ====================================
 * `TAB_ACCESS` and the role hierarchy below MIRROR the FastAPI backend's
 * `require_role` gates (src/api/auth.py / dependencies.py). The client is
 * defense-in-depth, NOT the enforcement point — the server always re-checks.
 * The client must NEVER grant access the server denies (never widen). If you
 * find a mismatch vs the backend, FLAG it — do not "fix" it by widening.
 *
 * Ported verbatim from the approved mockup
 * (docs/design/analyst-dashboard-mockup.html — the `GROUPS`, `TAB_ACCESS`,
 * `TIER_TABS`, and `_TAB_NAME_MAP` consts).
 * ===========================================================================
 */

import {
  AlertTriangle,
  BarChart3,
  BookOpen,
  Crosshair,
  FileSearch,
  FileText,
  Grid3x3,
  Layers,
  LayoutDashboard,
  Radar,
  RefreshCcw,
  ScanEye,
  Settings,
  ShieldAlert,
  Sparkles,
  Sun,
  Terminal,
  Ticket,
  Workflow,
  type LucideIcon,
} from "lucide-react";
import type { LicenseTierInfo, Role } from "./types";

// ---- Role hierarchy ---------------------------------------------------------
/** Roles least → most privileged. `mssp_admin` is the superuser (passes all). */
export const ROLE_ORDER: readonly Role[] = [
  "read_only",
  "analyst",
  "senior_analyst",
  "admin",
  "mssp_admin",
];

export function isRole(value: unknown): value is Role {
  return typeof value === "string" && (ROLE_ORDER as readonly string[]).includes(value);
}

/** True if `role` is at least `min` on the cumulative hierarchy. */
export function roleAtLeast(role: Role, min: Role): boolean {
  return ROLE_ORDER.indexOf(role) >= ROLE_ORDER.indexOf(min);
}

// ---- IA (nav groups + tabs) -------------------------------------------------
export interface TabDef {
  id: string;
  label: string;
  icon: LucideIcon;
}
export type NavGroup = readonly [group: string, tabs: readonly TabDef[]];

/** Four nav groups, in order — matches the mockup's `GROUPS` and the backend. */
export const GROUPS: readonly NavGroup[] = [
  [
    "Operations",
    [
      { id: "dailyreview", label: "Daily Review", icon: Sun },
      { id: "overview", label: "Overview", icon: LayoutDashboard },
      { id: "triage", label: "Triage", icon: ScanEye },
      { id: "incidents", label: "Incidents", icon: AlertTriangle },
    ],
  ],
  [
    "Intelligence",
    [
      { id: "detection", label: "Detection", icon: Radar },
      { id: "hunt", label: "Hunt", icon: Crosshair },
      { id: "feedback", label: "Closed Loop", icon: RefreshCcw },
      { id: "investigate", label: "Investigate", icon: Sparkles },
      { id: "mitre", label: "MITRE", icon: Grid3x3 },
      { id: "threatintel", label: "Threat Intel", icon: ShieldAlert },
      { id: "knowledge", label: "Knowledge", icon: BookOpen },
    ],
  ],
  [
    "Response",
    [
      { id: "soar", label: "SOAR", icon: Workflow },
      { id: "tickets", label: "Tickets", icon: Ticket },
      { id: "respond", label: "Respond", icon: Terminal },
      { id: "fim", label: "Host Integrity", icon: FileSearch },
      { id: "groups", label: "Agent Groups", icon: Layers },
    ],
  ],
  [
    "System",
    [
      { id: "metrics", label: "Metrics", icon: BarChart3 },
      { id: "reports", label: "Reports", icon: FileText },
      { id: "admin", label: "Admin", icon: Settings },
    ],
  ],
];

/** Flat map: tab id → label (for headings, dialogs, fallbacks). */
export const TAB_LABEL: Record<string, string> = Object.fromEntries(
  GROUPS.flatMap(([, tabs]) => tabs.map((t) => [t.id, t.label])),
);

/**
 * Role ACL per tab — mirrors the server's `require_role`. A tab is HIDDEN from
 * the sidebar if the active role is not in its list. NEVER widen these.
 */
export const TAB_ACCESS: Record<string, readonly Role[]> = {
  dailyreview: ["mssp_admin", "admin", "senior_analyst", "analyst", "read_only"],
  overview: ["mssp_admin", "admin", "senior_analyst", "analyst", "read_only"],
  triage: ["mssp_admin", "admin", "senior_analyst", "analyst"],
  incidents: ["mssp_admin", "admin", "senior_analyst", "analyst", "read_only"],
  detection: ["mssp_admin", "admin", "senior_analyst"],
  hunt: ["mssp_admin", "admin", "senior_analyst"],
  feedback: ["mssp_admin", "admin", "senior_analyst"],
  investigate: ["mssp_admin", "admin", "senior_analyst", "analyst"],
  mitre: ["mssp_admin", "admin", "senior_analyst", "analyst", "read_only"],
  threatintel: ["mssp_admin", "admin", "senior_analyst", "analyst", "read_only"],
  knowledge: ["mssp_admin", "admin", "senior_analyst", "analyst", "read_only"],
  soar: ["mssp_admin", "admin", "senior_analyst"],
  tickets: ["mssp_admin", "admin", "senior_analyst", "analyst", "read_only"],
  respond: ["mssp_admin", "admin", "senior_analyst"],
  fim: ["mssp_admin", "admin", "senior_analyst", "analyst"],
  groups: ["mssp_admin"],
  metrics: ["mssp_admin", "admin", "senior_analyst"],
  reports: ["mssp_admin", "admin", "senior_analyst"],
  admin: ["mssp_admin", "admin"],
};

/** A tab is visible in the sidebar iff the role is in its ACL. */
export function isTabVisible(tabId: string, role: Role): boolean {
  return (TAB_ACCESS[tabId] ?? []).includes(role);
}

// ---- Triage-review write gate (WO-U4) — MIRRORS the server ------------------
/**
 * The client-side mirror of the `POST /api/triage/review` authorization the
 * server enforces (src/api/routes/triage.py + WO-B10). The UI must NEVER offer
 * an action the server will reject:
 *
 *   - `read_only`         → view-only. The server's `require_role` excludes it
 *                           (no write path), so the whole verdict panel is
 *                           disabled.
 *   - `analyst`+          → may submit a FIRST human verdict (no existing one).
 *   - EXISTING verdict    → OVERRIDE is admin-only (WO-B10). `analyst` /
 *                           `senior_analyst` see the recorded verdict read-only
 *                           with a "requires admin to override" note; only
 *                           `admin` / `mssp_admin` may change it.
 *
 * The server remains the source of truth and re-checks; this only prevents dead
 * controls. NEVER widen (e.g. never let an analyst override).
 */
export type TriageWriteMode =
  | "first" // analyst+ recording the first human verdict
  | "override" // admin+ changing an existing human verdict
  | "readonly" // read_only — no write path at all
  | "override-denied"; // analyst/senior_analyst blocked from an existing-verdict override

export interface TriageWriteGate {
  /** the panel may submit a review */
  canSubmit: boolean;
  mode: TriageWriteMode;
  /** plain-language reason the panel is locked (for the disabled note) */
  lockNote?: string;
}

export function triageReviewGate(
  role: Role,
  hasExistingVerdict: boolean,
): TriageWriteGate {
  if (!roleAtLeast(role, "analyst")) {
    return {
      canSubmit: false,
      mode: "readonly",
      lockNote:
        "Read-only role — recording a verdict needs an analyst or higher. The server rejects writes from this role.",
    };
  }
  if (hasExistingVerdict && !roleAtLeast(role, "admin")) {
    return {
      canSubmit: false,
      mode: "override-denied",
      lockNote:
        "A human verdict is already recorded. Overriding it requires an admin — the server allows the override only for admin roles (WO-B10).",
    };
  }
  return {
    canSubmit: true,
    mode: hasExistingVerdict ? "override" : "first",
  };
}

// ---- Incident case-management write gate (WO-U4) — MIRRORS the server -------
/**
 * The client-side mirror of the per-action authorization the server enforces in
 * `src/api/routes/incidents.py`. The UI must NEVER offer an action the server
 * will reject — but the server always re-checks; this only prevents dead
 * controls. NEVER widen.
 *
 * Server contract mirrored here:
 *   - status / note / evidence  → `require_role("admin","senior_analyst","analyst")`
 *     PLUS `_check_incident_access`: an `analyst` may act ONLY on an incident
 *     assigned to them (admin / senior_analyst bypass the ownership check).
 *   - flag                      → `require_role(...,"analyst")`, NO ownership check.
 *   - assign / escalate / merge / review → `require_role("admin","senior_analyst")`.
 *   - merge ALSO needs the `incidents_merge` LICENSE feature (see `mergeLicensed`).
 *
 * `read_only` has no write path for any of these (excluded by `require_role`),
 * so every action is hidden from it.
 */
export type IncidentAction =
  | "status"
  | "note"
  | "evidence"
  | "flag"
  | "assign"
  | "escalate"
  | "merge"
  | "review";

/** Actions the server restricts to senior_analyst+ (no ownership check applies). */
const SENIOR_ACTIONS: ReadonlySet<IncidentAction> = new Set([
  "assign",
  "escalate",
  "merge",
  "review",
]);

/** Actions gated by `_check_incident_access` (analyst must own the incident). */
const OWNERSHIP_ACTIONS: ReadonlySet<IncidentAction> = new Set([
  "status",
  "note",
  "evidence",
]);

export interface IncidentActionGate {
  /**
   * The role is in the server's `require_role` set for this action. When false
   * the control is HIDDEN (a dead control the server would 403). When true but
   * `canSubmit` is false, the control is shown DISABLED with `lockNote` (the
   * role generally can, but not on THIS incident — an ownership block the user
   * needs explained).
   */
  visible: boolean;
  /** the panel may fire the write (role + ownership both satisfied). */
  canSubmit: boolean;
  reason: "ok" | "role" | "ownership";
  /** plain-language reason the control is disabled (for the disabled note). */
  lockNote?: string;
}

/**
 * @param role       the effective (mirrored) role.
 * @param action     which incident write.
 * @param isOwner    is the current user the incident's assignee?
 *                   `true` / `false` when known; `null` when UNKNOWN (e.g. no
 *                   `sub` claim in dev-preview) — ownership is then NOT blocked
 *                   client-side and the server remains the enforcement point.
 */
export function incidentActionGate(
  role: Role,
  action: IncidentAction,
  isOwner: boolean | null,
): IncidentActionGate {
  const min: Role = SENIOR_ACTIONS.has(action) ? "senior_analyst" : "analyst";
  if (!roleAtLeast(role, min)) {
    return {
      visible: false,
      canSubmit: false,
      reason: "role",
      lockNote:
        min === "senior_analyst"
          ? "Requires a senior analyst or higher — the server rejects this write from your role."
          : "Requires an analyst or higher — the server rejects this write from your role.",
    };
  }
  // Ownership only constrains a plain `analyst`; senior_analyst+ bypass it
  // server-side. `isOwner === null` (unknown) does NOT block — the server checks.
  if (
    OWNERSHIP_ACTIONS.has(action) &&
    !roleAtLeast(role, "senior_analyst") &&
    isOwner === false
  ) {
    return {
      visible: true,
      canSubmit: false,
      reason: "ownership",
      lockNote:
        "This incident is not assigned to you — only its assignee or a senior analyst can change it here. The server enforces this (403).",
    };
  }
  return { visible: true, canSubmit: true, reason: "ok" };
}

/**
 * Client-side mirror of the server's `incidents_merge` license gate
 * (`require_license_feature("incidents_merge")` → `License.has_feature`, which
 * treats `"full"` as a wildcard). Fails toward LOCKED when tier-info is absent.
 * Never widens: an unlisted feature returns false (the server 403s regardless).
 */
export function mergeLicensed(tier: LicenseTierInfo | null): boolean {
  if (!tier) return false; // fail-safe: no license info → treat as not licensed
  const f = tier.features ?? [];
  return f.includes("incidents_merge") || f.includes("full");
}

// ---- License tier gating ----------------------------------------------------
/**
 * UI-tab-id → LICENSE-tab-name (from app.js `_TAB_NAME_MAP`). The tier-info
 * `tabs` array uses license names; everything not listed maps to itself.
 */
export const TAB_NAME_MAP: Record<string, string> = {
  dailyreview: "daily_review",
  threatintel: "threat_intel",
  knowledge: "knowledge_base",
};

export function licenseTabName(tabId: string): string {
  return TAB_NAME_MAP[tabId] ?? tabId;
}

/**
 * Tier-lock rule — mirrors the legacy `_isTabLocked` in app.js. A tab is LOCKED
 * (visible but with a lock + upgrade overlay) iff:
 *   - it is NOT `admin` (Admin is never locked), AND
 *   - the license is not full (`features` does NOT include "full"), AND
 *   - the license-tab-name for the tab is not in `tabs`.
 *
 * Fails toward LOCKED when tier-info is unavailable (null) — never toward
 * unlocked. (Admin still passes so the app never fully bricks.)
 */
export function isTabLocked(
  tabId: string,
  tier: LicenseTierInfo | null,
): boolean {
  if (tabId === "admin") return false;
  if (!tier) return true; // fail-safe: no license info → treat paid tabs as locked
  if (tier.features?.includes("full")) return false;
  return !tier.tabs?.includes(licenseTabName(tabId));
}

/** The NL-Query copilot is a paid module. Present iff `nl_query` (or `full`). */
export function copilotAvailable(tier: LicenseTierInfo | null): boolean {
  if (!tier) return false; // fail-safe: degrade to locked
  return (
    tier.features?.includes("nl_query") === true ||
    tier.features?.includes("full") === true
  );
}

/** Show the "Community → upgrade" affordance when free or on the community tier. */
export function showUpgradeAffordance(tier: LicenseTierInfo | null): boolean {
  if (!tier) return false;
  return tier.is_free === true || tier.tier === "community";
}

// ---- Dev-preview synthetic tier-info ---------------------------------------
/**
 * A SYNTHETIC tier-info for the dev role/tier switcher, so the shell can be
 * eyeballed without a real license. In production the REAL `GET
 * /api/license/tier-info` payload is used instead; this is preview-only and is
 * never the production source of truth.
 *
 * Mirrors the mockup's `TIER_TABS`.
 */
const TIER_TABS: Record<string, string[] | "ALL"> = {
  community: [
    "dailyreview",
    "overview",
    "incidents",
    "tickets",
    "mitre",
    "threatintel",
    "knowledge",
    "admin",
  ],
  team: [
    "dailyreview",
    "overview",
    "triage",
    "incidents",
    "detection",
    "feedback",
    "investigate",
    "mitre",
    "threatintel",
    "knowledge",
    "soar",
    "tickets",
    "respond",
    "fim",
    "metrics",
    "reports",
    "admin",
  ],
  enterprise: "ALL",
};

const ALL_UI_TABS: string[] = GROUPS.flatMap(([, tabs]) => tabs.map((t) => t.id));

export function syntheticTierInfo(tier: string): LicenseTierInfo {
  const uiTabs = TIER_TABS[tier];
  const tabsList = uiTabs === "ALL" ? ALL_UI_TABS : (uiTabs ?? []);
  const licenseTabs = tabsList.map(licenseTabName);
  const features: string[] =
    tier === "enterprise"
      ? ["full", "nl_query"]
      : tier === "team"
        ? ["nl_query"]
        : []; // community strips paid modules
  return {
    tier,
    tier_display: tier.charAt(0).toUpperCase() + tier.slice(1),
    is_free: tier === "community",
    tabs: licenseTabs,
    features,
    upgrade_url: "https://securesleuths.in/pricing",
  };
}

/** The tiers the dev switcher offers. */
export const DEV_TIERS: readonly string[] = ["community", "team", "enterprise"];

// =============================================================================
// Active-response write gate (Respond tab) — MIRRORS the server
// -----------------------------------------------------------------------------
// Client-side mirror of the `require_role("senior_analyst","admin","mssp_admin")`
// gate the server enforces on `POST /api/response/approve/{id}`, `/execute`, and
// `/reverse/{id}` (src/api/routes/response.py). The server is the source of truth
// and re-checks every call; this only prevents dead controls. FAIL CLOSED: below
// senior_analyst there is no write path, so the controls are disabled with a
// plain-language lock note. NEVER widen (never let an analyst/read_only approve,
// execute, or reverse). The Respond tab's own TAB_ACCESS is already
// senior_analyst+, so in normal use every viewer passes — this gate is the
// defensive belt-and-braces that keeps the controls honest if that ever changes.
// =============================================================================
export interface ResponseActionGate {
  /** may approve a pending proposal (which the server also dispatches) */
  canApprove: boolean;
  /** may reverse (unblock) an active block_ip */
  canReverse: boolean;
  /** plain-language reason the controls are locked (for the disabled note) */
  lockNote?: string;
}

export function responseActionGate(role: Role): ResponseActionGate {
  if (!roleAtLeast(role, "senior_analyst")) {
    return {
      canApprove: false,
      canReverse: false,
      lockNote:
        "Approving, executing, or reversing a containment action requires a " +
        "senior analyst or higher. The server rejects these writes from this " +
        "role — the controls are shown locked, not hidden, so the queue stays " +
        "reviewable.",
    };
  }
  // senior_analyst, admin, mssp_admin — mirrors the server require_role exactly.
  return { canApprove: true, canReverse: true };
}

// =============================================================================
// Vulnerability-remediation write gate (Host Integrity `vuln` view) — MIRRORS
// the server · ACTIVE-RESPONSE-ADJACENT · ADMIN-ONLY (STRICTER than Respond/SOAR)
// -----------------------------------------------------------------------------
// Client-side mirror of the authorization on `POST /api/vulnerabilities/remediate`
// (src/api/routes/response.py::execute_remediation). This endpoint runs a REAL
// package-update command on a host via Wazuh active response, so it is
// deliberately the STRICTER gate: `require_admin` ⇒ ADMIN | mssp_admin ONLY —
// NOT senior_analyst (unlike responseActionGate / soarExecutionGate). The server
// ALSO enforces `require_license_feature("vuln_remediation")`, a 3/min rate limit,
// `_verify_agent_access`, and a Linux-only platform restriction; those are RUNTIME
// concerns the tab surfaces (402/403 → locked, 429 → rate-limited, 400 → platform
// unsupported), not pre-hidden here. FAILS CLOSED. The server re-checks every call
// and remains the enforcement point; this only prevents a dead control. NEVER
// widen — a senior_analyst or below must never get an enabled Remediate trigger.
// =============================================================================
export interface VulnRemediationGate {
  /** trigger a package-update remediation on a host — admin+ (require_admin). */
  canRemediate: boolean;
  /** plain-language note when the remediate control is locked. */
  lockNote?: string;
}

export function vulnRemediationGate(role: Role): VulnRemediationGate {
  const canRemediate = roleAtLeast(role, "admin"); // require_admin ⇒ admin | mssp_admin
  return {
    canRemediate,
    lockNote: canRemediate
      ? undefined
      : "Remediating a vulnerability runs a package-update command on the host via active response, so the server restricts it to administrators (require_admin — stricter than the other response actions). The control is shown locked, not hidden.",
  };
}

// =============================================================================
// Detection-engineering write gate (Detection tab) — MIRRORS the server
// -----------------------------------------------------------------------------
// Client-side mirror of the per-action authorization in
// `src/api/routes/detection.py`. The Detection tab itself is senior_analyst+
// (TAB_ACCESS.detection), but the WRITE actions have DIFFERENT, stricter gates —
// this mirrors each one EXACTLY and FAILS CLOSED. The server re-checks every
// call and remains the enforcement point; this only prevents dead controls.
// NEVER widen (in particular: deploy/rollback are mssp_admin ONLY — never admin).
//
// Server contract mirrored here:
//   - review (approve/reject) → require_role("admin","senior_analyst") [+mssp
//     bypass] ⇒ senior_analyst+.
//   - deploy                  → require_role("mssp_admin") ONLY. A Wazuh rule
//     change hits the SHARED backend across every tenant.
//   - rollback                → require_role("mssp_admin") ONLY.
//   - test / dry-run (validate) → require_admin ⇒ admin | mssp_admin.
// All are also behind require_license_feature("detection") (a runtime 402/403
// degrades the whole surface to FeatureLockedState — handled in the tab, not
// here). There is NO "edit before deploy" endpoint server-side, so no gate for
// it — the tab stubs that honestly.
// =============================================================================
export interface DetectionActionGate {
  /** approve/reject a proposal — senior_analyst+ (a lifecycle transition). */
  canReview: boolean;
  /** deploy an approved proposal to the SHARED Wazuh backend — mssp_admin ONLY. */
  canDeploy: boolean;
  /** roll a deployed rule back — mssp_admin ONLY. */
  canRollback: boolean;
  /** dry-run-test rule XML via wazuh-logtest — admin+ (read-only, no live change). */
  canTest: boolean;
  /** plain-language note for review controls when locked. */
  reviewLockNote?: string;
  /** plain-language note for deploy/rollback controls when locked. */
  deployLockNote?: string;
  /** plain-language note for the test control when locked. */
  testLockNote?: string;
}

export function detectionActionGate(role: Role): DetectionActionGate {
  const canReview = roleAtLeast(role, "senior_analyst");
  // mssp_admin ONLY — require_role("mssp_admin"). Do NOT widen to admin: a
  // shared-Wazuh rule change is intentionally the most privileged action.
  const canDeploy = role === "mssp_admin";
  const canRollback = role === "mssp_admin";
  const canTest = roleAtLeast(role, "admin"); // require_admin ⇒ admin | mssp_admin
  return {
    canReview,
    canDeploy,
    canRollback,
    canTest,
    reviewLockNote: canReview
      ? undefined
      : "Approving or rejecting a proposal requires a senior analyst or higher — the server rejects this write from your role.",
    deployLockNote: canDeploy
      ? undefined
      : "Deploying or rolling back a rule changes the shared Wazuh ruleset for every tenant, so the server restricts it to mssp_admin. The control is shown locked, not hidden, so the proposal stays reviewable.",
    testLockNote: canTest
      ? undefined
      : "Testing rule XML against wazuh-logtest requires an admin or higher — the server rejects this from your role.",
  };
}

// =============================================================================
// Tickets write gate (Tickets tab) — MIRRORS the server
// -----------------------------------------------------------------------------
// Client-side mirror of the per-action authorization in
// `src/api/routes/tickets.py`. The Tickets tab is visible to ALL roles
// (TAB_ACCESS.tickets includes read_only), but the WRITE actions are gated
// tighter — this mirrors each EXACTLY and FAILS CLOSED. The server re-checks
// every call and remains the enforcement point; this only prevents dead
// controls. NEVER widen. All three are ALSO behind
// require_license_feature("ticketing") (a runtime 402/403 degrades the whole
// surface to FeatureLockedState — handled in the tab).
//
// Server contract mirrored here:
//   - create  → require_role("admin","senior_analyst","analyst","mssp_admin")
//               ⇒ analyst+ (read_only has NO write path). Body carries a required
//               incident_id; NO reason required. 503 if ticketing is disabled.
//   - sync    → require_role("admin","senior_analyst","mssp_admin") ⇒
//               senior_analyst+ (NOTE: a plain `analyst` may create but NOT
//               force-sync — the gate reflects that asymmetry).
//   - retry   → require_role("admin","senior_analyst","mssp_admin") ⇒
//               senior_analyst+. The server also only retries a ticket whose
//               platform_status == "error" (400 otherwise); the tab offers Retry
//               only on error rows so it never fires a request the server rejects.
//
// There is NO ticket status/assignee/comment WRITE endpoint on this server —
// ticket status/assignee flow INBOUND from the external tracker via the HMAC
// webhook (`/api/webhooks/tickets/{provider}`), DHRUVA never pushes them. The
// tab stubs those honestly rather than inventing a client-only mutation.
// =============================================================================
export interface TicketActionGate {
  /** create a ticket from an incident — analyst+ (read_only excluded). */
  canCreate: boolean;
  /** force a re-sync of a ticket's status — senior_analyst+. */
  canSync: boolean;
  /** retry a failed (error-state) ticket push — senior_analyst+. */
  canRetry: boolean;
  /** plain-language note for the create control when locked. */
  createLockNote?: string;
  /** plain-language note for the sync/retry controls when locked. */
  syncLockNote?: string;
}

export function ticketActionGate(role: Role): TicketActionGate {
  const canCreate = roleAtLeast(role, "analyst");
  const canSync = roleAtLeast(role, "senior_analyst");
  return {
    canCreate,
    canSync,
    canRetry: canSync, // same server gate as sync (senior_analyst+)
    createLockNote: canCreate
      ? undefined
      : "Creating a ticket requires an analyst or higher — the server rejects this write from a read-only role.",
    syncLockNote: canSync
      ? undefined
      : "Forcing a re-sync or retrying a failed push requires a senior analyst or higher — the server rejects these from your role (a plain analyst may create a ticket but not re-sync it).",
  };
}

// =============================================================================
// SOAR write gates (SOAR tab) — MIRRORS the server · ACTIVE-RESPONSE-ADJACENT
// -----------------------------------------------------------------------------
// Client-side mirror of the authorization in `src/api/routes/soar.py`. The SOAR
// tab is senior_analyst+ (TAB_ACCESS.soar), but the WRITE actions have DIFFERENT
// server gates — this mirrors each EXACTLY and FAILS CLOSED. The server
// re-checks every call and remains the enforcement point. NEVER widen. All are
// ALSO behind require_license_feature("soar") (a runtime 402/403 degrades the
// whole surface to FeatureLockedState — handled in the tab).
//
// ACTIVE-RESPONSE POSTURE (the standing rule — unchanged by this UI):
// SOAR playbooks CONTAIN containment actions (block_ip / isolate_host /
// disable_user; see src/soar/playbooks.py). This makes SOAR writes
// active-response-adjacent, so every one below is confirm-gated in the tab and
// the copy NEVER implies auto-execution:
//   - APPROVE an execution runs it: on approval the engine dispatches the
//     execution's planned containment actions (engine.approve → _execute). The
//     `pending_approval` queue IS the human gate; approving is the human
//     completing it. Server gate: require_role("admin","senior_analyst") ⇒
//     senior_analyst+. Confirm dialog lists the exact actions before dispatch.
//   - TOGGLE (enable/disable a playbook) does NOT execute anything now — it
//     changes eligibility. When an ENABLED playbook later triggers, a containment
//     step still routes to the pending_approval human queue (require_approval);
//     the engine's M3 backstop keeps isolate/disable/kill ALWAYS-HUMAN even on a
//     require_approval=0 path, and only block_ip may auto-run — and only via the
//     SEPARATE per-tenant auto-block policy (default OFF), not touched here.
//     Server gate: require_role("admin") ⇒ admin+.
//   - REJECT cancels a pending execution (no containment runs). senior_analyst+.
//   - ROLLBACK reverses a completed execution's containment (inverse actions —
//     unblock/unisolate/enable). Server gate: require_role("admin") ⇒ admin+.
// There is NO manual "run playbook now" endpoint on this server (executions are
// engine-generated from real triage decisions), so no such control is offered —
// nothing can start containment from scratch here.
// =============================================================================
export interface SoarPlaybookGate {
  /** enable/disable a playbook — admin+ (require_role("admin")). */
  canToggle: boolean;
  /** plain-language note when the toggle is locked. */
  lockNote?: string;
}

export function soarPlaybookGate(role: Role): SoarPlaybookGate {
  const canToggle = roleAtLeast(role, "admin"); // require_role("admin") + mssp bypass
  return {
    canToggle,
    lockNote: canToggle
      ? undefined
      : "Enabling or disabling a playbook is an admin-only action server-side — a playbook governs whether containment can fire, so the server restricts the toggle to admins. The control is shown locked, not hidden.",
  };
}

export interface SoarExecutionGate {
  /** approve a pending execution — WHICH DISPATCHES ITS ACTIONS. senior_analyst+. */
  canApprove: boolean;
  /** reject/cancel a pending execution (no containment runs). senior_analyst+. */
  canReject: boolean;
  /** rollback a completed execution (reverse its containment). admin+. */
  canRollback: boolean;
  /** plain-language note for approve/reject controls when locked. */
  approveLockNote?: string;
  /** plain-language note for the rollback control when locked. */
  rollbackLockNote?: string;
}

export function soarExecutionGate(role: Role): SoarExecutionGate {
  const canApprove = roleAtLeast(role, "senior_analyst"); // require_role(admin, senior_analyst)
  const canRollback = roleAtLeast(role, "admin"); // require_role("admin")
  return {
    canApprove,
    canReject: canApprove, // same server gate as approve
    canRollback,
    approveLockNote: canApprove
      ? undefined
      : "Approving or rejecting a queued SOAR execution requires a senior analyst or higher — approving DISPATCHES the playbook's containment actions, so the server human-gates it. The control is shown locked, not hidden.",
    rollbackLockNote: canRollback
      ? undefined
      : "Rolling back a completed execution (reversing its containment) is admin-only server-side. The control is shown locked, not hidden.",
  };
}

// =============================================================================
// Closed-loop / feedback write gate (Closed Loop tab) — MIRRORS the server
// -----------------------------------------------------------------------------
// Client-side mirror of `src/api/routes/feedback.py`. The tab is senior_analyst+
// (TAB_ACCESS.feedback), but the only WRITE — trigger a feedback analysis cycle
// — is require_admin ⇒ admin | mssp_admin (and rate-limited 2/min server-side).
// FAILS CLOSED. The server re-checks and remains the enforcement point; this
// only prevents a dead control. NEVER widen. Also behind
// require_license_feature("feedback_loop") (402/403 → FeatureLockedState).
//
// There is NO per-pattern accept/dismiss endpoint and NO "mark a noisy rule for
// the Detection queue" endpoint on this server — the loop mines patterns
// automatically and the Detection AGENT turns them into rule proposals (reviewed
// on the Detection tab). Running a cycle re-mines patterns + regenerates those
// proposals. The tab stubs accept/dismiss/mark-for-detection honestly rather
// than inventing client-only mutations.
// =============================================================================
export interface FeedbackActionGate {
  /** trigger a feedback analysis cycle — admin+ (require_admin). */
  canRunCycle: boolean;
  /** plain-language note when the run-cycle control is locked. */
  lockNote?: string;
}

export function feedbackActionGate(role: Role): FeedbackActionGate {
  const canRunCycle = roleAtLeast(role, "admin"); // require_admin ⇒ admin | mssp_admin
  return {
    canRunCycle,
    lockNote: canRunCycle
      ? undefined
      : "Running a feedback cycle re-mines patterns and regenerates tuning proposals across the tenant, so the server restricts it to admins (require_admin). The control is shown locked, not hidden.",
  };
}

// =============================================================================
// Threat-intel collection gate (Threat Intel tab) — MIRRORS the server
// -----------------------------------------------------------------------------
// Client-side mirror of the authorization on `POST /api/threat-intel/collect`
// (src/api/routes/threat_intel.py). The Threat Intel TAB is visible to ALL roles
// (TAB_ACCESS.threatintel includes read_only) and its data is READ-ONLY, but the
// one WRITE — manually triggering a TI collection cycle — is gated tighter:
// require_role("admin","senior_analyst") ⇒ SENIOR_ANALYST+ (a plain analyst /
// read_only has NO trigger path). FAILS CLOSED. The server re-checks every call,
// is rate-limited 2/min, and remains the enforcement point; this only prevents a
// dead control. NEVER widen. Also behind require_license_feature("ti_feeds_tier1")
// (a runtime 402/403 degrades the whole surface to FeatureLockedState — handled
// in the tab, not here). There is no other TI write endpoint on this server (IOC
// lookup / CVE / stats / feeds are all reads), so no other gate is offered.
// =============================================================================
export interface TICollectGate {
  /** trigger a TI collection cycle — senior_analyst+ (require_role admin, senior_analyst). */
  canCollect: boolean;
  /** plain-language note when the collect control is locked. */
  lockNote?: string;
}

export function tiCollectGate(role: Role): TICollectGate {
  const canCollect = roleAtLeast(role, "senior_analyst"); // require_role(admin, senior_analyst) + mssp bypass
  return {
    canCollect,
    lockNote: canCollect
      ? undefined
      : "Running a threat-intel collection cycle refreshes every feed for the tenant, so the server restricts it to a senior analyst or higher. The control is shown locked, not hidden.",
  };
}

// =============================================================================
// Admin write-action gate (Admin tab) — MIRRORS the server
// -----------------------------------------------------------------------------
// Client-side mirror of the `require_role`/`require_admin` gates on the admin
// mutating endpoints (src/api/routes/admin.py + the guidance-reload in
// health.py). The server is the source of truth and re-checks every call; this
// only prevents dead controls. FAIL CLOSED, NEVER widen. The Admin TAB itself is
// already admin+ (TAB_ACCESS.admin), so a plain analyst never reaches these; the
// meaningful split this gate enforces inside the tab is mssp_admin-only tenant
// management vs the admin-level settings/user/reload actions.
//
// Server contract mirrored here (per endpoint):
//   - user create/edit ............ POST /api/admin/users[/{id}]        require_role("admin")
//   - assets/identities/IOC CRUD .. /api/admin/settings/*              require_role("admin")
//   - reload enrichers ............ POST /api/admin/settings/reload-enrichers  require_role("admin")
//   - guidance reload ............. POST /api/guidance/reload           require_admin
//   - shift handoff ............... POST /api/admin/shifts/handoff      require_role("admin","senior_analyst") + "sla" license
//   - tenant create/edit/agents ... /api/admin/tenants*                require_role("mssp_admin") (+ multi_tenant on create)
// =============================================================================
export type AdminAction =
  | "user_manage" // create / edit / role-change / deactivate — admin+
  | "settings_crud" // assets / identities / local-IOCs — admin+
  | "reload" // guidance reload + reload-enrichers — admin+
  | "handoff" // shift handoff — senior_analyst+ (server also needs the "sla" license)
  | "tenant_manage"; // tenant create / edit / agent-mapping — mssp_admin ONLY

export interface AdminActionGate {
  /** the role is in the server's require_role set — else the control is HIDDEN. */
  visible: boolean;
  /** the panel may fire the write. */
  canSubmit: boolean;
  /** plain-language reason the control is hidden/locked. */
  lockNote?: string;
}

export function adminActionGate(role: Role, action: AdminAction): AdminActionGate {
  const min: Role =
    action === "tenant_manage"
      ? "mssp_admin"
      : action === "handoff"
        ? "senior_analyst"
        : "admin";
  if (!roleAtLeast(role, min)) {
    return {
      visible: false,
      canSubmit: false,
      lockNote:
        min === "mssp_admin"
          ? "Tenant management is restricted to the MSSP administrator — the server rejects it (403) for a plain admin."
          : "Requires an administrator — the server rejects this write from your role.",
    };
  }
  return { visible: true, canSubmit: true };
}

// ---- Assignable-role hierarchy (mirrors admin.py `_validate_role_assignment`) --
/**
 * The set of roles an actor may ASSIGN when creating/editing a user, mirroring
 * the server's `_ASSIGNABLE_ROLES` + `_COMMUNITY_ASSIGNABLE_ROLES`
 * (src/api/routes/admin.py). An `admin` may NOT mint another `admin` (or
 * `mssp_admin`); only `mssp_admin` may assign `admin`. On the community tier the
 * server further restricts assignment to `{analyst, read_only}`.
 *
 * FAIL CLOSED: when tier-info is absent we cannot confirm a paid license, so we
 * apply the community restriction (the narrowest set) — the server re-checks and
 * 403s anything wider regardless. NEVER widen.
 */
const ASSIGNABLE_BY_ACTOR: Record<string, readonly Role[]> = {
  mssp_admin: ["admin", "senior_analyst", "analyst", "read_only"],
  admin: ["senior_analyst", "analyst", "read_only"],
};
const COMMUNITY_ASSIGNABLE: readonly Role[] = ["analyst", "read_only"];

export function assignableRoles(
  actorRole: Role,
  tier: LicenseTierInfo | null,
): Role[] {
  const base = ASSIGNABLE_BY_ACTOR[actorRole] ?? [];
  // Fail closed: unknown/absent tier or an explicit community tier → narrowest set.
  const community =
    !tier || tier.tier === "community" || tier.is_free === true;
  const allowed = community
    ? base.filter((r) => COMMUNITY_ASSIGNABLE.includes(r))
    : base;
  return [...allowed];
}

// =============================================================================
// Hunt write gate (Hunt tab) — MIRRORS the server
// -----------------------------------------------------------------------------
// Client-side mirror of the per-action authorization in `src/api/routes/hunt.py`.
// The Hunt TAB is senior_analyst+ (TAB_ACCESS.hunt), but the WRITE actions have
// DIFFERENT server gates — this mirrors each EXACTLY and FAILS CLOSED. The server
// re-checks every call and remains the enforcement point; this only prevents dead
// controls. NEVER widen.
//
// Server contract mirrored here (per endpoint):
//   - run cycle → POST /api/hunt/run            require_admin ⇒ admin | mssp_admin
//                 (+ require_license_feature("hunt"), rate-limited 3/min). Kicks a
//                 background hunt cycle for the tenant.
//   - review    → POST /api/hunt/review         require_role("admin","senior_analyst")
//                 ⇒ senior_analyst+ (+ "hunt" license). Confirm/dismiss a finding.
//                 CONFIRMING auto-creates an incident AND indexes the finding to
//                 the KB server-side — so confirm is treated as irreversible and
//                 gets an explicit confirm dialog. No server-side reason required
//                 (notes optional).
//   - replay    → POST /api/hunt/library/{id}/replay  require_role("admin",
//                 "senior_analyst") ⇒ senior_analyst+. NOTE: NOT license-gated
//                 (no `hunt` gate on this route). Re-executes a stored, key-
//                 validated OpenSearch query and RETURNS hit_count + sample hits —
//                 a read-ish action that mutates nothing, so no confirm dialog.
// =============================================================================
export interface HuntActionGate {
  /** trigger a background hunt cycle — admin+ (require_admin). */
  canRunCycle: boolean;
  /** confirm/dismiss a finding — senior_analyst+ (confirming auto-creates an incident). */
  canReview: boolean;
  /** re-run a saved hypothesis query — senior_analyst+ (read-ish, no mutation). */
  canReplay: boolean;
  /** plain-language note when the run-cycle control is locked. */
  runLockNote?: string;
  /** plain-language note when the review/replay controls are locked. */
  reviewLockNote?: string;
}

export function huntActionGate(role: Role): HuntActionGate {
  const canReview = roleAtLeast(role, "senior_analyst"); // require_role(admin, senior_analyst)
  const canRunCycle = roleAtLeast(role, "admin"); // require_admin ⇒ admin | mssp_admin
  return {
    canRunCycle,
    canReview,
    canReplay: canReview, // same server gate as review (senior_analyst+)
    runLockNote: canRunCycle
      ? undefined
      : "Triggering a hunt cycle re-runs every saved hypothesis against the alert corpus for the tenant, so the server restricts it to admins (require_admin). The control is shown locked, not hidden.",
    reviewLockNote: canReview
      ? undefined
      : "Confirming or dismissing a finding, and re-running a hypothesis, require a senior analyst or higher — the server rejects these writes from your role. Confirming a finding also auto-creates an incident server-side.",
  };
}

// =============================================================================
// Knowledge-base write gate (Knowledge tab) — MIRRORS the server
// -----------------------------------------------------------------------------
// Client-side mirror of the per-action authorization in
// `src/api/routes/knowledge_base.py`. The Knowledge TAB is visible to ALL roles
// (TAB_ACCESS.knowledge includes read_only), but the WRITE actions are gated
// tighter — with a DELIBERATE asymmetry this mirrors EXACTLY and FAILS CLOSED.
// The server re-checks every call and remains the enforcement point; this only
// prevents dead controls. NEVER widen. All three are ALSO behind
// require_license_feature("knowledge_base") (a runtime 402/403 degrades the whole
// surface to FeatureLockedState — handled in the tab).
//
// Server contract mirrored here (per endpoint) — note the create-vs-edit split:
//   - create → POST   /api/kb/documents        require_role("admin","senior_analyst",
//              "analyst","mssp_admin") ⇒ ANALYST+ (read_only has no write path).
//              Requires title+content; doc_type must be an allowed type. 503 if KB
//              disabled. No reason required.
//   - edit   → PUT    /api/kb/documents/{id}    require_role("admin","senior_analyst",
//              "mssp_admin") ⇒ SENIOR_ANALYST+. A plain `analyst` may CREATE a doc
//              but NOT edit one — the gate reflects that asymmetry exactly.
//   - delete → DELETE /api/kb/documents/{id}    same senior_analyst+ gate. DESTRUCTIVE
//              (hard delete) → the tab puts it behind an explicit confirm dialog.
//
// There is NO re-index / rebuild endpoint on this server — indexing is automatic
// (create/update write the tsvector; confirmed hunt findings self-index). The tab
// stubs any "rebuild index" affordance honestly rather than inventing one.
//
// ANONYMIZATION BOUNDARY: KB content is operational free-text authored by
// analysts; these forms carry title/content/tags/techniques only. This gate adds
// NO raw-identifier reverse-lookup surface (that risky Admin affordance is
// deliberately absent from the redesign) — nothing here resolves a token to PII.
// =============================================================================
export interface KnowledgeActionGate {
  /** create a KB document — analyst+ (read_only excluded). */
  canCreate: boolean;
  /** edit an existing KB document — senior_analyst+ (a plain analyst may create, not edit). */
  canEdit: boolean;
  /** hard-delete a KB document — senior_analyst+ (behind a confirm dialog). */
  canDelete: boolean;
  /** plain-language note when the create control is locked. */
  createLockNote?: string;
  /** plain-language note when the edit/delete controls are locked. */
  editLockNote?: string;
}

export function knowledgeActionGate(role: Role): KnowledgeActionGate {
  const canCreate = roleAtLeast(role, "analyst"); // require_role(..., "analyst", ...)
  const canEdit = roleAtLeast(role, "senior_analyst"); // require_role("admin","senior_analyst","mssp_admin")
  return {
    canCreate,
    canEdit,
    canDelete: canEdit, // same server gate as edit (senior_analyst+)
    createLockNote: canCreate
      ? undefined
      : "Adding a knowledge-base document requires an analyst or higher — the server rejects this write from a read-only role.",
    editLockNote: canEdit
      ? undefined
      : "Editing or deleting a document requires a senior analyst or higher — the server rejects these from your role (a plain analyst may add a document but not change or remove one).",
  };
}
