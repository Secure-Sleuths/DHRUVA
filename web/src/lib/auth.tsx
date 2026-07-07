"use client";

/**
 * Auth + gating context for the AI-SOC shell.
 *
 * Modelled on the sibling ASM repo's AuthProvider. Holds:
 *   - the JWT (localStorage-backed, see token.ts) and its decoded claims
 *     (DISPLAY ONLY — the server verifies + enforces),
 *   - the license tier-info fetched from `GET /api/license/tier-info`,
 *   - a dev role/tier OVERRIDE for previewing gating without a real login.
 *
 * SOURCE-OF-TRUTH RULES:
 *   - Real `role` comes from the JWT claim; real `tier` from tier-info.
 *   - The dev switcher only OVERRIDES for preview — it is never the production
 *     source of truth. When a real token is present, overrides start inactive.
 *   - Tier-info failure fails toward LOCKED/DEGRADED (never unlocked): a null
 *     effective tier locks every paid tab (see rbac.isTabLocked).
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { getTierInfo } from "./api";
import { decodeJwtClaims, getToken } from "./token";
import { isRole, syntheticTierInfo } from "./rbac";
import type { JwtClaims, LicenseTierInfo, Role } from "./types";

interface AuthState {
  /** true until the first client-side bootstrap (token read + tier fetch) settles */
  loading: boolean;
  /** a real JWT is present */
  authenticated: boolean;
  /** decoded JWT claims (display only) — null in dev-preview */
  claims: JwtClaims | null;

  /** the EFFECTIVE role used for gating (dev override → JWT → read_only) */
  role: Role;
  /** true when the dev switcher is overriding the role */
  roleIsPreview: boolean;

  /** the EFFECTIVE tier-info used for gating (dev override → real → null) */
  tier: LicenseTierInfo | null;
  /** true when the dev switcher is overriding the tier */
  tierIsPreview: boolean;
  /** the real tier-info fetch failed (we degrade toward locked) */
  tierError: string | null;

  /** tenant display name (JWT `tenant_name`, else a preview label) */
  tenantName: string;

  /** true only in a dev-preview build — gates the DevSwitcher + override path */
  devPreview: boolean;

  // dev switcher controls (no-ops in production — the switcher is not rendered)
  setDevRole: (role: Role | null) => void;
  setDevTier: (tier: string | null) => void;
  devRole: Role | null;
  devTier: string | null;
}

/**
 * Dev-preview gate. The dev role/tier switcher — and ANY client-side override of
 * the effective role/tier — exists ONLY in dev preview. In a PRODUCTION build the
 * effective role/tier come SOLELY from the JWT + `GET /api/license/tier-info`:
 * no override path, no switcher. Gated STRICTLY to non-production builds — there
 * is deliberately NO env-var escape hatch that could turn dev-preview on in a
 * production build (qa-audit F3: a stray `NEXT_PUBLIC_DHRUVA_DEV_PREVIEW=true`
 * on a real deploy would otherwise expose the switcher + skip the /login guard,
 * client-side). For a demo/screenshot bundle, build with NODE_ENV!==production.
 * `process.env.NODE_ENV` is statically inlined by Next, so the override branch
 * is dead-code-eliminated from a production bundle.
 */
export const DEV_PREVIEW = process.env.NODE_ENV !== "production";

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [loading, setLoading] = useState(true);
  const [claims, setClaims] = useState<JwtClaims | null>(null);
  const [authenticated, setAuthenticated] = useState(false);
  const [realTier, setRealTier] = useState<LicenseTierInfo | null>(null);
  const [tierError, setTierError] = useState<string | null>(null);

  // Dev overrides (dev-preview only — see DEV_PREVIEW). The login-less default
  // fails toward LEAST privilege: read_only + community-equivalent tier, so an
  // unauthenticated shell never visually implies elevated access. When a real
  // token is found during bootstrap we clear them so real values win. In a
  // production build these stay null and are never applied.
  const [devRole, setDevRole] = useState<Role | null>(
    DEV_PREVIEW ? "read_only" : null,
  );
  const [devTier, setDevTier] = useState<string | null>(
    DEV_PREVIEW ? "community" : null,
  );

  useEffect(() => {
    let cancelled = false;
    const token = getToken();

    if (!token) {
      // No token → dev-preview mode: keep the switcher defaults active.
      setLoading(false);
      return;
    }

    // Real session: decode claims for display, defer to real values.
    const decoded = decodeJwtClaims(token);
    setClaims(decoded);
    setAuthenticated(true);
    setDevRole(null);
    setDevTier(null);

    (async () => {
      try {
        const info = await getTierInfo();
        if (!cancelled) setRealTier(info);
      } catch (e) {
        // Fail toward locked: leave realTier null and record the error.
        if (!cancelled) {
          setRealTier(null);
          setTierError(e instanceof Error ? e.message : String(e));
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  const jwtRole: Role | null = isRole(claims?.role) ? (claims!.role as Role) : null;

  // Overrides only apply in dev preview; in production the JWT + tier-info are
  // the sole source of truth (defense-in-depth on top of the DEV_PREVIEW gate
  // that already hides the switcher).
  const activeDevRole = DEV_PREVIEW ? devRole : null;
  const activeDevTier = DEV_PREVIEW ? devTier : null;

  // Effective role: dev override → JWT → read_only (fail toward least privilege).
  const role: Role = activeDevRole ?? jwtRole ?? "read_only";

  // Effective tier: dev override (synthetic) → real fetch → null (fail-locked).
  const tier: LicenseTierInfo | null = useMemo(
    () => (activeDevTier ? syntheticTierInfo(activeDevTier) : realTier),
    [activeDevTier, realTier],
  );

  const tenantName =
    (typeof claims?.tenant_name === "string" && claims.tenant_name) ||
    (authenticated ? "Tenant" : "Acme Corp");

  const value: AuthState = {
    loading,
    authenticated,
    claims,
    role,
    roleIsPreview: activeDevRole !== null,
    tier,
    tierIsPreview: activeDevTier !== null,
    tierError,
    tenantName,
    devPreview: DEV_PREVIEW,
    setDevRole: useCallback((r: Role | null) => setDevRole(r), []),
    setDevTier: useCallback((t: string | null) => setDevTier(t), []),
    devRole: activeDevRole,
    devTier: activeDevTier,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within <AuthProvider>");
  return ctx;
}
