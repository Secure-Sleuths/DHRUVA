"use client";

import { FlaskConical } from "lucide-react";
import { cn, focusRing } from "@/lib/ui";
import { DEV_TIERS, ROLE_ORDER } from "@/lib/rbac";
import type { Role } from "@/lib/types";

/**
 * DevSwitcher — the mockup's role + tier `<select>`s, for demoing gating
 * WITHOUT a real login. Clearly labelled DEV. It only OVERRIDES the effective
 * role/tier for preview; the production source of truth stays the JWT (role) +
 * `GET /api/license/tier-info` (tier). When a real token is present, "Reset to
 * live" clears the override so real values win again.
 */
const REAL = "__live__";

export interface DevSwitcherProps {
  role: Role;
  tierId: string | null;
  /** whether a real JWT is present (enables the "reset to live" option) */
  authenticated: boolean;
  roleIsPreview: boolean;
  tierIsPreview: boolean;
  onSetRole: (role: Role | null) => void;
  onSetTier: (tier: string | null) => void;
}

export function DevSwitcher({
  role,
  tierId,
  authenticated,
  roleIsPreview,
  tierIsPreview,
  onSetRole,
  onSetTier,
}: DevSwitcherProps) {
  const selectCls = cn(
    "rounded-md border border-line bg-field px-2 py-1 text-[12px] text-ink",
    focusRing,
  );

  return (
    <div
      className="flex items-center gap-2 rounded-md border border-dashed border-line px-2 py-1"
      title="Dev-only: preview role/tier gating. Real values come from the JWT + license."
    >
      <span className="flex items-center gap-1 text-kbd uppercase tracking-wider text-dim2">
        <FlaskConical className="h-3 w-3" aria-hidden="true" /> Dev
      </span>

      <label htmlFor="dev-tier" className="text-kbd text-dim2">
        Tier
      </label>
      <select
        id="dev-tier"
        aria-label="Preview license tier (dev-only)"
        className={selectCls}
        value={tierIsPreview ? (tierId ?? "") : REAL}
        onChange={(e) =>
          onSetTier(e.target.value === REAL ? null : e.target.value)
        }
      >
        {authenticated && <option value={REAL}>live (license)</option>}
        {DEV_TIERS.map((t) => (
          <option key={t} value={t}>
            {t}
          </option>
        ))}
      </select>

      <label htmlFor="dev-role" className="text-kbd text-dim2">
        Role
      </label>
      <select
        id="dev-role"
        aria-label="Preview role (dev-only)"
        className={selectCls}
        value={roleIsPreview ? role : REAL}
        onChange={(e) =>
          onSetRole(e.target.value === REAL ? null : (e.target.value as Role))
        }
      >
        {authenticated && <option value={REAL}>live (JWT)</option>}
        {ROLE_ORDER.map((r) => (
          <option key={r} value={r}>
            {r}
          </option>
        ))}
      </select>
    </div>
  );
}
