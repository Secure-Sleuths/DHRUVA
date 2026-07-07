"use client";

/**
 * The real DHRUVA AI-SOC application shell (WO-U2).
 *
 * `AuthProvider` bootstraps the JWT (role, display claims) + license tier-info
 * and exposes the dev role/tier override; `AppShell` renders the role/tier-gated
 * 4-group sidebar, topbar, tab bodies (placeholders until later WOs register
 * them), tier-lock overlay, and the grounded copilot rail with paid-degradation.
 *
 * No token needed to view it: the dev switcher previews gating (senior_analyst /
 * Team by default). A real JWT + `GET /api/license/tier-info` take over when
 * present.
 */
import { AuthProvider } from "@/lib/auth";
import { AppShell } from "@/components/shell/AppShell";

export default function DashboardPage() {
  return (
    <AuthProvider>
      <AppShell />
    </AuthProvider>
  );
}
