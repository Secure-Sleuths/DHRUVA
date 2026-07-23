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
import { Suspense } from "react";
import { AuthProvider } from "@/lib/auth";
import { AppShell } from "@/components/shell/AppShell";

export default function DashboardPage() {
  return (
    <AuthProvider>
      {/*
        AppShell reads navigation state from the URL via `useSearchParams`
        (WO-H22). Under Next's static export (`output: export`) any component
        using `useSearchParams` must sit inside a Suspense boundary, so the page
        can prerender the fallback and hydrate the real query string on the
        client. The shell has its own loading placeholders once mounted.
      */}
      <Suspense
        fallback={
          <div className="flex min-h-screen items-center justify-center bg-bg text-dim">
            Loading…
          </div>
        }
      >
        <AppShell />
      </Suspense>
    </AuthProvider>
  );
}
