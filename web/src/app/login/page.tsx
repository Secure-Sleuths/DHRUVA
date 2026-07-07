"use client";

/**
 * Login page — the real auth entry point for the deployed SPA.
 *
 * Posts username/password to `POST /api/auth/login` (anonymous), stores the
 * returned JWT (token.ts), and routes to `/dashboard`. Standalone (outside the
 * AuthProvider): it needs no session. Credentials are sent over the same-origin
 * HTTPS the backend serves; nothing is logged or persisted beyond the token.
 */

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

import { ApiError, login } from "@/lib/api";
import { getToken, setToken } from "@/lib/token";

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // Already signed in → skip straight to the dashboard.
  useEffect(() => {
    if (getToken()) router.replace("/dashboard");
  }, [router]);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (submitting) return;
    setError(null);
    setSubmitting(true);
    try {
      const res = await login(username.trim(), password);
      setToken(res.access_token);
      router.replace("/dashboard");
    } catch (err) {
      const msg =
        err instanceof ApiError && err.status === 401
          ? "Invalid username or password."
          : err instanceof ApiError && err.status === 429
            ? "Too many attempts — wait a moment and try again."
            : err instanceof Error
              ? err.message
              : "Sign-in failed. Please try again.";
      setError(msg);
      setSubmitting(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-bg p-6">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-md bg-gradient-to-br from-teal to-acc text-[#04121f]">
            ◆
          </div>
          <div>
            <div className="text-title font-bold tracking-wide text-ink">
              DHRUVA
            </div>
            <div className="text-micro tracking-[0.13em] text-dim2">
              AI-SOC · sign in
            </div>
          </div>
        </div>

        <form
          onSubmit={onSubmit}
          className="rounded-xl border border-line bg-panel p-6 shadow-panel"
          aria-describedby={error ? "login-error" : undefined}
        >
          <label className="mb-1 block text-kbd text-dim2" htmlFor="username">
            Username
          </label>
          <input
            id="username"
            name="username"
            autoComplete="username"
            autoFocus
            required
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="mb-4 w-full rounded-md border border-line bg-field px-3 py-2 text-body text-ink outline-none focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-acc"
          />

          <label className="mb-1 block text-kbd text-dim2" htmlFor="password">
            Password
          </label>
          <input
            id="password"
            name="password"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="mb-4 w-full rounded-md border border-line bg-field px-3 py-2 text-body text-ink outline-none focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-acc"
          />

          {error && (
            <div
              id="login-error"
              role="alert"
              className="mb-4 rounded-md border border-sev-crit/40 bg-sev-crit/10 px-3 py-2 text-meta text-sev-crit"
            >
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={submitting}
            className="w-full rounded-md bg-[#25406a] px-4 py-2 text-body font-medium text-white hover:brightness-110 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-acc disabled:cursor-not-allowed disabled:opacity-60"
          >
            {submitting ? "Signing in…" : "Sign in"}
          </button>

          <p className="mt-4 text-kbd leading-relaxed text-dim2">
            Anonymization is the LLM boundary — identifiers are tokenized before
            AI analysis; you see the real values. Active response stays
            human-approved.
          </p>
        </form>
      </div>
    </main>
  );
}
