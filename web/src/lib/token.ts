/**
 * JWT storage + client-side claim decoding for the AI-SOC dashboard.
 *
 * Modelled on the sibling ASM repo (web/src/lib/token.ts): a localStorage-backed
 * token with an in-memory mirror so reads work before hydration completes. ALL
 * window access is `typeof window`-guarded so importing this at build/SSR time
 * is safe.
 *
 * The claim decoder base64-decodes the JWT payload segment for DISPLAY ONLY. It
 * does NOT verify the signature — the FastAPI backend is the enforcement point.
 * Never make an authorization decision from these claims (see rbac.ts).
 */

import type { JwtClaims } from "./types";

const TOKEN_KEY = "dhruva.aisoc.token";

let memoryToken: string | null = null;

function hasWindow(): boolean {
  return typeof window !== "undefined";
}

export function getToken(): string | null {
  if (memoryToken) return memoryToken;
  if (!hasWindow()) return null;
  try {
    memoryToken = window.localStorage.getItem(TOKEN_KEY);
  } catch {
    memoryToken = null;
  }
  return memoryToken;
}

export function setToken(token: string): void {
  memoryToken = token;
  if (!hasWindow()) return;
  try {
    window.localStorage.setItem(TOKEN_KEY, token);
  } catch {
    /* storage disabled — memory token still works for the session */
  }
}

export function clearToken(): void {
  memoryToken = null;
  if (!hasWindow()) return;
  try {
    window.localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* ignore */
  }
}

/** base64url → utf-8 string, environment-agnostic (browser or SSR). */
function base64UrlDecode(segment: string): string {
  const b64 = segment.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
  const padded = b64 + pad;
  if (typeof atob === "function") {
    // decode to a binary string then re-interpret as UTF-8
    const bin = atob(padded);
    try {
      return decodeURIComponent(
        Array.prototype.map
          .call(bin, (c: string) => `%${c.charCodeAt(0).toString(16).padStart(2, "0")}`)
          .join(""),
      );
    } catch {
      return bin;
    }
  }
  // Node/SSR fallback
  return Buffer.from(padded, "base64").toString("utf-8");
}

/**
 * Decode the JWT payload (middle segment) for DISPLAY ONLY. Returns null if the
 * token is missing/malformed. Signature is NOT verified — the server enforces.
 */
export function decodeJwtClaims(token: string | null): JwtClaims | null {
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length < 2) return null;
  try {
    const json = base64UrlDecode(parts[1]);
    const parsed = JSON.parse(json) as JwtClaims;
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}
