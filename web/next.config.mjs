/** @type {import('next').NextConfig} */

// Derive the API origin (for connect-src) from the build-time public env so a
// cross-origin FastAPI backend isn't blocked by the CSP. The AI-SOC dashboard
// talks to the FastAPI JSON API (JWT in Authorization header) at this origin.
let apiOrigin = "";
try {
  apiOrigin = new URL(
    process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000",
  ).origin;
} catch {
  apiOrigin = "";
}

const isProd = process.env.NODE_ENV === "production";

// Hardening headers that never break a same-origin SPA — applied in all envs.
const baseSecurityHeaders = [
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), interest-cohort=()",
  },
  {
    key: "Strict-Transport-Security",
    value: "max-age=31536000; includeSubDomains",
  },
];

// CSP applied only in production builds: dev uses eval for React Fast Refresh,
// which a strict script-src would break. NOTE: script-src still carries
// 'unsafe-inline' because the Next App Router emits inline bootstrap scripts
// without nonces — tightening to a nonce-based policy is the tracked pre-prod
// hardening item. No external script/frame origins: icons are bundled
// (lucide-react), so this app needs no CDN allowances.
const csp = [
  "default-src 'self'",
  "base-uri 'self'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "form-action 'self'",
  "img-src 'self' data: https:",
  "font-src 'self' data:",
  "style-src 'self' 'unsafe-inline'",
  "script-src 'self' 'unsafe-inline'",
  `connect-src 'self' ${apiOrigin}`.trim(),
].join("; ");

const nextConfig = {
  reactStrictMode: true,
  // Ship as a static SPA served same-origin by the FastAPI backend (the
  // monolith cutover — see src/api/routes/frontend.py). trailingSlash gives
  // clean per-route index.html files (dashboard/index.html) for static serving.
  // NOTE: the security headers below are applied by the backend at serve time,
  // not by `next export` (headers() is a no-op for static export).
  output: "export",
  trailingSlash: true,
  // The repo root carries its own package-lock.json (puppeteer-core tooling),
  // so Next would otherwise infer the workspace root one level up. Pin tracing
  // to this web/ app.
  outputFileTracingRoot: import.meta.dirname,
  async headers() {
    const headers = [...baseSecurityHeaders];
    if (isProd) {
      headers.push({ key: "Content-Security-Policy", value: csp });
    }
    return [{ source: "/:path*", headers }];
  },
};

export default nextConfig;
