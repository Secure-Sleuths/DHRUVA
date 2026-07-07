import type { Config } from "tailwindcss";

/**
 * DHRUVA AI-SOC — design tokens (single source of truth).
 *
 * Owned by WO-U1 (design-system). Every later screen composes these tokens;
 * do NOT introduce a second token source or hard-code hexes in components.
 *
 * Invariants baked in here:
 *  - Severity is a p-scale rendered as glyph + label + color, NEVER color
 *    alone (see src/lib/severity.ts for the glyph/label pairing). The `sev.*`
 *    colors below only ever appear next to a glyph + text label.
 *  - Confidence uses a NEUTRAL ramp (`acc` blue → `teal`), kept OFF the
 *    severity scale, so red reads as severity only — never "low confidence".
 *  - Dark theme is the product theme (per the approved mockup).
 */
const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // ---- Base surfaces (from the approved mockup) --------------------
        bg: "#0a0e14",
        panel: "#111826",
        panel2: "#0d1420",
        line: "#1e2a3a",
        "line-soft": "#16202f", // faint row / interior divider
        hover: "#0f1826", // table-row / interactive hover fill
        field: "#0d1622", // inputs, selects, code blocks
        ink: "#e6edf5",
        dim: "#8aa0b8",
        // dim2 is used for SMALL meta text (table headers, polling status,
        // captions). Bumped from #5c7086 (~3.5:1 on `panel` — fails AA for
        // <14px text) to #6e879e (~4.75:1 on `panel`, ~5.2:1 on `bg`) so muted
        // labels clear WCAG AA everywhere the token is used. Still clearly
        // dimmer than `dim`. (WO-U10 contrast pass — token, not per-component.)
        dim2: "#6e879e",

        // ---- Severity p-scale --------------------------------------------
        // Paired with a glyph + label in the UI; never carries meaning alone.
        sev: {
          crit: "#ff8a8a", // P0 ◆ Critical
          high: "#ffb37a", // P1 ▲ High
          med: "#ffe08a", // P2 ■ Medium
          low: "#8ad0ff", // P3 ● Low
          info: "#9fb6ff", // ○ Info
        },

        // ---- Neutral accents ---------------------------------------------
        // Confidence ramp lives here (blue → teal). A confidence bar must
        // never read as "critical", so it never touches the sev.* scale.
        acc: "#6ea8fe", // primary blue accent / focus ring
        teal: "#22d3aa", // high-confidence + "grounded" positive
        violet: "#a78bfa", // campaign / projection (heuristic, never actioned)
        bar: "#1a2636", // progress / confidence track

        // ---- Copilot rail palette ----------------------------------------
        ai: "#0f1a2b", // AI message bubble fill
        aibd: "#1c3350", // AI message bubble border
        user: "#16273e", // user message bubble fill
        userbd: "#24405f", // user message bubble border
        cite: {
          bg: "#12233a", // citation chip fill
          border: "#2a4a6b",
          ink: "#9cc4f5",
        },
        // Grounded / positive-teal surfaces (badges, "logtest PASS").
        grounded: {
          border: "#1c3a34",
          ink: "#7fe8cf",
        },
        // Gated active-response (containment) warm surface — signals a
        // human-approved, reason-required action, never auto-execution.
        gated: {
          bg: "#1c130d",
          border: "#5a3a2a",
          ink: "#ffb37a",
        },
      },

      // ---- Typography scale ---------------------------------------------
      fontFamily: {
        sans: [
          "ui-sans-serif",
          "system-ui",
          "-apple-system",
          "Segoe UI",
          "Roboto",
          "sans-serif",
        ],
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
      fontSize: {
        // Semantic ramp used across the console (name → [size, opts]).
        micro: ["9.5px", { lineHeight: "1.3" }], // pills, time ticks
        kbd: ["10.5px", { lineHeight: "1.4", letterSpacing: "0.04em" }], // dim meta labels
        meta: ["11px", { lineHeight: "1.45" }], // chips, badges
        data: ["12.5px", { lineHeight: "1.55" }], // table / body data
        body: ["13px", { lineHeight: "1.55" }], // prose, copilot bubbles
        title: ["15px", { lineHeight: "1.3", fontWeight: "600" }], // card titles
        h1: ["18px", { lineHeight: "1.25", fontWeight: "650" }], // page headings
        metric: ["22px", { lineHeight: "1.1", fontWeight: "800" }],
        kpi: ["24px", { lineHeight: "1.1", fontWeight: "800" }],
      },

      // ---- Radius / elevation / motion ----------------------------------
      borderRadius: {
        sm: "5px",
        md: "7px",
        lg: "9px",
        xl: "10px",
        pill: "999px",
      },
      boxShadow: {
        // Node glow on the kill-chain lane (severity-tinted; always with glyph).
        "glow-crit":
          "0 0 0 1px rgba(255,138,138,.4), 0 0 22px -6px rgba(255,138,138,.5)",
        "glow-high":
          "0 0 0 1px rgba(255,179,122,.35), 0 0 20px -8px rgba(255,179,122,.45)",
        "nav-on": "inset 2px 0 0 #22d3aa", // active nav-item marker
        panel: "0 1px 2px rgba(0,0,0,.3)",
        overlay: "0 24px 60px -20px rgba(0,0,0,.7)",
      },
      transitionDuration: {
        rail: "220ms", // copilot rail slide
      },
      transitionTimingFunction: {
        rail: "ease",
      },
      keyframes: {
        "fade-in": {
          from: { opacity: "0" },
          to: { opacity: "1" },
        },
        "overlay-in": {
          from: { opacity: "0", transform: "translateY(4px) scale(.99)" },
          to: { opacity: "1", transform: "translateY(0) scale(1)" },
        },
      },
      animation: {
        "fade-in": "fade-in 120ms ease",
        "overlay-in": "overlay-in 140ms ease",
      },
    },
  },
  plugins: [],
};

export default config;
