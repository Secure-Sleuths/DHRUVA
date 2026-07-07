/**
 * Small shared UI helpers for the DHRUVA design system.
 * No runtime deps — keep this dependency-free so every primitive can import it.
 */

/**
 * `cn` — join conditional class names. Falsy values are dropped.
 * (No tailwind-merge: primitives are authored not to emit conflicting classes;
 * callers append, they don't override token utilities.)
 *
 * @example cn("px-2", isOn && "bg-hover", disabled && "opacity-50")
 */
export function cn(
  ...parts: Array<string | false | null | undefined>
): string {
  return parts.filter(Boolean).join(" ");
}

/**
 * `focusRing` — the standard keyboard focus treatment (accessibility
 * invariant). Apply to every interactive element built on a non-native
 * control. `globals.css` also sets a document-level `:focus-visible` baseline,
 * so this is a belt-and-braces reinforcement that keeps the intent visible in
 * component source.
 */
export const focusRing =
  "focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-acc";
