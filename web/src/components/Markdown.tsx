"use client";

/**
 * Markdown — the ONE markdown renderer for backend-synthesized answers
 * (WO-U11, finding #1).
 *
 * The NL-Query copilot's `answer` is MARKDOWN (GFM tables, **bold**, bullets,
 * inline `code`). It is derived from UNTRUSTED alert data, so:
 *   - raw HTML is NOT rendered (react-markdown's default — we deliberately do
 *     NOT add `rehype-raw`), so an attacker can't inject markup via alert text;
 *   - only the GFM feature set (tables, strikethrough, task lists, autolinks)
 *     is enabled, via remark-gfm;
 *   - links open in a new tab with `rel="noreferrer nofollow"` and react-markdown's
 *     default url sanitizer drops `javascript:`/`data:` protocols.
 *
 * Every element is styled with WO-U1 tokens (no hard-coded hexes), matching the
 * dark copilot theme. Wide tables scroll inside their own container so the page
 * body never scrolls horizontally.
 */

import ReactMarkdown, { type Components } from "react-markdown";
import remarkGfm from "remark-gfm";
import { cn } from "@/lib/ui";

const components: Components = {
  // Paragraphs — the copilot bubble sets the base body size/leading.
  p: ({ children }) => <p className="my-2 first:mt-0 last:mb-0 leading-relaxed">{children}</p>,

  // Emphasis
  strong: ({ children }) => <strong className="font-semibold text-ink">{children}</strong>,
  em: ({ children }) => <em className="italic">{children}</em>,
  del: ({ children }) => <del className="text-dim2 line-through">{children}</del>,

  // Lists
  ul: ({ children }) => (
    <ul className="my-2 list-disc space-y-1 pl-5 first:mt-0 last:mb-0">{children}</ul>
  ),
  ol: ({ children }) => (
    <ol className="my-2 list-decimal space-y-1 pl-5 first:mt-0 last:mb-0">{children}</ol>
  ),
  li: ({ children }) => <li className="leading-relaxed">{children}</li>,

  // Headings — compact, since answers are rendered inside a chat bubble.
  h1: ({ children }) => (
    <h1 className="mb-1.5 mt-3 text-title font-semibold text-ink first:mt-0">{children}</h1>
  ),
  h2: ({ children }) => (
    <h2 className="mb-1.5 mt-3 text-title font-semibold text-ink first:mt-0">{children}</h2>
  ),
  h3: ({ children }) => (
    <h3 className="mb-1 mt-2.5 text-body font-semibold text-ink first:mt-0">{children}</h3>
  ),
  h4: ({ children }) => (
    <h4 className="mb-1 mt-2.5 text-body font-semibold text-ink first:mt-0">{children}</h4>
  ),
  h5: ({ children }) => (
    <h5 className="mb-1 mt-2 text-data font-semibold text-dim first:mt-0">{children}</h5>
  ),
  h6: ({ children }) => (
    <h6 className="mb-1 mt-2 text-data font-semibold text-dim first:mt-0">{children}</h6>
  ),

  // Links — new tab, sanitized protocol (default), no-referrer.
  a: ({ children, href }) => (
    <a
      href={href}
      target="_blank"
      rel="noreferrer nofollow"
      className="text-acc underline decoration-acc/40 underline-offset-2 hover:decoration-acc"
    >
      {children}
    </a>
  ),

  // Code — inline vs fenced block. react-markdown v9 passes the fenced state
  // via the presence of a language className / multiline content.
  code: ({ className, children }) => {
    const isBlock = /language-/.test(className ?? "");
    if (isBlock) {
      return (
        <code className={cn("font-mono text-data", className)}>{children}</code>
      );
    }
    return (
      <code className="rounded-sm border border-line bg-field px-1 py-0.5 font-mono text-[0.85em] text-ink">
        {children}
      </code>
    );
  },
  pre: ({ children }) => (
    <pre className="my-2 overflow-x-auto rounded-md border border-line bg-field p-2.5 text-data leading-relaxed first:mt-0 last:mb-0">
      {children}
    </pre>
  ),

  // Blockquote
  blockquote: ({ children }) => (
    <blockquote className="my-2 border-l-2 border-line pl-3 text-dim">{children}</blockquote>
  ),

  hr: () => <hr className="my-3 border-line" />,

  // Tables — GFM. Scroll wide tables inside their own container.
  table: ({ children }) => (
    <div className="my-2 overflow-x-auto rounded-md border border-line first:mt-0 last:mb-0">
      <table className="w-full border-collapse text-data">{children}</table>
    </div>
  ),
  thead: ({ children }) => <thead className="bg-panel2">{children}</thead>,
  tbody: ({ children }) => <tbody>{children}</tbody>,
  tr: ({ children }) => <tr className="border-b border-line-soft last:border-0">{children}</tr>,
  th: ({ children }) => (
    <th className="px-2.5 py-1.5 text-left text-kbd font-semibold uppercase tracking-wide text-dim2">
      {children}
    </th>
  ),
  td: ({ children }) => <td className="px-2.5 py-1.5 align-top text-ink">{children}</td>,
};

export interface MarkdownProps {
  /** the markdown source — treated as untrusted; raw HTML is NOT rendered. */
  children: string;
  className?: string;
}

/** Renders GFM markdown with dark-theme tokens; no raw HTML (untrusted input). */
export function Markdown({ children, className }: MarkdownProps) {
  return (
    <div className={cn("text-body", className)}>
      <ReactMarkdown remarkPlugins={[remarkGfm]} components={components}>
        {children}
      </ReactMarkdown>
    </div>
  );
}
