import type { ReactNode } from "react";

/**
 * PageHeading — the mockup's `h(title, sub)`: a tab's title + optional
 * sub-line. Every tab body renders one so headings stay consistent.
 */
export function PageHeading({
  title,
  sub,
}: {
  title: string;
  sub?: ReactNode;
}) {
  return (
    <div className="mb-3.5">
      <h1 className="text-h1">{title}</h1>
      {sub && <div className="mt-0.5 text-body text-dim">{sub}</div>}
    </div>
  );
}
