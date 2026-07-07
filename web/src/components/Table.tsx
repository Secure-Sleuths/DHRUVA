import type { ReactNode, ThHTMLAttributes, TdHTMLAttributes } from "react";
import { cn, focusRing } from "@/lib/ui";

/**
 * Table — the SOC data-table primitive, ported from the mockup's table CSS.
 * Composable parts (not a data-driven black box) so screens control columns:
 *
 *   <Table>
 *     <THead><TR><TH>Alert</TH><TH>Host</TH></TR></THead>
 *     <TBody>
 *       <TR onClick={open} aria-label="Open INC-204">
 *         <TD>Mimikatz-like LSASS access</TD><TD mono>WIN-APP-03</TD>
 *       </TR>
 *     </TBody>
 *   </Table>
 *
 * Wrap in a <Panel> for the bordered container look.
 * A row with `onClick` becomes fully keyboard-operable (Enter/Space) and
 * REQUIRES an `aria-label` describing where it navigates.
 */
export function Table({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <table
      className={cn("w-full border-collapse text-data text-ink", className)}
    >
      {children}
    </table>
  );
}

export function THead({ children }: { children: ReactNode }) {
  return <thead>{children}</thead>;
}

export function TBody({ children }: { children: ReactNode }) {
  return <tbody>{children}</tbody>;
}

export interface TRProps {
  children: ReactNode;
  /** makes the whole row a keyboard-operable button-like control */
  onClick?: () => void;
  /** required when `onClick` is set — names the row's destination for AT */
  "aria-label"?: string;
  className?: string;
}

export function TR({
  children,
  onClick,
  "aria-label": ariaLabel,
  className,
}: TRProps) {
  if (onClick) {
    return (
      <tr
        role="button"
        tabIndex={0}
        aria-label={ariaLabel}
        onClick={onClick}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            onClick();
          }
        }}
        className={cn(
          "cursor-pointer hover:bg-hover",
          focusRing,
          className,
        )}
      >
        {children}
      </tr>
    );
  }
  return <tr className={className}>{children}</tr>;
}

export function TH({
  children,
  className,
  ...rest
}: ThHTMLAttributes<HTMLTableCellElement> & { children?: ReactNode }) {
  return (
    <th
      className={cn(
        "border-b border-line px-2.5 py-2 text-left text-kbd font-medium uppercase tracking-wider text-dim2",
        className,
      )}
      {...rest}
    >
      {children}
    </th>
  );
}

export function TD({
  children,
  mono = false,
  className,
  ...rest
}: TdHTMLAttributes<HTMLTableCellElement> & {
  children?: ReactNode;
  /** monospace + tabular-nums for ids / hosts / numbers */
  mono?: boolean;
}) {
  return (
    <td
      className={cn(
        "border-b border-line-soft px-2.5 py-2.5 align-middle",
        mono && "font-mono tabular",
        className,
      )}
      {...rest}
    >
      {children}
    </td>
  );
}
