"use client";

import { useState } from "react";
import {
  BadgeCheck,
  Eye,
  Lock,
  Send,
  ShieldAlert,
  Sparkles,
  TerminalSquare,
  User,
  X,
} from "lucide-react";
import { cn, focusRing } from "@/lib/ui";
import type {
  CopilotMessage,
  CopilotMode,
  SuggestedQuery,
} from "@/lib/copilot";
import { Chip } from "./Chip";

/**
 * CopilotRail — the grounded copilot rail (mockup's `#copilot`).
 *
 * A message thread (user / ai bubbles) whose AI answers embed <Citation> chips,
 * suggested-investigation-query chips, a composer, and (when the copilot
 * proposes one) a gated <ContainmentActionCard> — all rendered from
 * `content`/`chips`. NO API calls: `onSend` / `onRunQuery` are supplied by the
 * caller (stub them in a gallery).
 *
 * Three modes match the mockup's degraded states:
 *   - "locked"   tier lacks the copilot → paid-feature upsell + disabled
 *                preview chips + disabled composer
 *   - "readonly" read_only role → view-only banner; chips + composer disabled
 *   - "normal"   full thread + working composer
 *
 * @example
 *   <CopilotRail mode="normal" role="senior_analyst" tier="team"
 *     contextLabel="INC-204" messages={messages}
 *     onSend={(t) => …} onRunQuery={(id) => …} />
 */
export interface CopilotRailProps {
  mode: CopilotMode;
  /** active role, shown in the header + gate copy */
  role: string;
  /** active tier, used in the locked upsell copy */
  tier: string;
  /** the entity the copilot is grounded to, e.g. "INC-204" */
  contextLabel: string;
  messages: CopilotMessage[];
  /** questions previewed (disabled) in the locked state */
  previewQueries?: string[];
  /** free-text ask (disabled unless normal) */
  onSend?: (text: string) => void;
  /** a suggested-query chip was activated */
  onRunQuery?: (query: SuggestedQuery) => void;
  /** upsell CTA in the locked state */
  onUpgrade?: () => void;
  /** show a close button (omit in the Investigate hero, where it's persistent) */
  onClose?: () => void;
  className?: string;
}

export function CopilotRail({
  mode,
  role,
  tier,
  contextLabel,
  messages,
  previewQueries = [],
  onSend,
  onRunQuery,
  onUpgrade,
  onClose,
  className,
}: CopilotRailProps) {
  const [draft, setDraft] = useState("");

  const send = () => {
    const v = draft.trim();
    if (!v) return;
    onSend?.(v);
    setDraft("");
  };

  return (
    <aside
      aria-label="Copilot"
      className={cn(
        "flex min-h-0 flex-col border-l border-line bg-[#0b1120]",
        className,
      )}
    >
      {/* header */}
      <div className="border-b border-line px-3 pb-2.5 pt-3">
        <div className="flex items-center gap-2">
          <Sparkles className="h-4 w-4 text-teal" aria-hidden="true" />
          <b className="text-body">Copilot</b>
          <Chip variant="grounded" icon={<BadgeCheck className="h-3 w-3" />}>
            Grounded
          </Chip>
          <span className="ml-auto text-kbd text-dim2">role: {role}</span>
          {onClose && (
            <button
              type="button"
              onClick={onClose}
              aria-label="Close copilot"
              className={cn(
                "ml-1 inline-flex h-6 w-6 items-center justify-center rounded-md text-dim hover:bg-hover hover:text-ink",
                focusRing,
              )}
            >
              <X className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          )}
        </div>
        <div className="mt-1.5 text-kbd text-dim2">
          NL-Query agent · context{" "}
          <b className="font-mono text-[#bcd]">{contextLabel}</b> · every answer
          cites its evidence, never a black box.
        </div>
      </div>

      {mode === "locked" ? (
        <LockedBody
          tier={tier}
          previewQueries={previewQueries}
          onUpgrade={onUpgrade}
        />
      ) : (
        <>
          <div className="min-h-0 flex-1 overflow-auto p-3" aria-live="polite">
            {messages.map((m) => (
              <MessageBubble
                key={m.id}
                message={m}
                canRun={mode === "normal"}
                onRunQuery={onRunQuery}
              />
            ))}
          </div>

          {mode === "readonly" ? (
            <div className="border-t border-line p-2.5">
              <div className="flex w-full items-center justify-center gap-1.5 rounded-md border border-[#4a4326] px-2 py-1.5 text-meta text-sev-med">
                <Eye className="h-3.5 w-3.5" aria-hidden="true" />
                Read-only role — viewing analyst questions; you can&apos;t run
                queries or approve actions
              </div>
              <textarea
                disabled
                rows={2}
                placeholder="Read-only: ask an analyst to run these…"
                className="mt-2 w-full resize-none rounded-lg border border-line bg-field p-2 text-data text-ink opacity-50"
              />
            </div>
          ) : (
            <div className="border-t border-line p-2.5">
              <label htmlFor="copilot-composer" className="sr-only">
                Ask the copilot about {contextLabel} in plain language
              </label>
              <textarea
                id="copilot-composer"
                rows={2}
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && !e.shiftKey) {
                    e.preventDefault();
                    send();
                  }
                }}
                placeholder={`Ask about ${contextLabel} in plain language…`}
                className={cn(
                  "w-full resize-none rounded-lg border border-line bg-field p-2 text-[12.5px] text-ink placeholder:text-dim2",
                  focusRing,
                )}
              />
              <div className="mt-1.5 flex items-center gap-2">
                <button
                  type="button"
                  onClick={send}
                  className={cn(
                    "ml-auto inline-flex cursor-pointer items-center gap-1.5 rounded-md border-none bg-[#25406a] px-2.5 py-1 text-meta text-white hover:brightness-110",
                    focusRing,
                  )}
                >
                  <Send className="h-3 w-3" aria-hidden="true" /> Ask
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </aside>
  );
}

function MessageBubble({
  message,
  canRun,
  onRunQuery,
}: {
  message: CopilotMessage;
  canRun: boolean;
  onRunQuery?: (q: SuggestedQuery) => void;
}) {
  const isAi = message.who === "ai";
  return (
    <div className={cn("my-2.5 text-body leading-relaxed", isAi ? "" : "ml-6")}>
      <div className="mb-1.5 flex items-center gap-1.5 text-kbd uppercase tracking-wide text-dim2">
        {isAi ? (
          <>
            <Sparkles className="h-3 w-3 text-teal" aria-hidden="true" /> Copilot
            · grounded
          </>
        ) : (
          <>
            <User className="h-3 w-3" aria-hidden="true" /> You
          </>
        )}
      </div>
      <div
        className={cn(
          "rounded-xl p-3",
          isAi
            ? "border border-aibd bg-ai"
            : "border border-userbd bg-user",
        )}
      >
        {message.content}
        {message.chips && message.chips.length > 0 && (
          <div className="mt-2.5">
            <div className="mb-0.5 text-kbd text-dim2">
              Suggested investigation queries
            </div>
            {message.chips.map((q) => (
              <button
                key={q.id}
                type="button"
                disabled={!canRun}
                onClick={() => onRunQuery?.(q)}
                className={cn(
                  "mt-1.5 flex w-full items-center gap-1.5 rounded-lg border border-[#26405f] bg-[#101d30] px-2.5 py-1.5 text-left text-data text-[#bcd6f5]",
                  focusRing,
                  canRun
                    ? "cursor-pointer hover:bg-[#152a44] hover:text-white"
                    : "cursor-not-allowed opacity-50",
                )}
              >
                {q.kind === "action" ? (
                  <ShieldAlert className="h-3 w-3 shrink-0" aria-hidden="true" />
                ) : (
                  <TerminalSquare
                    className="h-3 w-3 shrink-0"
                    aria-hidden="true"
                  />
                )}
                {q.label}
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function LockedBody({
  tier,
  previewQueries,
  onUpgrade,
}: {
  tier: string;
  previewQueries: string[];
  onUpgrade?: () => void;
}) {
  return (
    <>
      <div className="flex-1 overflow-auto p-3.5">
        <div className="rounded-xl border border-[#4a4326] bg-[#161206] p-3.5">
          <div className="flex items-center gap-2">
            <Lock className="h-4 w-4 text-sev-med" aria-hidden="true" />
            <b className="text-body">Copilot is a paid feature</b>
          </div>
          <p className="my-2 text-data text-dim">
            The NL-Query copilot isn&apos;t in the <b>{tier}</b> tier. You can
            still see the questions analysts ask — upgrade to run them and get
            cited answers.
          </p>
          {onUpgrade && (
            <button
              type="button"
              onClick={onUpgrade}
              className={cn(
                "cursor-pointer rounded-md border-none bg-[#25406a] px-2.5 py-1 text-meta text-white hover:brightness-110",
                focusRing,
              )}
            >
              Upgrade to unlock
            </button>
          )}
        </div>

        <div className="mb-1.5 mt-3.5 text-kbd uppercase tracking-wider text-dim2">
          Suggested questions (preview)
        </div>
        {previewQueries.map((q, i) => (
          <button
            key={i}
            type="button"
            disabled
            className="mt-1.5 block w-full cursor-not-allowed rounded-lg border border-[#26405f] bg-[#101d30] px-2.5 py-1.5 text-left text-data text-[#bcd6f5] opacity-50"
          >
            {q}
          </button>
        ))}
      </div>
      <div className="border-t border-line p-2.5">
        <textarea
          disabled
          rows={2}
          placeholder="Upgrade to ask the copilot…"
          className="w-full resize-none rounded-lg border border-line bg-field p-2 text-data text-ink opacity-50"
        />
      </div>
    </>
  );
}
