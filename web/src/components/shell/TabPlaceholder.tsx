import { Layout } from "lucide-react";
import { Panel } from "@/components";
import { TAB_LABEL } from "@/lib/rbac";
import { PageHeading } from "./PageHeading";

/**
 * TabPlaceholder — the mockup's `placeholder(id)`. Every tab not yet built out
 * in a later WO renders this: the real IA heading + a panel explaining the
 * module inherits the glass-box treatment. Later WOs replace it by registering
 * a real component in `tabRegistry.tsx`.
 */
export function TabPlaceholder({ tabId }: { tabId: string }) {
  const label = TAB_LABEL[tabId] ?? tabId;
  return (
    <>
      <PageHeading
        title={label}
        sub="Part of the real product IA — carries the glass-box design language"
      />
      <Panel className="px-6 py-11 text-center text-dim2">
        <Layout className="mx-auto h-7 w-7" aria-hidden="true" />
        <div className="mx-auto mt-2.5 max-w-[600px] text-data leading-relaxed">
          This module exists in DHRUVA and inherits the same treatment:
          interrogable numbers, provenance, plain-language severity, the
          anonymization boundary, and human-gated response.
          <br />
          <br />
          The app shell, RBAC/tier gating, and grounded copilot are live now
          (WO-U2). This tab&apos;s body is delivered by a later Work Order — the
          frame, access control, and states around it are already in place.
          Switch role/tier above to see access change live.
        </div>
      </Panel>
    </>
  );
}
