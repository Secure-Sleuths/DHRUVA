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
      <PageHeading title={label} />
      <Panel className="px-6 py-11 text-center text-dim2">
        <Layout className="mx-auto h-7 w-7" aria-hidden="true" />
        <div className="mx-auto mt-2.5 max-w-[600px] text-data leading-relaxed">
          This view isn&apos;t available.
        </div>
      </Panel>
    </>
  );
}
