"use client";

/**
 * Root entry. The product lives at /dashboard (which redirects to /login when
 * there's no session). This just forwards there so `/` is never a dead end.
 */
import { useEffect } from "react";
import { useRouter } from "next/navigation";

export default function Home() {
  const router = useRouter();
  useEffect(() => {
    router.replace("/dashboard");
  }, [router]);
  return (
    <main className="flex min-h-screen items-center justify-center bg-bg text-dim">
      Loading DHRUVA…
    </main>
  );
}
