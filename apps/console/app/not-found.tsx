import Link from "next/link";
import { AppShell } from "@/components/app-shell";

export default function NotFound() {
  return (
    <AppShell>
      <div className="panel p-8">
        <h1 className="text-2xl font-semibold text-slate-950">Report not found</h1>
        <p className="mt-2 text-sm text-slate-600">The requested frozen showcase report is unavailable or has not been built yet.</p>
        <Link href="/showcases" className="mt-5 inline-flex rounded-md bg-slate-900 px-4 py-2 text-sm font-semibold text-white">
          Open Showcase Gallery
        </Link>
      </div>
    </AppShell>
  );
}
