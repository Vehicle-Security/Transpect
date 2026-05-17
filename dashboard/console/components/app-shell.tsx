import Link from "next/link";
import type { ReactNode } from "react";
import { ShieldCheck } from "lucide-react";

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <div className="console-shell">
      <header className="border-b border-slate-200 bg-white/90 backdrop-blur">
        <div className="container flex h-16 items-center justify-between">
          <Link href="/" className="flex items-center gap-3">
            <span className="flex h-9 w-9 items-center justify-center rounded-md bg-slate-900 text-white">
              <ShieldCheck className="h-5 w-5" aria-hidden="true" />
            </span>
            <span>
              <span className="block text-sm font-semibold text-slate-950">Transpect</span>
              <span className="block text-xs text-slate-500">Agent Security Console</span>
            </span>
          </Link>
          <nav className="flex items-center gap-2 text-sm font-medium text-slate-600">
            <Link className="rounded-md px-3 py-2 hover:bg-slate-100" href="/">
              Overview
            </Link>
            <Link className="rounded-md px-3 py-2 hover:bg-slate-100" href="/showcases">
              Showcases
            </Link>
            <a className="rounded-md px-3 py-2 hover:bg-slate-100" href="http://127.0.0.1:8711/viewer/index.html?view=showcase">
              Static Viewer
            </a>
          </nav>
        </div>
      </header>
      <main className="container py-8">{children}</main>
    </div>
  );
}
