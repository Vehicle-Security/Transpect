"use client";

import Link from "next/link";
import { Copy, Database, ExternalLink } from "lucide-react";

export function ReportActions({ showcaseId }: { showcaseId: string }) {
  async function copyLink() {
    await navigator.clipboard.writeText(window.location.href);
  }

  return (
    <div className="flex flex-wrap items-center justify-end gap-2">
      <button
        type="button"
        onClick={copyLink}
        className="inline-flex h-10 items-center gap-2 rounded-md border border-white/20 bg-white/10 px-3.5 text-sm font-semibold text-white shadow-sm hover:bg-white/15"
      >
        <Copy className="h-4 w-4" aria-hidden="true" />
        Copy Link
      </button>
      <Link
        href={`/artifacts/${showcaseId}?path=security-reasoning%2Ffinal_judgment.json`}
        className="inline-flex h-10 items-center gap-2 rounded-md border border-white/20 bg-white/10 px-3.5 text-sm font-semibold text-white shadow-sm hover:bg-white/15"
      >
        <Database className="h-4 w-4" aria-hidden="true" />
        Open Raw Evidence
      </Link>
      <a
        href={`http://127.0.0.1:8711/viewer/index.html?view=showcase&id=${encodeURIComponent(showcaseId)}`}
        className="inline-flex h-10 items-center gap-2 rounded-md border border-white/20 bg-white/10 px-3.5 text-sm font-semibold text-white shadow-sm hover:bg-white/15"
      >
        <ExternalLink className="h-4 w-4" aria-hidden="true" />
        Static Viewer
      </a>
    </div>
  );
}
