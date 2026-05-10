import Link from "next/link";
import type { Artifact } from "@/lib/report-model";
import { Badge } from "./verdict-badge";

export function ArtifactTable({ showcaseId, artifacts }: { showcaseId: string; artifacts: Artifact[] }) {
  return (
    <section id="audit-artifacts" className="panel overflow-hidden">
      <div className="border-b border-slate-200 p-5">
        <h2 className="text-lg font-semibold text-slate-950">Audit Artifacts</h2>
        <p className="mt-1 text-sm text-slate-600">Every report conclusion links back to frozen evidence files.</p>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-left text-sm">
          <thead className="bg-slate-50 text-xs uppercase tracking-normal text-slate-500">
            <tr>
              <th className="px-4 py-3">Name</th>
              <th className="px-4 py-3">Source</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Relative Path</th>
              <th className="px-4 py-3">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {artifacts.map((artifact) => (
              <tr key={artifact.path}>
                <td className="px-4 py-3 font-medium text-slate-950">{artifact.name}</td>
                <td className="px-4 py-3 text-slate-600">{artifact.source}</td>
                <td className="px-4 py-3">
                  <Badge value={artifact.status} />
                </td>
                <td className="mono px-4 py-3 text-xs text-slate-600">{artifact.path}</td>
                <td className="px-4 py-3">
                  <Link className="font-semibold text-slate-900 underline decoration-slate-300 underline-offset-4" href={`/artifacts/${showcaseId}?path=${encodeURIComponent(artifact.path)}`}>
                    View
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
