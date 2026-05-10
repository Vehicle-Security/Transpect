import Link from "next/link";
import { notFound } from "next/navigation";
import { AppShell } from "@/components/app-shell";
import { Badge } from "@/components/verdict-badge";
import { listArtifacts, readArtifactContent, readReportModel } from "@/lib/showcase";

type Props = {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ path?: string }>;
};

function prettyPrint(path: string, content: string) {
  if (path.endsWith(".json")) {
    try {
      return JSON.stringify(JSON.parse(content), null, 2);
    } catch {
      return content;
    }
  }
  if (path.endsWith(".jsonl")) {
    return content
      .split(/\r?\n/)
      .filter(Boolean)
      .slice(0, 80)
      .map((line) => {
        try {
          return JSON.stringify(JSON.parse(line), null, 2);
        } catch {
          return line;
        }
      })
      .join("\n\n");
  }
  return content;
}

export default async function ArtifactViewerPage({ params, searchParams }: Props) {
  const { id } = await params;
  const { path } = await searchParams;
  const report = await readReportModel(id);
  if (!report) {
    notFound();
  }
  const artifacts = await listArtifacts(id);
  const selected = path || artifacts[0]?.path;
  const content = selected ? await readArtifactContent(id, selected).catch(() => null) : null;

  return (
    <AppShell>
      <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="text-sm font-semibold uppercase tracking-normal text-slate-500">Artifact Viewer</p>
          <h1 className="mt-2 text-3xl font-semibold tracking-normal text-slate-950">{report.title}</h1>
        </div>
        <Link href={`/showcases/${id}`} className="inline-flex items-center rounded-md bg-slate-900 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-slate-800">
          Back to Report
        </Link>
      </div>
      <div className="grid gap-6 lg:grid-cols-[320px_1fr]">
        <aside className="panel max-h-[70vh] overflow-hidden p-4">
          <h2 className="text-sm font-semibold text-slate-950">Allowed Artifacts</h2>
          <div className="mt-3 max-h-[calc(70vh-64px)] space-y-2 overflow-y-auto pr-1">
            {artifacts.map((artifact) => (
              <Link
                key={artifact.path}
                href={`/artifacts/${id}?path=${encodeURIComponent(artifact.path)}`}
                className={`block rounded-md border p-3 text-sm ${selected === artifact.path ? "border-slate-900 bg-slate-100" : "border-slate-200 bg-white hover:bg-slate-50"}`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-semibold text-slate-950">{artifact.name}</span>
                  <Badge value={artifact.status} />
                </div>
                <p className="mono mt-2 text-xs text-slate-500">{artifact.path}</p>
              </Link>
            ))}
          </div>
        </aside>
        <section className="panel self-start overflow-hidden">
          <div className="border-b border-slate-200 p-4">
            <h2 className="mono text-sm font-semibold text-slate-950">{selected || "No artifact selected"}</h2>
            {content?.truncated ? <p className="mt-1 text-xs text-amber-700">Large file truncated for browser display.</p> : null}
          </div>
          <pre className="mono max-h-[70vh] overflow-auto bg-slate-950 p-5 text-xs leading-5 text-slate-100">
            {content && selected ? prettyPrint(selected, content.content) : "Select an artifact to view its contents."}
          </pre>
        </section>
      </div>
    </AppShell>
  );
}
