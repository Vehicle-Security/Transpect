import "server-only";

import fs from "node:fs/promises";
import path from "node:path";
import { safeArtifactPath, safeShowcaseDir, SHOWCASE_ROOT } from "./paths";
import type { Artifact, ReportModel, ShowcaseIndexEntry, ShowcaseSummary } from "./report-model";
import { sortReportsForDemo } from "./format";

type ShowcaseIndex = {
  showcases?: ShowcaseIndexEntry[];
};

async function readJson<T>(filePath: string, fallback: T): Promise<T> {
  try {
    const text = await fs.readFile(filePath, "utf8");
    return JSON.parse(text) as T;
  } catch {
    return fallback;
  }
}

export async function readShowcaseIndex(): Promise<ShowcaseIndexEntry[]> {
  const index = await readJson<ShowcaseIndex>(path.join(SHOWCASE_ROOT, "index.json"), {});
  return Array.isArray(index.showcases) ? index.showcases : [];
}

export async function readReportModel(id: string): Promise<ReportModel | null> {
  try {
    const dir = safeShowcaseDir(id);
    return await readJson<ReportModel | null>(path.join(dir, "report_model.json"), null);
  } catch {
    return null;
  }
}

export async function listShowcaseSummaries(): Promise<ShowcaseSummary[]> {
  const entries = await readShowcaseIndex();
  const rows = await Promise.all(
    entries.map(async (entry) => {
      const report = await readReportModel(entry.id);
      return report ? { ...entry, report } : { ...entry };
    })
  );
  const withReports = rows.filter((row): row is ShowcaseSummary & { report: ReportModel } => "report" in row && Boolean(row.report));
  const sortedReports = sortReportsForDemo(withReports.map((row) => row.report));
  const rank = new Map(sortedReports.map((report, index) => [report.id, index]));
  return rows.sort((a, b) => (rank.get(a.id) ?? 999) - (rank.get(b.id) ?? 999));
}

export async function listArtifacts(id: string): Promise<Artifact[]> {
  const report = await readReportModel(id);
  return report?.artifacts ?? [];
}

export async function readArtifactContent(id: string, relativePath: string) {
  const report = await readReportModel(id);
  if (!report) {
    throw new Error("Showcase report not found");
  }
  const filePath = safeArtifactPath(id, relativePath, report.artifacts);
  const stat = await fs.stat(filePath);
  const maxBytes = 180_000;
  const handle = await fs.open(filePath, "r");
  try {
    const buffer = Buffer.alloc(Math.min(stat.size, maxBytes));
    await handle.read(buffer, 0, buffer.length, 0);
    const content = buffer.toString("utf8");
    return {
      content,
      truncated: stat.size > maxBytes,
      sizeBytes: stat.size,
      artifact: report.artifacts.find((item) => item.path === relativePath)
    };
  } finally {
    await handle.close();
  }
}
