import { NextResponse } from "next/server";
import { readReportModel } from "@/lib/showcase";
import { isValidShowcaseId } from "@/lib/paths";

export async function GET(_request: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  if (!isValidShowcaseId(id)) {
    return NextResponse.json({ error: "Invalid showcase id" }, { status: 400 });
  }
  const report = await readReportModel(id);
  if (!report) {
    return NextResponse.json({ error: "Showcase not found" }, { status: 404 });
  }
  return NextResponse.json(report);
}
