import { NextResponse } from "next/server";
import { isValidShowcaseId } from "@/lib/paths";
import { listArtifacts, readArtifactContent } from "@/lib/showcase";

export async function GET(request: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  if (!isValidShowcaseId(id)) {
    return NextResponse.json({ error: "Invalid showcase id" }, { status: 400 });
  }
  const url = new URL(request.url);
  const artifactPath = url.searchParams.get("path");
  try {
    if (artifactPath) {
      const content = await readArtifactContent(id, artifactPath);
      return NextResponse.json(content);
    }
    const artifacts = await listArtifacts(id);
    return NextResponse.json({ id, artifacts });
  } catch (error) {
    return NextResponse.json({ error: error instanceof Error ? error.message : "Artifact unavailable" }, { status: 404 });
  }
}
