import { NextResponse } from "next/server";
import { listShowcaseSummaries } from "@/lib/showcase";

export async function GET() {
  const showcases = await listShowcaseSummaries();
  return NextResponse.json({ showcases });
}
