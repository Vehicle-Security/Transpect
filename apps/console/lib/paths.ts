import path from "node:path";
import type { Artifact } from "./report-model";

export const REPO_ROOT = path.resolve(process.cwd(), "../..");
export const SHOWCASE_ROOT = path.resolve(REPO_ROOT, "state", "showcase");

export function isValidShowcaseId(id: string) {
  return /^[a-zA-Z0-9_-]+$/.test(id);
}

export function safeShowcaseDir(id: string) {
  if (!isValidShowcaseId(id)) {
    throw new Error("Invalid showcase id");
  }
  const root = path.resolve(SHOWCASE_ROOT);
  const dir = path.resolve(root, id);
  if (dir !== root && !dir.startsWith(`${root}${path.sep}`)) {
    throw new Error("Showcase path is outside the allowed root");
  }
  return dir;
}

export function safeArtifactPath(id: string, relativePath: string, artifacts: Artifact[]) {
  const allowed = artifacts.some((artifact) => artifact.path === relativePath);
  if (!allowed) {
    throw new Error("Artifact is not listed in the report model");
  }
  if (path.isAbsolute(relativePath) || relativePath.split(/[\\/]/).includes("..")) {
    throw new Error("Invalid artifact path");
  }
  const dir = safeShowcaseDir(id);
  const resolved = path.resolve(dir, relativePath);
  if (!resolved.startsWith(`${dir}${path.sep}`) && resolved !== dir) {
    throw new Error("Artifact path is outside the showcase directory");
  }
  return resolved;
}
