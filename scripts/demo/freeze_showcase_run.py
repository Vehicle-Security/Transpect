from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Any


sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))

from trace_common import WORKSPACE_ROOT, ensure_dir, normalize_path, read_json, safe_slug, write_json  # noqa: E402


SHOWCASE_SCHEMA = "transpect.showcase.index.v1"
DEFAULT_SHOWCASE_ROOT = WORKSPACE_ROOT / "state" / "showcase"

RUN_FILES = [
    "manifest.json",
    "task_input.json",
    "behavior-events.jsonl",
    "merged-trace.jsonl",
    "trace_index.json",
    "frida-events.jsonl",
    "runtime_status.json",
]
SECURITY_FILES = [
    "security_state.json",
    "defense_decision.json",
    "evidence_summary.json",
    "final_judgment.json",
]
RUN_DIRS = [
    "artifacts",
    "diagnosis/codetracer",
]


def display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return normalize_path(resolved.relative_to(WORKSPACE_ROOT)) or str(resolved)
    except ValueError:
        return normalize_path(resolved) or str(resolved)


def read_final_judgment(run_dir: Path) -> dict[str, Any]:
    payload = read_json(run_dir / "security-reasoning" / "final_judgment.json", default={})
    return payload if isinstance(payload, dict) else {}


def normalize_status(value: Any, *, default: str = "unavailable") -> str:
    text = str(value or default).strip().lower()
    if text in {"ok", "available", "degraded", "unavailable", "failed"}:
        return text
    if text in {"attach_failed", "not_running", "disabled", "empty"}:
        return "degraded"
    if text in {"error", "broken"}:
        return "failed"
    if text in {"missing"}:
        return "unavailable"
    return text or default


def extract_decision(final_judgment: dict[str, Any]) -> str:
    return str(final_judgment.get("finalDecision") or final_judgment.get("decision") or "unknown").strip().lower()


def extract_risk_level(final_judgment: dict[str, Any]) -> str:
    return str(final_judgment.get("riskLevel") or final_judgment.get("risk_level") or "unknown").strip().lower()


def trace_index_frida(trace_index: dict[str, Any]) -> dict[str, Any]:
    sources = trace_index.get("sources") if isinstance(trace_index.get("sources"), dict) else {}
    frida = sources.get("frida") if isinstance(sources.get("frida"), dict) else {}
    return frida


def extract_frida_status(final_judgment: dict[str, Any], trace_index: dict[str, Any]) -> tuple[str, int]:
    evidence = final_judgment.get("evidence") if isinstance(final_judgment.get("evidence"), dict) else {}
    nested = evidence.get("frida") if isinstance(evidence.get("frida"), dict) else {}
    frida_source = trace_index_frida(trace_index)
    status = normalize_status(nested.get("status") or frida_source.get("status"))
    count = nested.get("eventCount")
    if count is None:
        count = frida_source.get("eventCount")
    try:
        return status, int(count or 0)
    except (TypeError, ValueError):
        return status, 0


def extract_codetracer_status(final_judgment: dict[str, Any], frozen_dir: Path) -> str:
    evidence = final_judgment.get("evidence") if isinstance(final_judgment.get("evidence"), dict) else {}
    nested = evidence.get("codeTracer") if isinstance(evidence.get("codeTracer"), dict) else {}
    status = nested.get("status")
    if status:
        return normalize_status(status)
    if (frozen_dir / "diagnosis" / "codetracer" / "analysis" / "diagnosis_report.json").exists():
        return "ok"
    return "unavailable"


def count_jsonl(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        return sum(1 for line in handle if line.strip())


def evidence_event_count(run_dir: Path, final_judgment: dict[str, Any], trace_index: dict[str, Any]) -> int:
    behavior = (trace_index.get("sources") or {}).get("behavior") if isinstance(trace_index.get("sources"), dict) else {}
    if isinstance(behavior, dict) and behavior.get("eventCount") is not None:
        try:
            return int(behavior.get("eventCount") or 0)
        except (TypeError, ValueError):
            pass
    manifest = read_json(run_dir / "manifest.json", default={})
    if isinstance(manifest, dict) and manifest.get("eventCount") is not None:
        try:
            return int(manifest.get("eventCount") or 0)
        except (TypeError, ValueError):
            pass
    return count_jsonl(run_dir / "merged-trace.jsonl") or count_jsonl(run_dir / "behavior-events.jsonl")


def copy_if_exists(source: Path, destination: Path) -> bool:
    if not source.exists():
        return False
    ensure_dir(destination.parent)
    shutil.copy2(source, destination)
    return True


def copytree_if_exists(source: Path, destination: Path) -> bool:
    if not source.exists() or not source.is_dir():
        return False
    if destination.exists():
        shutil.rmtree(destination)
    ensure_dir(destination.parent)
    shutil.copytree(source, destination)
    return True


def load_showcase_index(showcase_root: Path) -> dict[str, Any]:
    index_path = showcase_root / "index.json"
    payload = read_json(index_path, default=None)
    if not isinstance(payload, dict):
        return {"schemaVersion": SHOWCASE_SCHEMA, "showcases": []}
    showcases = payload.get("showcases")
    if not isinstance(showcases, list):
        payload["showcases"] = []
    payload.setdefault("schemaVersion", SHOWCASE_SCHEMA)
    return payload


def upsert_showcase_entry(showcase_root: Path, entry: dict[str, Any]) -> Path:
    payload = load_showcase_index(showcase_root)
    showcases = [item for item in payload.get("showcases", []) if isinstance(item, dict) and item.get("id") != entry["id"]]
    showcases.append(entry)
    payload["showcases"] = showcases
    return write_json(showcase_root / "index.json", payload)


def freeze_showcase_run(
    run_dir: Path | str,
    *,
    showcase_root: Path | str = DEFAULT_SHOWCASE_ROOT,
    showcase_id: str,
    title: str,
    description: str,
) -> dict[str, Any]:
    source = Path(run_dir).expanduser().resolve()
    if not source.exists() or not source.is_dir():
        raise FileNotFoundError(f"run directory not found: {source}")
    resolved_root = Path(showcase_root).expanduser().resolve()
    frozen_id = safe_slug(showcase_id, "showcase")
    frozen_dir = resolved_root / frozen_id
    if frozen_dir.exists():
        shutil.rmtree(frozen_dir)
    ensure_dir(frozen_dir)

    copied: list[str] = []
    for relative in RUN_FILES:
        if copy_if_exists(source / relative, frozen_dir / relative):
            copied.append(relative)
    for relative in SECURITY_FILES:
        source_path = source / "security-reasoning" / relative
        if copy_if_exists(source_path, frozen_dir / "security-reasoning" / relative):
            copied.append(f"security-reasoning/{relative}")
    for relative in RUN_DIRS:
        if copytree_if_exists(source / relative, frozen_dir / relative):
            copied.append(relative)

    final_judgment = read_final_judgment(frozen_dir)
    trace_index = read_json(frozen_dir / "trace_index.json", default={})
    trace_index = trace_index if isinstance(trace_index, dict) else {}
    frida_status, frida_count = extract_frida_status(final_judgment, trace_index)
    code_status = extract_codetracer_status(final_judgment, frozen_dir)
    entry = {
        "id": frozen_id,
        "title": title,
        "description": description,
        "runDir": display_path(frozen_dir),
        "decision": extract_decision(final_judgment),
        "riskLevel": extract_risk_level(final_judgment),
        "fridaStatus": frida_status,
        "fridaEventCount": frida_count,
        "codeTracerStatus": code_status,
        "evidenceEventCount": evidence_event_count(frozen_dir, final_judgment, trace_index),
        "finalJudgmentPath": display_path(frozen_dir / "security-reasoning" / "final_judgment.json"),
        "viewerUrl": f"/viewer/index.html?view=showcase&id={frozen_id}",
    }
    index_path = upsert_showcase_entry(resolved_root, entry)
    return {
        "ok": True,
        "id": frozen_id,
        "runDir": display_path(frozen_dir),
        "indexPath": display_path(index_path),
        "copied": copied,
        "entry": entry,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Freeze a live Transpect run into state/showcase for product playback.")
    parser.add_argument("--run-dir", required=True, help="Source live/runs/<runId> directory.")
    parser.add_argument("--id", required=True, dest="showcase_id", help="Stable showcase id, e.g. staged_attack_block.")
    parser.add_argument("--title", required=True, help="Product-facing showcase title.")
    parser.add_argument("--description", required=True, help="Product-facing showcase description.")
    parser.add_argument("--showcase-root", default=str(DEFAULT_SHOWCASE_ROOT), help="Output showcase root.")
    args = parser.parse_args()
    result = freeze_showcase_run(
        args.run_dir,
        showcase_root=args.showcase_root,
        showcase_id=args.showcase_id,
        title=args.title,
        description=args.description,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
