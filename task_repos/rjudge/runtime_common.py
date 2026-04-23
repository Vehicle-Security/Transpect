from __future__ import annotations

import importlib.util
import json
import os
import shutil
import socket
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


FALLBACK_MODEL = "qwen-plus"
RESOLUTION_ALLOWED_FALLBACK_REASONS = {"model_name_unavailable"}
MODEL_RESOLUTION_MACHINE_REASONS = {
    "model_name_unavailable",
    "model_auth_failed",
    "model_quota_failed",
    "model_service_unreachable",
    "model_service_env_missing",
}


def normalize_path(path: Path | str | None) -> str | None:
    if path is None:
        return None
    return str(path).replace("\\", "/")


def normalize_base_url(base_url: str) -> str:
    return str(base_url or "").strip().rstrip("/")


def build_chat_completions_url(base_url: str) -> str:
    return f"{normalize_base_url(base_url)}/chat/completions"


def build_models_url(base_url: str) -> str:
    return f"{normalize_base_url(base_url)}/models"


def _error_text(payload: Any) -> str:
    if isinstance(payload, dict):
        error_obj = payload.get("error")
        if isinstance(error_obj, dict):
            parts = [
                str(error_obj.get("message") or "").strip(),
                str(error_obj.get("code") or "").strip(),
                str(error_obj.get("type") or "").strip(),
            ]
            return " ".join(part for part in parts if part)
    return ""


def classify_model_error(*, http_status: int | None, payload: Any | None, error_text: str | None) -> str:
    text = f"{_error_text(payload)} {error_text or ''}".lower()
    if http_status in {401, 403} or "invalid api key" in text or "unauthorized" in text or "forbidden" in text:
        return "model_auth_failed"
    if http_status == 429 or "quota" in text or "billing" in text or "rate limit" in text or "insufficient" in text:
        return "model_quota_failed"
    model_words = ("model", "models")
    unavailable_words = (
        "not found",
        "does not exist",
        "do not exist",
        "unavailable",
        "unsupported",
        "unknown",
        "invalid model",
        "no such model",
        "not support",
        "not available",
        "未开通",
        "不存在",
        "不可用",
    )
    if http_status in {400, 404} and any(word in text for word in model_words) and any(word in text for word in unavailable_words):
        return "model_name_unavailable"
    return "model_service_unreachable"


def probe_model_resolution(*, base_url: str, api_key: str, model_name: str, timeout_seconds: int = 20) -> dict[str, Any]:
    if not normalize_base_url(base_url):
        return {
            "ok": False,
            "reason": "model_service_env_missing",
            "httpStatus": None,
            "error": "MODEL_BASE_URL is empty",
            "model": model_name,
            "probeUrl": None,
        }
    payload = {
        "model": model_name,
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": 1,
        "temperature": 0,
    }
    encoded = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        build_chat_completions_url(base_url),
        data=encoded,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            body = response.read().decode("utf-8", errors="replace")
            parsed = json.loads(body) if body.strip() else None
            return {
                "ok": int(response.status) < 400,
                "reason": None,
                "httpStatus": int(response.status),
                "error": None,
                "model": model_name,
                "probeUrl": build_chat_completions_url(base_url),
                "responseModel": parsed.get("model") if isinstance(parsed, dict) else None,
            }
    except urllib.error.HTTPError as error:
        raw = error.read().decode("utf-8", errors="replace")
        parsed = None
        try:
            parsed = json.loads(raw) if raw.strip() else None
        except json.JSONDecodeError:
            parsed = None
        reason = classify_model_error(http_status=error.code, payload=parsed, error_text=raw)
        return {
            "ok": False,
            "reason": reason,
            "httpStatus": error.code,
            "error": raw or str(error),
            "model": model_name,
            "probeUrl": build_chat_completions_url(base_url),
        }
    except (urllib.error.URLError, TimeoutError, socket.timeout) as error:
        return {
            "ok": False,
            "reason": "model_service_unreachable",
            "httpStatus": None,
            "error": str(error),
            "model": model_name,
            "probeUrl": build_chat_completions_url(base_url),
        }


def resolve_model_configuration(
    *,
    requested_model: str,
    base_url: str,
    api_key: str,
    fallback_model: str = FALLBACK_MODEL,
) -> dict[str, Any]:
    requested_probe = probe_model_resolution(base_url=base_url, api_key=api_key, model_name=requested_model)
    if requested_probe.get("reason") == "model_service_unreachable" and requested_probe.get("httpStatus") is None:
        requested_probe = probe_model_resolution(base_url=base_url, api_key=api_key, model_name=requested_model, timeout_seconds=60)
    if requested_probe.get("ok"):
        return {
            "ok": True,
            "requestedModel": requested_model,
            "effectiveModel": requested_model,
            "fallbackUsed": False,
            "resolutionStatus": "requested_model_ok",
            "failureReason": None,
            "attempts": [requested_probe],
        }
    requested_reason = str(requested_probe.get("reason") or "")
    if requested_reason not in RESOLUTION_ALLOWED_FALLBACK_REASONS:
        return {
            "ok": False,
            "requestedModel": requested_model,
            "effectiveModel": None,
            "fallbackUsed": False,
            "resolutionStatus": "failed_requested_model",
            "failureReason": requested_reason,
            "attempts": [requested_probe],
        }
    fallback_probe = probe_model_resolution(base_url=base_url, api_key=api_key, model_name=fallback_model)
    if fallback_probe.get("reason") == "model_service_unreachable" and fallback_probe.get("httpStatus") is None:
        fallback_probe = probe_model_resolution(base_url=base_url, api_key=api_key, model_name=fallback_model, timeout_seconds=60)
    if fallback_probe.get("ok"):
        return {
            "ok": True,
            "requestedModel": requested_model,
            "effectiveModel": fallback_model,
            "fallbackUsed": True,
            "resolutionStatus": "fallback_model_ok",
            "failureReason": None,
            "attempts": [requested_probe, fallback_probe],
        }
    return {
        "ok": False,
        "requestedModel": requested_model,
        "effectiveModel": None,
        "fallbackUsed": True,
        "resolutionStatus": "failed_fallback_model",
        "failureReason": str(fallback_probe.get("reason") or requested_reason or "model_name_unavailable"),
        "attempts": [requested_probe, fallback_probe],
    }


def apply_effective_model(prepared_env: dict[str, Any], resolution: dict[str, Any]) -> None:
    effective_model = str(resolution.get("effectiveModel") or "")
    requested_model = str(resolution.get("requestedModel") or "")
    fallback_used = bool(resolution.get("fallbackUsed"))
    for env_name in ("commonEnv", "repoEnv", "templateEnv"):
        env_map = prepared_env.get(env_name)
        if not isinstance(env_map, dict):
            continue
        if effective_model:
            env_map["MODEL_NAME"] = effective_model
            env_map["EFFECTIVE_MODEL_NAME"] = effective_model
        if requested_model:
            env_map["REQUESTED_MODEL_NAME"] = requested_model
        env_map["MODEL_FALLBACK_USED"] = "true" if fallback_used else "false"


def resolution_from_environment(env: dict[str, str] | None = None) -> dict[str, Any]:
    values = env or os.environ
    requested_model = str(values.get("REQUESTED_MODEL_NAME") or values.get("MODEL_NAME") or "").strip()
    effective_model = str(values.get("EFFECTIVE_MODEL_NAME") or values.get("MODEL_NAME") or "").strip()
    fallback_used = str(values.get("MODEL_FALLBACK_USED") or "").strip().lower() == "true"
    return {
        "requestedModel": requested_model or None,
        "effectiveModel": effective_model or None,
        "fallbackUsed": fallback_used,
        "resolutionStatus": "environment",
        "failureReason": None,
    }


def write_model_resolution(path: Path, resolution: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "requestedModel": resolution.get("requestedModel"),
        "effectiveModel": resolution.get("effectiveModel"),
        "fallbackUsed": bool(resolution.get("fallbackUsed")),
        "resolutionStatus": resolution.get("resolutionStatus"),
        "failureReason": resolution.get("failureReason"),
        "attempts": resolution.get("attempts") or [],
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def load_module_from_path(module_name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"unable to load module from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_risk_identification_input_from_results(repo_root: Path, model_name: str) -> list[dict[str, Any]]:
    model_results_root = repo_root / "results" / model_name
    if not model_results_root.exists():
        return []
    rows_by_id: dict[int, dict[str, Any]] = {}
    for result_path in sorted(model_results_root.rglob("results.json")):
        payload = json.loads(result_path.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            continue
        for data in payload:
            if not isinstance(data, dict) or int(data.get("label", 0)) != 1:
                continue
            row_id = int(data.get("id"))
            candidate_text = ""
            contents = data.get("contents") or []
            if isinstance(contents, list) and len(contents) >= 3:
                candidate_entry = contents[-3]
                if isinstance(candidate_entry, dict):
                    candidate_text = str(candidate_entry.get("content") or "")
            record = rows_by_id.setdefault(
                row_id,
                {
                    "id": row_id,
                    "scenario": data.get("scenario"),
                    "contents": contents[1:-4] if isinstance(contents, list) else [],
                    "label": data.get("label"),
                    "reference": data.get("risk_description") or data.get("reference"),
                    "candidates": {},
                    "attack_type": data.get("attack_type"),
                },
            )
            record["candidates"][model_name] = candidate_text
    return [rows_by_id[key] for key in sorted(rows_by_id)]


def ensure_risk_identification_input(repo_root: Path, model_name: str) -> dict[str, Any]:
    target = repo_root / "eval" / "overall_result_unsafe.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    generated_rows = build_risk_identification_input_from_results(repo_root, model_name)
    if generated_rows:
        target.write_text(json.dumps(generated_rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return {
            "source": "current_model_results",
            "path": normalize_path(target.resolve()),
            "rowCount": len(generated_rows),
        }
    packaged_seed = repo_root / "eval" / "results" / "overall_result_unsafe.json"
    if packaged_seed.exists():
        shutil.copy2(packaged_seed, target)
        payload = json.loads(target.read_text(encoding="utf-8"))
        row_count = len(payload) if isinstance(payload, list) else None
        return {
            "source": "packaged_seed",
            "path": normalize_path(target.resolve()),
            "rowCount": row_count,
        }
    raise FileNotFoundError("unable to prepare eval/overall_result_unsafe.json from current results or packaged seed")
