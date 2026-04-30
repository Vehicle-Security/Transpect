from __future__ import annotations

import json
import os
import re
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


Decision = str
Opener = Callable[[urllib.request.Request, int], Any]


@dataclass(frozen=True)
class ModelJudgeConfig:
    enabled: bool
    endpoint: str | None = None
    api_key: str | None = None
    model: str | None = None


def _read_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        value = value.strip().strip("\"'")
        values[key.strip()] = value
    return values


def _completion_endpoint(base_url: str) -> str:
    base = base_url.rstrip("/")
    if base.endswith("/chat/completions"):
        return base
    return f"{base}/chat/completions"


def _default_env_path() -> Path:
    cwd_env = Path.cwd() / ".env"
    if cwd_env.exists():
        return cwd_env
    return Path(__file__).resolve().parents[2] / ".env"


def load_model_config(env_path: Path | str | None = None) -> ModelJudgeConfig:
    env_file = Path(env_path) if env_path else _default_env_path()
    values = _read_dotenv(env_file)
    base_url = values.get("BASE_URL") or os.environ.get("BASE_URL")
    api_key = values.get("API_KEY") or os.environ.get("API_KEY")
    model = values.get("MODEL_ID") or os.environ.get("MODEL_ID")
    if not base_url or not api_key or not model:
        return ModelJudgeConfig(enabled=False)
    return ModelJudgeConfig(enabled=True, endpoint=_completion_endpoint(base_url), api_key=api_key, model=model)


def _json_from_text(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped, flags=re.IGNORECASE)
        stripped = re.sub(r"\s*```$", "", stripped)
    try:
        parsed = json.loads(stripped)
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", stripped, re.DOTALL)
        if not match:
            return {}
        try:
            parsed = json.loads(match.group(0))
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}


def _normalize_decision(value: Any) -> Decision | None:
    decision = str(value or "").strip().lower()
    return decision if decision in {"allow", "warn", "require_confirmation", "block"} else None


def _normalize_risk(value: Any, decision: Decision) -> str:
    risk = str(value or "").strip().lower()
    if risk in {"low", "medium", "high", "critical"}:
        return risk
    return {
        "allow": "low",
        "warn": "medium",
        "require_confirmation": "high",
        "block": "critical",
    }[decision]


def _build_prompt(payload: dict[str, Any]) -> list[dict[str, str]]:
    system = (
        "You are an enterprise security judge for an AI agent runtime. "
        "Return only strict JSON with keys decision, risk, reasons, confidence. "
        "Allowed decisions: allow, warn, require_confirmation, block. "
        "Never include secrets or API keys in the output."
    )
    user = {
        "instruction": "Judge this gray-zone action. Blocks from deterministic policy are not sent here.",
        "payload": payload,
    }
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": json.dumps(user, ensure_ascii=False)},
    ]


def judge_gray_zone(
    payload: dict[str, Any],
    *,
    env_path: Path | str | None = None,
    opener: Opener | None = None,
    timeout_seconds: int = 30,
) -> dict[str, Any] | None:
    config = load_model_config(env_path)
    if not config.enabled or not config.endpoint or not config.api_key or not config.model:
        return None

    body = {
        "model": config.model,
        "messages": _build_prompt(payload),
        "temperature": 0,
        "response_format": {"type": "json_object"},
    }
    request = urllib.request.Request(
        config.endpoint,
        data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {config.api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    open_fn = opener or urllib.request.urlopen
    try:
        with open_fn(request, timeout_seconds) as response:
            response_payload = json.loads(response.read().decode("utf-8"))
    except Exception:
        return None

    content = (
        ((response_payload.get("choices") or [{}])[0].get("message") or {}).get("content")
        if isinstance(response_payload, dict)
        else None
    )
    parsed = _json_from_text(str(content or ""))
    decision = _normalize_decision(parsed.get("decision"))
    if not decision:
        return None
    reasons_raw = parsed.get("reasons")
    reasons = [str(item) for item in reasons_raw] if isinstance(reasons_raw, list) and reasons_raw else ["LLM gray-zone judge returned a decision."]
    confidence = parsed.get("confidence")
    return {
        "decision": decision,
        "riskLevel": _normalize_risk(parsed.get("risk") or parsed.get("riskLevel"), decision),
        "reasons": reasons,
        "confidence": confidence if isinstance(confidence, int | float) else 0.5,
        "source": "llm_gray_zone_judge",
    }
