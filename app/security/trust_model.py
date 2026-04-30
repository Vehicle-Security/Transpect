from __future__ import annotations

from typing import Any


TRUST_LEVELS = {
    "system_policy": "high",
    "user_instruction": "high",
    "web_page": "medium",
    "comment": "low",
    "advertisement": "low",
    "popup": "low",
    "external_website": "low",
    "button": "unknown",
    "tool_result": "medium",
    "unknown": "unknown",
}


def classify_source(payload: dict[str, Any] | None, default: str = "unknown") -> str:
    data = payload or {}
    raw = data.get("sourceType") or data.get("source") or data.get("provenanceKind") or data.get("stage")
    if isinstance(raw, str) and raw.strip():
        normalized = raw.strip().lower()
        if normalized in TRUST_LEVELS:
            return normalized
    text = " ".join(str(data.get(key) or "") for key in ("content", "message", "text", "target", "url", "name", "action"))
    lowered = text.lower()
    if "评论" in text or "comment" in lowered or "ugc" in lowered:
        return "comment"
    if "广告" in text or "advert" in lowered:
        return "advertisement"
    if "popup" in lowered or "弹窗" in text:
        return "popup"
    if "button" in lowered or "按钮" in text:
        return "button"
    if "http://" in lowered or "https://" in lowered:
        return "external_website"
    return default


def trust_level(source_type: str) -> str:
    return TRUST_LEVELS.get(source_type, "unknown")
