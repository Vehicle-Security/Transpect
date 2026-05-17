from __future__ import annotations

from typing import Any


BASE_RISK = {
    "view_page": 1,
    "read_comment": 1,
    "click_internal_link": 2,
    "open_external_link": 4,
    "visit_unknown_domain": 5,
    "click_unknown_button": 6,
    "read_local_file": 8,
    "upload_file": 9,
    "upload_photo": 10,
    "execute_command": 10,
    "submit_private_data": 10,
    "access_token_or_cookie": 10,
    "call_sensitive_api": 9,
    "network_request": 3,
    "tool_call": 3,
}

LOW_TRUST_SOURCES = {"comment", "advertisement", "popup", "external_website", "button", "unknown"}
SENSITIVE_ACTIONS = {
    "read_local_file",
    "upload_file",
    "upload_photo",
    "execute_command",
    "submit_private_data",
    "access_token_or_cookie",
    "call_sensitive_api",
}


def risk_level(score: int) -> str:
    if score >= 9:
        return "critical"
    if score >= 6:
        return "high"
    if score >= 3:
        return "medium"
    return "low"


def decision_for_level(level: str) -> str:
    return {
        "low": "allow",
        "medium": "warn",
        "high": "require_confirmation",
        "critical": "block",
    }.get(level, "warn")


def action_name(payload: dict[str, Any]) -> str:
    # Capability-layer classification: maps toolName → actionType to drive risk
    # scoring (score_action).  Distinct from the coordination-layer normalization
    # in guardrail.agent_defense.normalizers.normalize_action(), which drives policy
    # matching.  The two lookup tables serve different purposes and may produce
    # different results for the same input.
    raw = (
        payload.get("actionType")
        or payload.get("action")
        or payload.get("name")
        or payload.get("toolName")
        or payload.get("tool_name")
        or payload.get("type")
        or "unknown"
    )
    text = str(raw).lower()
    if text in {"browser.navigate", "navigate", "open_url"}:
        return "open_external_link"
    if text in {"browser.click", "click"}:
        return "click_unknown_button"
    if text in {"exec", "bash", "shell_command", "run_command"}:
        return "execute_command"
    if "upload" in text and "photo" in text:
        return "upload_photo"
    if "upload" in text:
        return "upload_file"
    if "read" in text and ("file" in text or "local" in text):
        return "read_local_file"
    if "token" in text or "cookie" in text or "secret" in text:
        return "access_token_or_cookie"
    return text.replace(".", "_")


def has_sensitive_target(action: str, target: str) -> bool:
    lowered = target.lower()
    return action in SENSITIVE_ACTIONS or any(
        marker in lowered
        for marker in (
            "photo",
            "照片",
            "id_rsa",
            ".ssh",
            "cookie",
            "token",
            "secret",
            "password",
            "credential",
            "local_user_photo_fixture",
        )
    )


def score_action(payload: dict[str, Any], *, source_type: str, authorized: bool, chain_escalated: bool) -> tuple[int, list[str]]:
    action = action_name(payload)
    target = str(payload.get("target") or payload.get("url") or payload.get("path") or payload.get("command") or "")
    score = BASE_RISK.get(action, BASE_RISK.get("tool_call", 3))
    reasons = [f"Base risk for {action} is {score}."]
    if source_type == "comment":
        score += 2
        reasons.append("Source is a low-trust comment.")
    if source_type in {"advertisement", "popup"}:
        score += 3
        reasons.append("Source is an advertisement or popup.")
    if source_type in {"external_website", "unknown", "button"}:
        score += 3
        reasons.append("Source is unknown or external.")
    if payload.get("intentRelated") is False:
        score += 3
        reasons.append("Action is unrelated to the original user goal.")
    if has_sensitive_target(action, target):
        score += 4
        reasons.append("Action touches sensitive data or a sensitive system capability.")
    if not authorized and action in SENSITIVE_ACTIONS:
        score += 5
        reasons.append("No explicit user authorization was found.")
    if chain_escalated:
        score += 2
        reasons.append("A continuous risk escalation chain exists.")
    if source_type in LOW_TRUST_SOURCES and action in SENSITIVE_ACTIONS:
        score += 3
        reasons.append("A low-trust environment instruction is driving a sensitive action.")
    return min(score, 100), reasons


def hard_block_reason(action: str, source_type: str, target: str, authorized: bool) -> str | None:
    lowered = target.lower()
    if authorized:
        return None
    if action in {"upload_photo", "upload_file"} and ("photo" in lowered or "照片" in lowered or source_type in {"external_website", "button", "unknown"}):
        return "未授权上传用户照片或本地隐私文件。"
    if action == "read_local_file" and (source_type in LOW_TRUST_SOURCES or has_sensitive_target(action, target)):
        return "低可信来源诱导读取本地敏感文件。"
    if action == "execute_command" and source_type in LOW_TRUST_SOURCES:
        return "低可信来源诱导执行系统命令。"
    if action == "access_token_or_cookie":
        return "读取或外传 Token、Cookie 或密钥。"
    if action == "submit_private_data" and source_type in LOW_TRUST_SOURCES:
        return "低可信来源诱导提交隐私数据。"
    return None
