from __future__ import annotations

import fnmatch
import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


SCHEMA_VERSION = "transpect.agent-defense.policy.v1"
_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_POLICY_PATH = _ROOT / "config" / "agent-defense-policy.json"
LEGACY_POLICY_PATH = _ROOT / "config" / "security-policy.json"


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def resolve_policy_path(path: str | Path | None = None) -> Path:
    if path:
        return Path(path).expanduser().resolve()
    env_path = os.environ.get("TRANSPECT_AGENT_DEFENSE_POLICY", "").strip()
    if env_path:
        return Path(env_path).expanduser().resolve()
    if DEFAULT_POLICY_PATH.exists():
        return DEFAULT_POLICY_PATH
    return LEGACY_POLICY_PATH


def load_policy(path: str | Path | None = None) -> dict[str, Any]:
    policy_path = resolve_policy_path(path)
    policy = _read_json(policy_path)
    if not policy:
        return {"schemaVersion": SCHEMA_VERSION, "allow": [], "block": [], "confirm": []}
    policy.setdefault("schemaVersion", SCHEMA_VERSION)
    policy["_policyPath"] = str(policy_path)
    policy.setdefault("allow", [])
    policy.setdefault("block", [])
    policy.setdefault("confirm", [])
    policy.setdefault("sensitiveMarkers", [])
    policy.setdefault("trustedDomains", [])
    policy.setdefault("bypassRules", [])
    return policy


def _target_text(action: dict[str, Any]) -> str:
    parts = [
        action.get("target"),
        action.get("url"),
        action.get("path"),
        action.get("command"),
        action.get("cmd"),
        action.get("script"),
        action.get("toolName"),
        action.get("actionType"),
    ]
    return " ".join(str(part) for part in parts if part is not None)


def _domain(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"https://{value}")
    return parsed.netloc.lower()


def domain_matches(domain: str, patterns: list[str]) -> bool:
    cleaned = domain.lower()
    for pattern in patterns:
        candidate = str(pattern).lower().strip()
        if not candidate:
            continue
        if candidate.startswith("*.") and cleaned.endswith(candidate[1:]):
            return True
        if cleaned == candidate or cleaned.endswith(f".{candidate}"):
            return True
        if fnmatch.fnmatch(cleaned, candidate):
            return True
    return False


def is_trusted_target(action: dict[str, Any], policy: dict[str, Any] | None = None) -> bool:
    policy = policy or load_policy()
    domains = [str(item) for item in policy.get("trustedDomains") or []]
    if not domains:
        return False
    target = str(action.get("url") or action.get("target") or "")
    if not target:
        return False
    return domain_matches(_domain(target), domains)


def _rule_matches(rule: dict[str, Any], action: dict[str, Any], *, sensitive_markers: list[str]) -> bool:
    action_type = str(action.get("actionType") or action.get("action") or action.get("toolName") or "").lower()
    target = _target_text(action)
    lowered_target = target.lower()

    actions = [str(item).lower() for item in rule.get("actions") or rule.get("actionTypes") or []]
    if actions and action_type not in actions:
        return False

    markers = [str(item).lower() for item in (rule.get("markers") or [])]
    markers.extend(str(item).lower() for item in sensitive_markers)
    if markers and any(marker and marker in lowered_target for marker in markers):
        return True

    domains = [str(item) for item in rule.get("domains") or rule.get("trustedDomains") or []]
    if domains:
        target_url = str(action.get("url") or action.get("target") or "")
        if target_url and domain_matches(_domain(target_url), domains):
            return True

    paths = [str(item) for item in rule.get("paths") or []]
    if paths:
        expanded_target = os.path.expanduser(str(action.get("path") or action.get("target") or target))
        for pattern in paths:
            expanded_pattern = os.path.expanduser(pattern)
            if fnmatch.fnmatch(expanded_target, expanded_pattern) or expanded_pattern in expanded_target:
                return True

    return bool(not markers and not domains and not paths and actions)


def evaluate_policy(action: dict[str, Any], policy: dict[str, Any] | None = None) -> dict[str, Any] | None:
    policy = policy or load_policy()
    sensitive_markers = [str(item) for item in policy.get("sensitiveMarkers") or []]

    for rule in policy.get("block") or []:
        if isinstance(rule, dict) and _rule_matches(rule, action, sensitive_markers=sensitive_markers):
            return {
                "decision": "block",
                "riskLevel": "critical",
                "riskScore": 10,
                "ruleId": rule.get("id") or "policy.block",
                "reason": rule.get("description") or "Agent Defense policy blocked this action.",
            }

    for rule in policy.get("confirm") or []:
        if isinstance(rule, dict) and _rule_matches(rule, action, sensitive_markers=[]):
            return {
                "decision": "require_confirmation",
                "riskLevel": "high",
                "riskScore": 7,
                "ruleId": rule.get("id") or "policy.confirm",
                "reason": rule.get("description") or "Agent Defense policy requires confirmation.",
            }

    for rule in policy.get("allow") or []:
        if isinstance(rule, dict) and _rule_matches(rule, action, sensitive_markers=[]):
            return {
                "decision": "allow",
                "riskLevel": "low",
                "riskScore": 1,
                "ruleId": rule.get("id") or "policy.allow",
                "reason": rule.get("description") or "Agent Defense policy explicitly allows this action.",
            }

    return None
