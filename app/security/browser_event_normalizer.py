from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlparse


SUSPICIOUS_BUTTONS = ("详情", "继续", "下载", "上传", "授权", "打开", "detail", "continue", "download", "upload", "authorize", "open")


@dataclass
class BrowserEvent:
    event_id: str | int | None
    timestamp: str | None
    actor: str
    event_type: str
    tool_name: str
    raw_input: Any = None
    raw_output: Any = None
    url_before: str | None = None
    url_after: str | None = None
    page_title: str | None = None
    visible_text_summary: str | None = None
    element_ref: str | None = None
    element_text: str | None = None
    media_paths: list[str] = field(default_factory=list)
    risk_tags: list[str] = field(default_factory=list)
    raw_event: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _parse_maybe_json(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    text = value.strip()
    if not text or text[0] not in "[{":
        return value
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return value


def _first_non_empty(*values: Any) -> Any:
    for value in values:
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        return value
    return None


def _nested(data: dict[str, Any], *path: str) -> Any:
    value: Any = data
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False)
    except TypeError:
        return str(value)


def _find_url(*values: Any) -> str | None:
    for value in values:
        if isinstance(value, dict):
            direct = _first_non_empty(value.get("url"), value.get("href"), value.get("targetUrl"), value.get("target"))
            if isinstance(direct, str) and direct.strip():
                return direct.strip()
        text = _text(value)
        match = re.search(r"https?://[^\s\"'<>）)]+", text)
        if match:
            return match.group(0)
    return None


def _domain(url: str | None) -> str:
    if not url:
        return ""
    parsed = urlparse(url)
    host = parsed.netloc or parsed.path.split("/", 1)[0]
    return host.lower()


def _extract_media_paths(*values: Any) -> list[str]:
    media: list[str] = []
    stack = list(values)
    while stack:
        value = stack.pop()
        if isinstance(value, dict):
            for key, item in value.items():
                if key in {"mediaPaths", "media_paths", "screenshot", "screenshots", "path", "filePath"}:
                    stack.append(item)
                elif isinstance(item, (dict, list)):
                    stack.append(item)
        elif isinstance(value, list):
            stack.extend(value)
        elif isinstance(value, str) and re.search(r"\.(png|jpe?g|webp|gif|mp4)$", value, re.I):
            media.append(value)
    return sorted(set(media))


class BrowserEventNormalizer:
    def __init__(self, allowed_domains: list[str] | None = None) -> None:
        self.allowed_domains = [domain.lower() for domain in allowed_domains or []]

    def normalize(self, events: list[dict[str, Any]], sidecars: dict[str, Any] | None = None) -> list[BrowserEvent]:
        sidecars = sidecars or {}
        normalized: list[BrowserEvent] = []
        current_url: str | None = None
        for event in events:
            browser_event = self._normalize_one(event, sidecars, current_url)
            if browser_event is None:
                continue
            if browser_event.url_after:
                current_url = browser_event.url_after
            normalized.append(browser_event)
        return normalized

    def _normalize_one(self, event: dict[str, Any], sidecars: dict[str, Any], current_url: str | None) -> BrowserEvent | None:
        preview = event.get("preview") if isinstance(event.get("preview"), dict) else {}
        target = event.get("target") if isinstance(event.get("target"), dict) else {}
        evidence = event.get("evidence") if isinstance(event.get("evidence"), dict) else {}
        sidecar_input = _sidecar_payload(sidecars, evidence, "input")
        sidecar_output = _sidecar_payload(sidecars, evidence, "output")
        input_value = _parse_maybe_json(_first_non_empty(event.get("input"), preview.get("params"), sidecar_input))
        output_value = _parse_maybe_json(_first_non_empty(event.get("output"), preview.get("result"), preview.get("responseBody"), sidecar_output))
        tool_name = str(
            _first_non_empty(
                target.get("toolName"),
                _nested(event, "tool", "name"),
                evidence.get("toolName"),
                event.get("toolName"),
                event.get("tool_name"),
                event.get("name"),
                "",
            )
        )
        if tool_name.startswith("tool."):
            tool_name = tool_name.removeprefix("tool.")
        lower_tool = tool_name.lower()
        kind = str(event.get("kind") or event.get("type") or "").lower()
        if "browser" not in lower_tool and kind not in {"network"}:
            return None

        url = _find_url(input_value, output_value, preview, target, event)
        event_type = self._event_type(lower_tool, kind)
        if event_type is None:
            return None
        element_text = self._element_text(input_value, output_value, preview)
        risk_tags = self._risk_tags(event_type, url, element_text, input_value, output_value)
        return BrowserEvent(
            event_id=event.get("eventId") or event.get("event_id") or event.get("id") or event.get("seq"),
            timestamp=event.get("ts") or event.get("timestamp"),
            actor="agent",
            event_type=event_type,
            tool_name=tool_name or ("network.fetch" if kind == "network" else "browser.unknown"),
            raw_input=input_value,
            raw_output=output_value,
            url_before=current_url,
            url_after=url or (current_url if event_type in {"observation", "click", "input", "file", "screenshot"} else None),
            page_title=self._page_title(output_value, preview),
            visible_text_summary=self._visible_text(output_value, preview),
            element_ref=self._element_ref(input_value, output_value, preview),
            element_text=element_text,
            media_paths=_extract_media_paths(input_value, output_value, sidecar_input, sidecar_output, preview, event),
            risk_tags=risk_tags,
            raw_event=event,
        )

    def _event_type(self, tool_name: str, kind: str) -> str | None:
        if kind == "network":
            return "file" if any(token in tool_name for token in ("upload", "download")) else "navigation"
        if any(token in tool_name for token in ("open", "navigate", "goto")):
            return "navigation"
        if "snapshot" in tool_name or "observe" in tool_name:
            return "observation"
        if "click" in tool_name or "press" in tool_name:
            return "click"
        if "type" in tool_name or "input" in tool_name:
            return "input"
        if "upload" in tool_name or "download" in tool_name or "file" in tool_name:
            return "file"
        if "screenshot" in tool_name:
            return "screenshot"
        return None

    def _risk_tags(self, event_type: str, url: str | None, element_text: str | None, *values: Any) -> list[str]:
        tags: set[str] = set()
        text = " ".join(_text(value).lower() for value in values)
        domain = _domain(url)
        if event_type == "navigation" and url and self.allowed_domains and not any(domain.endswith(allowed) for allowed in self.allowed_domains):
            tags.add("external_navigation")
        if "评论" in text or "comment" in text or "ugc" in text:
            tags.add("comment_observed")
        if any(token in text for token in ("详情请访问", "detail", "external link", "外链")):
            tags.add("untrusted_content")
        if event_type == "click" and element_text and any(token in element_text.lower() for token in SUSPICIOUS_BUTTONS):
            tags.add("suspicious_button")
        if event_type == "file" or any(token in text for token in ("upload", "download", "file picker", "local_user_photo", "照片", "photo")):
            tags.add("file_upload" if "upload" in text or "照片" in text or "photo" in text else "file_action")
        if "permission" in text or "授权" in text:
            tags.add("permission_request")
        return sorted(tags)

    def _element_text(self, *values: Any) -> str | None:
        for value in values:
            if isinstance(value, dict):
                direct = _first_non_empty(value.get("text"), value.get("label"), value.get("buttonText"), value.get("elementText"))
                if isinstance(direct, str) and direct.strip():
                    return direct.strip()
            text = _text(value)
            for token in SUSPICIOUS_BUTTONS:
                if token in text:
                    return token
        return None

    def _element_ref(self, *values: Any) -> str | None:
        for value in values:
            if isinstance(value, dict):
                direct = _first_non_empty(value.get("ref"), value.get("elementRef"), value.get("selector"))
                if isinstance(direct, str) and direct.strip():
                    return direct.strip()
            match = re.search(r"\bref[=:]\s*([A-Za-z0-9_-]+)", _text(value))
            if match:
                return match.group(1)
        return None

    def _page_title(self, *values: Any) -> str | None:
        for value in values:
            if isinstance(value, dict):
                title = value.get("title") or value.get("pageTitle")
                if isinstance(title, str) and title.strip():
                    return title.strip()
        return None

    def _visible_text(self, *values: Any) -> str | None:
        text = _first_non_empty(*[_text(value) for value in values if value is not None])
        if not isinstance(text, str) or not text.strip():
            return None
        return text.strip()[:1000]


def _sidecar_payload(sidecars: dict[str, Any], evidence: dict[str, Any], kind: str) -> Any:
    artifacts = evidence.get("artifacts") if isinstance(evidence.get("artifacts"), dict) else {}
    key = artifacts.get(kind)
    if not key:
        return None
    sidecar = sidecars.get(key)
    if isinstance(sidecar, dict):
        return sidecar.get("payload", sidecar)
    return sidecar
