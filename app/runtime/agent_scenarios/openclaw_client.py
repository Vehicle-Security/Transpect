from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
COMMON = ROOT / "scripts" / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from trace_common import get_gateway_status, run_openclaw_agent  # noqa: E402


@dataclass(frozen=True)
class AgentRunResult:
    ok: bool
    run_id: str | None
    session_id: str | None
    status: str
    raw: dict[str, Any]
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "run_id": self.run_id,
            "session_id": self.session_id,
            "status": self.status,
            "error": self.error,
            "raw": self.raw,
        }


@dataclass(frozen=True)
class OpenClawStatus:
    ok: bool
    raw: dict[str, Any]
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "error": self.error, "raw": self.raw}


class OpenClawAgentClient:
    """Natural-language-only OpenClaw Agent client.

    This class deliberately exposes no browser action helpers. Real experiments
    must let the Agent decide whether to call browser tools.
    """

    def send_task(
        self,
        prompt: str,
        agent_id: str = "main",
        timeout_seconds: int = 300,
        metadata: dict[str, Any] | None = None,
        session_id: str | None = None,
    ) -> AgentRunResult:
        del metadata  # metadata is for caller-side report correlation only.
        payload = run_openclaw_agent(
            message=str(prompt),
            agent_id=agent_id,
            timeout_seconds=int(timeout_seconds),
            session_id=session_id,
            no_wait=True,
        )
        return AgentRunResult(
            ok=bool(payload.get("ok")),
            run_id=payload.get("runId"),
            session_id=payload.get("sessionId"),
            status="started" if payload.get("ok") else "failed",
            raw=payload,
            error=payload.get("error"),
        )

    def get_status(self) -> OpenClawStatus:
        try:
            raw = get_gateway_status(include_probe=False, timeout_seconds=30)
            return OpenClawStatus(ok=True, raw=raw)
        except Exception as error:  # noqa: BLE001
            return OpenClawStatus(ok=False, raw={}, error=str(error))

    def ensure_gateway_ready(self) -> OpenClawStatus:
        return self.get_status()

