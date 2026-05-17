"""Agent Defense coordination layer.

This package orchestrates online agent defense by composing policy
evaluation, bypass detection, action normalization, and the security
guard pipeline (from ``guardrail.security``).  It is the Python side of the
bridge called by the OpenClaw behavior mediator.

Public entry point: ``guardrail.agent_defense.bridge.handle``.

This package MAY import from ``guardrail.security``.  ``guardrail.security`` MUST
NEVER import from ``guardrail.agent_defense``.
"""

from .bridge import handle

__all__ = ["handle"]
