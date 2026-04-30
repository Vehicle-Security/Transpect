from __future__ import annotations

import os
import shlex
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class CommandPolicyResult:
    decision: str
    risk_level: str
    risk_score: int
    reasons: list[str] = field(default_factory=list)
    hard_block_reason: str | None = None
    command_name: str | None = None
    targets: list[str] = field(default_factory=list)
    gray_zone: bool = False


READ_COMMANDS = {"cat", "sed", "head", "tail", "less", "more"}
LIST_COMMANDS = {"ls", "pwd", "find"}
DESTRUCTIVE_COMMANDS = {"rm", "dd", "mkfs", "mkfs.ext4", "mkfs.xfs", "diskutil"}
NETWORK_COPY_COMMANDS = {"scp", "rsync", "ftp", "sftp"}
SHELL_INTERPRETERS = {"sh", "bash", "zsh", "fish", "python", "python3", "node", "perl", "ruby"}
BOOTSTRAP_FILES = {"BOOTSTRAP.md", "IDENTITY.md", "USER.md", "MEMORY.md"}
SENSITIVE_MARKERS = (
    ".env",
    ".ssh",
    "id_rsa",
    "id_ed25519",
    "credential",
    "credentials",
    "cookie",
    "token",
    "secret",
    "password",
    "api_key",
    "apikey",
    "private_key",
    "browser profile",
    "login data",
)


def _split_pipeline(command: str) -> list[list[str]]:
    segments: list[list[str]] = []
    for raw_segment in command.split("|"):
        try:
            parts = shlex.split(raw_segment, posix=True)
        except ValueError:
            return []
        if parts:
            segments.append(parts)
    return segments


def _command_name(token: str) -> str:
    name = Path(token).name.lower()
    return name[:-4] if name.endswith(".exe") else name


def _is_flag(token: str) -> bool:
    return token.startswith("-") and token not in {"-", "--"}


def _expand_path(value: str) -> str:
    return str(Path(os.path.expandvars(os.path.expanduser(value))).resolve()) if value else value


def _looks_like_url(value: str) -> bool:
    lowered = value.lower()
    return lowered.startswith("http://") or lowered.startswith("https://")


def _path_targets(parts: list[str]) -> list[str]:
    targets: list[str] = []
    skip_next_for_option = False
    options_with_values = {"-o", "--output", "-C", "--directory", "-f", "--file"}
    for token in parts[1:]:
        if skip_next_for_option:
            skip_next_for_option = False
            continue
        if token in options_with_values:
            skip_next_for_option = True
            continue
        if _is_flag(token) or token in {"2>&1", "1>&2"}:
            continue
        if _looks_like_url(token):
            continue
        targets.append(token)
    return targets


def _is_openclaw_bootstrap_path(value: str) -> bool:
    expanded = _expand_path(value)
    workspace = str((Path.home() / ".openclaw" / "workspace").resolve())
    path = Path(expanded)
    return expanded.startswith(workspace) and (path.name in BOOTSTRAP_FILES or "memory" in path.parts)


def _has_bootstrap_intent(user_goal: str) -> bool:
    lowered = user_goal.lower()
    return any(marker.lower() in lowered for marker in ("bootstrap", "identity.md", "user.md", "memory.md", "openclaw 初始化", "初始化"))


def _is_sensitive_path(value: str) -> bool:
    lowered = _expand_path(value).lower()
    return any(marker in lowered for marker in SENSITIVE_MARKERS)


def _is_root_or_device_target(value: str) -> bool:
    expanded = _expand_path(value)
    lowered = expanded.lower()
    return expanded == "/" or lowered.startswith("/dev/") or lowered in {"/etc", "/bin", "/sbin", "/usr", "/system"}


def _curl_has_upload(parts: list[str]) -> bool:
    data_flags = {"-d", "--data", "--data-raw", "--data-binary", "--form", "-F", "--upload-file", "-T"}
    for index, token in enumerate(parts):
        if token in data_flags:
            return True
        if any(token.startswith(f"{flag}=") for flag in data_flags if flag.startswith("--")):
            return True
        if token.startswith("-d") and token != "-d":
            return True
        if token.startswith("-F") and token != "-F":
            return True
        if token.startswith("@") and index > 0 and parts[index - 1] in data_flags:
            return True
    return False


def _pipeline_executes_download(segments: list[list[str]]) -> bool:
    if len(segments) < 2:
        return False
    first = _command_name(segments[0][0])
    if first not in {"curl", "wget"}:
        return False
    return any(_command_name(segment[0]) in SHELL_INTERPRETERS for segment in segments[1:])


def analyze_file_read(path: str, *, source_type: str = "unknown", user_goal: str = "", authorized: bool = False) -> CommandPolicyResult:
    if _is_openclaw_bootstrap_path(path) and (_has_bootstrap_intent(user_goal) or authorized):
        return CommandPolicyResult("allow", "low", 1, ["OpenClaw bootstrap workspace file read is explicitly allowed."], targets=[path])
    if _is_sensitive_path(path):
        return CommandPolicyResult(
            "block",
            "critical",
            10,
            ["File read targets a sensitive credential, token, cookie, or secret path."],
            hard_block_reason="读取本地敏感凭据或密钥文件。",
            targets=[path],
        )
    if source_type in {"external_website", "comment", "advertisement", "popup"} and not authorized:
        return CommandPolicyResult(
            "require_confirmation",
            "high",
            6,
            ["Low-trust source requested a local file read."],
            targets=[path],
            gray_zone=True,
        )
    return CommandPolicyResult("allow", "low", 1, ["File read target is not classified as sensitive."], targets=[path])


def analyze_command(command: str, *, source_type: str = "unknown", user_goal: str = "", authorized: bool = False) -> CommandPolicyResult:
    segments = _split_pipeline(command)
    if not segments:
        return CommandPolicyResult("require_confirmation", "high", 6, ["Command could not be parsed safely."], gray_zone=True)

    first = segments[0]
    name = _command_name(first[0])
    targets = _path_targets(first)

    if _pipeline_executes_download(segments):
        return CommandPolicyResult(
            "block",
            "critical",
            10,
            ["Downloaded content is piped into an interpreter."],
            hard_block_reason="下载内容直接交给解释器执行。",
            command_name=name,
            targets=targets,
        )

    if name in {"sudo", "su"}:
        return CommandPolicyResult(
            "block",
            "critical",
            10,
            ["Command attempts privilege escalation."],
            hard_block_reason="命令尝试提升权限。",
            command_name=name,
            targets=targets,
        )

    if name in DESTRUCTIVE_COMMANDS:
        if name == "rm" and not any(flag in first for flag in ("-r", "-R", "-rf", "-fr", "--recursive")):
            return CommandPolicyResult("require_confirmation", "high", 6, ["File removal requires confirmation."], command_name=name, targets=targets)
        if any(_is_root_or_device_target(target) for target in targets) or name != "rm":
            return CommandPolicyResult(
                "block",
                "critical",
                10,
                ["Command can destructively modify filesystems, disks, or critical paths."],
                hard_block_reason="命令可能破坏文件系统或关键路径。",
                command_name=name,
                targets=targets,
            )
        if source_type in {"unknown", "comment", "external_website", "advertisement", "popup"} and not authorized:
            return CommandPolicyResult(
                "block",
                "critical",
                10,
                ["Low-trust source requested recursive deletion."],
                hard_block_reason="低可信来源诱导执行删除命令。",
                command_name=name,
                targets=targets,
            )
        return CommandPolicyResult("require_confirmation", "high", 6, ["Recursive removal requires confirmation."], command_name=name, targets=targets)

    if name == "chmod" and any(token == "777" or token.endswith("777") for token in first[1:]):
        return CommandPolicyResult(
            "block",
            "critical",
            9,
            ["Command makes a path world-writable."],
            hard_block_reason="命令会设置高风险权限。",
            command_name=name,
            targets=targets,
        )

    if name in {"nc", "netcat", "ncat"}:
        return CommandPolicyResult(
            "block",
            "critical",
            10,
            ["Netcat-style command can create shells or exfiltrate data."],
            hard_block_reason="命令可能建立反向 shell 或外传数据。",
            command_name=name,
            targets=targets,
        )

    if name in NETWORK_COPY_COMMANDS:
        return CommandPolicyResult(
            "require_confirmation",
            "high",
            7,
            ["Network file transfer requires explicit confirmation."],
            command_name=name,
            targets=targets,
            gray_zone=True,
        )

    if name == "curl":
        if _curl_has_upload(first):
            return CommandPolicyResult(
                "block",
                "critical",
                10,
                ["curl includes data upload or form submission arguments."],
                hard_block_reason="命令可能外传本地数据。",
                command_name=name,
                targets=targets,
            )
        return CommandPolicyResult("warn", "medium", 3, ["curl fetch without upload is recorded for audit."], command_name=name, targets=targets)

    if name in READ_COMMANDS:
        path_results = [analyze_file_read(target, source_type=source_type, user_goal=user_goal, authorized=authorized) for target in targets]
        blocking = next((item for item in path_results if item.decision == "block"), None)
        if blocking:
            return CommandPolicyResult(
                "block",
                "critical",
                blocking.risk_score,
                blocking.reasons,
                hard_block_reason=blocking.hard_block_reason,
                command_name=name,
                targets=targets,
            )
        confirm = next((item for item in path_results if item.decision == "require_confirmation"), None)
        if confirm:
            return CommandPolicyResult("require_confirmation", "high", confirm.risk_score, confirm.reasons, command_name=name, targets=targets, gray_zone=True)
        reasons = [reason for item in path_results for reason in item.reasons] or ["Read-only command targets non-sensitive paths."]
        return CommandPolicyResult("allow", "low", 1, reasons, command_name=name, targets=targets)

    if name in LIST_COMMANDS:
        if any(_is_sensitive_path(target) and not _is_openclaw_bootstrap_path(target) for target in targets):
            return CommandPolicyResult(
                "require_confirmation",
                "high",
                6,
                ["Listing sensitive directories requires confirmation."],
                command_name=name,
                targets=targets,
                gray_zone=True,
            )
        return CommandPolicyResult("allow", "low", 1, ["Read-only listing/search command is allowed."], command_name=name, targets=targets)

    return CommandPolicyResult(
        "require_confirmation",
        "high",
        6,
        ["Command is not covered by deterministic allow/block policy."],
        command_name=name,
        targets=targets,
        gray_zone=True,
    )
