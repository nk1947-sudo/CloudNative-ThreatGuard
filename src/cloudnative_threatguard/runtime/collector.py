"""
Live Tetragon event collection.

Reads the structured event stream a Tetragon DaemonSet exports to stdout
(container ``export-stdout``) for a bounded time window, keeps only events
for the target workload, deduplicates repeated export records by their source
identity, and redacts sensitive command-line arguments. Capture problems are
returned as an explicit status; an empty result is never silently presented
as a healthy capture.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from cloudnative_threatguard.config import settings

EVENT_KEYS = ("process_exec", "process_exit", "process_kprobe")
_FRACTION_RE = re.compile(r"(\.\d{6})\d+")
_SECRET_ARG_RE = re.compile(
    r"(?i)((?:password|passwd|secret|token|api[-_]?key|authorization)\s*[=:]\s*)\S+"
)

Runner = Callable[[list[str]], tuple[int, str]]


def kubectl_runner(args: list[str]) -> tuple[int, str]:
    try:
        proc = subprocess.run(["kubectl", *args], capture_output=True, text=True, timeout=60, check=False)
    except FileNotFoundError:
        return 127, "kubectl not found"
    except subprocess.TimeoutExpired:
        return 124, "kubectl timed out"
    return proc.returncode, proc.stdout if proc.returncode == 0 else (proc.stdout + proc.stderr)


@dataclass
class CollectionResult:
    events: list[dict[str, Any]] = field(default_factory=list)
    status: str = "ok"  # ok | degraded | unavailable
    parse_errors: int = 0
    duplicates_dropped: int = 0
    dropped_other_pods: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def event_kinds(self) -> dict[str, int]:
        kinds: dict[str, int] = {}
        for event in self.events:
            kind = event_kind(event)
            kinds[kind] = kinds.get(kind, 0) + 1
        return kinds

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_kinds": self.event_kinds,
            "status": self.status,
            "events_captured": len(self.events),
            "parse_errors": self.parse_errors,
            "duplicates_dropped": self.duplicates_dropped,
            "dropped_other_pods": self.dropped_other_pods,
            "errors": self.errors,
            "collector_version": settings.COLLECTOR_VERSION,
        }


def parse_time(value: str) -> datetime | None:
    """Parses Tetragon RFC 3339 timestamps (nanosecond precision) to aware datetimes."""
    if not value or not isinstance(value, str):
        return None
    text = _FRACTION_RE.sub(r"\1", value.strip())
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def event_kind(event: dict[str, Any]) -> str:
    for key in EVENT_KEYS:
        if key in event and isinstance(event[key], dict):
            return key
    return ""


def event_process(event: dict[str, Any]) -> dict[str, Any]:
    kind = event_kind(event)
    process = event[kind].get("process") if kind else None
    return process if isinstance(process, dict) else {}


def event_pod(event: dict[str, Any]) -> tuple[str, str]:
    pod = event_process(event).get("pod")
    if not isinstance(pod, dict):
        return "", ""
    return pod.get("namespace") or "", pod.get("name") or ""


def source_identity(event: dict[str, Any]) -> str:
    """Stable identity for deduplication. Prefers Tetragon's own exec id; never a random value."""
    kind = event_kind(event)
    process = event_process(event)
    body = event.get(kind, {}) if kind else {}
    parts = [
        kind,
        str(event.get("time", "")),
        str(process.get("exec_id", "")),
        str(process.get("pid", "")),
        str(body.get("function_name", "")),
        json.dumps(body.get("args", ""), sort_keys=True),
        str(body.get("signal", "")),
        str(process.get("binary", "")),
        str(process.get("arguments", "")),
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:24]


def redact(event: dict[str, Any]) -> dict[str, Any]:
    """Returns a copy keeping only needed fields, with secret-looking arguments masked."""
    kind = event_kind(event)
    if not kind:
        return {}
    body = event[kind]
    process = dict(body.get("process") or {})
    keep = {k: process[k] for k in ("exec_id", "pid", "uid", "binary", "arguments", "pod", "start_time") if k in process}
    if isinstance(keep.get("arguments"), str):
        keep["arguments"] = _SECRET_ARG_RE.sub(r"\1[REDACTED]", keep["arguments"])
    out_body: dict[str, Any] = {"process": keep}
    for key in ("function_name", "args", "action", "signal", "status", "policy_name"):
        if key in body:
            out_body[key] = body[key]
    return {"time": event.get("time", ""), "node_name": event.get("node_name", ""), kind: out_body}


def parse_event_lines(lines: Iterable[str]) -> tuple[list[dict[str, Any]], int]:
    """Parses JSON lines; counts malformed lines instead of silently skipping them."""
    events: list[dict[str, Any]] = []
    errors = 0
    for line in lines:
        text = line.strip()
        if not text:
            continue
        try:
            event = json.loads(text)
        except json.JSONDecodeError:
            errors += 1
            continue
        if not isinstance(event, dict) or not event_kind(event):
            continue
        events.append(event)
    return events, errors


def collect_live_events(
    since: str,
    namespace: str,
    pod: str,
    runner: Runner = kubectl_runner,
    tetragon_namespace: str = "tetragon",
    container: str = "export-stdout",
    tail: int = 5000,
) -> CollectionResult:
    """Reads one bounded window of the exported event stream for the target pod."""
    result = CollectionResult()
    code, out = runner([
        "logs", "-n", tetragon_namespace, "-l", "app.kubernetes.io/name=tetragon",
        "-c", container, f"--since-time={since}", f"--tail={tail}", "--prefix=false",
    ])
    if code != 0:
        result.status = "unavailable"
        result.errors.append(f"kubectl logs failed (exit {code}): {out.strip()[:200]}")
        return result

    raw, result.parse_errors = parse_event_lines(out.splitlines())
    if result.parse_errors:
        result.status = "degraded"
        result.errors.append(f"{result.parse_errors} malformed event line(s) skipped")

    seen: set[str] = set()
    for event in raw:
        ns, name = event_pod(event)
        if ns != namespace or name != pod:
            result.dropped_other_pods += 1
            continue
        identity = source_identity(event)
        if identity in seen:
            result.duplicates_dropped += 1
            continue
        seen.add(identity)
        cleaned = redact(event)
        if cleaned:
            result.events.append(cleaned)
    return result


def events_in_window(events: list[dict[str, Any]], start: datetime, end: datetime) -> list[dict[str, Any]]:
    """Events whose own timestamp falls inside [start, end]; untimestamped events are excluded."""
    selected = []
    for event in events:
        when = parse_time(str(event.get("time", "")))
        if when is not None and start <= when <= end:
            selected.append(event)
    return selected


def enforcement_observed(events: list[dict[str, Any]]) -> bool:
    """True when the window contains a kill action or a SIGKILL process exit."""
    for event in events:
        kind = event_kind(event)
        body = event.get(kind, {}) if kind else {}
        if kind == "process_exit" and str(body.get("signal", "")).upper() == "SIGKILL":
            return True
        if kind == "process_kprobe" and "SIGKILL" in str(body.get("action", "")).upper():
            return True
    return False
