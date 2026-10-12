#!/usr/bin/env python3
"""Validation and anomaly checks for FrankenLibC logs."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Iterable, List, Optional

try:
    from log_parser import LogEntry
except ImportError:  # pragma: no cover
    from .log_parser import LogEntry  # type: ignore


KNOWN_HEALING_ACTIONS = {
    "ClampSize",
    "TruncateWithNull",
    "IgnoreDoubleFree",
    "IgnoreForeignFree",
    "ReallocAsMalloc",
    "ReturnSafeDefault",
    "UpgradeToSafeVariant",
    "Deny",
    "hook_enable",
    "hook_disable",
    "hook_skip",
}

POINTER_RE = re.compile(r"^0x[0-9a-fA-F]+$")


@dataclass
class ValidationIssue:
    severity: str
    message: str
    line: int
    call: str


class LogValidator:
    def __init__(
        self,
        known_actions: Optional[set[str]] = None,
        max_latency_ns: int = 1_000_000_000,
        high_latency_ns: int = 10_000_000,
    ) -> None:
        self.known_actions = known_actions or KNOWN_HEALING_ACTIONS
        self.max_latency_ns = max_latency_ns
        self.high_latency_ns = high_latency_ns
        self._last_ts_by_pid: Dict[int, datetime] = {}

    def validate_entry(self, entry: LogEntry) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = []

        if entry.latency_ns < 0 or entry.latency_ns > self.max_latency_ns:
            issues.append(
                ValidationIssue(
                    "error",
                    f"latency out of bounds: {entry.latency_ns}",
                    entry.source_line,
                    entry.call,
                )
            )
        elif entry.latency_ns > self.high_latency_ns:
            issues.append(
                ValidationIssue(
                    "warning",
                    f"high latency detected: {entry.latency_ns}",
                    entry.source_line,
                    entry.call,
                )
            )

        if entry.action and entry.action not in self.known_actions:
            issues.append(
                ValidationIssue(
                    "warning",
                    f"unknown action: {entry.action}",
                    entry.source_line,
                    entry.call,
                )
            )

        if entry.result and isinstance(entry.result, dict):
            ptr = entry.result.get("ptr")
            if isinstance(ptr, str) and ptr and not POINTER_RE.match(ptr):
                issues.append(
                    ValidationIssue(
                        "error",
                        f"invalid pointer format: {ptr}",
                        entry.source_line,
                        entry.call,
                    )
                )

        ts = self._parse_timestamp(entry.timestamp) if entry.timestamp is not None else None
        if entry.timestamp is not None and ts is None:
            issues.append(
                ValidationIssue(
                    "error",
                    f"invalid timestamp: {entry.timestamp}",
                    entry.source_line,
                    entry.call,
                )
            )
        elif ts is not None and entry.pid is not None:
            prev = self._last_ts_by_pid.get(entry.pid)
            if prev and ts < prev:
                issues.append(
                    ValidationIssue(
                        "warning",
                        f"non-monotonic timestamp for pid {entry.pid}: {entry.timestamp}",
                        entry.source_line,
                        entry.call,
                    )
                )
            self._last_ts_by_pid[entry.pid] = ts

        return issues

    def validate(self, entries: Iterable[LogEntry]) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = []
        for entry in entries:
            issues.extend(self.validate_entry(entry))
        return issues

    @staticmethod
    def _parse_timestamp(value: str) -> Optional[datetime]:
        try:
            if value.endswith("Z"):
                value = value[:-1] + "+00:00"
            return datetime.fromisoformat(value)
        except Exception:  # noqa: BLE001
            return None
