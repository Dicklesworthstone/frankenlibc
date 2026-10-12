#!/usr/bin/env python3
"""Statistics aggregation for FrankenLibC log entries."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, Set

try:
    from log_parser import LogEntry
except ImportError:  # pragma: no cover
    from .log_parser import LogEntry  # type: ignore


@dataclass
class LogStats:
    total_entries: int = 0
    by_call: Dict[str, int] = field(default_factory=dict)
    by_action: Dict[str, int] = field(default_factory=dict)
    by_event: Dict[str, int] = field(default_factory=dict)
    by_mode: Dict[str, int] = field(default_factory=dict)
    latency_sum_ns: int = 0
    latency_max_ns: int = 0
    unique_pids: Set[int] = field(default_factory=set)

    def record(self, entry: LogEntry) -> None:
        self.total_entries += 1
        self.by_call[entry.call] = self.by_call.get(entry.call, 0) + 1
        if entry.action:
            self.by_action[entry.action] = self.by_action.get(entry.action, 0) + 1
        if entry.event:
            self.by_event[entry.event] = self.by_event.get(entry.event, 0) + 1
        if entry.runtime_mode:
            self.by_mode[entry.runtime_mode] = self.by_mode.get(entry.runtime_mode, 0) + 1
        self.latency_sum_ns += entry.latency_ns
        self.latency_max_ns = max(self.latency_max_ns, entry.latency_ns)
        if entry.pid is not None:
            self.unique_pids.add(entry.pid)

    def extend(self, entries: Iterable[LogEntry]) -> None:
        for entry in entries:
            self.record(entry)

    @property
    def latency_avg_ns(self) -> float:
        if self.total_entries == 0:
            return 0.0
        return self.latency_sum_ns / self.total_entries

    def to_dict(self) -> Dict[str, object]:
        return {
            "total_entries": self.total_entries,
            "by_call": dict(self.by_call),
            "by_action": dict(self.by_action),
            "by_event": dict(self.by_event),
            "by_mode": dict(self.by_mode),
            "latency_avg_ns": round(self.latency_avg_ns, 2),
            "latency_max_ns": self.latency_max_ns,
            "unique_pids": sorted(self.unique_pids),
            "unique_pid_count": len(self.unique_pids),
        }
