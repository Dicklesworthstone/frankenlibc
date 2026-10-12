#!/usr/bin/env python3
"""FrankenLibC JSONL parser for runtime and hook events."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional


HEX_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]+$")


@dataclass
class ParseError(Exception):
    line_num: int
    message: str
    line: str = ""

    def __str__(self) -> str:
        return f"line {self.line_num}: {self.message}"


@dataclass
class LogEntry:
    timestamp: Optional[str]
    pid: Optional[int]
    call: str
    latency_ns: int
    event: Optional[str] = None
    runtime_mode: Optional[str] = None
    schema_version: Optional[str] = None
    tid: Optional[int] = None
    args: Dict[str, Any] = field(default_factory=dict)
    result: Optional[Dict[str, Any]] = None
    action: Optional[str] = None
    action_details: Optional[Dict[str, Any]] = None
    stack_hash: Optional[str] = None
    source_line: int = 0
    raw: Dict[str, Any] = field(default_factory=dict)


class LogParser:
    def __init__(self, strict: bool = True) -> None:
        self.strict = strict
        self.errors: List[ParseError] = []

    def parse_file(self, path: Path) -> Iterator[LogEntry]:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line_num, line in enumerate(fh, 1):
                entry = self.parse_line(line, line_num)
                if entry is not None:
                    yield entry

    def parse_line(self, line: str, line_num: int = 1) -> Optional[LogEntry]:
        stripped = line.strip()
        if not stripped:
            return None
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError as exc:
            return self._handle_error(ParseError(line_num, f"invalid JSON: {exc}", stripped))

        try:
            entry = self._normalize(payload, line_num)
        except ParseError as exc:
            return self._handle_error(exc)
        return entry

    def _normalize(self, payload: Dict[str, Any], line_num: int) -> LogEntry:
        if not isinstance(payload, dict):
            raise ParseError(line_num, "JSON value must be an object", json.dumps(payload))

        timestamp = payload.get("ts") or payload.get("timestamp")
        pid = payload.get("pid")
        call = payload.get("call")
        latency_ns = payload.get("latency_ns")
        event = payload.get("event")
        outcome = payload.get("outcome")
        is_repair = event == "repair" or (
            outcome == "repair" and payload.get("healing_action") is not None
        )
        is_deny = event == "deny"
        is_exit_summary = event == "exit_summary"
        is_runtime_sink_row = is_repair or is_deny or is_exit_summary

        if is_runtime_sink_row:
            self._validate_runtime_sink_row(payload, line_num, str(event or outcome))
            if is_exit_summary:
                call = "__exit_summary__"
            else:
                call = payload.get("symbol") or payload.get("api_family")
            latency_ns = 0 if latency_ns is None else latency_ns

        if call is None and event is not None:
            call = "__hook_event__"
        if latency_ns is None:
            latency_ns = 0

        missing = []
        if timestamp is None and not is_runtime_sink_row:
            missing.append("ts|timestamp")
        if pid is None:
            missing.append("pid")
        if call is None:
            missing.append("call|event")
        if latency_ns is None:
            missing.append("latency_ns")
        if missing:
            raise ParseError(line_num, f"missing required field(s): {', '.join(missing)}", json.dumps(payload))

        action = payload.get("action")
        if is_repair:
            action = payload.get("healing_action")
        elif is_deny:
            action = "Deny"
        if action is None and payload.get("event") in {"enable", "disable", "skip"}:
            action = f"hook_{payload['event']}"

        args_value = payload.get("details") if is_repair else payload.get("args")
        args = args_value if isinstance(args_value, dict) else {}
        result = payload.get("result") if isinstance(payload.get("result"), dict) else None
        action_details_value = (
            payload.get("details") if is_repair else payload.get("action_details")
        )
        action_details = action_details_value if isinstance(action_details_value, dict) else None

        try:
            pid_int = int(pid) if pid is not None else None
            tid_int = int(payload["tid"]) if payload.get("tid") is not None else None
            latency_int = int(latency_ns)
        except Exception as exc:  # noqa: BLE001
            raise ParseError(line_num, f"type conversion error: {exc}", json.dumps(payload)) from exc

        return LogEntry(
            timestamp=str(timestamp) if timestamp is not None else None,
            pid=pid_int,
            call=str(call),
            latency_ns=latency_int,
            event=str(event) if event is not None else None,
            runtime_mode=(
                str(payload.get("runtime_mode"))
                if payload.get("runtime_mode") is not None
                else None
            ),
            schema_version=(
                str(payload.get("schema_version"))
                if payload.get("schema_version") is not None
                else None
            ),
            tid=tid_int,
            args=args,
            result=result,
            action=str(action) if action is not None else None,
            action_details=action_details,
            stack_hash=str(payload.get("stack_hash")) if payload.get("stack_hash") is not None else None,
            source_line=line_num,
            raw=payload,
        )

    @staticmethod
    def _validate_runtime_sink_row(payload: Dict[str, Any], line_num: int, event: str) -> None:
        required = ["schema_version", "seq", "pid", "runtime_mode"]
        if event == "repair":
            required.extend(
                [
                    "api_family",
                    "symbol",
                    "healing_action",
                    "errno",
                    "signal_context",
                    "details",
                ]
            )
        elif event == "deny":
            required.extend(
                ["api_family", "symbol", "reason", "errno", "policy_id", "signal_context"]
            )
        elif event == "exit_summary":
            required.extend(["denials", "runtime_log_written_records"])

        missing = [field for field in required if payload.get(field) is None]
        if missing:
            raise ParseError(
                line_num,
                f"{event} row missing required field(s): {', '.join(missing)}",
                json.dumps(payload),
            )
        if str(payload["schema_version"]) != "1.0":
            raise ParseError(
                line_num,
                f"unsupported runtime sink schema_version: {payload['schema_version']}",
                json.dumps(payload),
            )
        if payload["runtime_mode"] not in {"strict", "hardened", "off"}:
            raise ParseError(
                line_num,
                f"invalid runtime_mode: {payload['runtime_mode']}",
                json.dumps(payload),
            )
        if type(payload["seq"]) is not int or payload["seq"] <= 0:
            raise ParseError(
                line_num,
                f"{event} row seq must be a positive integer",
                json.dumps(payload),
            )
        for field in ("address", "addr_hint"):
            if field not in payload:
                continue
            if payload["runtime_mode"] != "hardened":
                raise ParseError(
                    line_num,
                    f"{event} row {field} is forbidden outside hardened mode",
                    json.dumps(payload),
                )
            value = payload[field]
            if not isinstance(value, str) or HEX_ADDRESS_RE.fullmatch(value) is None:
                raise ParseError(
                    line_num,
                    f"{event} row {field} must be a hexadecimal address",
                    json.dumps(payload),
                )
        if event in {"repair", "deny"} and not isinstance(payload["signal_context"], bool):
            raise ParseError(
                line_num,
                f"{event} row signal_context must be boolean",
                json.dumps(payload),
            )
        if event == "repair":
            errno = payload["errno"]
            if type(errno) is not int or not -(2**31) <= errno < 2**31:
                raise ParseError(
                    line_num,
                    "repair row errno must be a signed 32-bit integer",
                    json.dumps(payload),
                )
            symbol = payload["symbol"]
            if not isinstance(symbol, str) or not symbol.strip():
                raise ParseError(
                    line_num,
                    "repair row symbol must be a non-empty canonical symbol",
                    json.dumps(payload),
                )
            if symbol != symbol.strip() or symbol.casefold() == "unknown":
                raise ParseError(
                    line_num,
                    f"repair row symbol is not canonical: {symbol!r}",
                    json.dumps(payload),
                )

    def _handle_error(self, error: ParseError) -> Optional[LogEntry]:
        self.errors.append(error)
        if self.strict:
            raise error
        return None
