#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)  # type: ignore[attr-defined]
    return module


class LogParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        repo = Path(__file__).resolve().parents[2]
        scripts = repo / "scripts/gentoo"
        cls.log_parser = load_module("log_parser", scripts / "log_parser.py")
        cls.log_stats = load_module("log_stats", scripts / "log_stats.py")
        cls.log_validator = load_module("log_validator", scripts / "log_validator.py")
        cls.fixtures = repo / "tests/gentoo/fixtures/sample_logs"

    def test_parse_valid_runtime_log(self) -> None:
        parser = self.log_parser.LogParser(strict=True)
        entries = list(parser.parse_file(self.fixtures / "valid_runtime.jsonl"))
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].call, "malloc")
        self.assertEqual(entries[0].action, "ClampSize")
        self.assertEqual(entries[0].latency_ns, 185)

    def test_parse_valid_hook_log(self) -> None:
        parser = self.log_parser.LogParser(strict=True)
        entries = list(parser.parse_file(self.fixtures / "valid_hook.jsonl"))
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].call, "__hook_event__")
        self.assertEqual(entries[0].action, "hook_enable")

    def test_parse_deployed_runtime_sink_rows(self) -> None:
        rows = [
            {
                "schema_version": "1.0",
                "event": "repair",
                "trace_id": "membrane::heal::0000000000000001",
                "decision_id": 1,
                "pid": 12345,
                "runtime_mode": "hardened",
                "api_family": "string_memory",
                "symbol": "memcpy",
                "action": "Repair",
                "outcome": "repair",
                "healing_action": "ClampSize",
                "details": {"requested": 32, "clamped": 8},
            },
            {
                "schema_version": "1.0",
                "event": "deny",
                "seq": 1,
                "pid": 12345,
                "runtime_mode": "hardened",
                "api_family": "Signal",
                "symbol": "kill",
                "action": "Deny",
                "outcome": "deny",
                "reason": "invalid_signal_number",
                "errno": 22,
                "policy_id": 0,
                "risk_upper_bound_ppm": 0,
                "evidence_seqno": 0,
                "addr_hint": "0xffffffffffffffff",
                "requested_bytes": 0,
                "is_write": False,
            },
            {
                "schema_version": "1.0",
                "event": "exit_summary",
                "pid": 12345,
                "runtime_mode": "hardened",
                "symbol": "process",
                "denials": 1,
                "total_heals": 1,
                "runtime_log_written_records": 2,
                "runtime_log_dropped_records": 0,
                "runtime_log_short_writes": 0,
                "runtime_log_open_failures": 0,
            },
        ]
        parser = self.log_parser.LogParser(strict=True)
        entries = [
            parser.parse_line(json.dumps(row), index)
            for index, row in enumerate(rows, 1)
        ]

        self.assertEqual(
            [entry.event for entry in entries], ["repair", "deny", "exit_summary"]
        )
        self.assertEqual(
            [entry.call for entry in entries],
            ["memcpy", "kill", "__exit_summary__"],
        )
        self.assertEqual([entry.action for entry in entries], ["ClampSize", "Deny", None])
        self.assertTrue(all(entry.timestamp is None for entry in entries))
        self.assertEqual(self.log_validator.LogValidator().validate(entries), [])

        stats = self.log_stats.LogStats()
        stats.extend(entries)
        snapshot = stats.to_dict()
        self.assertEqual(
            snapshot["by_event"], {"repair": 1, "deny": 1, "exit_summary": 1}
        )
        self.assertEqual(snapshot["by_mode"], {"hardened": 3})

    def test_deployed_runtime_sink_rejects_missing_deny_symbol(self) -> None:
        parser = self.log_parser.LogParser(strict=True)
        row = {
            "schema_version": "1.0",
            "event": "deny",
            "pid": 12345,
            "runtime_mode": "hardened",
            "api_family": "Signal",
            "reason": "invalid_signal_number",
            "errno": 22,
            "policy_id": 0,
        }
        with self.assertRaises(self.log_parser.ParseError) as error:
            parser.parse_line(json.dumps(row))
        self.assertIn("deny row missing required field(s): symbol", str(error.exception))

    def test_deployed_runtime_sink_rejects_missing_repair_symbol(self) -> None:
        parser = self.log_parser.LogParser(strict=True)
        row = {
            "schema_version": "1.0",
            "event": "repair",
            "pid": 12345,
            "runtime_mode": "hardened",
            "api_family": "string_memory",
            "healing_action": "ClampSize",
            "details": {"requested": 32, "clamped": 8},
        }
        with self.assertRaises(self.log_parser.ParseError) as error:
            parser.parse_line(json.dumps(row))
        self.assertIn("repair row missing required field(s): symbol", str(error.exception))

    def test_deployed_runtime_sink_rejects_blank_or_unknown_repair_symbol(self) -> None:
        parser = self.log_parser.LogParser(strict=True)
        row = {
            "schema_version": "1.0",
            "event": "repair",
            "pid": 12345,
            "runtime_mode": "hardened",
            "api_family": "string_memory",
            "healing_action": "ClampSize",
            "details": {"requested": 32, "clamped": 8},
        }
        for symbol in ("", "   ", "unknown", "UNKNOWN", "UnKnOwN"):
            with self.subTest(symbol=symbol):
                with self.assertRaises(self.log_parser.ParseError):
                    parser.parse_line(json.dumps({**row, "symbol": symbol}))

    def test_invalid_json_raises_in_strict_mode(self) -> None:
        parser = self.log_parser.LogParser(strict=True)
        with self.assertRaises(self.log_parser.ParseError):
            list(parser.parse_file(self.fixtures / "invalid_json.jsonl"))

    def test_invalid_line_collected_in_non_strict_mode(self) -> None:
        parser = self.log_parser.LogParser(strict=False)
        entries = list(parser.parse_file(self.fixtures / "invalid_missing_field.jsonl"))
        self.assertEqual(entries, [])
        self.assertEqual(len(parser.errors), 1)
        self.assertIn("missing required field", str(parser.errors[0]))

    def test_stats_and_validator(self) -> None:
        parser = self.log_parser.LogParser(strict=True)
        entries = list(parser.parse_file(self.fixtures / "valid_runtime.jsonl"))

        stats = self.log_stats.LogStats()
        stats.extend(entries)
        snapshot = stats.to_dict()
        self.assertEqual(snapshot["total_entries"], 2)
        self.assertIn("malloc", snapshot["by_call"])

        validator = self.log_validator.LogValidator()
        issues = validator.validate(entries)
        self.assertEqual(issues, [])


if __name__ == "__main__":
    unittest.main()
