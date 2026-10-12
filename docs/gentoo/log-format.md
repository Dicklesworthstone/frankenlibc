# FrankenLibC Gentoo Log Format

This document defines the JSONL schema accepted by:

- `scripts/gentoo/log_parser.py`
- `scripts/gentoo/log_validator.py`
- `scripts/gentoo/log_stats.py`

## Deployed `FRANKENLIBC_LOG` Schema

The runtime appends three event kinds to the path named by `FRANKENLIBC_LOG`.
All use `schema_version="1.0"`, include `pid` and `runtime_mode`, and are valid
independent JSON objects separated by newlines. The hot-path sink does not add a
wall-clock timestamp or per-call latency; consumers must preserve file order.

Repair events include the healing action and its old/new values. The `symbol`
is mandatory and names the non-empty canonical operation that actually
delegated to the repair. Aliases therefore log that canonical delegated
operation rather than the caller-visible alias; blank values and `unknown`
(in any letter case) are invalid.

```json
{
  "schema_version": "1.0",
  "event": "repair",
  "pid": 12345,
  "runtime_mode": "hardened",
  "api_family": "string_memory",
  "symbol": "memcpy",
  "action": "Repair",
  "outcome": "repair",
  "healing_action": "ClampSize",
  "details": { "requested": 8192, "clamped": 4096 }
}
```

Denial events identify the ABI symbol and the semantic or runtime-policy reason:

```json
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
  "policy_id": 0
}
```

The final row is `event="exit_summary"`. It contains `denials`, all healing
counters, and the `runtime_log_*` written/dropped/short-write/open-failure
counters. A successful fixture run must contain this row; its absence means the
process did not reach normal teardown or the sink failed before the summary.

The sink is opened lazily with append semantics. If a process forks after the
sink has opened, the child reopens the configured path before user child
handlers run. Parent and child therefore have distinct open-file descriptions,
and a log path rotated before `fork()` is observed by the child instead of the
child continuing to write through the parent's inherited descriptor. The
`fixture_hardened_first_heal` gate rotates the path before forking and rejects
overlapping parent/child PIDs across the two resulting JSONL files.

## Captured Call Schema

The parser also accepts older, higher-volume call captures produced by tooling:

```json
{
  "ts": "2026-02-13T01:45:00.123456Z",
  "pid": 12345,
  "tid": 12346,
  "call": "malloc",
  "args": { "size": 4096 },
  "result": { "ptr": "0x7f1234567890", "actual_size": 4096 },
  "action": "ClampSize",
  "action_details": {
    "original_size": 8589934592,
    "clamped_size": 4096,
    "reason": "size_exceeds_max"
  },
  "latency_ns": 185,
  "stack_hash": "abc123def456"
}
```

Required:

For captured call rows:

- `ts` (or `timestamp`)
- `pid`
- `call` (or `event` for hook logs)
- `latency_ns` (`0` accepted for hook events)

## Hook Event Schema

Hook logs emitted by `frankenlibc-ebuild-hooks.sh` use:

```json
{
  "timestamp": "2026-02-13T01:45:00Z",
  "event": "enable",
  "atom": "sys-apps/coreutils-9.9-r1",
  "phase": "src_test",
  "pid": 4567,
  "message": "enabled"
}
```

Parser normalization:

- `event` -> `call="__hook_event__"`
- `event=enable|disable|skip` -> `action=hook_enable|hook_disable|hook_skip`

## Validation Rules

- Deployed runtime rows require `schema_version="1.0"`, `pid`, and
  `runtime_mode=strict|hardened|off`.
- `repair` rows require `api_family`, a non-empty canonical `symbol` other than
  case-insensitive `unknown`, `healing_action`, and `details`. Aliases record
  the canonical delegated operation.
- `deny` rows require `api_family`, `symbol`, `reason`, `errno`, and `policy_id`.
- `exit_summary` rows require `denials` and `runtime_log_written_records`.
- Timestamp, when present, parseable as ISO8601.
- Latency in `[0, 1_000_000_000]` ns.
- Pointer fields under `result.ptr` must match `0x[0-9a-fA-F]+`.
- Healing actions should be one of known actions (`ClampSize`, `IgnoreDoubleFree`, etc.).
- Per-PID timestamps are checked for monotonic non-decreasing order.
