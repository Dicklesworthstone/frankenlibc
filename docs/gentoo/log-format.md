# FrankenLibC Gentoo Log Format

This document defines the JSONL schema accepted by:

- `scripts/gentoo/log_parser.py`
- `scripts/gentoo/log_validator.py`
- `scripts/gentoo/log_stats.py`

## Deployed `FRANKENLIBC_LOG` Schema

The runtime appends three event kinds to the path named by `FRANKENLIBC_LOG`.
All use `schema_version="1.0"`, include `pid` and `runtime_mode`, and are valid
independent JSON objects separated by newlines. The hot-path sink does not add a
wall-clock timestamp or per-call latency.
Every row also carries a positive process-local `seq` from one atomic namespace
shared by repair, denial, and exit-summary producers. Concurrent writers can
reserve numbers before an earlier writer reaches `writev`, so consumers that
need causal presentation should sort by `(pid, seq)` rather than assuming
physical append order is sequence order.

Repair events include the healing action and its old/new values. The `symbol`
is mandatory and names the non-empty canonical operation that actually
delegated to the repair. Aliases therefore log that canonical delegated
operation rather than the caller-visible alias; blank values and `unknown`
(in any letter case) are invalid.

```json
{
  "schema_version": "1.0",
  "event": "repair",
  "seq": 1,
  "pid": 12345,
  "runtime_mode": "hardened",
  "api_family": "string_memory",
  "symbol": "memcpy",
  "action": "Repair",
  "outcome": "repair",
  "healing_action": "ClampSize",
  "signal_context": false,
  "details": { "requested": 8192, "clamped": 4096 }
}
```

Semantic denial events identify the ABI symbol and reason. A generic policy
denial emitted while signal-context tracing TLS is unavailable uses the
reserved `runtime_policy` symbol instead:

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
  "policy_id": 0,
  "addr_hint": "0x0",
  "signal_context": false
}
```

`addr_hint` is an opaque policy input, not necessarily a pointer: some API
families use it for scalar descriptors or identifiers. It is emitted only in
`hardened` mode. Strict and off rows omit the key entirely so enabling evidence
does not expand address disclosure in non-hardening modes.

The final row is `event="exit_summary"`. It carries the next shared `seq` and
contains `denials`, all healing
counters, and the `runtime_log_*` written/dropped/short-write/open-failure
counters. A successful fixture run must contain this row; its absence means the
process did not reach normal teardown or the sink failed before the summary.

The sink is opened with append semantics during FrankenLibC's startup
constructor, after mode resolution and before the runtime is published ready.
After a process forks, the child's first continuation step reopens the
configured path, so ordinary post-fork work uses a distinct open-file
description and observes a path rotated before `fork()`. Signals are not yet
masked across the clone-to-reopen interval; a pending handler can therefore
emit one early row through the inherited descriptor before reopen. The
`fixture_hardened_first_heal` gate rotates the path before forking and rejects
overlapping parent/child PIDs across the two resulting JSONL files.

On Linux x86_64 and aarch64, repair and denial records emitted from an
interposed signal-handler trampoline use a fixed 1 KiB stack formatter and one
bounded record write to the preopened descriptor, with at most four raw
`writev(2)` attempts when interrupted by `EINTR`. That path does not allocate,
lock, read the environment, touch Rust
TLS, or update the heap-backed diagnostic ledger/ring. A regular-file syscall
can still wait in the filesystem, so this is an async-signal-safe producer
contract, not a hard real-time guarantee.
`fixture_hardened_first_heal` induces both a `strlen` repair and a leaf
`pthread_kill` semantic denial inside `SIGUSR1`, requires
`signal_context=true` on both rows, and checks the exact parent/child event
sequences and exit counters.

Repair and denial events are never sampled or rate-limited: suppressing an
adverse decision would make the evidence contract misleading. Each generated
repair, denial, or summary record is bounded to 1 KiB. Invalid/oversized
records and writes that fail or short-write increment
`runtime_log_dropped_records`; sink-open failures increment
`runtime_log_open_failures`. Allow decisions are not currently emitted, so
there is no high-volume allow stream to rate-limit. `FRANKENLIBC_HEAL_LOG`
controls only the heap-backed diagnostic ledger/ring; it cannot suppress the
deployed file stream when `FRANKENLIBC_LOG` is configured.

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

- Deployed runtime rows require `schema_version="1.0"`, a positive integer
  process-local `seq`, `pid`, and `runtime_mode=strict|hardened|off`.
- `repair` rows require `api_family`, a non-empty canonical `symbol` other than
  case-insensitive `unknown`, `healing_action`, `signal_context`, and `details`.
  Aliases record the canonical delegated operation.
- `deny` rows require `api_family`, `symbol`, `reason`, `errno`, `policy_id`, and
  `signal_context`.
- `address` and `addr_hint`, when present, must be hexadecimal strings and are
  forbidden outside `hardened` mode.
- `exit_summary` rows require `denials` and `runtime_log_written_records`.
- Timestamp, when present, parseable as ISO8601.
- Latency in `[0, 1_000_000_000]` ns.
- Pointer fields under `result.ptr` must match `0x[0-9a-fA-F]+`.
- Healing actions should be one of known actions (`ClampSize`, `IgnoreDoubleFree`, etc.).
- Per-PID timestamps are checked for monotonic non-decreasing order.
