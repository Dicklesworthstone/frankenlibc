# Terminal Signature Algebra

`bd-2gjs.6` grounds the R17 terminal/PTY runtime artifact in a compact algebra over terminal-mode transitions instead of treating `tcsetattr`/`cfset*speed` as opaque mutations.

## State Space

Each observed terminal state is projected into a small signature class:

- `mode ∈ { cooked, cbreak, raw, noncanonical }`
- `echo_enabled ∈ { false, true }`
- `speed_coupling ∈ { coupled, diverged }`

The implementation lives in [`termios_abi.rs`](/data/projects/frankenlibc/crates/frankenlibc-abi/src/termios_abi.rs). `TerminalSignatureClass::from_termios` extracts the class from a live `termios`, and `is_legal` rejects canonical cooked states with diverged input/output baud because that combination silently breaks the expected POSIX control surface.

## Observation Vector

Each transition is compiled into a four-dimensional rough-path observation:

1. Mode code: cooked `0`, cbreak `1/3`, raw `2/3`, noncanonical `1`
2. Echo bit: `0` or `1`
3. Speed-coupling bit: `0` for coupled, `1` for diverged
4. Apply disposition code: immediate `0`, drain `1/2`, flush `1`

`rough_path_observation` feeds those coordinates into `RoughPathMonitor`, giving the tracker a bounded anomaly score and state classification per transition while keeping the hot path O(1).

## Sequence Algebra

The runtime artifact tracks two related objects:

- `TerminalTransitionReport`: one-step delta with changed axes and legality
- `TerminalSequenceSignature`: an order-insensitive summary of axis counts, final class, and apply-mask

The sequence signature is intentionally commutative for independent axes. That lets us prove that sequences such as:

- cooked -> echo-off -> cbreak
- cooked -> cbreak -> echo-off

are equivalent when they reach the same final class with the same axis-change multiset. The unit test `order_independent_sequences_share_signature` encodes that invariant directly.

## PTY Legality Model

The PTY regression test `pty_bash_vim_tmux_sequences_stay_legal` uses a real `openpty` pair and exercises a representative shell/editor/multiplexer path:

- bash/login shell baseline in cooked mode
- vim-like cbreak + no-echo preparation
- tmux/screen-like raw handoff
- restore to the original cooked configuration

The tracker must keep `illegal_transition_count == 0` for that path.

## Logging Contract

Every observed transition emits a structured JSONL row and a `tracing` event with:

- `trace_id`
- `mode`
- `api_family = "termios"`
- `symbol`
- `decision_path = "termios->rough_path_signature"`
- `healing_action = null`
- `errno = 0`
- `latency_ns`
- `artifact_refs`

This log is exported by `export_terminal_signature_log_jsonl` for deterministic test assertions and triage.

## Acceptance Mapping

- Legal signature classes and illegal canonical/diverged-speed detection: `canonical_diverged_speed_is_illegal`
- Order-independent equivalence: `order_independent_sequences_share_signature`
- Struct-level illegal transition detection: `cfsetospeed_tracks_struct_level_illegal_transition`
- Real PTY legitimacy path: `pty_bash_vim_tmux_sequences_stay_legal`
- Structured log coverage: `terminal_signature_logs_include_required_fields`
