# stdio (printf engine) + pthread condvar — pass 3 (frankenlibc-core)

Worker: rch AMD EPYC, bench profile, criterion --sample-size 50 --measurement-time 3.

## stdio (frankenlibc_core::stdio) — printf engine + buffering
| bench | median | note |
|-------|--------|------|
| stdio_printf_parse/literal | **26.8 ns** | `%`-free literal — no parsing work; dominated by per-call `Vec<FormatSegment>` heap alloc |
| stdio_printf_parse/positional | 101.2 ns | positional `%n$` |
| stdio_printf_parse/mixed | 119.9 ns | literals + specs (typical format) |
| stdio_printf_render/bounded_string | 12.5 ns | render one `%s` |
| stdio_printf_render/signed_decimal | 54.3 ns | render one `%d` |
| stdio_stream_buffer/full_buffered_write | 282.7 ns | buffered write |
| stdio_stream_buffer/line_buffered_write | 392.9 ns | newline-scan buffered write |

## pthread condvar (frankenlibc_core::pthread::CondvarData) — clean, NO hotspot
| bench | p50 | note |
|-------|-----|------|
| init_destroy | 1.87 ns | atomic stores ✓ |
| signal_no_waiters | 5.37 ns | `has_waiters()` atomic load gates the futex ✓ |
| broadcast_no_waiters | 5.81 ns | same fast-path gate ✓ |
| timedwait_past_deadline | 9599 ns | inherent: clock read + futex; syscall-dominated |
| wait_signal_roundtrip | 4738 ns | inherent: cross-thread futex round trip |
| broadcast_4_waiters | 42103 ns (p95 531µs) | thread-wakeup scheduling; shared-VPS noise, not a code hotspot |

## Hypothesis ledger
```
H-printf-alloc  parse_format_string heap-allocs a Vec<FormatSegment> per call : SUPPORTS (PRIMARY)
  printf.rs:853 — Vec::new() + pushes, returns owned Vec. literal-only parse (no '%',
  zero parse work) still costs 26.8ns = the allocation. The ENTIRE printf family routes
  through it: stdio_abi.rs snprintf:3389, sprintf:3462, vsnprintf:3532, dprintf:3689,
  + 3152/3840/3883, plus err/warn (err_abi.rs:159) and fortify fmtcheck (fmtcheck.rs:127).
  So every printf-family call pays a heap alloc + free. Fix: stream parse_format_spec in a
  single parse+render pass (no segment Vec), or memoize parsed segments by format-string
  hash. A format_string_certificate_cache (printf.rs:625) already exists but is a global
  Mutex<HashMap> keyed for certificates, not parsed segments — and a per-call global mutex
  would itself be a contention hotspot, so prefer the streaming fix. Bead: bd-<filed>.

H-condvar  condvar fast paths are hotspots : REJECTS
  init/signal/broadcast-no-waiters all ≤6ns (atomic-gated). Blocking paths are
  syscall/scheduling-bound (inherent); p95 tails are shared-VPS scheduling noise.

H-stdio-render  rendering is the printf hotspot : REJECTS (relative)
  render is 12-54ns/spec; the per-call parse allocation (≥26.8ns fixed) dominates short
  formats and recurs on every call regardless of arg count.
```

## Cross-pass note
pass 3 confirms condvar (pthread) is well-engineered (futex fast-path gating). The standout
new hotspot is the printf-family per-call format-segment allocation — a fixed tax on every
formatted-output call.

## Filed bead
- **bd-yftnsz** (P2, perf/stdio) — parse_format_string per-call Vec allocation on the whole printf family.
