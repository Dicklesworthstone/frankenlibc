# bd-0m5vaw printf `%s\n` direct payload fast path

## Attempt

- Bead: `bd-0m5vaw`
- Agent lane: `cod-b` / `DarkRiver`
- Lever: classify exact non-NULL `"%s\n"` at the ABI printf boundary and
  avoid materializing `string + "\n"` when the destination can preserve the old
  single-render semantics.
- Runtime surfaces changed:
  - `snprintf`, `sprintf`, `vsnprintf`, `vsprintf`: copy caller string bytes
    directly and append the trailing newline byte only if truncation leaves
    room for it.
  - `fprintf`, `printf`, `vfprintf`, `vprintf`: use the two-slice path only
    for managed memory-backed streams or fully buffered streams with enough
    remaining capacity to absorb both slices without a flush boundary.
  - `dprintf` and `vdprintf`: intentionally unchanged. Raw-fd output must keep
    the single rendered buffer so `"%s\n"` does not become two write syscalls.
- Alien/perf route: zero-copy slice transport and bounded state-machine guards
  from the stdio/parser map; no unbounded buffering, no syscall-count increase.

## Negative-Evidence Screen

| Candidate | Ledger decision |
| --- | --- |
| `bd-7ak6cm` calloc skip zeroing fresh mmap pages | Not attempted in this cargo-check-only turn. The bead itself requires recycled-block calloc differential coverage before shipping. |
| `bd-hqo6b6` per-FILE/sharded stdio locking | Not attempted. It is architectural and thread-safety critical; needs full stdio/thread stress and lock-order conformance. |
| `bd-wutxl6` fwrite/fread direct bypass | Not attempted. Ordering, partial write, and short-read behavior require test-capable verification. |
| Raw-fd `%s\n` split for `dprintf`/`vdprintf` | Explicit no-ship. Two `write` syscalls are slower and can change partial-write behavior. |
| Line-buffered FILE `%s\n` split | Deferred. Splitting can change offset/error behavior if the newline-triggered flush fails. Needs a writev-style single-failure-boundary design before retrying. |
| `memchr_absent` panel/width/SWAR families | Not retried. Prior same-worker ledgers mark these as no-ship or routing-only. |
| `memcmp` load-shape/source-loop retunes | Not retried. Prior focused gates rejected adjacent source-shape families. |
| `malloc_free_256` hot-list/slab micro retunes | Not retried. Prior focused gates closed this family as not a current source-edit target. |
| `log2f` exponent/atanh and nearby math micro-levers | Not retried. Prior proof-clean attempts regressed focused gates. |

## Proof Shape

- Output bytes: exact `"%s\n"` is `string bytes` followed by one newline.
- NULL `%s`: falls through to the existing renderer so `(null)` semantics stay
  unchanged.
- Bounded output: copy length is still `min(total_len, size - 1)`, with the
  trailing NUL written at `copy_len`.
- FILE output: the split path is used only when no new flush syscall/failure
  boundary is introduced. Line-buffered, unbuffered, host-delegated, and
  capacity-overflow cases render the original single buffer.
- Floating-point: N/A.
- RNG/global ordering: N/A.

## Guard

- `printf_direct_payload_classifies_string_newline_only_for_nonnull_s` pins the
  exact-format/non-NULL classifier and rejects decorated formats.
- `printf_direct_payload_copy_preserves_snprintf_truncation_boundary` pins
  direct bounded-copy exact-fit and truncation behavior.
- `printf_direct_newline_stream_only_absorbs_full_buffered_without_flush` pins
  the managed-stream safety predicate: full-buffered absorption allowed,
  line-buffered split refused.

## Pending Keep/Reject Predicate

Batch validation should run the focused ABI and Criterion gates, at minimum:

```bash
AGENT_NAME=DarkRiver CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
  cargo test -p frankenlibc-abi printf_direct_payload -- --nocapture

AGENT_NAME=DarkRiver CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
  cargo bench -p frankenlibc-bench --features abi-bench --bench stdio_glibc_baseline_bench -- --noplot
```

Keep only if the batch run shows no printf conformance regressions and
`snprintf`/managed FILE `%s\n` rows improve or remain within noise. Reject if
line-buffered/raw-fd behavior changes, syscall count increases, or any printf
fixture diverges from host glibc.

## Validation This Turn

Passed:

```bash
AGENT_NAME=DarkRiver CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
  cargo check -p frankenlibc-abi

AGENT_NAME=DarkRiver CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
  cargo check -p frankenlibc-bench --features abi-bench --bench stdio_glibc_baseline_bench
```

No tests, rch, or Criterion benchmarks are run in this turn by campaign
instruction. The cargo checks completed with pre-existing warning debt in
`frankenlibc-core` iconv and `frankenlibc-abi` math/poll/signal/erf-table
areas.
