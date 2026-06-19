# bd-fgnxc0 wide printf format buffer pool

## Scenario

Realistic workload: repeated `swprintf`/`wprintf` style formatting from a stable
wide format string, common in C code that localizes output through wide stdio.

Targeted hot cost: each wide printf entry point converted `wchar_t *format` into
a fresh `Vec<u8>` before parsing. The format bytes are temporary and
byte-identical across fresh vs pooled conversion, so this batch removes only the
per-call allocation/reallocation churn.

## Alien / Optimization Mapping

- Canonical graveyard summary: hot-path allocation churn is a first-pass scan
  target, and `format!`/allocation-style work in loops should be rewritten into
  reused buffers when behavior stays identical.
- FrankenLibC map: `stdio/parser/locale format paths` are explicit
  parser-state and memory/I/O surfaces for artifact-level optimization.
- Baseline comparator: host glibc `swprintf` in
  `stdio_glibc_baseline_swprintf_wide_format`.

## Change

- Added a TLS `Vec<u8>` pool for wide printf format conversion.
- Kept the original fresh `wide_to_narrow` converter for non-target callers.
- Routed only `swprintf`, `wprintf`, `fwprintf`, `vswprintf`, `vwprintf`, and
  `vfwprintf` through the pooled converter.
- Added helper-level guard coverage proving the pooled converter matches the
  fresh converter, including invalid-wide-codepoint replacement.
- Added a Criterion target comparing FrankenLibC ABI `swprintf(L"value=%d\n")`
  against host glibc.

## Behavior Preservation

- Ordering preserved: yes. Format bytes are produced in the same scan order.
- Tie-breaking unchanged: N/A.
- Floating-point: N/A.
- Invalid codepoint handling: unchanged; both converters emit UTF-8 U+FFFD.
- Fallback behavior: null format still returns an empty converted buffer, and
  public wide printf entry points still reject null format before conversion.

## Negative-Evidence Ledger

| Candidate | Status | Evidence / reason |
|---|---|---|
| `calloc` fresh-mmap zero-skip | Deferred | Higher impact but correctness-critical; bead requires recycled-block differential tests forbidden in this cargo-check-only turn. |
| per-FILE stdio locking | Deferred | Higher impact but architectural/threaded state-model change; requires full stdio/thread stress suite. |
| bulk `fwrite`/`fread` direct bypass | Deferred | Higher impact but partial I/O and flush-ordering sensitive; requires test-capable turn. |
| `%e/%g/%a` temp-String elimination | Deferred | Needs float differential because those paths post-process formatted output. |
| `memchr_absent` lane-width/SWAR families | Reject/no-retry | Prior same-worker ledgers show proof-clean variants regressed or missed the focused gate. |
| `log2f` exponent/atanh-series | Reject/no-retry | Prior same-worker ledger rejected the family; retry only with generated f32 minimax/table artifact. |
| `malloc_free_256` hot-cycle and `memcmp` load-port micro-levers | Reject/no-retry | Prior ledgers classify them as proof-clean but not keep-gate wins. |
| wide printf format TLS pool | Batch pending | Cargo-check-safe allocation-elision lever; benchmark/conformance verdict intentionally pending. |

## Batch Keep / Reject Predicate

Keep only if the later batch run shows `stdio_glibc_baseline_swprintf_wide_format`
improves the FrankenLibC row without changing wide printf differential output.
Reject and revert if the row regresses, is within noise with extra complexity, or
any wide printf conformance guard fails.

## Validation

Allowed now and passed:

```bash
AGENT_NAME=DarkRiver CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b cargo check -p frankenlibc-abi
AGENT_NAME=DarkRiver CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b cargo check -p frankenlibc-bench --features abi-bench --bench stdio_glibc_baseline_bench
```

Observed warning debt: existing missing SMT solver notice for generated stdio
tables plus pre-existing iconv, math, poll, signal, unistd, and erf-table
warnings. No new compiler errors from this batch.

Not run in this batch by instruction: tests, RCH, Criterion execution,
workspace checks.

## Batch Verdict 2026-06-19

Measured by `cod-b` / `BlackThrush` after RCH benches were allowed.

```bash
AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
  rch exec -- cargo bench -p frankenlibc-bench --features abi-bench \
  --bench stdio_glibc_baseline_bench swprintf_wide_format -- --noplot
```

Criterion result on worker `vmi1227854`:

- FrankenLibC ABI: `[306.41 ns 317.94 ns 328.11 ns]`
- Host glibc: `[971.13 ns 1.0154 us 1.0729 us]`
- Central ratio: `317.94 ns / 1015.4 ns = 0.313x` vs glibc
- Conservative interval ratio: `328.11 / 971.13 = 0.338x`
- Outliers: FrankenLibC 2 high mild; host glibc 4 low severe.
- Verdict: `WIN`, keep the optimization.

Validation:

- `cargo check -p frankenlibc-abi` passed with `AGENT_NAME=BlackThrush`
  and `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b`.
- `cargo test -p frankenlibc-abi` remains blocked by pre-existing
  `zz_scratch_divmin` integration-test compile errors.
- `cargo test -p frankenlibc-abi --lib -- --list` confirms `wchar_abi`
  tests are not compiled in test mode because the module is `#[cfg(not(test))]`
  in `src/lib.rs`.
