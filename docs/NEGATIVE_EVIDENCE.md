# FrankenLibC Perf Negative-Evidence Ledger

Measured head-to-head **vs host glibc** for perf optimizations that were committed
"code-first, batch-test pending". Records **every** result — win, loss, or neutral —
so dead ends are never retried and real wins are confirmed with numbers.

## Method

- Bench harness: `crates/frankenlibc-bench` (criterion). Run per-crate, not workspace-wide:
  `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b rch exec -- \
   cargo bench -p frankenlibc-bench --bench <NAME> --features=abi-bench`
- Each bench group compares `frankenlibc_abi` vs `host_glibc` on a realistic workload.
- **ratio = fl_median / glibc_median** (lower is better; <1 = fl faster, >1 = fl slower).
- **Verdict:** `WIN` ratio ≤ 0.95 · `NEUTRAL` 0.95–1.05 · `LOSS` ratio ≥ 1.05.
- **Action on LOSS / NEUTRAL-with-cost:** revert the optimization (keep conformance green),
  unless the lever's value is correctness/safety rather than speed (noted).

## Results

| Date | Lever / bead | Bench | fl | glibc | ratio | verdict | action |
|------|--------------|-------|----|----|-------|---------|--------|
| 2026-06-19 | `%s\n` direct payload fast path (`bd-0m5vaw`) | `stdio_glibc_baseline_snprintf_s_newline` | 471.49 ns | 550.41 ns | 0.856x | WIN | Keep. Head-to-head Criterion on `vmi1227854`, cache miss; conservative CI ratio still < 0.90. |
| 2026-06-19 | Wide printf format TLS pool (`bd-fgnxc0`) | `stdio_glibc_baseline_swprintf_wide_format` | 317.94 ns | 1.0154 us | 0.313x | WIN | Keep. Head-to-head Criterion on `vmi1227854`, cache miss; outliers noted but conservative CI ratio still < 0.34. |
| _pending_ | stdio registry local hasher (bd-2jgvp9) | stdio_glibc_baseline_fgetc_4096 | — | — | — | — | — |

<!-- rows appended as benches complete -->

## 2026-06-19 stdio cod-b gauntlet notes

- Bench command, `%s\n`: `AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b rch exec -- cargo bench -p frankenlibc-bench --features abi-bench --bench stdio_glibc_baseline_bench snprintf_s_newline -- --noplot`
- Bench command, wide printf: `AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b rch exec -- cargo bench -p frankenlibc-bench --features abi-bench --bench stdio_glibc_baseline_bench swprintf_wide_format -- --noplot`
- Both benches selected worker `vmi1227854`; RCH rewrote the target dir to `/data/projects/frankenlibc/.rch-target-vmi1227854-pool-2740363b0b76e0a08f9b35b4f209a994`.
- Both RCH runs reported `Cache: MISS`; total wall time is not used as evidence.
- Validation: `AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b cargo check -p frankenlibc-abi` passed locally with pre-existing warning debt.
- Test caveat: `cargo test -p frankenlibc-abi ...` without `--lib` is blocked by pre-existing `zz_scratch_divmin` integration-test compile errors. `cargo test -p frankenlibc-abi --lib -- --list` shows `stdio_abi` and `wchar_abi` inline tests are not present because those modules are `#[cfg(not(test))]` in `crates/frankenlibc-abi/src/lib.rs`.
- RCH caveat: an attempted `--lib` guard run on `ovh-b` failed in `blake3` build script with SIGILL before crate compilation; not counted as conformance evidence.
