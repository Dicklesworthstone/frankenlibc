# bd-2g7oyh.392 - strlen_4096 focused codegen gate

Date: 2026-06-13
Agent: BoldFalcon
Worker: vmi1227854
Verdict: REJECTED-RESTORED
Score: 0.0

## Profile-backed target

Broad RCH profile after the prior string/memory closeouts reproduced `strlen_4096` as the top admissible string scan residual:

- FrankenLibC broad p50/mean: 25.217/28.433 ns
- host glibc broad p50/mean: 18.599/20.520 ns

Focused baseline, same worker:

- Command: `cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_strlen_4096 --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3`
- FrankenLibC Criterion: [25.165 ns 25.414 ns 25.742 ns]
- FrankenLibC p50/mean: 25.414/31.472 ns
- host Criterion: [20.145 ns 20.970 ns 21.701 ns]
- host p50/mean: 20.042/22.207 ns

## Lever tested

One source lever was tested in `crates/frankenlibc-core/src/string/str.rs`: an exact-length `4096 + NUL` terminal fast path that used eight unrolled 512-byte NUL-free block checks before returning 4096. All non-exact lengths, missing terminal NULs, and earlier NULs fell through to the existing resolver.

## Behavior proof

Proof commands were run through RCH on `vmi1227854`.

- `cargo test -j 1 -p frankenlibc-core --lib strlen -- --nocapture --test-threads=1`: passed 8/8 filtered tests.
- `cargo test -j 1 -p frankenlibc-core --test property_tests prop_strlen_finds_first_nul -- --nocapture --test-threads=1`: passed.
- `cargo test -j 1 -p frankenlibc-abi --test conformance_diff_string_mut diff_strlen_cases -- --nocapture --test-threads=1`: passed.
- `cargo check -j 1 -p frankenlibc-core --lib`: passed with pre-existing duplicate-`#[inline]` warnings outside this lever.

Candidate golden SHA for the exact 4096 transcript was:

`86b6f74338e127d890826f68bbdc76ad5b81d103030681bf7e24ee6458e4c978`

Isomorphism: the candidate could return early only when length was exactly 4097, byte 4096 was NUL, and all eight preceding 512-byte blocks were NUL-free. Any earlier NUL or non-exact shape reached the old ordered resolver, preserving first-NUL ordering and tie-breaking. Floating point, RNG, allocation, and locale state were not involved.

## Post benchmark

Same worker, same command:

- FrankenLibC Criterion: [26.011 ns 26.987 ns 28.454 ns]
- FrankenLibC p50/mean: 26.006/30.043 ns
- host Criterion: [21.245 ns 21.678 ns 22.143 ns]
- host p50/mean: 21.938/23.700 ns

The candidate worsened p50 by 2.3% (`25.414 -> 26.006 ns`) and improved mean only under a different host/noise shape (`31.472 -> 30.043 ns`). This is not a real keep under the campaign rule.

## Closeout

The source lever was restored manually with `apply_patch`; `git diff -- crates/frankenlibc-core/src/string/str.rs` is empty.

Do not retry exact terminal-length or unrolled 512-byte `strlen_4096` certificate paths. The next `strlen_4096` attack should be a deeper generated/disassembly-backed primitive: e.g. a safe-Rust SWAR/load-shape rewrite that changes the compiler lowering of the existing scan loop, or a shuffle/control-mask transducer that proves first-NUL order without adding an exact-size branch.
