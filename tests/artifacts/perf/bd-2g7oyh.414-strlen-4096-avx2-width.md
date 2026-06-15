# bd-2g7oyh.415 strlen_4096 AVX2-width scan gate

Date: 2026-06-15
Agent: BoldFalcon
Worker: vmi1227854
Verdict: REJECTED-RESTORED
Score: 0.0
Re-key: local bd-2g7oyh.414 became bd-2g7oyh.415 after origin/main used .414 for memmove_4096. The artifact filename is retained to avoid destructive churn.

## Profile-backed target

Current-head broad RCH profile on `vmi1227854` after the `memcmp_4096` keep
still showed a `strlen_4096` residual:

- FrankenLibC broad p50/mean: `25.968/28.026 ns`
- host glibc broad p50/mean: `19.019/22.696 ns`

Focused same-worker baseline reproduced a narrower gap:

- Command: `cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_strlen_4096 --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3`
- FrankenLibC Criterion: `[24.447 ns 24.620 ns 24.807 ns]`
- FrankenLibC p50/mean: `24.548/26.516 ns`
- host Criterion: `[18.949 ns 19.385 ns 19.937 ns]`
- host p50/mean: `21.490/25.468 ns`

## Lever tested

One source lever was tested in `crates/frankenlibc-core/src/string/str.rs`:
route `strlen` through four folded 32-byte panels per 128-byte block instead of
the existing 64-byte/512-byte folded sequence. This changed the safe-Rust vector
load shape toward the AVX2-width primitive and intentionally avoided the prior
no-retry families: page-scale certificates, dual-512 loops, and exact terminal
length gates.

The candidate also added a temporary `strlen` golden transcript over 32/64/128/
512/4096 boundary positions and no-NUL cases. Candidate golden SHA:

`fa3f785fdf9372389f6e4f62e4ef81fd1fe7c80394d88754ca23f0030c6ea231`

## Behavior proof while candidate was present

RCH on `vmi1227854`:

- `cargo test -j 1 -p frankenlibc-core --lib strlen -- --nocapture --test-threads=1`: passed 7/7 filtered tests, including the golden transcript.
- `FRANKENLIBC_MODE=strict cargo test -j 1 -p frankenlibc-abi --test conformance_diff_string_mut diff_strlen_cases -- --nocapture --test-threads=1`: passed 1/1.

Isomorphism: the candidate only changed NUL-free block detection width. Any
flagged block still fell into the existing left-to-right word/byte resolver, so
first-NUL ordering and no-NUL return behavior were unchanged. Floating point,
RNG, allocation, locale, and tie-breaking state were not involved.

The first broader proof command, `cargo test -j 1 -p frankenlibc-core strlen`,
compiled unrelated integration tests and failed on pre-existing
`strftime_differential_probe.rs` `BrokenDownTime` field drift. It was not a
candidate behavior failure; the corrected `--lib` and ABI proofs above passed.

## Post benchmark

An accidental post run selected `ovh-a` despite the worker-pinning environment;
it is recorded as cross-worker sanity only and was not used for the decision.

Same-worker post on `vmi1227854`:

- Command: same focused benchmark command, with fresh target/criterion dirs.
- FrankenLibC Criterion: `[28.128 ns 28.792 ns 29.437 ns]`
- FrankenLibC p50/mean: `28.654/31.781 ns`
- host Criterion: `[18.299 ns 18.756 ns 19.211 ns]`
- host p50/mean: `19.419/21.705 ns`

The candidate regressed FrankenLibC by `16.7%` p50 and `19.9%` mean versus the
focused baseline (`24.548/26.516 ns -> 28.654/31.781 ns`).

## Closeout

Rejected and restored. `crates/frankenlibc-core/src/string/str.rs` was manually
restored; `git diff --exit-code -- crates/frankenlibc-core/src/string/str.rs`
is empty. Restored source SHA256:

`0305360b0772daceb7c7920e2e025204be11d92f4737a2d9d15fc1933f4929e8`

Do not retry 32-byte-lane folded `strlen_4096` scan reshaping. The next
admissible `strlen` route needs a generated/disassembly-backed primitive that
changes the lowering more fundamentally, or a different focused hotspot.
