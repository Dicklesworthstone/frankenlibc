# bd-2g7oyh.269 - strrchr absent-needle certificate

## Target

- Bead: `bd-2g7oyh.269`
- Symbol/workload: `strrchr_absent`, 4096-byte reverse scan for absent byte.
- Profile basis: post-`bd-2g7oyh.266` profiles kept showing a residual in `strrchr_absent`.

## Lever

One source lever in `crates/frankenlibc-core/src/string/str.rs`:

- For `c != 0`, run the existing optimized safe-Rust `memchr(s, c, s.len())` first.
- If it returns `None`, return `None` immediately.
- If it returns `Some(_)`, discard that witness and run the existing exact forward last-match resolver unchanged.

## Same-worker RCH Baseline

Command:

```text
env AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd269-clean-baseline-rch cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_strrchr_absent --noplot --sample-size 35 --warm-up-time 1 --measurement-time 2
```

Worker: `vmi1153651`

- FrankenLibC: p50 `95.566 ns`, mean `106.192 ns`, p95 `137.472 ns`, p99 `262.450 ns`, throughput `9,155,212 ops/s`.
- Host glibc: p50 `92.260 ns`, mean `104.299 ns`, p95 `150.000 ns`, p99 `161.989 ns`, throughput `9,899,999 ops/s`.

## Same-worker RCH Post

Command:

```text
env RCH_BUILD_SLOTS=1 AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd269-post-vmi1153651-rch cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_strrchr_absent --noplot --sample-size 35 --warm-up-time 1 --measurement-time 2
```

Worker: `vmi1153651`

- FrankenLibC: p50 `61.617 ns`, mean `66.270 ns`, p95 `95.000 ns`, p99 `152.480 ns`, throughput `16,970,688 ops/s`.
- Host glibc: p50 `102.281 ns`, mean `154.722 ns`, p95 `456.642 ns`, p99 `1049.451 ns`, throughput `6,098,090 ops/s`.

Result:

- p50 speedup: `1.55x` (`35.5%` lower latency).
- mean speedup: `1.60x` (`37.6%` lower latency).
- p95 speedup: `1.45x` (`30.9%` lower latency).
- p99 speedup: `1.72x` (`41.9%` lower latency).
- Score: `12.0` (`Impact 4.0 x Confidence 4.5 / Effort 1.5`).

Cross-worker confirmation on `vmi1156319` also showed FrankenLibC p50 `56.371 ns`, mean `62.362 ns`.

## Isomorphism Proof

- `c == 0`: unchanged branch returns `Some(strlen(s))`.
- `c != 0` and `memchr(s, c, s.len()) == None`: no byte in the whole slice equals `c`; therefore no byte before the first NUL equals `c`; the old exact resolver would return `None`.
- `c != 0` and `memchr(s, c, s.len()) == Some(_)`: the witness is not used for the returned index; control falls through to the previous resolver unchanged, preserving last-before-NUL ordering and ignoring matches after the terminator.
- Tie-breaking: unchanged for found cases because the resolver loop is unchanged.
- Floating point and RNG: not involved.

Golden transcript SHA-256:

```text
a2d88c8fc144d9705080a44619c97736b57b2199a5425ea5b9367fe16c606afb
```

## Validation

- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/str.rs`: passed.
- `git diff --check -- crates/frankenlibc-core/src/string/str.rs`: passed.
- RCH `vmi1156319`: `cargo test -p frankenlibc-core strrchr -- --nocapture --test-threads=1`: passed 7 direct `strrchr` tests plus `string_properties::prop_strchr_strrchr_both_find_or_miss`.
- RCH `vmi1156319`: `cargo check -p frankenlibc-core --lib`: passed; known missing-SMT-solver build warning only.
- RCH `vmi1153651`: `cargo clippy -p frankenlibc-core --lib -- -D warnings` with existing unrelated lint-family allowlist: passed; known missing-SMT-solver build warning only.

No existing found-case `strrchr` Criterion benchmark was present. Found, post-NUL, and NUL-needle behavior are covered by the passing direct tests and property test.

## Next Route

If `strrchr_absent` reappears as a top residual, avoid another retune of this absence certificate. Use a deeper dual-mask/rank-select primitive: compute `needle_mask` and `nul_mask` per panel, mask matches after the first NUL, and resolve the last set bit before the terminator directly.
