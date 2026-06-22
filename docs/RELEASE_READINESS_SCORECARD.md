# FrankenLibC Release Readiness Scorecard

Last updated: 2026-06-21 by `cod-a` / `cod-b` / `BlackThrush`.

## Current gate snapshot

| Area | Score | Evidence | Risk |
|---|---:|---|---|
| Measured perf backlog conversion | 33 / many pending | Added cod-a parser-batch classification for `bd-2g7oyh.480`, `.484`, `.486`, `.488`, `.489`, `.490`, `.491`, `bd-v4t889`, `bd-rpc-byte-program-number-wq60gz`, plus `bd-2g7oyh.479` runtime-design stack candidates, `bd-li0so3` hosts field scanner, `bd-7ak6cm` calloc `alloc_zeroed` skip, `bd-4crkqx` aliases member scanner, `bd-xxrfvu` `/etc/networks` byte network-number parser, `bd-f874go` strict allocator reentry-slot reuse, the 2026-06-20 `bd-2g7oyh` calloc tombstone-compaction reject, the `bd-f874go` fallback-table exact hot-slot reject, the `bd-f874go` strict calloc one-slot recycle/live-slot reject, the 2026-06-20 `bd-deployed-malloc-membrane-50x-vmuu73` bounded hot-class slab reject, the 2026-06-20 `bd-2g7oyh` vDSO timing pointer-cache reject, the 2026-06-20 deployed `ato*` single-pass keep, the 2026-06-20 deployed `strtol` direct C-string parser keep, the 2026-06-20 deployed `getenv` fused-name gap cut, the `bd-2g7oyh.496` deployed hot-key `getenv` cache keep, the 2026-06-20 `qsort_16_i32` small-sort screen, `bd-0ft0w3` strict exact `snprintf("%s")`/`"%s\n"` fused direct-copy keep, `bd-zexi06` strict pure-literal `snprintf` read-only-cache direct-copy keep, the `bd-f874go` strict fallback `realloc` same-size-class in-place keep, and the `bd-2g7oyh.485` snprintb streaming visitor reject/source revert. Parser rows are internal old-vs-new except `ato*`/`strtol`/`getenv`; timing/getenv parser rows use deployed ABI vs host glibc; stdio and allocator rows use deployed ABI vs host-glibc bench evidence; snprintb is old-vs-new only because BSD `snprintb` has no host-glibc comparator. | Large backlog remains across stdio registry, resolver/NSS parser, string, allocator, runtime membrane, timing, and peer-owned leaves. Long/hex `strtol` still lose at 1.23x/1.14x in the latest same-worker run, `clock_gettime`/`time` still lose at 1.35x/1.66x, and allocator small/realloc rows still need deeper work vs glibc. Exact string and pure-literal `snprintf` now beat glibc, and deployed hot repeated-key `getenv` now beats glibc at 0.78x/0.92x; cold, long-name, or multithreaded env workloads remain separate profiles. The strict calloc one-slot recycle line, bounded hot-class slab line, vDSO pointer-cache timing line, and snprintb streaming visitor are explicitly rejected. |
| Negative-evidence ledger | 1 committed ledger + bead-local rejects | `docs/NEGATIVE_EVIDENCE.md` records win/loss/neutral policy and the parser/allocator/stdio batch, now including the strict calloc one-slot recycle/live-slot reject with local routing baseline plus three remote candidate tables, the bounded hot-class slab reject with same-worker baseline/candidate tables, the vDSO timing cache reject with two same-worker candidate tables, the getenv hot-cache full final `strtol_glibc_bench` row table, and the snprintb old-vs-new streaming visitor reject. `tests/artifacts/perf/bd-f874go-native-reentry-slot.md`, `tests/artifacts/perf/bd-2g7oyh-calloc-strict-fastpath.md`, `tests/artifacts/perf/bd-f874go-fallback-hot-slot.md`, `tests/artifacts/perf/bd-deployed-malloc-membrane-50x-vmuu73-cod-b-slab.md`, `tests/artifacts/perf/bd-2g7oyh-strtol-atoi-fastpath.md`, `tests/artifacts/perf/bd-2g7oyh-strtol-direct-cstring.md`, `tests/artifacts/perf/bd-2g7oyh-getenv-fused-name-scan.md`, `tests/artifacts/perf/bd-2g7oyh-getenv-hot-cache.md`, `tests/artifacts/perf/bd-2g7oyh-vdso-time-cache-reject.md`, `tests/artifacts/perf/bd-0ft0w3-cod-b-snprintf-direct.md`, `tests/artifacts/perf/bd-zexi06-cod-b-literal-snprintf.md`, `tests/artifacts/perf/bd-f874go-realloc-same-class.md`, and `tests/artifacts/perf/bd-2g7oyh.485-snprintb-stream-names.md` record the kept native reentry-slot reduction, reverted tombstone compaction, reverted exact hot-slot cache, rejected hot-class slab, kept deployed `ato*` fast path, kept deployed `strtol` direct parser gap cut, kept deployed `getenv` fused-name gap cut plus hot-cache closeout plus qsort screen, rejected vDSO timing pointer-cache/counter shapes, kept exact string `snprintf` fused direct path, kept pure-literal `snprintf` read-only-cache direct-copy path, kept `realloc` same-size-class path with root causes and retry predicates, and rejected/reverted the snprintb streaming visitor. | Existing per-bead artifacts still contain many pending local ledgers; central ledger needs every later result appended when it is not peer-owned dirty. |
| Revert discipline | Green for measured cluster | Winning rows kept; losing/neutral parser source shapes were reversed without deleting evidence artifacts or benchmark rows. Prior glibc losses (`bd-2g7oyh.478`, `bd-2g7oyh.482`) remain reverted. `bd-2g7oyh.479` stack candidates, `bd-li0so3` hosts scanner, `bd-7ak6cm` calloc `alloc_zeroed`, `bd-4crkqx` aliases member scanner, the 2026-06-20 calloc tombstone compaction, the `bd-f874go` fallback-table hot-slot cache, the `bd-f874go` strict calloc one-slot recycle/live-slot candidate, the `bd-deployed-malloc-membrane-50x-vmuu73` bounded hot-class slab candidate, the `bd-2g7oyh` vDSO pointer-cache/counter candidates, and the `bd-2g7oyh.485` snprintb streaming visitor were reverted after measurement. The first `bd-zexi06` no-render and length-cache-only attempts are recorded as losses, not credited as keeps. `bd-xxrfvu`, the earlier `bd-f874go` native reentry-slot reuse, the deployed `ato*` parser, the deployed `getenv` fused-name scanner plus hot-cache closeout, the fused exact string `snprintf` path, the final pure-literal `snprintf` cache+word-copy path, and the `bd-f874go` same-size-class `realloc` path measured as keeps. The qsort screen kept only benchmark apparatus; the snprintb reject kept benchmark apparatus and the behavior guard. No qsort source lever was landed; snprintb source was reverted. | Future neutral/loss rows must be reverted or explicitly marked safety/correctness exceptions. |
| Conformance guard | Partial green | Focused parser guards passed previously. For `.479`, touched-file rustfmt and `cargo check -p frankenlibc-membrane --lib` passed. For `bd-li0so3`, touched-file rustfmt, 10 hosts parser tests, and `cargo check -p frankenlibc-core` passed. For allocator work, `bd-f874go` passed its focused guards, and the 2026-06-20 calloc tombstone compaction plus fallback-table hot-slot rejects were reverted; post-revert `malloc_abi_test` passed 53/0/1 ignored under `rch exec` local fallback after remote pressure refused a remote test, and `RCH_REQUIRE_REMOTE=1 rch exec -- cargo build -p frankenlibc-abi --release` passed on `hz2`. The one-slot recycle/live-slot reject passed focused `cargo check -p frankenlibc-abi --lib` and its focused reuse test before measurement, then its source/test hunks were reverted; current tree `cargo check -p frankenlibc-abi --lib` passes with known pre-existing warnings. The bounded hot-class slab reject passed touched-file rustfmt and `cargo check -p frankenlibc-abi --lib` before measurement, completed same-worker `rch` `calloc_glibc_bench`, then source was reverted; post-revert touched-file rustfmt and `cargo check -p frankenlibc-abi --lib` pass with known pre-existing warnings. The same-size-class `realloc` keep passed `malloc_abi_test realloc` 7/0 on rch and `cargo build -p frankenlibc-abi --release` on rch. For the `ato*` keep, touched-file rustfmt, `git diff --check`, strict refinement integration (16/16), strtol-family differential fuzz (1,000,000 comparisons, 0 divergences), `cargo build -p frankenlibc-abi --release`, and deployed `strtol_glibc_bench` passed via `rch`; the final fuzz rerun used `rch exec` local fallback after remote workers were unavailable. For the deployed `strtol` direct-parser keep, touched-file rustfmt passed, strtol-family differential fuzz passed 1,000,000 comparisons with 0 divergences on `vmi1152480`, and the deployed release bench passed via `rch`. For the rejected vDSO timing candidates, touched-file rustfmt and `git diff --check` passed while source was present, focused `time_abi_test vdso` passed 10/10 via rch on `vmi1227854`, and final source was reverted after same-worker `hz2` bench rejection. For the deployed `getenv` fused-name keep, `git diff --check` passed, `conformance_diff_getenv` passed 2/0, `metamorphic_getenv` passed 9/0, and `cargo build -p frankenlibc-abi --release` passed via rch on `vmi1227854`; crate rustfmt remains blocked by pre-existing formatting drift in the touched ABI and bench files and was not normalized here. For `bd-2g7oyh.496`, touched-file rustfmt and `git diff --check` passed, local `cargo check -p frankenlibc-abi --lib` passed with known warnings, local getenv conformance passed 2/0 + 9/0, `cargo build -p frankenlibc-abi --release` passed via rch on `vmi1152480`, and focused rch getenv conformance passed 2/0 + 9/0 on `vmi1227854` after worker reroute. For `bd-0ft0w3`, `git diff --check` passed, `cargo build -p frankenlibc-abi --release` passed on `hz1`, and focused rch conformance passed `diff_snprintf_string_specifiers`, `diff_snprintf_truncation`, and `printf_null_string_precision_matches_glibc`. For `bd-zexi06`, focused rch conformance passed `diff_snprintf` 7/0 and `cargo build -p frankenlibc-abi --release` passed on `hz1`; broad rustfmt remains blocked by pre-existing formatting drift in touched files and was not normalized here. For `bd-2g7oyh.485`, post-revert rch validation passed `cargo test -p frankenlibc-core stdio::snprintb --lib` 13/13 and `cargo check -p frankenlibc-bench --bench stdio_bench` on `hz1`, with only known pre-existing iconv/math warnings. For `bd-4crkqx`, source was reverted to split/filter/collect; touched-file rustfmt passed, 30 aliases-filtered core tests passed, and `cargo check -p frankenlibc-core` passed. For `bd-xxrfvu`, touched-file rustfmt passed, `netnum` filtered tests passed 12/12, `network_` filtered tests passed 15/15, and `cargo check -p frankenlibc-core` passed. For `bd-z8p3mx`, the powf gates passed against host glibc 2.42. Two pre-existing unrelated failures remain (`diff_sign_min_max_dim_helpers_*`, `fminf`/`fmaxf`/`fdimf` — fail on clean HEAD too, not touched here). | Full core tests are blocked by unrelated iconv/glob failures; workspace check/clippy by missing packaged files in `asupersync-conformance 0.3.4`; workspace fmt and crate fmt are blocked by broad formatting drift. |
| Release posture | Not ready | Additional getopt and group lookup wins recorded, real `getgrgid(0)` neutral and passwd lookup losses routed deeper, `bd-f874go` strict allocator reentry-slot reuse and same-size-class `realloc` in-place path narrow allocator gaps, tombstone compaction plus fallback-table exact hot-slot plus strict calloc one-slot recycle/live-slot plus bounded hot-class slab plus vDSO timing pointer-cache attempts are recorded as reverts, deployed `atoi`/`atol`/`atoll` beat glibc at 0.36x-0.57x in the latest same-worker run, deployed `getenv_hit`/`getenv_miss` now beat glibc at 0.78x/0.92x after the hot-cache keep, exact string `snprintf` beats glibc at 0.781x/0.679x mean, pure-literal `snprintf` beats glibc at 0.497x mean, and the snprintb streaming visitor was neutral/slower and reverted. | Not release-ready until scratch test debt is isolated/fixed, central ledger covers the pending backlog, conformance/bench gates are repeatable, allocator small/realloc rows no longer carry large glibc losses, and the remaining long/hex `strtol`, `time`, and `clock_gettime` deployed losses are closed or accepted. |

2026-06-21 supersession note: `bd-2g7oyh.497` below converts the current
`strtol_dec_short`/`strtol_dec_long`/`strtol_hex` rows to same-worker host-glibc
wins at 0.50x/0.57x/0.78x. The older snapshot cells that still call long/hex
`strtol` red are now stale; `clock_gettime`, `time`, and the focused
`pthread_self` row remain routed timing/TLS losses.

## 2026-06-19 measured stdio cluster

| Bead | Workload | FrankenLibC | glibc | Ratio | Verdict | Action |
|---|---|---:|---:|---:|---|---|
| `bd-0m5vaw` | `snprintf("%s\n")` with 128-byte destination and stable log payload | 471.49 ns | 550.41 ns | 0.856x | WIN | Keep. |
| `bd-fgnxc0` | `swprintf(L"value=%d\n")` into 32-wide-char buffer | 317.94 ns | 1.0154 us | 0.313x | WIN | Keep. |

## 2026-06-20 `bd-0ft0w3` strict exact `snprintf` keep

The exact `snprintf("%s")` and `snprintf("%s\n")` strict-mode path now bypasses
the runtime-policy/printf-engine stack and fuses C-string scan with destination
copy. This supersedes the earlier parser-only shortcut, which improved the old
path but still lost to glibc.

| Workload | Current-head FL | Current-head ratio | Final FL | Final glibc | Final ratio | Verdict |
|---|---:|---:|---:|---:|---:|---|
| `snprintf("%s\n")` | 392.83 ns | 12.23x | 67.224 ns mean | 86.029 ns mean | 0.781x | WIN |
| `snprintf("%s")` | 561.55 ns | 6.67x | 63.297 ns mean | 93.254 ns mean | 0.679x | WIN |

Validation/build: `git diff --check -- crates/frankenlibc-abi/src/stdio_abi.rs`
passed; `cargo build -p frankenlibc-abi --release` passed via rch; focused rch
conformance passed `diff_snprintf_string_specifiers`, `diff_snprintf_truncation`,
and `printf_null_string_precision_matches_glibc`. Crate fmt remains blocked by
pre-existing broad ABI formatting drift and was not normalized in this perf
commit. Full evidence: `tests/artifacts/perf/bd-0ft0w3-cod-b-snprintf-direct.md`.

## 2026-06-20 `bd-zexi06` strict pure-literal `snprintf` keep

The strict pure-literal `snprintf("literal")` path now recognizes conversion-free
formats, caches read-only literal lengths, and copies the payload with exact
unaligned word moves before the runtime-policy/printf-engine stack. Cache
admission is restricted to `/proc/self/maps` read-only mappings so mutable
format strings remain scanned on every call and cannot stale-hit after mutation.

| Workload | Baseline FL | Baseline ratio | Final FL | Final glibc | Final ratio | Verdict |
|---|---:|---:|---:|---:|---:|---|
| `snprintf("literal")` | 1.9118 us mean | 72.73x loss | 10.960 ns mean | 22.036 ns mean | 0.497x | WIN |
| first no-render shortcut | 55.287 ns mean | 3.80x loss | - | 14.563 ns mean | 3.80x | REJECT |
| length-cache-only shortcut | 27.941 ns mean | 1.58x loss | - | 17.671 ns mean | 1.58x | REJECT |

Regression guards on the same final `hz1` run stayed green versus glibc:
`snprintf("%s\n")` measured 24.130 ns vs 35.897 ns (0.672x), and
`snprintf("%s")` measured 23.474 ns vs 28.263 ns (0.831x).

Validation/build: focused rch conformance passed `diff_snprintf` 7/0, and
`cargo build -p frankenlibc-abi --release` passed on `hz1`. Broad rustfmt remains
blocked by pre-existing formatting drift in touched files and was not normalized
in this perf commit. Full evidence:
`tests/artifacts/perf/bd-zexi06-cod-b-literal-snprintf.md`.

## 2026-06-20 `bd-2g7oyh.485` snprintb stream-name reject

The `snprintb` streaming bit-name visitor removed a temporary `Vec<&[u8]>`, but
same-worker evidence showed no performance win. BSD `snprintb` has no host glibc
comparator, so this is an explicitly old-vs-new reject rather than a glibc
head-to-head row.

| Workload | Old collect-Vec p50 | Streaming visitor p50 | Ratio | Verdict | Action |
|---|---:|---:|---:|---|---|
| `stdio_snprintb/named_bits_stream_12` (`vmi1149989`) | 1.3316 us | 1.3500 us | 1.014x | NEUTRAL/REJECT | Reverted source to `collect_set_names`; kept the benchmark hook and behavior guard. |

Validation/build: post-revert rch validation passed
`cargo test -p frankenlibc-core stdio::snprintb --lib` 13/13 and
`cargo check -p frankenlibc-bench --bench stdio_bench` on `hz1`.
`cargo fmt --check -p frankenlibc-core` remains blocked by pre-existing broad
formatting drift, and focused rch
`cargo clippy -p frankenlibc-core --lib -- -D warnings` remains blocked by
pre-existing unrelated core lints in iconv/math/resolv/printf, with no
`snprintb` failure. Full evidence:
`tests/artifacts/perf/bd-2g7oyh.485-snprintb-stream-names.md`.

## 2026-06-20 `bd-2g7oyh` deployed `ato*` keep

The deployed `atoi`/`atol`/`atoll` path now uses a base-10 single-pass parser
instead of the generic `strtol` scan/parse/endptr shape. Same-worker `vmi1149989`
evidence converted six red rows into wins versus host glibc. The final clean
numbers below are the post-rebase rerun after upstream added a weaker membrane
fast path; the direct parser still wins every `ato*` row.

| Workload | Baseline FL | Candidate FL | Candidate glibc | Final ratio | Verdict |
|---|---:|---:|---:|---:|---|
| `atoi_short` | 31.56 ns | 2.97 ns | 5.25 ns | 0.57x | WIN |
| `atoi_long` | 37.19 ns | 7.51 ns | 14.67 ns | 0.51x | WIN |
| `atol_short` | 28.66 ns | 2.80 ns | 4.91 ns | 0.57x | WIN |
| `atol_long` | 41.88 ns | 9.31 ns | 10.77 ns | 0.87x | WIN |
| `atoll_short` | 28.46 ns | 2.53 ns | 4.92 ns | 0.52x | WIN |
| `atoll_long` | 28.99 ns | 7.57 ns | 10.99 ns | 0.69x | WIN |

Scorecard effect: the `ato*` integer parse surface moves from `2.54x-3.43x`
slower than glibc to `0.51x-0.87x` of glibc. The same bench still records
unchanged `strtol_*` and `strtod_*` losses, so parser release work is not closed;
the next credible lever is a single-pass `strtol`/`strtod` parser rather than
another membrane branch tweak.

Validation/build: touched-file rustfmt and `git diff --check` passed. RCH
strict refinement integration passed 16/16 both before and after rebase,
strtol-family differential fuzz compared 1,000,000 cases with 0 divergences
before rebase on `hz2` and again on the current tree through `rch exec` local
fallback when remote workers were unavailable, and
`cargo build -p frankenlibc-abi --release` passed after rebase. Full evidence:
`tests/artifacts/perf/bd-2g7oyh-strtol-atoi-fastpath.md`.

## 2026-06-20 `bd-2g7oyh` deployed `strtol` direct C-string keep

The deployed `strtol` base-10/base-16 path now fuses the numeric C-string scan
and parse instead of scanning once for a prefix and then rescanning through the
generic core parser. Same-worker `vmi1152480` evidence used clean `e464f5c31`
as the baseline and the same `CARGO_TARGET_DIR`/bench command for the candidate.

| Workload | Baseline FL | Baseline ratio | Candidate FL | Candidate glibc | Final ratio | Verdict |
|---|---:|---:|---:|---:|---:|---|
| `strtol_dec_short` | 14.21 ns | 1.62x | 7.65 ns | 4.82 ns | 1.59x | NEUTRAL gap-cut |
| `strtol_dec_long` | 34.25 ns | 1.90x | 22.16 ns | 17.88 ns | 1.24x | WIN gap-cut |
| `strtol_hex` | 37.68 ns | 2.07x | 21.38 ns | 18.02 ns | 1.19x | WIN gap-cut |

Scorecard effect: major `strtol` rows move near parity but not to glibc
domination. The short row remains 1.59x, and `strtod` is still a separate
parser-family loss. The next credible parser lever is short-row entrypoint /
`endptr` overhead or a direct `strtod` parser, not another generic membrane
branch tweak.

Validation/build: touched-file rustfmt passed; `strtol_family_differential_fuzz`
passed 1,000,000 comparisons with 0 divergences vs host glibc on `vmi1152480`;
and the deployed `strtol_glibc_bench` release run passed via `rch`. Full
evidence: `tests/artifacts/perf/bd-2g7oyh-strtol-direct-cstring.md`.

## 2026-06-20 `bd-2g7oyh` deployed `strtod` exact-integer keep

The deployed `strtod` path now has a narrow exact-integer decimal fast path for
tokens that normalize to an exactly representable `f64` integer. It bypasses the
scan-then-core-parser stack only for exact cases; fractional, rounded, hex,
NaN/Inf, overflow, and extreme-exponent cases fall through unchanged.

| Workload | Baseline FL | Baseline ratio | Candidate FL | Candidate glibc | Final ratio | Verdict |
|---|---:|---:|---:|---:|---:|---|
| `strtod_int` | 38.73 ns | 1.10x | 11.73 ns | 34.89 ns | 0.34x | WIN |
| `strtod_simple` | 53.14 ns | 0.77x | 55.85 ns | 65.76 ns | 0.85x | WIN |
| `strtod_sci` | 68.09 ns | 1.38x | 20.09 ns | 45.58 ns | 0.44x | WIN |

Scorecard effect: the measured deployed `strtod` rows in `strtol_glibc_bench`
now all beat host glibc. At this point the remaining red rows in that bench
were long/hex `strtol`, `getenv`, `clock_gettime`, and `time`; later rows below
close hot-cache `getenv` and positive-prefix `strtol`.

Validation/build: `strtod_strtof_live_differential_probe` passed via rch with
8071 inputs and 0 divergences vs host glibc, including the exact-integer and
malformed-exponent cases that route through or around this fast path. The
release `strtol_glibc_bench` run passed via `rch` on `hz1`. Full evidence:
`tests/artifacts/perf/bd-2g7oyh-strtod-exact-fastpath.md`.

## 2026-06-20 `bd-2g7oyh` deployed `getenv` fused-name gap cut

The deployed strict `getenv` path now fuses bounded NUL discovery with invalid
name rejection (`=` or empty string) and then walks `environ` by raw
pointer/length. This removes the previous second name pass through
`valid_env_name` and avoids slice indexing in the environment-entry compare.

| Workload | Baseline FL | Baseline ratio | Candidate FL | Candidate glibc | Final ratio | FL old/new | Verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| `getenv_hit` | 26.42 ns | 2.50x | 19.15 ns | 10.14 ns | 1.89x | 0.725x | WIN gap-cut |
| `getenv_miss` | 36.10 ns | 2.66x | 27.66 ns | 14.68 ns | 1.88x | 0.766x | WIN gap-cut |

Scorecard effect: deployed `getenv` remains slower than glibc, but the same
worker A/B cuts FrankenLibC latency by 27.5% on hit and 23.4% on miss. The
next credible lever is generationed environment lookup state or an exactly
invalidated hot-key cache across `setenv`/`putenv`/`unsetenv`, not another
micro-tweak to the name scan.

Validation/build: `git diff --check` passed; focused rch conformance passed
`conformance_diff_getenv` 2/0 and `metamorphic_getenv` 9/0; and
`cargo build -p frankenlibc-abi --release` passed on `vmi1227854`. Crate
rustfmt remains blocked by pre-existing formatting drift in
`stdlib_abi.rs:454` and `glibc_baseline_bench.rs:2851/2889`; not normalized in
this perf commit. Full evidence:
`tests/artifacts/perf/bd-2g7oyh-getenv-fused-name-scan.md`.

## 2026-06-20 `bd-2g7oyh.496` deployed `getenv` hot-cache keep

The next getenv lever adds a single-entry TLS cache for the deployed strict
single-threaded repeated-key path. The key is exact name length plus the first
16 name bytes packed into two `u64`s. `ENVIRON_EPOCH` invalidates the cache
after successful `setenv`, `unsetenv`, `putenv`, and `clearenv`; test builds
and multithreaded processes stay on the existing path.

| Workload | Baseline FL | Baseline ratio | Final FL | Final glibc | Final ratio | FL old/new | Verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| `getenv_hit` | 41.20 ns | 2.39x | 12.43 ns | 15.93 ns | 0.78x | 0.302x | WIN |
| `getenv_miss` | 64.90 ns | 2.53x | 21.45 ns | 23.34 ns | 0.92x | 0.330x | WIN |

Scorecard effect: hot repeated-key `getenv` is no longer a red row in
`strtol_glibc_bench`. At this point the same final run still left long/hex
`strtol`, `clock_gettime`, and `time` as losses; the next `bd-2g7oyh.497`
section closes the deployed `strtol` rows.

Validation/build: touched-file rustfmt and `git diff --check` passed; local
`cargo check -p frankenlibc-abi --lib` passed with known warnings; local getenv
conformance passed 2/0 + 9/0; `cargo build -p frankenlibc-abi --release` passed
via rch on `vmi1152480`; focused rch getenv conformance passed 2/0 + 9/0 on
`vmi1227854` after worker reroute. Full evidence:
`tests/artifacts/perf/bd-2g7oyh-getenv-hot-cache.md`.

## 2026-06-21 `bd-2g7oyh.497` deployed `strtol` positive-prefix keep

The code-first positive/no-whitespace `strtol` fast path from `6f311ef07` was
verified with same-worker remote evidence on `vmi1152480`. It splits direct
base-10 digit prefixes and base-16 digit/`0x` prefixes away from the generic
whitespace/sign/base setup while preserving fallback semantics for signed,
whitespace-prefixed, invalid-base, overflow, and `0x`-without-hex cases.

| Workload | Baseline FL | Baseline ratio | Final FL | Final glibc | Final ratio | Verdict |
|---|---:|---:|---:|---:|---:|---|
| `strtol_dec_short` | 9.35 ns | 0.96x | 4.64 ns | 9.33 ns | 0.50x | WIN |
| `strtol_dec_long` | 25.21 ns | 1.21x | 9.95 ns | 17.38 ns | 0.57x | WIN |
| `strtol_hex` | 21.55 ns | 1.13x | 13.52 ns | 17.30 ns | 0.78x | WIN |

Scorecard effect: the measured deployed `strtol` rows in
`strtol_glibc_bench` now all beat host glibc. The same final run leaves
`clock_gettime` at 1.33x, `time` at 1.64x, and `pthread_self` at 1.10x; route
those separately and do not retry the rejected vDSO pointer-cache family.

Validation/build: touched-file rustfmt check and `git diff --check` passed.
RCH `conformance_strtol_family` passed; RCH
`strtol_family_differential_fuzz` compared 1,000,000 cases with 0 divergences;
RCH `cargo check -p frankenlibc-abi --lib` and
`cargo build -p frankenlibc-abi --release` passed with known pre-existing
warnings. RCH clippy was attempted per crate but blocked because `cargo-clippy`
is not installed for `nightly-2026-04-28-x86_64-unknown-linux-gnu`. Full
evidence:
`tests/artifacts/perf/bd-2g7oyh.497-strtol-positive-prefix-pending.md`.

## 2026-06-20 `bd-2g7oyh` `qsort_16_i32` screen

The small-qsort route was remeasured before editing sort code. No qsort source
lever was landed.

| Workload | FrankenLibC | glibc | Ratio | Verdict |
|---|---:|---:|---:|---|
| `qsort_16_i32` core-only screen (`hz1`) | 160.522 ns p50 | 244.160 ns p50 | 0.657x | WIN, no source change |
| `qsort_16_i32` deployed ABI screen (`vmi1293453`) | 12562.578 ns p50 | 12476.459 ns p50 | 1.007x | NEUTRAL, no source change |

Scorecard effect: stale small-qsort loss routing is closed for now. The core
sort already wins the 16-element case, and the deployed ABI row is effectively
parity; qsort is not a current top loss without a different workload profile.

## 2026-06-19 `bd-2g7oyh.479` measured reject

The runtime-design stack candidate array was converted from code-first pending
to same-worker rch evidence and rejected.

| Workload | Baseline heap `Vec` | Candidate stack array | Ratio | Verdict | Action |
|---|---:|---:|---:|---|---|
| `runtime_math_kernels/design_choose_plan/strict` p50 (`hz2`) | 367.188 ns | 370.153 ns | 1.008x | NEUTRAL/LOSS | Reverted to heap `Vec`. |
| same row custom mean (`hz2`) | 372.889 ns | 471.061 ns | 1.263x | LOSS | Reverted. |
| same row p95 / p99 (`hz2`) | 418.648 ns / 438.791 ns | 1058.839 ns / 1356.561 ns | 2.529x / 3.092x | LOSS | Do not retry fixed `[ProbeCandidate; 17]` layout. |

## 2026-06-19 `bd-li0so3` measured reject

The `/etc/hosts` hostname field scanner was converted from code-first pending
to same-worker rch evidence and rejected.

| Workload | Baseline split/filter/collect | Candidate field scanner | Ratio | Verdict | Action |
|---|---:|---:|---:|---|---|
| `parse_hosts_line_typical` p50 (`vmi1149989`) | 74.106 ns | 92.461 ns | 1.248x | LOSS | Reverted to split/filter/collect. |
| same row mean (`vmi1149989`) | 69.717 ns | 94.178 ns | 1.351x | LOSS | Reverted. |
| same row p95 / p99 (`vmi1149989`) | 80.096 ns / 88.041 ns | 104.067 ns / 111.742 ns | 1.299x / 1.269x | LOSS | Do not retry this scanner family without a fresh allocation-dominant profile. |

## 2026-06-19 `bd-4crkqx` measured reject

The `/etc/aliases` member scanner was converted from code-first pending to
same-worker rch evidence and rejected.

| Workload | Baseline split/filter/collect | Candidate manual scanner | Ratio | Verdict | Action |
|---|---:|---:|---:|---|---|
| `parse_aliases_line_typical` p50 (`hz2`) | 91.103 ns | 106.877 ns | 1.173x | LOSS | Reverted to split/filter/collect. |
| same row mean (`hz2`) | 91.762 ns | 116.684 ns | 1.272x | LOSS | Reverted. |
| same row p95 / p99 (`hz2`) | 95.303 ns / 96.391 ns | 171.807 ns / 192.406 ns | 1.803x / 1.996x | LOSS | Do not retry this manual scanner family without a new SIMD/memchr-backed multi-delimiter primitive or a long-row profile. |

## 2026-06-19 `bd-xxrfvu` measured keep

The `/etc/networks` byte network-number parser was converted from code-first
pending to same-worker rch evidence and kept.

| Workload | Baseline UTF-8 + str split | Candidate byte parser | Ratio | Verdict | Action |
|---|---:|---:|---:|---|---|
| `parse_networks_line_typical` p50 (`vmi1153651`) | 243.090 ns | 195.091 ns | 0.803x | WIN | Keep. |
| same row mean (`vmi1153651`) | 446.336 ns | 223.541 ns | 0.501x | WIN | Keep. |
| same row p95 / p99 (`vmi1153651`) | 1603.047 ns / 3399.881 ns | 230.951 ns / 761.473 ns | 0.144x / 0.224x | WIN | Throughput improved 1.997x. |

Validation: touched-file rustfmt passed, `netnum` filtered core tests passed
12/12, `network_` filtered core tests passed 15/15, and
`cargo check -p frankenlibc-core` passed with existing unrelated iconv warnings.

## Blocking follow-ups

- Move or gate `zz_scratch_*` integration probes so crate-scoped test filters can build the intended test binary without unrelated scratch compile failures.
- Add test-mode-safe coverage for `stdio_abi` and `wchar_abi` helper tests, or move the helper invariants into a module that is built under `cargo test --lib`.
- Continue converting `code-first batch-test pending` beads into central ledger rows, starting with `bd-2jgvp9` stdio registry local hasher and cod-b-owned resolver/NSS parser rows.

## 2026-06-19 BlackThrush measured update (thin-LTO, current bench)

Re-ran the stdio cluster and extended to mem/string head-to-heads. Honest reconciliation + new data
(full evidence in `docs/NEGATIVE_EVIDENCE.md`):

| Bead / function | fl | glibc | ratio | verdict | note |
|---|---|---|---|---|---|
| `bd-2jgvp9` stdio registry hasher (`fgetc_4096`) | 5.22 ms | 9.46 ms | **0.552×** | **WIN** | robust (0.577× on prior run) |
| `bd-0m5vaw` `snprintf("%s\n")` | 945 ns | 947 ns | 0.998× | NEUTRAL | cod-b's 0.856× was an earlier, lighter bench — does **not** reproduce |
| `bd-fgnxc0` `swprintf` wide | 2.635 µs | 2.622 µs | 1.005× | NEUTRAL | cod-b's 0.313× does **not** reproduce (bench workload changed ~2.6×) |
| `fgetc_unlocked` | 9.56 ms | 9.56 ms | 1.001× | NEUTRAL | fl unlocked slower than fl locked → `bd-djtvqq` |
| memset (64 B→64 K) | — | — | 1.00–6.84× | **WIN** | beats glibc at every size |
| memmove (64 B→64 K) | — | — | 1.02–10.57× | **WIN** | beats glibc at every size |
| memcpy @64 K | 2208 ns | 1204 ns | **0.55×** | **LOSS** | WIN small/med; large loses → `bd-4ibo52` |
| strlen scan @≥4 K | — | — | 0.81–0.90× | **LOSS** | WIN small → `bd-4ibo52` |
| strchr (absent scan) | 9120 ns | 588 ns | **0.06×** | **LOSS** | severe — glibc 2–16× faster → `bd-4rxozm` |

**Revised posture (measured):** fl has genuine WINS (fgetc / memset / memmove — small-buffer + registry
paths) but genuine LOSSES vs glibc's hand-tuned AVX on large scans (**strchr severe**, memcpy@64 K,
strlen@large). **Not release-competitive on `strchr`/`strrchr`** until the large-scan SIMD gap closes
(`bd-4rxozm`, P2). Two previously-claimed printf wins (`bd-0m5vaw`/`bd-fgnxc0`) are **NEUTRAL** on the
current bench — corrected here. The critical LTO methodology trap (no-LTO invalidates fl ratios) is
logged so it is never retried. No source regressions: every loss is a gap to glibc, not vs fl's own
prior code (fl-new beats fl-old everywhere), so nothing is reverted.

### Measured backlog tally (this session)
- **Robust WINS:** fgetc (0.552×), memset (≤6.84×), memmove (≤10.57×), + memcpy/strlen/strchr small sizes.
- **NEUTRAL:** snprintf `%s\n`, swprintf wide, fgetc_unlocked.
- **LOSSES (gaps filed):** strchr (`bd-4rxozm` P2), memcpy@64K + strlen@large (`bd-4ibo52` P3).
- **New lever from measurement:** getc_unlocked (`bd-djtvqq`).

## 2026-06-19 COMPREHENSIVE head-to-head (67 functions, glibc_baseline_bench, thin-LTO)

**Headline: fl beats glibc on ~58 of 67 measured functions.** Full table in
`docs/NEGATIVE_EVIDENCE.md`. Categories:

- **WINS (fl faster):** strstr (0.001×), malloc (0.008×), strcmp/strlen/memcmp/scanf/strtol,
  memcpy_4096 (0.486×), memchr/memmove, **all ~25 libm math fns 2–4× faster** (exp/log/sin/cos/pow…).
- **NEUTRAL:** bare-%f (printf_f_6 0.953×), qsort (0.992×), memset_4096 (1.037×), strchr small (1.038×), getenv.
- **LOSSES:** `powf` (2.2–2.7×, **new** → P2 bead), `strcpy_4096` (1.345×), and large-size
  `strchr`/`memcpy`/`strlen` (glibc AVX scales better at ≥16 KB — bd-4rxozm/bd-4ibo52, size-specific).

**Revised release posture:** fl is broadly **competitive-to-faster than glibc** across string, small/
medium mem, malloc, scanf, and scalar math. The earlier "not release-competitive on strchr" is
**softened** — strchr is neutral at typical (short) sizes; only large-buffer scans lose. Remaining
genuine gaps to close before a perf-release claim: **`powf`** (clear loss), `strcpy`, and large-size
SIMD scaling (strchr/memcpy/strlen). The two earlier printf "wins" (bd-0m5vaw/bd-fgnxc0) are NEUTRAL
on the current bench. No regressions vs fl's own prior code → nothing reverted.

## 2026-06-19 FINAL deployed-vs-core verdict (BlackThrush)

The gauntlet now separates fl's **algorithmic ceiling** (core) from its **deployed reality** (real
`frankenlibc_abi`, with the per-call membrane). Both measured head-to-head vs glibc (thin-LTO):

| Layer | Result vs glibc |
|---|---|
| **CORE** (raw kernels, no membrane) | fl beats glibc on **~58/67** fns; math 2–4×, string/mem/malloc/scanf wins. fl's algorithms are genuinely faster. |
| **DEPLOYED** (public abi, with membrane) | **Parity-to-win, no losses** on measured workloads: `fgetc` 0.552× WIN, `strlen` 0.392× WIN; memset/strcmp/math/snprintf/swprintf NEUTRAL. |

**Why deployed < core:** the per-call membrane (`stage_context`/`runtime_policy::decide`+`observe`)
is **path-specific** — memset ~1 ns (thin), strcmp ~82 ns, math ~180 ns. On hot small fns it
consumes the core's 2–4× advantage, leaving parity. No catastrophic losses, but short-string strcmp
would lose (fixed ~82 ns vs glibc ~5 ns).

**Release posture (measured, honest):** fl is **competitive (parity-to-faster) with glibc on the
deployed path** — a credible perf-release position. The single highest-leverage improvement is
**bd-n40in2** (a shared membrane fast-path for hot small fns) which would lift deployed math/strcmp
back toward the core 2–4× wins. Specific deployed gaps to close: `powf` (core libm, 2.7×), `strcpy`,
large-buffer SIMD scaling. For that deployed-vs-core sweep, no source revert was needed because
the losses were gaps-to-glibc / membrane-ceiling, not regressions vs fl's own prior code.

## 2026-06-20 GB18030 iconv closeout (BlackThrush)

The post-CP932 iconv residual was GB18030 CJK encode/decode. Baseline
`iconv_glibc_bench gb18030` on `hz1` showed two real losses:
`utf8_cjk_to_gb18030` 5622.3 ns vs glibc 3495.2 ns (1.609x) and
`gb18030_to_utf8` 121728.2 ns vs glibc 2603.6 ns (46.756x). The kept lever adds
packed BMP-3 transducers for the common CJK shape: UTF-8 three-byte BMP scalars
directly to GB18030 two-byte keys, and GB18030 two-byte keys directly to packed
UTF-8 triples. Non-hot-shape cases fall through before consuming input.

Final head-to-head run used the same command/target dir, but `rch` selected
`hz2` despite the `hz1` preference, so baseline-to-final self-speedup is
directional. The final in-run deployed ratios are clean wins:

| Workload | fl | glibc | ratio | verdict |
|---|---:|---:|---:|---|
| `utf8_cjk_to_gb18030` | 1401.1 ns | 2592.7 ns | 0.540x | WIN |
| `gb18030_to_utf8` | 976.4 ns | 2206.2 ns | 0.443x | WIN |

Validation: `iconv_cjk_differential_fuzz_vs_glibc` passed 216000 conversions
with 0 divergences, `cargo check -p frankenlibc-core` passed with pre-existing
warnings, and `git diff --check` passed. `cargo fmt --check -p
frankenlibc-core` remains blocked by unrelated existing formatting drift across
generated/table and legacy files; the deny-warnings `frankenlibc-core` clippy
gate remains blocked by pre-existing lint debt. Scorecard for this targeted lane:
**2 WIN / 0 NEUTRAL / 0 LOSS**. Evidence:
`tests/artifacts/perf/bd-2g7oyh-gb18030-direct-codec.md`.

## 2026-06-23 algorithmic / scalar-gather wins (cc)

Three measured, byte-identical wins this session, all the ALGORITHMIC class
(heap-alloc removal or scalar-gather→true-SIMD-load), recorded in full in
`docs/NEGATIVE_EVIDENCE.md`. All ratios are same-run fl-vs-glibc (glibc as the
stable yardstick, the only worker-invariant reference):

| Workload | fl before | fl after | glibc | verdict | mechanism |
|---|---:|---:|---:|---|---|
| `inet_pton` AF_INET6 (parse_ipv6) | 112.6 ns | 38.2 ns | ~41 ns | 2.76x LOSS → **0.90x WIN** | single-pass glibc `inet_pton6` port (drop `from_utf8` + ~5 whole-string rescans) |
| `inet_net_pton` AF_INET | 20.2 ns | 13.9 ns | 31.5 ns | 0.64x → **0.49x WIN** (1.45x self) | per-call `Vec` → bounded stack array |
| `iconv` utf16le→utf8 (ASCII) | 2024 ns | 490.9 ns | 1593 ns | 1.27x LOSS → **0.31x WIN** (4.1x self) | scalar `cp_at` gather → true 32-B `Simd::<u8,32>` load + `simd_swizzle!` deinterleave |
| `iconv` utf16be→utf8 (ASCII) | ~2024 ns | 596.9 ns | 2519 ns | 0.75x → **0.24x WIN** (3.4x self) | same true-SIMD-load run generalized to BE (swap lo/hi swizzle masks) |
| `iconv` utf32le→utf8 (ASCII) | ~2000 ns | 719.2 ns | 1789 ns | → **0.40x WIN** (~2.8x self) | 4-byte-unit true-SIMD load: `(v & mask)`-zero ASCII check + low-byte swizzle |
| `iconv` utf32be→utf8 (ASCII) | ~2000 ns | 735.7 ns | 1863 ns | → **0.39x WIN** (~2.8x self) | same, BE low-byte lane = 3 |
| `iconv` utf8→utf16le (ASCII) | 829 ns | 399.6 ns | 1453 ns | 0.58x → **0.275x WIN** (~2.1x self) | scalar widen scatter → two-input `simd_swizzle!` interleave-with-zeros |
| `iconv` utf8→utf32le (ASCII) | ~700 ns | 408.2 ns | 1417 ns | ~0.5x → **0.288x WIN** (~1.7x self) | same SIMD widen (64-byte store) |
| `iconv` utf8 2-byte→utf16le (Cyrillic) | 798 ns | 469.3 ns | ~1245 ns | 0.64x → **0.38x WIN** (~1.7x self) | SIMD-decoded `wc` scalar-scatter store → `lo`/`hi` cast + `simd_swizzle!` interleave |

Validation (byte-identical vs LIVE glibc): parse_ipv6 — 40k-round
`inet_pton_ntop_differential_fuzz` + `conformance_diff_inet_pton6_edges` + 150
core inet unit; net_pton — `inet_net_ntop_differential_fuzz` (0 divergences) +
`conformance_diff_inet_net` + 38 core unit; iconv — `iconv_differential_fuzz` +
`conformance_diff_iconv` + `golden_iconv_utf8_fastpath` +
`conformance_diff_iconv_simd` + 285 core iconv unit. iconv is now **8/8
fl-dominant**. Lane scorecard: **3 WIN / 0 NEUTRAL / 0 LOSS**.

Also retired 3 dead levers via same-process A/B (no code shipped, ledger only):
strspn_range range-test = 2.1x REGRESSION (x86 has no native unsigned SIMD
compare); strcmp exact-256 probe = red herring; memrchr raw-index = ~8%, still
floor-class. Meta-lesson: a perf hypothesis on SIMD op-count MUST be settled
with a same-process A/B before claiming — op-counting lies on x86, fl absolute
ns swings 18→120 ns across rch workers.

## 2026-06-20 `bd-2g7oyh` calloc tombstone compaction reject

The allocator follow-up tested deletion-time tombstone compaction in the
fallback allocation table. It was measured with deployed `calloc/free` against
host glibc via `calloc_glibc_bench` on `vmi1293453`.

| Size | Candidate FL | glibc | FL/glibc | Same-worker candidate / prior FL | Verdict |
|---|---:|---:|---:|---:|---|
| 16 B | 126.620 ns | 11.529 ns | 10.98x | 1.027x | LOSS/regression |
| 256 B | 747.608 ns | 37.921 ns | 19.72x | 0.958x | LOSS vs glibc |
| 4096 B | 823.597 ns | 153.098 ns | 5.38x | 0.925x | LOSS vs glibc |
| 262144 B | 5016.522 ns | 4126.736 ns | 1.22x | 0.901x p50, 1.710x mean | LOSS/tail regression |
| 1048576 B | 21035.057 ns | 19578.059 ns | 1.07x | 1.082x | LOSS/regression |
| 4194304 B | 108814.652 ns | 118209.750 ns | 0.92x | 1.263x | Mixed; absolute regression |

Action: reverted the source to the prior tombstone-on-remove behavior and kept
only evidence. The retry predicate is now explicit: do not retry deletion-time
tombstone clearing/coalescing; the next allocator lane needs a different shape
such as a slim strict `calloc/free` fast path or a same-run profile that explains
the diffuse allocator overhead first.

Evidence: `tests/artifacts/perf/bd-2g7oyh-calloc-strict-fastpath.md`.

## 2026-06-20 `bd-f874go` fallback-table exact hot-slot reject

The next cod-b allocator screen tested a per-thread exact fallback-table slot
cache for strict `malloc/calloc` paired with a lock-free exact-slot remove in
strict `free`. This kept the existing locked fallback table as the correctness
path and only optimized same-thread exact cycles.

Current-head baseline on `vmi1153651` still shows the deployed small-size
allocator gap:

| Size | FL p50 | glibc p50 | p50 ratio | FL mean | glibc mean | mean ratio | Verdict |
|---:|---:|---:|---:|---:|---:|---:|---|
| 16 | 114.960 ns | 10.819 ns | 10.63x | 140.949 ns | 25.417 ns | 5.55x | LOSS |
| 256 | 435.260 ns | 37.111 ns | 11.73x | 562.837 ns | 56.385 ns | 9.98x | LOSS |
| 4096 | 498.224 ns | 104.550 ns | 4.77x | 538.890 ns | 156.296 ns | 3.45x | LOSS |
| 65536 | 1536.001 ns | 1042.184 ns | 1.47x | 1865.195 ns | 1358.150 ns | 1.37x | LOSS |
| 262144 | 4372.561 ns | 4142.734 ns | 1.06x | 5460.396 ns | 4884.627 ns | 1.12x | LOSS |
| 1048576 | 20454.473 ns | 20917.348 ns | 0.98x | 23103.947 ns | 29813.969 ns | 0.77x | WIN |
| 4194304 | 102830.806 ns | 96288.569 ns | 1.07x | 158753.434 ns | 117990.544 ns | 1.35x | LOSS |

The candidate run selected `vmi1167313` despite the worker preference, so it was
used only as a screen. Its in-run deployed FL-vs-glibc result was not
competitive: 0 wins, 1 neutral, 13 losses across p50+mean cells, with a severe
4 KiB mean/tail outlier and a 1 MiB row that flipped from baseline win to loss.

Action: source reverted; evidence kept. Retry predicate: do not retry
per-thread exact fallback-slot caching as a standalone lever. Next allocator
attempt should first split the deployed `calloc/free` cycle into host allocator,
fallback metadata, stats accounting, and reentry-guard substages, or use a
materially different proof-carrying path that removes fallback-table
participation for common strict pairs.

Evidence: `tests/artifacts/perf/bd-f874go-fallback-hot-slot.md`.

## 2026-06-20 `bd-f874go` fallback-tracked `realloc` same-class keep

The next allocator lever avoided host `realloc` for strict fallback-tracked
requests that either keep the same size or shrink within the same small malloc
size class. The fallback metadata is tightened on shrink, so
`known_remaining` reflects the requested size even when the host pointer stays
in place.

Baseline and candidate both ran `calloc_glibc_bench realloc_cycle` on
`vmi1149989` with the cod-b rch target dir.

| Workload | Baseline FL | Candidate FL | Candidate glibc | Candidate FL/glibc | Candidate/base FL | Verdict |
|---|---:|---:|---:|---:|---:|---|
| `same_256` | 69.188 ns | 13.333 ns | 3.288 ns | 4.06x | 0.193x | LOSS vs glibc / WIN vs FL |
| `same_class_shrink_256_to_240` | 226.960 ns | 170.314 ns | 7.480 ns | 22.77x | 0.750x | LOSS vs glibc / WIN vs FL |
| `cross_class_shrink_256_to_128` | 324.102 ns | 239.357 ns | 17.063 ns | 14.03x | 0.739x | LOSS vs glibc / guard-only FL improvement |
| `same_class_shrink_4096_to_3584` | 283.024 ns | 171.915 ns | 24.170 ns | 7.11x | 0.607x | LOSS vs glibc / WIN vs FL |

Action: keep as a measured gap-narrowing source win, not a perf-closeout.
Every row still loses to host glibc. Validation: `malloc_abi_test realloc`
passed 7/0 on rch, `cargo build -p frankenlibc-abi --release` passed on rch,
and touched-file rustfmt plus `git diff --check` passed.

Evidence: `tests/artifacts/perf/bd-f874go-realloc-same-class.md`.

## 2026-06-19 `bd-2g7oyh.478` measured reject

The exact `strcpy_4096` eight-block unroll was converted from code-first pending to measured
head-to-head evidence and rejected.

| Bead | Workload | FrankenLibC | glibc | Ratio | Verdict | Action |
|---|---|---:|---:|---:|---|---|
| `bd-2g7oyh.478` | `glibc_baseline_strcpy_4096` (`hz1`, thin-LTO) | 68.555 ns | 54.857 ns | 1.250x | LOSS | Reverted to the prior counted block loop. |

Focused post-revert guards passed (`cargo check -p frankenlibc-core` and the two
`test_strcpy_exact_4096_path*` tests). `strcpy_4096` remains a genuine glibc gap after the revert;
retry only with a materially different generated/backend primitive.

## 2026-06-19 `bd-2g7oyh.487` measured keep

The fused `getopt` optstring lookup was converted from code-first pending to measured
head-to-head evidence and kept.

| Bead | Workload | FrankenLibC | glibc | Ratio | Verdict | Action |
|---|---|---:|---:|---:|---|---|
| `bd-2g7oyh.487` | `getopt_short_bundle_glibc_comparable` (`ovh-a`, thin-LTO) | 93.699 ns | 168.676 ns | 0.556x | WIN | Keep fused lookup. |

Harness correction: host glibc `getopt` must be loaded through the corrected
`dlmopen` path and both libc/process `opt*` globals must be reset. Earlier
plain-`dlopen` rows are invalid because `frankenlibc_abi` exports `optind` and
can interpose glibc state. Focused guard: `cargo test -p frankenlibc-core getopt
--lib` passed 39 tests. Clippy was attempted, but the selected rch nightly lacks
the `cargo-clippy` component.

## 2026-06-19 `bd-9ran7n` resolver decimal parser measured keep

The NSS service/protocol byte-decimal parser was converted from code-first pending to deployed
ABI evidence vs host glibc on `hz1`.

| Workload | FrankenLibC | glibc | Ratio | Verdict | Action |
|---|---:|---:|---:|---|---|
| `getservbyname("http","tcp")` | 28.532 us | 435.582 us | 0.0655x | WIN | Keep. |
| `getprotobyname("tcp")` | 125.854 us | 129.508 us | 0.9718x | NEUTRAL | Keep; no regression and same lever has a large services win. |

Conformance stayed green for the focused path: resolver parser unit filters passed, and the
`conformance_diff_netdb_aliases`, `conformance_diff_protoent_r_aliases`, and
`conformance_diff_netdb_r_aliases` ABI differential tests matched glibc.

## 2026-06-19 `bd-2g7oyh.481` group parser measured partial keep

| Workload | FrankenLibC | glibc | Ratio | Verdict | Action |
|---|---:|---:|---:|---|---|
| `getgrnam("root")` | 9.788 us | 24.779 us | 0.395x | WIN | Keep the splitn group parser as a partial deployed win. |
| `getgrgid(0)` | 24.631 us | 24.435 us | 1.008x | NEUTRAL | Route gid lookup/cache path deeper; do not retry colon-tail parser reshaping for this gap. |

Conformance stayed green after the gauntlet rejected signed gid fields again:
core group parser tests passed, `grp_abi_test getgr` passed, and group
differential tests passed.

## 2026-06-21 `bd-owsx6w` group GID byte-parser measured partial keep

The pending code-first GID byte parser now has a same-worker remote verdict on
`hz2`. The parser microbench itself has no host-glibc comparator, so it is
routing evidence only (`parse_group_line_typical` p50 `63.508 ns`, mean
`90.590 ns`). The deployed ABI comparison is still the release gate:

| Workload | FrankenLibC | glibc | Ratio | Verdict | Action |
|---|---:|---:|---:|---|---|
| `getgrnam("root")` | 5.559 us | 11.124 us | 0.500x | WIN | Keep the byte parser as part of the deployed group parser stack. |
| `getgrgid(0)` | 7.767 us | 7.623 us | 1.019x | NEUTRAL | Do not credit as gid domination; route residual p50 work below the field parser. |

Focused conformance stayed green: remote `cargo test -p frankenlibc-core
grp:: --lib` passed 37 tests; remote `cargo test -p frankenlibc-abi --test
grp_abi_test getgr` passed 36 filtered tests with the signed-gid guard green.
The live differential `conformance_diff_getgrent` and `conformance_diff_getbyid_r`
tests passed, but that command fell back local because `rch` had no admissible
worker slots.

## 2026-06-19 `bd-2g7oyh.482` measured reject

The passwd field scanner was converted from pending code-first status into
deployed ABI evidence vs host glibc and rejected.

| Workload | FrankenLibC | glibc | Ratio | Verdict | Action |
|---|---:|---:|---:|---|---|
| `getpwnam("root")` | 10.906 us | 10.013 us | 1.089x | LOSS | Reverted parser optimization. |
| `getpwuid(0)` | 31.495 us | 9.957 us | 3.163x | LOSS | Reverted parser optimization; route uid lookup/cache path deeper. |

Post-revert focused conformance stayed green: `cargo test -p frankenlibc-core
pwd:: --lib` passed 79 tests, and the updated `baseline_capture_bench` check
passed with known pre-existing warning debt. Clippy remains blocked on rch by
missing `cargo-clippy` for the selected nightly toolchain.

## 2026-06-19 cod-a parser batch measured classification

Internal core parser old-vs-new gate on `vmi1153651`; not host-glibc evidence.

| Bead / row | Baseline | Candidate | Ratio | Verdict | Action |
|---|---:|---:|---:|---|---|
| `bd-2g7oyh.484` `parse_shadow_line_typical` | 390.734 ns | 145.133 ns | 0.371x | WIN | Keep. |
| `bd-2g7oyh.489` `resolver_should_try_absolute_first_typical` | 11.271 ns | 8.834 ns | 0.784x | WIN | Keep. |
| `bd-2g7oyh.480` + `.491` `parse_proc_net_route_has_ipv4_typical` | 193.540 ns | 186.230 ns | 0.962x | WEAK WIN | Keep combined route batch; post-reversal source measured 164.474 ns. |
| `bd-2g7oyh.486` `parse_maps_line_typical` | 173.755 ns | 243.944 ns | 1.404x | LOSS | Source reverted. |
| `bd-rpc-byte-program-number-wq60gz` `parse_rpc_line_typical` | 166.474 ns | 164.140 ns | 0.986x p50 / 1.063x mean | NEUTRAL/LOSS | Source reverted. |
| `bd-v4t889` + `bd-2g7oyh.488` `parse_resolv_conf_options_typical` | 262.342 ns | 310.177 ns | 1.182x | LOSS | Source reverted. |
| `bd-2g7oyh.490` `parse_proc_net_if_inet6_has_ipv6_typical` | 226.138 ns | 305.105 ns | 1.349x | LOSS | Source reverted. |

Validation summary: focused parser tests passed; full workspace gates remain
blocked by unrelated pre-existing failures listed in the current gate snapshot.

### 2026-06-19 deployed-math DEFINITIVELY resolved (same-run, BlackThrush)

Clean same-run core+abi+glibc (`bench_math_abi` 3-way, one worker) confirms the deployed-math
picture with no cross-run confounding: **core math 2–4× faster** than glibc (3.6–7.8 ns vs 12.5–19 ns);
the `unary_entry` membrane adds **~8–11 ns/call**, bringing **deployed math to glibc parity** (NEUTRAL,
0.97–1.02×). Earlier "~180 ns" was a per-batch misread — corrected. **bd-n40in2 (P2) is the validated
top deployed-perf lever:** cheapen the membrane (memset's path proves ~1 ns achievable) → recover
~2× on deployed math. Method note: per-call membrane delta MUST be measured same-run (worker
variance otherwise dominates); cross-run core-vs-deployed comparisons are invalid.

### 2026-06-19 `bd-fused-f64-pow-exp-log-kernels-iw3rwz` f64 exp2 keep

F64 `exp2` now uses an ARM/glibc-style 128-entry table kernel on the normal-result
interior, falling back to `libm::exp2` for denormal-tiny, overflow, underflow,
inf, and NaN cases.

| Row | FrankenLibC | Comparator | Ratio | Verdict |
|---|---:|---:|---:|---|
| dedicated core vs old libm fallback | 2.4008 ns p50 / 2.5758 ns mean | 3.0104 ns p50 / 3.3109 ns mean | 0.798x / 0.778x | WIN |
| dedicated core vs host glibc | 2.4008 ns p50 / 2.5758 ns mean | 4.8920 ns p50 / 7.7200 ns mean | 0.491x / 0.334x | WIN |
| standard core `glibc_baseline_math/exp2` vs host glibc | 163.950 ns p50 / 162.282 ns mean | 621.670 ns p50 / 651.402 ns mean | 0.264x / 0.249x | WIN |
| deployed ABI `glibc_baseline_math_abi/exp2_abi` vs host glibc | 610.605 ns p50 / 656.530 ns mean | 662.209 ns p50 / 657.528 ns mean | 0.922x / 0.998x | WIN p50 / NEUTRAL mean |

Conformance: `conformance_diff_exp2_f64_general` passed 221,546 interior inputs
within 4 ULP vs host glibc, worst 1 ULP; boundary/special inputs exact.
Remaining route: f64 `pow` still needs a true fused log+exp port; standalone
`math::exp2` is not a sufficient retry lever for that path.

### 2026-06-19 deployed calloc status (BlackThrush / cod-a)

Same-worker deployed ABI `calloc` + `free` gauntlet on `vmi1293453` confirms the
allocator surface is still not release-dominant against glibc for small sizes:
current-head p50+mean score is **2 wins, 0 neutral, 12 losses**. Worst p50
ratios are 256B `22.16x`, 16B `10.86x`, and 4096B `8.29x`.

Two bold allocator levers were measured and rejected with source reverted before
commit:

| Lever | Score / evidence | Release action |
|---|---|---|
| Lock-free fallback allocation table reservation | Regressed 16B FL to 153.918 ns p50 / 195.183 ns mean and 256B FL to 854.457 ns / 943.974 ns. | Do not ship. |
| Strict free-path ownership probe elision | Candidate score vs glibc was 1 win, 1 neutral, 12 losses; 4 MiB regressed to 101202.424 ns p50 / 147881.717 ns mean. | Do not ship. |

Release posture: deployed math can be parity-to-faster, but deployed allocator
small-size `calloc/free` remains a blocker for "dominates glibc" claims. The
next allocator work should split zero-fill from metadata cost and pursue a
deeper metadata/allocator deployment change, not another branch-local tweak.

### 2026-06-20 `bd-f874go` allocator fast-path keep (BlackThrush / cod-b)

Same-worker `vmi1152480` `calloc_glibc_bench` A/B kept one narrow strict-host
allocator fast-path reduction: reuse the public allocator guard's reentry slot
inside native host `calloc`/`free` instead of looking the slot up again.

| Size | Baseline FL | Candidate FL | Candidate glibc | Candidate ratio | Verdict |
|---|---:|---:|---:|---:|---|
| 16 B | 85.087 ns | 86.020 ns | 7.148 ns | 12.03x | LOSS row |
| 256 B | 454.890 ns | 237.286 ns | 21.068 ns | 11.26x | WIN vs baseline, still LOSS vs glibc |
| 4096 B | 446.897 ns | 273.946 ns | 47.993 ns | 5.71x | absolute WIN, ratio loss/noise |
| 262144 B | 2911.750 ns | 1862.715 ns | 1561.114 ns | 1.19x | WIN vs baseline, still LOSS vs glibc |
| 1048576 B | 14664.400 ns | 10027.183 ns | 9393.547 ns | 1.07x | near parity |
| 4194304 B | 47376.372 ns | 47365.083 ns | 67326.391 ns | 0.70x | WIN vs glibc, neutral vs baseline |

Scorecard effect: allocator readiness improves but does not flip to release
dominance. The worst measured 256 B row moved from 19.55x to 11.26x vs glibc,
and 1 MiB moved from 1.55x to 1.07x. Remaining blocker: small `calloc/free`
still carries double-digit glibc loss at 16 B and 256 B. Evidence:
`tests/artifacts/perf/bd-f874go-native-reentry-slot.md`.

Validation: touched-file rustfmt passed, `frankenlibc-abi` malloc ABI conformance
passed on `rch` (53 passed, 0 failed, 1 ignored), and the earlier same-patch
`cargo check -p frankenlibc-abi` passed with pre-existing warning debt.

### 2026-06-20 CP932 iconv decode keep (BlackThrush / cod-a)

Same-worker `hz1` head-to-head converted the CP932-family decode residual from
a catastrophic glibc loss to neutral.

| Workload | Baseline FL | Final FL | Final glibc | Final ratio | Verdict |
|---|---:|---:|---:|---:|---|
| `iconv_glibc_bench` `cp932_to_utf8` | 27169.4 ns | 509.5 ns | 493.0 ns | 1.033x | NEUTRAL vs glibc, 53.3x self-win |
| paired `utf8_jp_to_cp932` guard | 2384.5 ns | 2025.2 ns | 2335.7 ns | 0.867x | WIN |

The shipped lever is a packed `DBCS key -> UTF-8 triple` table for CP932,
IBM943, and IBM932 BMP-3 pairs, with a 4-pair emission loop and exact fallback
to the generic path for single-byte, invalid, incomplete, astral/surrogate, and
short-output cases. Final score for the CP932 bench group: 1 win, 0 losses,
1 neutral versus host glibc.

Conformance/build: `rch exec -- cargo check -p frankenlibc-core` passed with
pre-existing warnings; `rch exec -- cargo test -p frankenlibc-abi --test
conformance_diff_iconv_cp932 -- --nocapture` passed 3/3. Touched-file rustfmt is
blocked by pre-existing monolithic/generated iconv formatting drift that would
cause broad unrelated churn.

### 2026-06-20 Stdio `snprintf` exact-format keep (BlackThrush / cod-a)

The deployed `snprintf("%s")` / `snprintf("%s\n")` surface is still glibc-red,
but the exact-format parser bypass is a measured same-worker FrankenLibC
self-win and the benchmark now uses a robust host denominator.

| Workload | Final FL | Fast path disabled | Host glibc | Final FL/glibc | Verdict |
|---|---:|---:|---:|---:|---|
| `snprintf("%s\n")` | 615.58 ns | 785.41 ns | 65.319 ns | 9.424x | WIN vs old FL, LOSS vs glibc |
| `snprintf("%s")` | 679.92 ns | 1.1712 us | 88.771 ns | 7.659x | WIN vs old FL, LOSS vs glibc |

The Stdio runtime-policy consult hypothesis was rejected separately: adding
`ApiFamily::Stdio` to the strict high-frequency family set did not produce a
stable improvement and was reverted. The remaining release blocker is the
printf architecture itself: variadic extraction, format parsing, and TLS
entrypoint machinery. The next credible stdio route is an exact-format
specializer/JIT-style mini-parser for common printf shapes, measured against the
same `dlmopen` host glibc arm.

Validation/build: `rch exec -- cargo test -p frankenlibc-abi --test
conformance_diff_printf_fastpaths -- --nocapture` fell back to local because no
workers were admissible and passed 3/3. The Criterion `snprintf_s` A/B bench
completed remotely on `vmi1293453` with
`CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a`. `cargo check
-p frankenlibc-abi --all-targets` remains blocked by pre-existing
`zz_scratch_divmin` integration-test trait errors, and workspace rustfmt remains
blocked by broad pre-existing formatting drift.

### 2026-06-21 `bd-2g7oyh.499` timing partial-resume bench (BlackThrush / cod-b)

Disk-low code-only pass: `clock_gettime` now has a stack-output fast path for
normal caller `timespec` outputs and a local common-clock validity fast path for
clock ids already accepted by the existing validators.

Measured partial-resume row: remote `hz1` `strtol_glibc_bench` reports
`clock_gettime` at 38.23 ns versus glibc 33.33 ns (`1.15x`, still a loss) and
`time(NULL)` at 7.10 ns versus glibc 3.57 ns (`1.99x`, untouched by this lever).
Focused clock conformance is green: remote `vmi1152480`
`conformance_diff_clock` passed 6/6 with zero divergences.

Scorecard effect: timing remains a release blocker. The `clock_gettime` row is
materially narrower than the prior `1.33x`/`1.35x` residual rows, so the source
is kept as a partial gap-cut, but this is not a glibc-domination claim.

Evidence ledger: `docs/NEGATIVE_EVIDENCE.md`. Evidence artifact:
`tests/artifacts/perf/bd-2g7oyh.499-clock-gettime-clock-id-fast-pending.md`.
