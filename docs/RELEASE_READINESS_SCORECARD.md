# FrankenLibC Release Readiness Scorecard

Last updated: 2026-06-20 by `cod-a` / `cod-b` / `BlackThrush`.

## Current gate snapshot

| Area | Score | Evidence | Risk |
|---|---:|---|---|
| Measured perf backlog conversion | 21 / many pending | Added cod-a parser-batch classification for `bd-2g7oyh.480`, `.484`, `.486`, `.488`, `.489`, `.490`, `.491`, `bd-v4t889`, `bd-rpc-byte-program-number-wq60gz`, plus `bd-2g7oyh.479` runtime-design stack candidates, `bd-li0so3` hosts field scanner, `bd-7ak6cm` calloc `alloc_zeroed` skip, `bd-4crkqx` aliases member scanner, `bd-xxrfvu` `/etc/networks` byte network-number parser, `bd-f874go` strict allocator reentry-slot reuse, and the 2026-06-20 `bd-2g7oyh` calloc tombstone-compaction reject. Parser rows are internal old-vs-new; allocator rows use deployed-ABI calloc vs host-glibc bench evidence. | Large backlog remains across stdio registry, resolver/NSS parser, string, allocator, runtime membrane, and peer-owned leaves. Deployed ABI vs glibc evidence is still required for release perf claims. |
| Negative-evidence ledger | 1 committed ledger + bead-local rejects | `docs/NEGATIVE_EVIDENCE.md` records win/loss/neutral policy and the parser/allocator batch. `tests/artifacts/perf/bd-f874go-native-reentry-slot.md` and `tests/artifacts/perf/bd-2g7oyh-calloc-strict-fastpath.md` record the kept native reentry-slot reduction and reverted tombstone compaction with root causes and retry predicates. | Existing per-bead artifacts still contain many pending local ledgers; central ledger needs every later result appended when it is not peer-owned dirty. |
| Revert discipline | Green for measured cluster | Winning rows kept; losing/neutral parser source shapes were reversed without deleting evidence artifacts or benchmark rows. Prior glibc losses (`bd-2g7oyh.478`, `bd-2g7oyh.482`) remain reverted. `bd-2g7oyh.479` stack candidates, `bd-li0so3` hosts scanner, `bd-7ak6cm` calloc `alloc_zeroed`, `bd-4crkqx` aliases member scanner, and the 2026-06-20 calloc tombstone compaction were reverted after measurement. `bd-xxrfvu` and `bd-f874go` measured as keeps. | Future neutral/loss rows must be reverted or explicitly marked safety/correctness exceptions. |
| Conformance guard | Partial green | Focused parser guards passed previously. For `.479`, touched-file rustfmt and `cargo check -p frankenlibc-membrane --lib` passed. For `bd-li0so3`, touched-file rustfmt, 10 hosts parser tests, and `cargo check -p frankenlibc-core` passed. For allocator work, `bd-f874go` passed its focused guards, and the 2026-06-20 calloc tombstone compaction reject was reverted; the current tree's `malloc_abi_test` passed 53/0/1 ignored and `rch exec -- cargo build -p frankenlibc-abi --release` passed on `hz1`. For `bd-4crkqx`, source was reverted to split/filter/collect; touched-file rustfmt passed, 30 aliases-filtered core tests passed, and `cargo check -p frankenlibc-core` passed. For `bd-xxrfvu`, touched-file rustfmt passed, `netnum` filtered tests passed 12/12, `network_` filtered tests passed 15/15, and `cargo check -p frankenlibc-core` passed. For `bd-z8p3mx`, the powf gates passed against host glibc 2.42. Two pre-existing unrelated failures remain (`diff_sign_min_max_dim_helpers_*`, `fminf`/`fmaxf`/`fdimf` — fail on clean HEAD too, not touched here). | Full core tests are blocked by unrelated iconv/glob failures; workspace check/clippy by missing packaged files in `asupersync-conformance 0.3.4`; workspace fmt by broad formatting drift. |
| Release posture | Not ready | Additional getopt and group lookup wins recorded, real `getgrgid(0)` neutral and passwd lookup losses routed deeper, `bd-f874go` strict allocator reentry-slot reuse narrows the deployed `calloc/free` gap, and the tombstone compaction attempt is recorded as a revert. | Not release-ready until scratch test debt is isolated/fixed, central ledger covers the pending backlog, conformance/bench gates are repeatable, and allocator small sizes no longer carry double-digit glibc losses. |

## 2026-06-19 measured stdio cluster

| Bead | Workload | FrankenLibC | glibc | Ratio | Verdict | Action |
|---|---|---:|---:|---:|---|---|
| `bd-0m5vaw` | `snprintf("%s\n")` with 128-byte destination and stable log payload | 471.49 ns | 550.41 ns | 0.856x | WIN | Keep. |
| `bd-fgnxc0` | `swprintf(L"value=%d\n")` into 32-wide-char buffer | 317.94 ns | 1.0154 us | 0.313x | WIN | Keep. |

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
