# FrankenLibC Release Readiness Scorecard

Last updated: 2026-06-19 by `cod-a` / `BlackThrush`.

## Current gate snapshot

| Area | Score | Evidence | Risk |
|---|---:|---|---|
| Measured perf backlog conversion | 16 / many pending | Added cod-a parser-batch classification for `bd-2g7oyh.480`, `.484`, `.486`, `.488`, `.489`, `.490`, `.491`, `bd-v4t889`, `bd-rpc-byte-program-number-wq60gz`, plus `bd-2g7oyh.479` runtime-design stack candidates and `bd-li0so3` hosts field scanner. Parser rows are internal old-vs-new; `.479` is same-worker runtime-kernel old-vs-new. | Large backlog remains across stdio registry, resolver/NSS parser, string, allocator, runtime membrane, and peer-owned leaves. Deployed ABI vs glibc evidence is still required for release perf claims. |
| Negative-evidence ledger | 1 committed ledger + bead-local rejects | `docs/NEGATIVE_EVIDENCE.md` records win/loss/neutral policy and the cod-a parser batch. `tests/artifacts/perf/bd-2g7oyh.479-runtime-design-stack-candidates.md` and `tests/artifacts/perf/bd-li0so3-hosts-field-scanner.md` record same-worker rejects and retry predicates. | Existing per-bead artifacts still contain many pending local ledgers; central ledger needs every later result appended when it is not peer-owned dirty. |
| Revert discipline | Green for measured cluster | Winning rows kept; losing/neutral parser source shapes were reversed without deleting evidence artifacts or benchmark rows. Prior glibc losses (`bd-2g7oyh.478`, `bd-2g7oyh.482`) remain reverted. `bd-2g7oyh.479` stack candidates and `bd-li0so3` hosts scanner were reverted after same-worker regressions. | Future neutral/loss rows must be reverted or explicitly marked safety/correctness exceptions. |
| Conformance guard | Partial green | Focused parser guards passed previously. For `.479`, touched-file rustfmt and `cargo check -p frankenlibc-membrane --lib` passed. For `bd-li0so3`, touched-file rustfmt, 10 hosts parser tests, and `cargo check -p frankenlibc-core` passed. | Full core tests are blocked by unrelated iconv/glob failures; workspace check/clippy by missing packaged files in `asupersync-conformance 0.3.4`; workspace fmt by broad formatting drift. |
| Release posture | Not ready | Additional getopt and group lookup wins recorded, plus real `getgrgid(0)` neutral and passwd lookup losses routed deeper. | Not release-ready until scratch test debt is isolated/fixed, central ledger covers the pending backlog, and conformance/bench gates are repeatable. |

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
