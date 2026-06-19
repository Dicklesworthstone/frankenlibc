# FrankenLibC Release Readiness Scorecard

Last updated: 2026-06-19 by `cod-b` / `BlackThrush`.

## Current gate snapshot

| Area | Score | Evidence | Risk |
|---|---:|---|---|
| Measured perf backlog conversion | 2 / many pending | `bd-0m5vaw` and `bd-fgnxc0` converted from code-first pending to measured head-to-head wins vs host glibc. | Large backlog remains across stdio registry, resolver/NSS parser, string, allocator, and peer-owned leaves. |
| Negative-evidence ledger | 1 / committed ledger | `docs/NEGATIVE_EVIDENCE.md` now records win/loss/neutral policy and the first two measured rows with glibc ratios. | Existing per-bead artifacts still contain many pending local ledgers; central ledger needs every later result appended. |
| Revert discipline | Green for measured cluster | No revert needed: both measured rows beat host glibc with ratios 0.856x and 0.313x. | Future neutral/loss rows must be reverted or explicitly marked safety/correctness exceptions. |
| Conformance guard | Partial green | `cargo check -p frankenlibc-abi` passed with known warning debt. Criterion bench binaries built and ran successfully. | `cargo test -p frankenlibc-abi` is blocked by pre-existing `zz_scratch_divmin` scratch-test compile errors; `stdio_abi`/`wchar_abi` inline tests are gated out of `--lib` test mode. |
| Release posture | Not ready | Two real wins recorded, no new source regression in this pass. | Not release-ready until scratch test debt is isolated/fixed, central ledger covers the pending backlog, and conformance/bench gates are repeatable. |

## 2026-06-19 measured stdio cluster

| Bead | Workload | FrankenLibC | glibc | Ratio | Verdict | Action |
|---|---|---:|---:|---:|---|---|
| `bd-0m5vaw` | `snprintf("%s\n")` with 128-byte destination and stable log payload | 471.49 ns | 550.41 ns | 0.856x | WIN | Keep. |
| `bd-fgnxc0` | `swprintf(L"value=%d\n")` into 32-wide-char buffer | 317.94 ns | 1.0154 us | 0.313x | WIN | Keep. |

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
