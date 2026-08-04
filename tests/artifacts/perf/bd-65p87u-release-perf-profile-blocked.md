# bd-65p87u release-perf profile evidence

Date: 2026-08-04

## Scope

This is the required prerequisite capture for the `segment_free` structural
bead.  The intended workload is the deployed allocator's
`segment_allocator_3way` member in `malloc_bench`, built with `abi-bench` so it
exercises exported `malloc`/`free` rather than Rust's process allocator.

## Ledger preflight and historical-row adjudication

`scripts/check_perf_ledger_integrity.py preflight --lever bd-65p87u --surface
segment_free --comparison legacy-incumbent --incumbent host-glibc` now returns
**PREFLIGHT OK**. The three formerly blocking rows are retained as provenance,
but are hand-adjudicated in `docs/NEGATIVE_EVIDENCE.md` as `VOID-CV / RETRY
SATISFIED`: the CPU/longer-sample retry, candidate-contrast gate correction,
and quiet-worker retry were each actually performed by the following row in
the historical chain. This does not promote any old CV-gated result to a win.

Staged-ledger lint also returned `0 REJECT row(s), 0 timed positive row(s), 0
refused`; the profile below is attribution evidence, not a new performance
claim or code-change verdict.

## Remote build provenance

| Build | Worker | Command | Result |
| --- | --- | --- | --- |
| Former link probe | `vmi1293453` | `cargo bench -j 1 -p frankenlibc-bench --features abi-bench --profile release-perf --bench malloc_bench --no-run` | RCH build `29961269708587295`, exit 0 after `aff100890` removed the duplicate fenv export. |
| Profile + same-invocation control | `vmi1227854` | `RCH_REQUIRE_REMOTE=1 env -u CARGO_TARGET_DIR rch exec -- cargo bench -j 1 -p frankenlibc-bench --features abi-bench --bench malloc_bench --profile release-perf -- segment_allocator_3way --noplot` | RCH build `29961269708587341`, exit 0; 737.219 s total (690.408 s remote execution). |

`release-perf` has line tables and is unstripped. The benchmark starts `perf
record -F 4999 --call-graph fp` against its own candidate process, then writes
the returned perf report and paired control sample record. Its self-reported
executing benchmark ELF is SHA-256
`f43d036667a34de51a6d780815953b551422c9f26975f4b2c3258940e3ea002a`
(55,560,312 bytes).

## Returned profiling artifacts

The remote result returned non-empty artifacts under
`target/criterion/bd-dcrhgl-segment-production/run-1849146-1785843292492949423/`:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `candidate.perf` | 231,708 | `daae218ce1b4f6f7b98a1a62db05ace7b1c62e21d0529fecfae0b916776a0a82` |
| `perf-report.txt` | 2,573 | `b9d4de760938ca575575afaf09704d09348794fa6c096ebed2ca94e8bb795837` |
| `paired.json` | 36,220 | `120ab23660853dd2c99339215dd13ee5ff2f2572a18553d4a210de4491cad4d7` |
| `executable.sha256` | 202 | `c202e95b709ccbe4c9ac5602018e9873c55f120690f32ccaac95fdf7f5e12666` |

The perf capture reports 1K cycles samples with **zero lost samples**. The
committed report is a flat `--no-children --call-graph none` attribution view
of the deployed candidate workload; the future structural predicate still
requires its separate matched no-call-graph multi-threaded capture.

## Attribution table

| Frame | Self time | Evidence |
| --- | ---: | --- |
| `malloc_abi::segment_free` | **25.83%** | Largest deployed allocator frame. |
| exported `free` | 20.37% | Free-side wrapper, distinct from `segment_free`. |
| `malloc_abi::segment_slot_view` | 11.18% | Allocator liveness/metadata view. |
| `malloc_abi::enter_allocator_reentry_guard` | 7.22% | Separate reentrancy contract; not interchangeable with the slot swap. |
| `malloc_abi::record_stats` | 4.48% | Allocator statistics bookkeeping. |
| exported `malloc` | 1.33% | Malloc-side wrapper. |
| `malloc_abi::segment_allocate` | 0.82% | Candidate allocation core. |

The benchmark's parser totals allocator frames at **48.35%**: malloc-side
**2.15%**, free-side **46.20%**. The profile therefore clears the bead's
profile-share threshold for `segment_free`, but it is single-threaded and does
not establish the bead's separate 8-thread 20/20 churn prerequisite or its
instruction-level >=80% liveness-RMW predicate.

## Same-invocation controls and incumbent arm

Every size used 41 raw samples, 12,582,912 malloc/free pairs per arm per
sample, exact interleaved ORIG/ORIG A/A controls, all six ORIG/CAND/glibc
orders, and a live host-glibc `dlmopen` arm. The scoring CPU was 3 on
`vmi1227854`; bootstrap median CIs—not CV—decide the retained-vs-candidate
maintenance comparison.

| Size | A/A median [95% CI] | CAND/ORIG median [95% CI] | CAND/glibc median [95% CI] |
| ---: | --- | --- | --- |
| 16 | 1.000333 [0.998266, 1.002772] | 0.772229 [0.764662, 0.779212] | 9.404524 [9.339418, 9.459497] |
| 64 | 0.999381 [0.997148, 1.000829] | 0.762560 [0.756653, 0.771789] | 9.523667 [9.382614, 9.556857] |
| 256 | 1.000523 [0.999344, 1.002003] | 0.763689 [0.757815, 0.771592] | 9.448935 [9.332710, 9.520579] |
| 1024 | 0.998843 [0.997906, 1.001047] | 0.750448 [0.743435, 0.758384] | 9.398820 [9.314275, 9.457944] |

All four median-CI gates passed and the candidate beat the retained original
at every size. The live incumbent ratio remains a roughly 9.4–9.5x loss; no
new campaign win is claimed because this run changes no production lever.

No value in this table is a zero measurement.  There is no `perf.data`, no
executing-ELF SHA-256, and no competitive conclusion from this attempt.

## Structural-bead next predicate

This evidence identifies `segment_free` as the first allocator lever but does
not authorize a source change. Only proceed to a liveness-map experiment after
the fixed-path eight-thread churn gate completes 20/20 **and** a matched
no-call-graph multi-threaded capture keeps at least 15% self time in
`segment_free` with at least 80% of that frame on the liveness RMW, followed by
the required equivalence proof and adversarial concurrent-double-free test.
