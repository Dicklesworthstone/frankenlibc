# bd-spo1lu pass181 memchr_absent mask-fold rejection

Date: 2026-06-17
Agent: BoldFalcon
Mode: local fallback, `RCH_REQUIRE_REMOTE=0` because `ts1`/remote RCH is offline
Commit base: `fbc7a40a8` (`perf(string): reuse strlen for exact strcpy4096`)

Note: this artifact filename was created before the remote pass180 routing commit
(`bd-2g7oyh.464`) landed. The progress log records this as pass181 after
rebasing on top of that remote routing pass.

## Target

Current-head local routing after the pass179 `strcpy_4096` keep ranked
`glibc_baseline_memchr_absent` as the largest host gap:

| row | FrankenLibC p50 / mean | host p50 / mean |
| --- | ---: | ---: |
| broad profile | `30.042 / 33.165 ns` | `19.822 / 24.241 ns` |

Broad profile log SHA-256:

`89a8623d4c079bdef9a6187285a14f60a38735610fe8110e92e35b21ab36181b`

Focused local gate reproduced the residual:

| impl | Criterion interval | p50 | mean |
| --- | ---: | ---: | ---: |
| FrankenLibC | `[31.533 ns 32.254 ns 33.028 ns]` | `32.270 ns` | `34.202 ns` |
| host glibc | `[19.659 ns 20.112 ns 20.583 ns]` | `19.084 ns` | `20.188 ns` |

Focused baseline log SHA-256:

`0737b628c5da3547d699b63327572a04f70eede684d7f31f5bcb922ca2810400`

## No-Repeat Context

Recent `memchr_absent` passes already ruled out folded-panel widening,
exact-4096 dispatch, slice `contains` certificates, loop/tail rearrangement,
SWAR word-group scans, rank/select extraction, indexed folded scans, wrapper
inlining, and hot/cold outlining. Pass178 also showed the current source lowers
through 16-byte SSE panels locally and that safe per-function target-feature
dispatch is not admissible in `frankenlibc-core` without unsafe calls.

## Candidate

Replace the folded absence certificate in `has_byte_memchr_folded` with explicit
64-lane `to_bitmask()` extraction for each 64-byte panel, then OR the four masks
in scalar space. This keeps the same 256-byte block size, same panel order, same
first-hit resolver, and same safe portable-SIMD API, but targets the previous
backend finding about aggregate mask reductions.

## Post Benchmark

| impl | Criterion interval | p50 | mean |
| --- | ---: | ---: | ---: |
| FrankenLibC candidate | `[31.613 ns 32.390 ns 33.257 ns]` | `31.202 ns` | `33.292 ns` |
| host glibc | `[20.297 ns 20.896 ns 21.633 ns]` | `19.947 ns` | `21.571 ns` |

Post log SHA-256:

`2fe7086331ca976b7eca8da9d9a4657aa7c415b46653b886705d8b5ecec296af`

The custom p50/mean moved slightly, but Criterion's own interval did not
improve (`31.533-33.028 ns` baseline vs `31.613-33.257 ns` post). This is not a
credible keep under the Score `>= 2.0` rule.

## Behavior Proof

The candidate was behavior-isomorphic while present:

- first-match ordering remained low-to-high;
- absent scans still returned `None`;
- `n` remained clamped to `haystack.len()`;
- reads stayed inside `haystack[..count]`;
- block size, panel order, positive-hit resolver, and tail paths were unchanged;
- `memrchr`, substring search callers, allocation state, errno, locale, FP
  state, and RNG state were unchanged.

The source patch was rejected and manually restored. `git diff --exit-code --
crates/frankenlibc-core/src/string/mem.rs` passed after restoration, so current
behavior is identity with the base commit.

## Verdict

Rejected, Score `0.0`. Do not retry explicit folded mask-OR for
`memchr_absent`. The next `memchr` attempt needs a fundamentally different
backend/generated-dispatch primitive, not another source-level folded-mask
retune.
