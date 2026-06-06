# bd-efdftu memcmp large equal-slice rejection

## Target

- Bead: `bd-efdftu`
- Scope: `crates/frankenlibc-core/src/string/mem.rs`
- Profile-backed target: `glibc_baseline_memcmp_4096`, equal N-byte buffers
- Candidate lever: for `count >= 1024`, return `Equal` immediately when the bounded prefixes compare equal via safe Rust slice equality; any non-equal case falls through to the existing ordered resolver.

## Baseline

Fresh broad RCH profile on `vmi1149989`:

| Row | FrankenLibC p50 | FrankenLibC mean | host p50 | host mean |
| --- | ---: | ---: | ---: | ---: |
| `memcpy_4096` | 30.382 ns | 31.700 ns | 26.457 ns | 28.081 ns |
| `memset_4096` | 17.698 ns | 18.788 ns | 25.919 ns | 29.510 ns |
| `memcmp_4096` | 59.390 ns | 65.808 ns | 38.750 ns | 42.295 ns |
| `memmove_4096` | 29.829 ns | 33.976 ns | 24.720 ns | 26.229 ns |
| `memchr_absent` | 22.007 ns | 23.665 ns | 17.029 ns | 19.794 ns |

Focused RCH pre-edit baseline on `vmi1227854`:

| Row | FrankenLibC p50 | FrankenLibC mean | host p50 | host mean |
| --- | ---: | ---: | ---: | ---: |
| `memcmp_16` | 3.684 ns | 5.290 ns | 1.912 ns | 3.164 ns |
| `memcmp_256` | 4.473 ns | 5.597 ns | 3.210 ns | 4.238 ns |
| `memcmp_4096` | 47.562 ns | 54.652 ns | 42.396 ns | 43.890 ns |

## Behavior Proof

Commands:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=Codex cargo test -p frankenlibc-core --lib memcmp -- --nocapture --test-threads=1
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=Codex cargo test -p frankenlibc-core --test property_tests golden_memcmp_corpus_sha256 -- --nocapture
```

Results:

- Focused memcmp/timingsafe/wmemcmp tests passed: 29 passed, 0 failed.
- `golden_memcmp_corpus_sha256` passed.
- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs` passed after formatting a concurrent `memchr` hunk.
- `git diff --check -- crates/frankenlibc-core/src/string/mem.rs` passed.

Isomorphism:

- Ordering preserved: yes. The candidate returned early only when the full bounded prefixes were equal.
- Tie-breaking unchanged: yes. Every non-equal case fell through to the existing first-difference resolver.
- Floating point: N/A.
- RNG: N/A.

## Isolated A/B

Because the main worktree gained an unrelated concurrent `memchr` hunk, the candidate post benchmark used an isolated scratch worktree with only the `memcmp` hunk applied. RCH routed the post run to `ts1`. The scratch worktree did not inherit the ignored local `Cargo.lock`, so the acceptance comparison used a clean-source run from the same scratch worktree and same `ts1` worker for a paired A/B.

Candidate on `ts1`:

| Row | Candidate FrankenLibC p50 | Candidate FrankenLibC mean | host p50 | host mean |
| --- | ---: | ---: | ---: | ---: |
| `memcmp_16` | 4.142 ns | 5.306 ns | 2.446 ns | 3.296 ns |
| `memcmp_256` | 6.413 ns | 10.690 ns | 3.488 ns | 4.493 ns |
| `memcmp_4096` | 59.669 ns | 60.512 ns | 55.155 ns | 65.632 ns |

Clean source on `ts1`:

| Row | Clean FrankenLibC p50 | Clean FrankenLibC mean | host p50 | host mean |
| --- | ---: | ---: | ---: | ---: |
| `memcmp_16` | 4.120 ns | 5.762 ns | 2.454 ns | 3.343 ns |
| `memcmp_256` | 6.132 ns | 6.879 ns | 4.338 ns | 5.467 ns |
| `memcmp_4096` | 61.626 ns | 65.381 ns | 47.050 ns | 49.166 ns |

## Verdict

Rejected and restored. The target row showed only a weak p50 improvement and the untouched `memcmp_256` guard row regressed in the paired run:

- `memcmp_4096`: 61.626 -> 59.669 ns p50, 65.381 -> 60.512 ns mean.
- `memcmp_256`: 6.132 -> 6.413 ns p50, 6.879 -> 10.690 ns mean.

Score: `(Impact 1 * Confidence 1) / Effort 1 = 1.0`.

No source was kept. The next memcmp attack should use a genuine mask-producing first-difference/rank-select resolver or another deeper primitive, not another equal-buffer certificate.
