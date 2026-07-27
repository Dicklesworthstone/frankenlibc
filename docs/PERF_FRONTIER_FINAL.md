# Current Performance Evidence (2026-07-27)

This public summary contains current measured claims. Detailed experiment records, rejected
mechanisms, and retry predicates live in `NEGATIVE_EVIDENCE.md` and `LEDGER_RESURRECTION.md`.

## Evidence classes

- A **campaign win** is FrankenLibC versus the actual host-glibc incumbent, run side-by-side in the
  same invocation. The host arm must be protected from symbol interposition and the incumbent ratio
  must clear the bootstrap median-CI/null-control gate.
- A **maintenance self-speedup** is FrankenLibC before versus FrankenLibC after. It can justify a
  code change, but it is not a competitive claim or campaign output.

## Campaign wins

Both incumbent arms below resolve `libc.so.6` through `dlmopen(LM_ID_NEWLM)`, run in the same
invocation as FrankenLibC, and are paired with a source-identical A/A null.

| Surface | Commit | FrankenLibC / host glibc median | 95% bootstrap median CI | Current latency |
|---|---|---:|---:|---:|
| exact C-locale `strftime("%A")` | `ac74b07bc` | **0.540615** | **[0.537130, 0.549644]** | 8.41 ns vs 15.49 ns |
| exact C-locale `%FT%T` `wcsftime` alias | `3c03993b1` | **0.111264** | **[0.106929, 0.116409]** | 17.10 ns vs 152.55 ns |

The `strftime` differential compared 200,000 cases with zero divergences. The `wcsftime` gate
combined focused exact-fit coverage, 11 live-glibc conformance cases, and a 200,000-case
differential with zero divergences.

## Maintenance self-speedups

| Surface | Commit | FrankenLibC before / after | Incumbent status |
|---|---|---:|---|
| FFI-PCC gate hot/cold split on malloc/free | `7c9d0d8c2` | **0.9463** | current paired FrankenLibC / glibc median **10.010** |
| append-only publication for `textdomain(NULL)` | `8320a0b4a` | **0.228** (11.32 ns to 2.58 ns) | current FrankenLibC / glibc median **1.192201** |
| allocation-free in-memory hosts scanner | `3aedb3f69` | **0.428468**, CI **[0.411170, 0.444882]** | no legacy-incumbent arm; isolated mechanism evidence |

These maintenance rows are not competitive claims.

## Current allocator attribution

A matched no-call-graph profile attributes **30.28%** of process self-time to
membrane/runtime-policy framing and **33.96%** to allocator data structures.
`segment_free` is the largest production allocator frame at **22.85%**.
