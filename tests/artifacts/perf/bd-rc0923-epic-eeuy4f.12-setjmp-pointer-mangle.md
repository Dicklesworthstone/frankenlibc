# bd-rc0923-epic-eeuy4f.12 setjmp/longjmp pointer mangling (aarch64 + guard)

## Attempt

- Bead: `bd-rc0923-epic-eeuy4f.12` (P1 security).
- Lever: this is a SECURITY change, not an optimization. It adds glibc-style
  pointer mangling to the native non-local-jump path so a `jmp_buf` overwrite is
  no longer a direct control-flow hijack primitive. The perf question is the
  *cost* of that mangling, which the bead accepts ("a few ns ... acceptable").
- x86_64 already shipped the mangled form (commit `d5c680528`); this work adds
  the aarch64 mangling, whose guard is FrankenLibC's own AT_RANDOM-seeded
  `__frankenlibc_pointer_guard` (aarch64-only; x86_64 keeps glibc's `%fs:0x30`).

## A/B measurement (cost of mangling)

Native x86_64 microbenchmark, one `setjmp`+`longjmp` round trip per iteration,
50,000,000 iterations, interleaved mangled/unmangled runs to damp frequency
drift (`scratchpad/x86_verify/perf_x86.c` + `sj_x86.S`, a faithful standalone
copy of the shipped naked asm; guard read from the real `%fs:0x30`). The
unmangled arm is the same asm with the `xor/rol` (save) and `ror/xor` (restore)
guard ops removed.

| variant | ns / round trip (run 1) | ns / round trip (run 2) |
| --- | --- | --- |
| mangled (shipped) | 5.172 | 5.458 |
| unmangled (baseline) | 3.372 | 3.828 |
| delta (mangling cost) | 1.800 | 1.629 |

Mangling costs ~1.6–1.8 ns per `setjmp`+`longjmp` round trip (3× `xor`+`rol`
plus `%fs:0x30` reads on save, 3× `ror`+`xor` on restore). aarch64 is the same
order (3× `eor` plus one GOT-indirect guard load each side); it was exercised
only under qemu-user, which is not a representative timing environment, so the
x86_64 real-hardware delta above is the honest cost figure.

## A/B vs origin/main

- x86_64: **zero** delta vs `origin/main`. origin/main already stores
  `rol(v ^ %fs:0x30, 17)`; this change does not touch the x86_64 asm, so the
  per-call cost is unchanged. Re-verified byte-identical to glibc in strict and
  hardened (`fixture_setjmp_guard` preload corpus).
- aarch64: origin/main stored `x29`/`x30`/`sp` in plaintext (no mangling), so
  this change *adds* the ~1.7 ns-order cost on aarch64 in exchange for closing
  the hijack primitive. Measured functional behaviour (round trips, inspection,
  negative, planted negative) under qemu-user; see the bead comment.

## Proof Shape

- Ordering preserved: N/A (no data structure ordering changes).
- Floating-point: N/A.
- RNG seeds: the guard is per-process random from `AT_RANDOM`; demangling uses
  the same guard, so round trips are exact.
- Safety: no new allocation, no new host calls on the hot path; the added work
  is register arithmetic plus (aarch64) one cold GOT load per call.

## Guard (regression pins)

- `tests/integration/fixture_setjmp_guard.c` (x86_64, byte-compared to glibc):
  `rsp_plaintext=0 rsp_demangles=1 rip_demangles_into_main=1 guard_nonzero=1`,
  `overwritten_rip_signaled=1`, `chk_returned_frame=SIGABRT`.
- `tests/integration/fixture_setjmp_edges.c` (aarch64, under FrankenLibC
  preload): saved sp/pc are mangled and demangle correctly; an overwritten
  saved return address faults instead of branching to the attacker address.
