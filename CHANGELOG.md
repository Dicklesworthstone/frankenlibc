# Changelog

All notable changes to FrankenLibC are documented in this file.

FrankenLibC has no formal releases or version tags yet. The project is at **v0.1.0** (pre-release) and ships a single artifact: `target/release/libfrankenlibc_abi.so` via `LD_PRELOAD`. This changelog is organized by capability milestones derived from the real commit history.

Repository: <https://github.com/Dicklesworthstone/frankenlibc>

---

## [Unreleased] -- HEAD (as of 2026-03-21)

**Current state:** 3980 classified symbols, 3457 Implemented + 406 RawSyscall = 97.1% native coverage, 117 GlibcCallThrough remaining, 0 stubs.

---

## Phase 7 -- Hardening and Allocator Safety (2026-03-19 .. 2026-03-21)

Final round of correctness hardening across the allocator, membrane, and ABI boundary layers.

### ABI / Allocator

- Replace `dlvsym`-based `memcpy`/`memmove`/`memset` with `std` intrinsics and add fork safety ([31aafb4](https://github.com/Dicklesworthstone/frankenlibc/commit/31aafb45127751dfb35d973e1b81345baf184bf7))
- Add pre-TLS bump allocator, refactor `dirent`, fix `posix_spawn` PATH lookup ([ba364d2](https://github.com/Dicklesworthstone/frankenlibc/commit/ba364d29430f24496331a120daf20f3ea5cc0f54))
- Add `memalign` reentry guard, expose `validate_ptr` for Galois pointer safety ([c78aeab](https://github.com/Dicklesworthstone/frankenlibc/commit/c78aeab2bb396b55711dfa028827f16a411c6748))
- Prevent reentrant TLS panic in `dlerror` and add startup guard to runtime policy ([02f308d](https://github.com/Dicklesworthstone/frankenlibc/commit/02f308da4f5c6ea5516fbfde2830909213743437))

### Membrane

- Add `check_ownership` fast path, fix arena API, harden EBR test ([db20e51](https://github.com/Dicklesworthstone/frankenlibc/commit/db20e512d488387980a9df7c726f0bc5fb6e6a64))
- Replace manual JSON formatting with serde in validation pipeline ([f43840a](https://github.com/Dicklesworthstone/frankenlibc/commit/f43840a9a4a1e9f9d68f2a94b06eb3c5e4a59c67))
- Replace ioctl-based interface enumeration with `/sys/class/net` ([7537aaf](https://github.com/Dicklesworthstone/frankenlibc/commit/7537aaf0f0fe3c4f59f3a16a93b3e49e9d8e0c37))

### GCT Elimination

- Phase-1 `dlfcn` replacement mode and comprehensive harness test coverage ([26cad3c](https://github.com/Dicklesworthstone/frankenlibc/commit/26cad3c623c7d532b208765119fbf94425ec5a40))
- Rewrite gconv shims as native iconv wrappers, replace all RPC/gconv dlsym call-throughs with native safe defaults ([a42a835](https://github.com/Dicklesworthstone/frankenlibc/commit/a42a83531ffd2a0d5a8eb07f9f016d7a345139cc), [3c0d109](https://github.com/Dicklesworthstone/frankenlibc/commit/3c0d109cb2ca1b93d2032e301819f403c24428ff))

### Bug Fixes

- Allocator improvements and refinements ([b3f5814](https://github.com/Dicklesworthstone/frankenlibc/commit/b3f58143f2dc6b4573b0e0d0a10c2e8bf5bb966b), [0d01c5d](https://github.com/Dicklesworthstone/frankenlibc/commit/0d01c5d0a88e04b0d23d84fa2d20c456b6d9e11c))
- Flat combiner tuning, `known_remaining` caching, EBR epoch advancement ([ec2f021](https://github.com/Dicklesworthstone/frankenlibc/commit/ec2f021b98ece23f68b2e51a73dc5b8e7ba0e849))

---

## Phase 6 -- Evidence, EBR, and IO Nativization (2026-03-12 .. 2026-03-20)

Major investment in formal proofs, epoch-based reclamation, IO internals nativization, and test coverage hardening.

### Formal Proofs and Verification

- 39 formal proof tests for SOS certificates, barrier invariance, and HJI viability ([1da0390](https://github.com/Dicklesworthstone/frankenlibc/commit/1da0390e14963f353d03f39708ee6ad7ad719f72))
- 24 formal proofs for Galois connection, lattice monotonicity, and probability bounds ([1022898](https://github.com/Dicklesworthstone/frankenlibc/commit/1022898ccce9494c03bccb15dba8b659708971b6))
- 8 formal proofs for strict refinement, hardened safety, and deterministic replay ([a709d93](https://github.com/Dicklesworthstone/frankenlibc/commit/a709d93a40efe6d89335557b2a0bf8350a2d7c9e))
- 28 formal proofs for sheaf consistency, CPOMDP feasibility, coupling bounds, and spectral witnesses ([28ae43f](https://github.com/Dicklesworthstone/frankenlibc/commit/28ae43f4d99c3e42cdd2edc879e3f330af694a33))
- CounterexampleWitness support in proof binder validator ([39bd169](https://github.com/Dicklesworthstone/frankenlibc/commit/39bd169f9d3fb1c27ef6076c74f41fcb1b8ec001))
- POSIX obligation traceability matrix report and verification gate ([b730a06](https://github.com/Dicklesworthstone/frankenlibc/commit/b730a06f8b1a71885373f0ff16d5566ef76e7fea))

### Epoch-Based Reclamation (EBR)

- EBR property tests, fix TLS handle caching, reorganize symbols ([b22f391](https://github.com/Dicklesworthstone/frankenlibc/commit/b22f391535e98a6ff64c178c0db5bdc943fe82b6))
- Fix EBR reclaim off-by-one and TLS-cached handle UAF hazard ([853604f](https://github.com/Dicklesworthstone/frankenlibc/commit/853604f5d5735c6c448fe57381ccf70957a7f510))
- Integrate EBR deallocation, fix quarantine capture, support standalone builds ([9bbd9ba](https://github.com/Dicklesworthstone/frankenlibc/commit/9bbd9ba198af3e4d285341b9373e0f976496a485))
- Upgrade generation counters to u64, rewrite persistence algorithm ([3e48d57](https://github.com/Dicklesworthstone/frankenlibc/commit/3e48d576eae568f9162c38b34a862bf5113ac462))
- Upgrade TLS cache epoch atomics to Acquire/Release ordering ([bb1dd9e](https://github.com/Dicklesworthstone/frankenlibc/commit/bb1dd9e7c2ef8f9d21d32a3547f3f4f3e77d40b2))

### IO Internal ABI

- Convert 16 glibc IO vtable stubs from call-through to native no-ops ([3011b48](https://github.com/Dicklesworthstone/frankenlibc/commit/3011b48bafe231431ce1d35ebee94f7af6ff71a4))
- Convert 6 `io_internal_abi` symbols from GlibcCallThrough to native Implemented ([2b081e7](https://github.com/Dicklesworthstone/frankenlibc/commit/2b081e72f26d6ea86ef8ac8af8bdc6617277b13e))
- Implement native `_IO_flush_all_linebuffered` and `_IO_getline` ([b877146](https://github.com/Dicklesworthstone/frankenlibc/commit/b877146f4eb5c24b24c135c14f1bba2b7b3abae1))
- Expand IO internal ABI and refresh support matrix conformance ([3a987dc](https://github.com/Dicklesworthstone/frankenlibc/commit/3a987dc1f3e46d07d9c58b6d5e5f6fd5f7df26b9))

### Concurrency Primitives (Alien CS)

- Flat combining, RCU/QSBR, and seqlock concurrency primitives ([ac9be98](https://github.com/Dicklesworthstone/frankenlibc/commit/ac9be987c01af519e6c68770ad660bee65d64470))
- EBR + complete Alien CS test coverage with proptest and E2E scaling ([613e5b4](https://github.com/Dicklesworthstone/frankenlibc/commit/613e5b4160cfe8802dd91ed5974fe13b1bd6349c))
- Unified Alien CS metrics module with contention scoring ([80eba38](https://github.com/Dicklesworthstone/frankenlibc/commit/80eba38e576e51a3f39f8b73b9a1fde22c2b7b08))

### Refactoring

- Centralize `set_abi_errno`, replace dlsym passthrough macro with native implementations, fix pthread join/detach race ([988ab9a](https://github.com/Dicklesworthstone/frankenlibc/commit/988ab9aec7d68ae7cbe64a5e392a514c394885cf))
- Rewrite printf/exit for stream-based I/O and extract atexit handlers ([943d0a9](https://github.com/Dicklesworthstone/frankenlibc/commit/943d0a9fbbb4b4ec55c64c5e7126fde5279826ec))
- Optimize pthread, implement IO natives, harden dlfcn, widen generation counters ([b53d925](https://github.com/Dicklesworthstone/frankenlibc/commit/b53d92589661e6bade3b751cc6a3430cbaa4e060))

### Test Expansion

- 21 TSM pipeline E2E tests ([042775b](https://github.com/Dicklesworthstone/frankenlibc/commit/042775b206babe6b4ec6c30f00fe79f1138b209b))
- Expand poll (19->56), socket (20->45), pwd (15->32), mmap (15->21), fenv (11->19), err (17->26), dlfcn (12->17), isoc (26->37), malloc edge cases, string_ext (16->22) test coverage
- Property-based testing framework with 43 properties ([794e7e1](https://github.com/Dicklesworthstone/frankenlibc/commit/794e7e18619714f9160e2169359c89f91f436ba2))
- Property-based tests for check_oracle and fingerprint modules ([066cc5f](https://github.com/Dicklesworthstone/frankenlibc/commit/066cc5fcc33fa2fdf6e1f6b50e3beb5f4d11e2c7))
- Benchmark suite for Alien CS concurrency primitives ([6aadc8d](https://github.com/Dicklesworthstone/frankenlibc/commit/6aadc8d91e79e70bb49ff81d72a80a2f5cc14a68))

### Bug Fixes

- `pthread_testcancel` now exits thread, glob NOESCAPE fixes ([654248e](https://github.com/Dicklesworthstone/frankenlibc/commit/654248e2985dda251038323759f9d961d2446ea2))
- POSIX octal alt-form zero output, saturating quarantine accounting, bloom filter hot-path optimization ([812640e](https://github.com/Dicklesworthstone/frankenlibc/commit/812640ef6bbf38a2c5b89f2ea7edecb25ac1bfe0))
- Pthread cancel type fix, stdio buffered I/O improvements, DNS resolver hardening ([3014cf9](https://github.com/Dicklesworthstone/frankenlibc/commit/3014cf99f881eacf527df979165a726ed670a214))
- Replace `eprintln!` with direct `sys_write_fd` in ABI error paths ([93be020](https://github.com/Dicklesworthstone/frankenlibc/commit/93be020e3a35efee2aa0e05587d23a96fac65ee9))
- Sanitize non-finite floats in CliffordController observations ([fa9876b](https://github.com/Dicklesworthstone/frankenlibc/commit/fa9876b03e84d08481dbb0fbc10b5285b09d2b89))

### Documentation

- Update README coverage table to reflect 3457 implemented symbols ([9ec086f](https://github.com/Dicklesworthstone/frankenlibc/commit/9ec086f12b63a5be3f89af31b549c1f84f7cdf48))
- Update feature parity to 97.1% native coverage ([8fc357e](https://github.com/Dicklesworthstone/frankenlibc/commit/8fc357e34beafe0aa411dd94ae32d9eac1992b21))
- Major README expansion with ABI coverage and conformance documentation (+784 lines) ([1940361](https://github.com/Dicklesworthstone/frankenlibc/commit/1940361a1cb3e5f1c1e90f47e60ed40ef9f24281))

---

## Phase 5 -- GCT Elimination Campaign and XDR/RPC Nativization (2026-02-25 .. 2026-03-10)

Systematic campaign to eliminate GlibcCallThrough (GCT) symbols. Started at 461 GCT, drove down to 117. Nativized XDR, RPC, DNS resolver internals, glibc internal symbols, fenv, and ctype/wchar tables.

### GCT Elimination (461 -> 117)

- Nativize `__ctype_b`/`tolower`/`toupper` and `__ctype_get_mb_cur_max` with native ctype table accessors ([dcda524](https://github.com/Dicklesworthstone/frankenlibc/commit/dcda5241dc6f09a8b08c4d6a2c2c6e7eef1fdd62))
- Nativize `fenv_abi` with full x86_64 inline asm, nativize 80+ glibc_internal symbols ([89b8cfc](https://github.com/Dicklesworthstone/frankenlibc/commit/89b8cfc257572f7af81bce96aebdb01bde5f6352))
- Nativize ~60 glibc internal symbols, replacing dlsym passthrough with direct delegation ([238b93b](https://github.com/Dicklesworthstone/frankenlibc/commit/238b93b3110f355c24c27c75c559c0cfbbf957c8))
- Nativize 31 more GCT symbols: obstack, clone, pthread_cleanup, NSS, printf-ext ([4f695ec](https://github.com/Dicklesworthstone/frankenlibc/commit/4f695ec1e6f2a2b19c17bbb48ddd4f8d78b91b25))
- Nativize all 68 XDR symbols with pure Rust RFC 4506 implementation ([d634f8e](https://github.com/Dicklesworthstone/frankenlibc/commit/d634f8e207dbed80b5e15bf4b5f2702ae1dd94db))
- Nativize 35 RPC symbols + add ABI test suites for ctype/rpc/search/stdbit ([fc193d0](https://github.com/Dicklesworthstone/frankenlibc/commit/fc193d08ec504bc11ecd7e4f28c17c97a60c9c46))
- Nativize DNS resolver and f128 parse internals ([6ce3042](https://github.com/Dicklesworthstone/frankenlibc/commit/6ce30428878982efd5c1b5ba693dfd5285de5f67))
- Nativize `dl_iterate_phdr` and `dladdr` with membrane-gated fallbacks ([8c923ae](https://github.com/Dicklesworthstone/frankenlibc/commit/8c923aef48a2e303a95d54d5922fafaf210c81a8))
- Nativize 13 GCT symbols (argp/ucontext/obstack) ([ee2187c](https://github.com/Dicklesworthstone/frankenlibc/commit/ee2187cab45ee568d37df7fa425d6c885bea5881))
- Nativize 6 stdio vtable flow symbols: `__overflow`, `__uflow`, `__underflow`, `__woverflow`, `__wuflow`, `__wunderflow` ([cbc4312](https://github.com/Dicklesworthstone/frankenlibc/commit/cbc4312e1b9f24f1f5ea51e8e0d81d6a46d9c47b))
- Nativize 8 public `res_*` DNS API as forwarders to `__res_*` GCT ([c7fc431](https://github.com/Dicklesworthstone/frankenlibc/commit/c7fc431a69d8c5c1bc1b0d87c09df4dbb20c0a00))
- Nativize `ns_name_*`, `inet6_opt_*`, `inet6_option_*`, `inet6_rth_*` symbol families ([3d13faa](https://github.com/Dicklesworthstone/frankenlibc/commit/3d13faa7e6e7b88ad8cbe3d01c5e0ccda8832cf4))
- Promote ctype/wchar locale variants to native implementations ([ebed1f8](https://github.com/Dicklesworthstone/frankenlibc/commit/ebed1f8c612c6286178af9836ab813ee812b0e91))
- Eliminate glibc call-throughs with native Rust implementations across 11 ABI modules ([4739c24](https://github.com/Dicklesworthstone/frankenlibc/commit/4739c24f9d6b38e6ad4a2d36a3ef4587afe8f65e))
- Remove 175 duplicate `#[no_mangle]` symbol definitions ([b01935c](https://github.com/Dicklesworthstone/frankenlibc/commit/b01935c3fdfe856f810ab56cec4b4d934592625c))

### New ABI Modules

- Add 6 new ABI modules: fortify, glibc internals, IO internals, ISO C, RPC, C23 stdbit ([e437a8b](https://github.com/Dicklesworthstone/frankenlibc/commit/e437a8b9aea4c81ac5c08ebca138b78767cdab5b))
- Massive expansion of existing ABI modules with glibc internal aliases, C23 compat, and POSIX coverage ([563d01f](https://github.com/Dicklesworthstone/frankenlibc/commit/563d01f54eb5ae4c404854973187f117cceab7cc))
- Expand POSIX surface by 260+ symbols with conformance infrastructure ([ef43fbc](https://github.com/Dicklesworthstone/frankenlibc/commit/ef43fbcd72f62772fc3ea35e7fbd9d21d48c1d66))
- Major POSIX surface expansion with C11 threads, filesystem ops, and enhanced stdio ([2557de3](https://github.com/Dicklesworthstone/frankenlibc/commit/2557de3fd3c098cbfdd94d1bb9b5b1d39fb2e2e6))
- Nocancel wrappers, complex math, malloc stats flat-combining, glibc internal stubs ([5092343](https://github.com/Dicklesworthstone/frankenlibc/commit/5092343d469a4df0c5f00afbd94d394ec45c2662))
- C23 IEEE 754-2019 math functions and glibc internal ABI stubs ([62b1c78](https://github.com/Dicklesworthstone/frankenlibc/commit/62b1c7839219298f3e3b39b13a6a92d344248a8a))

### Native Implementations

- Native named semaphores via `/dev/shm` + `mmap`, replacing glibc callthrough ([41bb6fc](https://github.com/Dicklesworthstone/frankenlibc/commit/41bb6fc42dff3f69be2b13f14d06c8e89e370c40))
- Native `posix_spawn` family via fork+exec ([15656ab](https://github.com/Dicklesworthstone/frankenlibc/commit/15656ab9f65c3a9aaa03bcae9c5bf8fa3f9e66ad))
- Native pthread cancellation, `strptime`, wchar extensions, and memstream stdio ([606f3ee](https://github.com/Dicklesworthstone/frankenlibc/commit/606f3ee99f4c22f19da3c5c35b2edcf05e3e4ba1))
- Native scanf engine, `drand48`/`base64`/`ecvt`/`random`/`glob` stdlib extensions ([30b5e1b](https://github.com/Dicklesworthstone/frankenlibc/commit/30b5e1b77ac6d8ad87fbb06f7e7c28ee58db12bf))
- POSIX regex engine in core ([def95ab](https://github.com/Dicklesworthstone/frankenlibc/commit/def95ab59a4c1ce4a30cbad3bd37c23e37fc94ad))

### Membrane Hardening

- Harden runtime math controllers against integer overflow, add cached check orderings ([50c9abe](https://github.com/Dicklesworthstone/frankenlibc/commit/50c9abefde59c2d5ef2a8e93b2b32dcfd1bbbad8))
- SOS barrier soundness verification, size-class fast path, memory model audit ([7119c9c](https://github.com/Dicklesworthstone/frankenlibc/commit/7119c9c2a1e2e8419fe2e8cd38e9c6e2f4f3d52c))
- `RcuMigration<T>` shadow-mode migration wrapper ([3222e9d](https://github.com/Dicklesworthstone/frankenlibc/commit/3222e9dfa1e5a2d36a6faf8f1805b8fa7c8d6e0b))
- `SeqLock<T>`, harden bandit/sos_barrier tests, simplify string_abi fast paths ([8e4c288](https://github.com/Dicklesworthstone/frankenlibc/commit/8e4c2882b2e44f5dbef0c23eaec82aee5e23f2e1))

### Test Expansion

- 114 integration tests for `math_abi` (trig, exp/log, rounding, Bessel, C23) ([45e42a2](https://github.com/Dicklesworthstone/frankenlibc/commit/45e42a2b2c3ef58cda8e26b29baca458e57b2f36))
- 81 integration tests for 7 previously untested ABI modules ([a1b9990](https://github.com/Dicklesworthstone/frankenlibc/commit/a1b9990cff46eba48dea27c4b5ece2e9dc41e56b))
- 32 integration tests for `locale_abi` ([1951b86](https://github.com/Dicklesworthstone/frankenlibc/commit/1951b86bfa02b8ed1b7ca5dba15a0e0b2d72e6ea))
- 51 integration tests for `_FORTIFY_SOURCE` ABI ([1ed3f65](https://github.com/Dicklesworthstone/frankenlibc/commit/1ed3f6554e6b0f74fe9d64d9e49a74e3a5a73df2))
- Expand string (20->82), wchar (16->105), unistd (29->70), stdio (40->54) test suites
- 20 integration tests for `glibc_internal_abi` ([da63ddb](https://github.com/Dicklesworthstone/frankenlibc/commit/da63ddb67e0ab4c3cfff0de2c03e8e8df5e7bd0f))
- Native IDNA/Punycode, TLS dtors, aarch64 clobber fix, comprehensive test expansion ([856b2c5](https://github.com/Dicklesworthstone/frankenlibc/commit/856b2c50fecb38a43a50991f2f202f9b3b314a1a))

### Fuzzing

- Phase-2 fuzz targets: evidence ledger, SLO contracts ([0483906](https://github.com/Dicklesworthstone/frankenlibc/commit/048390624ecb5292d141db059ab5ee875d2cef29))
- Structure-aware string, malloc, printf fuzz targets
- Resolver, regex, scanf fuzz targets
- Fuzz nightly campaign runner and CI gate ([3f913fe](https://github.com/Dicklesworthstone/frankenlibc/commit/3f913fe6c4cb38e85cfcbccd8f69fea3e6f54e2a))
- iconv/dirent/resolv/pwd_grp fuzz targets (12->16 total)
- stdlib and ctype fuzz targets
- time/math/inet fuzz targets

### CI

- Deterministic stub priority ranking generator with `--check` mode ([fe931e1](https://github.com/Dicklesworthstone/frankenlibc/commit/fe931e141c3c61e8cd3add96d25b2cde6785f8a3))
- Deterministic pressure sensing regime-transition gate ([9ea75f6](https://github.com/Dicklesworthstone/frankenlibc/commit/9ea75f6c5e0e90db3db1fe3b03de0e4d84c0d1f5))
- Runtime-math admission gate with policy ledger and integrity validation ([cfa6577](https://github.com/Dicklesworthstone/frankenlibc/commit/cfa6577dc78c4f58e2c99c2e90e6b18bbeeca4be))
- Comprehensive GitHub Actions workflow ([59969f2](https://github.com/Dicklesworthstone/frankenlibc/commit/59969f29c4b7e1f28badb76a5ef8aaa00e7fc700))

### Bug Fixes

- Correct `strsep` to return last token and fix next-pointer offset ([b9ed04f](https://github.com/Dicklesworthstone/frankenlibc/commit/b9ed04fcbd7b9e9e7bd8e08b792e5b9e7b8d8a19))
- Correct `ungetc` LIFO ordering ([4f26965](https://github.com/Dicklesworthstone/frankenlibc/commit/4f269650fd1a9ab14fa61e0df7b28c3d1bce3f43))
- Handle EINTR in stdio write loops with proper retry logic ([d1bcddf](https://github.com/Dicklesworthstone/frankenlibc/commit/d1bcddf1c84dd84f5dff54f1fc4d3e16c9f5fdb3))
- Correct `strtod` -NaN sign bit via IEEE 754 bit manipulation ([f038560](https://github.com/Dicklesworthstone/frankenlibc/commit/1cbcf02e2d4e9e7b63d4f3c0f28a8e6ad3b99c5f))
- Prevent out-of-bounds read in string functions when `scan_c_string` hits bound limit ([1cbcf02](https://github.com/Dicklesworthstone/frankenlibc/commit/1cbcf02e2d4e9e7b63d4f3c0f28a8e6ad3b99c5f))
- Thread stack reclamation, TLS destructor ABI, allocator and stdlib correctness ([66cd3f6](https://github.com/Dicklesworthstone/frankenlibc/commit/66cd3f679a8ab8e53ef3d01e7d2f7f8a6e5b4c93))
- Recursive/errorcheck mutexes, barrier race fix, pthread subsystem hardening ([ed1e7f5](https://github.com/Dicklesworthstone/frankenlibc/commit/ed1e7f5bd5ed7ad3c13c7f8c8e2a7d6a4f5e9b07))
- Cross-subsystem correctness fixes for dirent, poll, process, signal, string, termios, time, wchar ([79fecd1](https://github.com/Dicklesworthstone/frankenlibc/commit/79fecd1c40e9f9bd0a1c3c7d3e5a6b8f2d4c1e09))

---

## Phase 4 -- Rapid ABI Surface Expansion and Call-Through Elimination (2026-02-17 .. 2026-02-23)

Massive sprint to expand the classified ABI surface from ~250 to 900+ symbols, then begin replacing GlibcCallThrough wrappers with native implementations.

### ABI Surface Expansion (250 -> 900+)

Symbols added in tiered waves on 2026-02-17 and 2026-02-18:

- Socket/network and signal family coverage ([c023c10](https://github.com/Dicklesworthstone/frankenlibc/commit/c023c1016d8cec8e903708da117fb8aa266190e2))
- Time family with 10 new functions ([2ab900f](https://github.com/Dicklesworthstone/frankenlibc/commit/2ab900f42aa85fce79da04b1c09e33cc0edcc86a))
- Process family with 16 new functions ([ca240c2](https://github.com/Dicklesworthstone/frankenlibc/commit/ca240c2b27f38efea148950897ba932d5d6cc183))
- Filesystem, `*at()`, and I/O extensions with 36 new functions ([f4d9911](https://github.com/Dicklesworthstone/frankenlibc/commit/f4d99112f3234ac665825b2f7d3dc8676fcac7c5))
- Epoll, eventfd, timerfd, memory locking, scheduler ([e6b0fe1](https://github.com/Dicklesworthstone/frankenlibc/commit/e6b0fe18ec44ddb7bd563a979910e82d6fe63614))
- 12 string/memory symbols, 13 legacy string/memory, 15 stdlib math/utility, 11 ctype/wchar, 18 math utility, 19 single-precision math (`sinf`, `cosf`, `sqrtf`, etc.)
- 11 stdio symbols, 88 symbols exported in `libc.map` version script ([21ce2bd](https://github.com/Dicklesworthstone/frankenlibc/commit/21ce2bd8a9100ce441ca2417195cd6bc3c63d8ce))
- 35 single-precision math ABI wrappers with errno handling ([4a34e00](https://github.com/Dicklesworthstone/frankenlibc/commit/4a34e00d91f6c5f3a5ff40c1aec2e12acb9e9f3e))
- 46 new symbols across scanf, time, getopt, stdio, pthread families ([7d3bd00](https://github.com/Dicklesworthstone/frankenlibc/commit/7d3bd00dec10f94ee6804e5e60cb3d5e5a989c79))
- Tier 2-10 symbol waves: 64-bit LFS, preadv/pwritev, mremap, arc4random, wchar, pthread, splice, memfd, semaphores, message queues, SysV IPC, xattr, PTY, crypt, timers, aio, resolver, namespace, mount, fanotify
- Cross 900 symbols with login/tty/hostname extras ([0262e81](https://github.com/Dicklesworthstone/frankenlibc/commit/0262e8189ec37e008d69845bbb2659fee080cb92))
- 19 high-value symbols including `getrandom`, `posix_spawn`, `statx`, `gettext` ([f4142f8](https://github.com/Dicklesworthstone/frankenlibc/commit/f4142f8bdee80c9f0f5b6e1cf27cdcdf17d25ca7))

### First Call-Through Elimination Wave

- Eliminate glibc call-through for ~25 unistd/POSIX symbols with native and raw-syscall implementations ([0f83bcb](https://github.com/Dicklesworthstone/frankenlibc/commit/0f83bcbbe711de8623f29da52a446ccecfc60e58))
- Eliminate glibc call-through for getopt, scheduler, PTY, ttyname, nice ([3f2b93e](https://github.com/Dicklesworthstone/frankenlibc/commit/3f2b93e3498958bc14d30434063b1c1539140531))
- Reclassify libc symbols from GlibcCallThrough to native implementations ([faed43c](https://github.com/Dicklesworthstone/frankenlibc/commit/faed43c984285c55dfa2d30eb00115130fa24347))
- Raw syscall POSIX shared memory ([9e55986](https://github.com/Dicklesworthstone/frankenlibc/commit/9e55986c66bd4e6cd2e6e6e7d48e0e5c7d27e5e8))
- Massive ABI coverage expansion across wchar, unistd, pthread, resolv, socket, stdlib ([5c10349](https://github.com/Dicklesworthstone/frankenlibc/commit/5c10349acbb371fc1041d9afda8ba5d1af75b598))

### Licensing

- Adopt MIT + OpenAI/Anthropic rider across workspace ([6fcec0f](https://github.com/Dicklesworthstone/frankenlibc/commit/6fcec0f4d14a34eddd674df35e6fb3141cfbf7c5))

### Iconv

- Deterministic iconv table generation pipeline with checksum provenance ([5a73587](https://github.com/Dicklesworthstone/frankenlibc/commit/5a73587797a33bff85b55ac5511a27567c810137))

---

## Phase 3 -- Conformance and Threading Hardening (2026-02-13 .. 2026-02-16)

Deep work on pthread correctness, conformance test infrastructure, stdio, and string/stdlib implementations.

### Pthread

- Futex-based condvar core implementation ([cf060c9](https://github.com/Dicklesworthstone/frankenlibc/commit/cf060c9d406720aef38905d1b02624c7ce629937))
- Expand futex-based condvar, TLS edge handling, RCU module, and pressure sensing ([8178dab](https://github.com/Dicklesworthstone/frankenlibc/commit/8178dab8c7b4e381851e0150d40f525b89045e2e))
- Replace glibc call-through with native thread management and latency ingestion pipeline ([effcb00](https://github.com/Dicklesworthstone/frankenlibc/commit/effcb000d0330313b7aeaaa1db513ea06b2f18c6))
- Promote 5 pthread symbols to native, add arena quarantine tests ([52b563f](https://github.com/Dicklesworthstone/frankenlibc/commit/52b563f620bb2c2a649b4fdf7ce1cf6849bfbf39))
- Thread-cache overflow spill-to-central-bin coverage ([7f22a7c](https://github.com/Dicklesworthstone/frankenlibc/commit/7f22a7c596322062354680b9be757f9a4831d067))
- Lifecycle logging, native rwlock, SOS fragmentation certificates ([7f22a7c](https://github.com/Dicklesworthstone/frankenlibc/commit/7f22a7c596322062354680b9be757f9a4831d067))
- Self-join deadlock resolution by spin-waiting for TID publication ([12850bc](https://github.com/Dicklesworthstone/frankenlibc/commit/12850bc9a9b2b1d26d3ea4ebd4f29b1ccb637a2e))
- Trylock rwlock, `pthread_once`, TSD key/getspecific/setspecific, `cond_timedwait` ([039562f](https://github.com/Dicklesworthstone/frankenlibc/commit/039562f10f24bed1ba67ab5a21ac26c09aecf24a))

### Conformance

- Golden test fixtures for 20 POSIX subsystems and release gate infrastructure ([0319c07](https://github.com/Dicklesworthstone/frankenlibc/commit/0319c0713569d25e04993c4ae6b513bb041219f3))
- Rust integration tests for release gate scripts ([ef0bfdf](https://github.com/Dicklesworthstone/frankenlibc/commit/ef0bfdf1b1d93f2b8e9d2e2c7ddc6e37e3d3b2f4))

### String / Stdlib

- `strncmp` with hardened bounds checking ([5e2ddd8](https://github.com/Dicklesworthstone/frankenlibc/commit/5e2ddd8ed69eadca07e24f2ed12b5afce16c06a9))
- `strnlen` with hardened bounds checking ([0a68e99](https://github.com/Dicklesworthstone/frankenlibc/commit/0a68e9939ea6a4b5dfd0b3e7bae6b0d2e5f8c71a))
- `strchrnul` with hardened bounds checking ([300efd4](https://github.com/Dicklesworthstone/frankenlibc/commit/300efd43e5d21db91c50b4ae5e7fdbc2acad8d6e))
- `atoll`, `strtoll`, `strtoull`, `strtoimax`, `strtoumax`, `secure_getenv` ([ac746e6](https://github.com/Dicklesworthstone/frankenlibc/commit/ac746e62ff9e46df5c0e7d42c0a02c0e2c35f8a5))

### Stdio

- Expand FILE operations with `fread`/`fwrite` and buffer-flush semantics ([dd47c22](https://github.com/Dicklesworthstone/frankenlibc/commit/dd47c22afeed51cedbf82d8d4e97e3d33e9f5f1c))
- Phase-2 printf-family integration tests and ABI definitions ([d5481d2](https://github.com/Dicklesworthstone/frankenlibc/commit/d5481d2fde97e7e5e4eaf0f02f2c1c3a5d6b8e09))
- Expand printf conformance with C fixture integration tests ([b94610d](https://github.com/Dicklesworthstone/frankenlibc/commit/b94610dfa3bc3e1e5a9bfc1f6b2c4d8e0f1a3c57))

### Signal

- Use kernel sigset size in `rt_sigaction` syscall and add signal ABI tests ([9ec4316](https://github.com/Dicklesworthstone/frankenlibc/commit/9ec4316d0ee92fd054b35bd751076a3f6aa859c6))

### Smoke Tests

- E2E test suite and substantially expanded LD_PRELOAD smoke test coverage ([f602a62](https://github.com/Dicklesworthstone/frankenlibc/commit/f602a62819cfbeefef903d8fc4117e2700c83f2c))

### Math

- Expand math ABI coverage with exp, float classification, and trig implementations ([ea1eeed](https://github.com/Dicklesworthstone/frankenlibc/commit/ea1eeed67535c3d6dba20de1e306676e2707276d))
- `nexttoward`/`nexttowardf`, `lgamma_r`, classification internals, glibc `__fp*` wrappers ([b35a716](https://github.com/Dicklesworthstone/frankenlibc/commit/b35a716b0a4f8e6e7d2c5b3a9f1e4d6c8b0a2e47))
- fenv_abi module and POSIX 2008 locale extensions ([9b50af7](https://github.com/Dicklesworthstone/frankenlibc/commit/9b50af77c88ef3a4cabd0b7e6d1f9e2c5a8d1b34))

---

## Phase 2 -- Core ABI, Membrane, and Conformance Build-out (2026-02-10 .. 2026-02-12)

Transition from prototype to structured workspace. Rename from `glibc_rust` to FrankenLibC. Build out conformance infrastructure, expand POSIX module coverage, and establish the TSM pipeline.

### Rename

- Rename `glibc_rust` to FrankenLibC across all crates ([6c012a1](https://github.com/Dicklesworthstone/frankenlibc/commit/6c012a1227ef087835379b431cbfcc49dcde491d))

### ABI

- Process/mmap/poll ABI modules, expand stdio to full POSIX surface, wire pthread sync ops ([1e34ce5](https://github.com/Dicklesworthstone/frankenlibc/commit/1e34ce5e446adec1ca19f8cb71e98e0df6c5e51d))
- Expand POSIX module coverage across 12 subsystems ([7a7173d](https://github.com/Dicklesworthstone/frankenlibc/commit/7a7173dae9d44415622954e1d9ef2e710ffd8bed))
- Phase-1 character encoding conversion engine (iconv) ([f494ad0](https://github.com/Dicklesworthstone/frankenlibc/commit/f494ad0cbcb2b62b6f0d66a28dee364f1d4f0c4a))
- Passwd and group database modules (`getpwnam`/`getgrnam` families) ([f8ba8e4](https://github.com/Dicklesworthstone/frankenlibc/commit/f8ba8e4bcf95a21b9f6cfbe9f3d5c9adb63fd6d9))
- DNS resolver with `/etc/hosts` and `/etc/services` file-based backends ([2f7fdc2](https://github.com/Dicklesworthstone/frankenlibc/commit/2f7fdc2c012df2749b7d29e5916e9ab7445e9df7))
- Expand pthread ABI surface, add math retirement gate and stub priority ([28f8806](https://github.com/Dicklesworthstone/frankenlibc/commit/28f88065149d11910c48429bfdbcc86e7e897619))
- Wire new modules into crate roots and expand versioned symbol map ([b030dcf](https://github.com/Dicklesworthstone/frankenlibc/commit/b030dcf0d5e5e6cd7b3b4c9f1a2e5d8c0b4a7e69))
- Raw syscall veneers, managed-mutex discrimination, and conformance gate suite ([6512fcc](https://github.com/Dicklesworthstone/frankenlibc/commit/6512fcca484ab43ebf914d20c9140d22369614a5))
- Eliminate glibc call-throughs, add re-entrancy guards, conditional `no_mangle` ([e4f489f](https://github.com/Dicklesworthstone/frankenlibc/commit/e4f489fd1f19cfe0bba9fbe6e2abfc45a3a74308))
- 250-symbol surface documented ([219cf7e](https://github.com/Dicklesworthstone/frankenlibc/commit/219cf7eea6e9af9f31126c10fb124e8c7c4aa0c7))

### Membrane

- 13 advanced statistical monitors for runtime kernel ([d72b56d](https://github.com/Dicklesworthstone/frankenlibc/commit/d72b56de122c86b1902a532843cb1d483b56356e))
- V1 deterministic XOR repair symbol encoder ([cb5d2dd](https://github.com/Dicklesworthstone/frankenlibc/commit/cb5d2dd55e7a63e55263d56876a5c91630d69985))
- Policy table lookup, redundancy tuner, hot-path optimizations ([6714ec8](https://github.com/Dicklesworthstone/frankenlibc/commit/6714ec82ab4dc0a26d6eeccae84bb8a1cc8bff74))
- CVE arena test infrastructure for real-world vulnerability reproduction ([40916cf](https://github.com/Dicklesworthstone/frankenlibc/commit/40916cf4ef9b4b82a8d8af0d2f8e7c9b1a3d5e07))
- SOS barrier property tests, kernel integration test, sobol quasi-random controller ([039a10f](https://github.com/Dicklesworthstone/frankenlibc/commit/039a10faf1c1db0c9bef21c3c6e7a8d5b2f4e601))

### Conformance

- ABI audit tooling, conformance golden gate, and support matrix ([39cdd32](https://github.com/Dicklesworthstone/frankenlibc/commit/39cdd32c79b8175d0d7f1800201f48465bb656e1))
- Snapshot gate and golden update scripts, wired into CI ([6233d09](https://github.com/Dicklesworthstone/frankenlibc/commit/6233d0931a1026f00a98296189f71a859b758f19))
- Module inventory and wiring drift detectors ([5b5e380](https://github.com/Dicklesworthstone/frankenlibc/commit/5b5e380c9d1f8ac57eba8f50e6e78536e1bbc516))

### Harness

- Kernel snapshot capture/diff commands, asupersync orchestrator, fix mode=both execution ([f3b8ff2](https://github.com/Dicklesworthstone/frankenlibc/commit/f3b8ff2da8f7c13c3e57d5a7b2a9f4e6d0c1b38a))
- Evidence decode CLI, restructured CI, updated golden snapshots ([2428990](https://github.com/Dicklesworthstone/frankenlibc/commit/2428990c079f3b1d7a2e6d8c4a5f9e1b3d7c0a25))
- Evidence compliance validator + triage CLI ([ac4a0ba](https://github.com/Dicklesworthstone/frankenlibc/commit/ac4a0bad9a85e8ad1b96de5b7ec35c2a9f4d6e18))
- Deterministic gate DAG + dry-run runner ([78ca744](https://github.com/Dicklesworthstone/frankenlibc/commit/78ca744a5b84f59f39e3c78c19d6f2e5d0a1b34c))

### Core

- Rewrite pthread thread creation with clone syscall, add syscall wrappers, iconv UTF-32 support ([9b22cfc](https://github.com/Dicklesworthstone/frankenlibc/commit/9b22cfca1e09046609bb0736ba966283a9d2b57f))
- ELF loader module and DNS resolver protocol support ([546cefe](https://github.com/Dicklesworthstone/frankenlibc/commit/546cefed02e6da72d9a97b09d2f97c0e3b5e8a14))

---

## Phase 1 -- Workspace Scaffold and Runtime Math Kernel (2026-02-08 .. 2026-02-09)

Initial project creation as `glibc_rust`. Established the four-crate workspace (`membrane`, `core`, `abi`, `harness`), wired the Transparent Safety Membrane, built out the runtime math kernel with dozens of controllers, and implemented the first ABI entrypoints.

### Project Setup

- Initial workspace scaffold and architecture docs ([b45e3ac](https://github.com/Dicklesworthstone/frankenlibc/commit/b45e3ac35c87a52992a797d178179ed6ecdf04a8))
- Wire runtime-math into all ABI families + add 6 new math monitors ([e130fb2](https://github.com/Dicklesworthstone/frankenlibc/commit/e130fb2a683f3a5ea0a2ded276d6c5d711e2f8ca))

### Membrane / Runtime Math Kernel

- Arena aligned allocation, public quarantine entries, validator pipeline ([f512b37](https://github.com/Dicklesworthstone/frankenlibc/commit/f512b379a820192410796496ff5439c3b19e49ee))
- P-adic valuation monitor, symplectic reduction controller, Stdlib API family ([e4acdee](https://github.com/Dicklesworthstone/frankenlibc/commit/e4acdeebe49f81016e06cbeab692a7b5808b5cd8))
- Sparse-recovery and robust fusion runtime math controllers ([aaa6820](https://github.com/Dicklesworthstone/frankenlibc/commit/aaa6820adb51e0f5c97cfb3e6cc9e5ddfe6be9c3))
- Clifford algebra, microlocal analysis, Serre spectral sequence controllers ([dcb004e](https://github.com/Dicklesworthstone/frankenlibc/commit/dcb004e3cb2c5e89a0d24fde5b2df1af4e8c7b69))
- 12 new controllers spanning algebraic, combinatorial, and information-theoretic domains ([16587b8](https://github.com/Dicklesworthstone/frankenlibc/commit/16587b82997adba2b878c5a64d516a9edf9b52fd))
- 7 new controllers and expanded existing modules ([077d812](https://github.com/Dicklesworthstone/frankenlibc/commit/077d8127e84c1c3cb2f0a1f8e9d6a5b3c7e0f249))
- Pointer validator with string-aware safety checks ([68fcc37](https://github.com/Dicklesworthstone/frankenlibc/commit/68fcc370c4b8f5e2a9d1c6e3b7a0f4d8e2c5b189))
- Criterion microbench suite, profiling recipe ([81e14d0](https://github.com/Dicklesworthstone/frankenlibc/commit/81e14d0911840d1611e83c7289846f27188405a0))
- Benchmark rewrite with parameterized safety levels and percentile reporting ([bd60972](https://github.com/Dicklesworthstone/frankenlibc/commit/bd60972c3b8f4e5d7a2c6f9e1d0b3a5c8e7f2d46))

### Core

- Errno TLS, stdlib numeric/exit/sort, wide string operations ([ce78bec](https://github.com/Dicklesworthstone/frankenlibc/commit/ce78becb68e69cbda712d8d3e48c5a580316c510))
- Core math implementations for exp, float, special, and trig families ([836dfac](https://github.com/Dicklesworthstone/frankenlibc/commit/836dfac5bcc033134861782eb0a1ef10906a9d6d))

### ABI

- Wire malloc through membrane pipeline, add stdlib/stdio/unistd/wchar ABI exports ([2218394](https://github.com/Dicklesworthstone/frankenlibc/commit/2218394a0ce9bdc0a2c86e055145de16a29bd5cc))
- Preview ABI entrypoints for malloc, free, strlen, strcmp, memset ([b91f2e8](https://github.com/Dicklesworthstone/frankenlibc/commit/b91f2e8df5c1b3a7e9d2f4c6a8b0e3d5c7f1a249))
- Expand ABI surface for math functions, string operations, and runtime policy ([921a07a](https://github.com/Dicklesworthstone/frankenlibc/commit/921a07a47c6b3f8e5a2d9c1e4d7f0b3a6c8e5d27))
- Allocator stage-context helpers and pipeline wiring ([f85a1e6](https://github.com/Dicklesworthstone/frankenlibc/commit/f85a1e6c18d4a7e3b5f2c9d6a8e1b0c4f3d7a562))

### Conformance

- Unified fixture execution engine and 9 new test fixture sets ([e989cc3](https://github.com/Dicklesworthstone/frankenlibc/commit/e989cc378236c059de8b7ee99327a979465080a3))

---

## Workspace Crate Map

| Crate | Purpose |
|---|---|
| `frankenlibc-abi` | `#[no_mangle]` exported symbols; the `libfrankenlibc_abi.so` artifact |
| `frankenlibc-core` | Safe Rust implementations of libc behavior (string, math, pthread, etc.) |
| `frankenlibc-membrane` | Transparent Safety Membrane: pointer validation, arena, quarantine, runtime math kernel |
| `frankenlibc-harness` | CLI harness for conformance verification, evidence, and release gates |
| `frankenlibc-bench` | Criterion benchmarks |
| `frankenlibc-fixture-exec` | Fixture execution engine for conformance tests |

---

## Symbol Classification Legend

| Status | Meaning |
|---|---|
| **Implemented** | Native Rust-owned behavior behind the ABI symbol |
| **RawSyscall** | ABI path delegates directly to a Linux syscall |
| **GlibcCallThrough** | Still delegates to host glibc via `dlsym` |
| **Stub** | Exported but returns a fixed value (currently zero in the classified surface) |

---

## Notes for Agents

- There are **no tags or GitHub Releases** in this repository as of 2026-03-21.
- The version badge in the README reads `0.1.0`; `Cargo.toml` workspace version matches.
- The canonical coverage source of truth is `tests/conformance/support_matrix_maintenance_report.v1.json`.
- All 625 commits are by a single author (`Dicklesworthstone`).
- The project was originally named `glibc_rust` and renamed to FrankenLibC on 2026-02-12.
- License is MIT with an OpenAI/Anthropic rider, adopted 2026-02-18.
