# R2: External Software CVE Candidates for TSM Reproduction

> CVE Arena -- Transparent Safety Membrane validation against real-world vulnerabilities
>
> **Status:** Research complete
> **Last updated:** 2026-02-10

---

## Table of Contents

1. [Objective](#objective)
2. [TSM Capabilities Under Test](#tsm-capabilities-under-test)
3. [Candidate CVEs](#candidate-cves)
   - [CVE-2021-3156 -- Baron Samedit (sudo)](#cve-2021-3156----baron-samedit-sudo)
   - [CVE-2024-6197 -- curl/libcurl Stack UAF](#cve-2024-6197----curllibcurl-stack-uaf)
   - [CVE-2024-56406 -- Perl tr/// Heap Overflow](#cve-2024-56406----perl-tr-heap-overflow)
   - [CVE-2024-46461 -- VLC MMS Integer Overflow](#cve-2024-46461----vlc-mms-integer-overflow)
   - [CVE-2025-49844 -- RediShell (Redis)](#cve-2025-49844----redishell-redis)
4. [Feasibility Matrix](#feasibility-matrix)
5. [Recommended Priority Order](#recommended-priority-order)
6. [References](#references)

---

## Objective

The CVE Arena test suite validates that the glibc_rust Transparent Safety Membrane
(TSM) can detect, contain, or neutralize real-world memory safety vulnerabilities
when deployed via `LD_PRELOAD` against unmodified C binaries. This document
catalogs external software CVEs selected for reproduction, analyzes the
applicability of each TSM detection/healing mechanism, and assesses feasibility
of automated reproduction within our CI/test infrastructure.

Each candidate was selected based on four criteria:

1. The root cause must involve libc-level memory operations (malloc/free/realloc,
   memcpy/strcpy, or pointer arithmetic on heap buffers).
2. The vulnerable software must be open-source with reproducible builds.
3. The vulnerability must be triggerable without complex environmental setup
   (no kernel exploits, no hardware dependencies).
4. At least one TSM mechanism must be architecturally capable of detecting or
   healing the fault.

---

## TSM Capabilities Under Test

The following TSM mechanisms are relevant to the selected CVEs. Each is
implemented in `crates/glibc-rs-membrane/src/` and exposed via the `libc.so`
LD_PRELOAD shim.

| Mechanism | Source Module | Detection/Healing |
|-----------|---------------|-------------------|
| Trailing canary (8-byte SipHash-derived) | `fingerprint.rs` | Detects heap buffer overflow at `free()` time |
| Allocation fingerprint (16-byte header) | `fingerprint.rs` | Integrity verification, bounds metadata |
| Generational arena with quarantine | `arena.rs` | UAF detection (generation mismatch), delayed reuse |
| Bloom filter pre-check | `bloom.rs` | O(1) pointer ownership query, zero false negatives |
| Page oracle (two-level bitmap) | `page_oracle.rs` | O(1) page-level ownership, rejects stack/foreign pointers |
| Validation pipeline | `ptr_validator.rs` | 7-stage pointer validation with TLS cache fast path |
| HealingAction::ClampSize | `heal.rs` | Clamps allocation/copy sizes to safe bounds |
| HealingAction::IgnoreDoubleFree | `heal.rs` | Silently ignores double-free |
| HealingAction::IgnoreForeignFree | `heal.rs` | Silently ignores free of non-arena pointer |
| HealingAction::ReallocAsMalloc | `heal.rs` | Treats realloc of freed pointer as fresh malloc |
| HealingAction::TruncateWithNull | `heal.rs` | Truncates string ops, ensures null terminator |
| HealingAction::UpgradeToSafeVariant | `heal.rs` | Replaces unbounded ops (e.g., strcpy -> strncpy) |
| HealingAction::ReturnSafeDefault | `heal.rs` | Returns safe default instead of performing unsafe op |
| Bounds computation | `ptr_validator.rs` | Computes remaining bytes from pointer within allocation |

---

## Candidate CVEs

---

### CVE-2021-3156 -- Baron Samedit (sudo)

| Field | Value |
|-------|-------|
| **CVE ID** | CVE-2021-3156 |
| **CVSS Score** | 7.8 (High) |
| **Disclosure Date** | 2021-01-26 |
| **Discoverer** | Qualys Research Team |
| **Software** | sudo |
| **Vulnerable Versions** | 1.8.2 through 1.8.31p2, 1.9.0 through 1.9.5p1 |
| **Target Version for Reproduction** | 1.9.5p1 |
| **Build Complexity** | Easy |
| **CWE Classification** | CWE-122 (Heap-based Buffer Overflow), CWE-193 (Off-by-One Error) |

#### Root Cause Analysis

The vulnerability lies in sudo's command-line argument parsing when invoked in
"shell mode" via `sudoedit -s` or `sudo -s`. The `set_cmnd()` function in
`sudo_edit.c` concatenates command-line arguments into a heap buffer, performing
backslash escape processing. When an argument ends with an unescaped trailing
backslash character (`\`), the escape-processing loop reads one byte past the
end of the argument and writes past the end of the allocated heap buffer.

The off-by-one write compounds across concatenated arguments. By crafting
arguments of specific lengths, an attacker can achieve controlled heap overflow
of arbitrary size, ultimately overwriting heap metadata or adjacent heap objects
to gain code execution as root.

The critical code path:

```
sudoedit -s '\' $(python3 -c 'print("A"*65536)')
```

This causes `set_cmnd()` to:
1. Calculate the concatenated buffer size (incorrectly, due to backslash handling).
2. Allocate a heap buffer via `malloc()`.
3. Copy arguments into the buffer, overflowing past the allocated size.

#### Exploitation Mechanism

- **Attacker capability required:** Any local user account (no sudo privileges needed).
- **Trigger:** Run `sudoedit -s '\' $(python3 -c 'print("A"*65536)')`.
- **Effect:** Heap buffer overflow in sudo's argument buffer, leading to
  privilege escalation to root.

#### TSM Detection and Healing

**Primary detection: Trailing canary corruption.**

When sudo calls `malloc()` through our LD_PRELOAD shim, the TSM's generational
arena (`arena.rs`) allocates the buffer with:
- A 16-byte fingerprint header before the user-visible pointer.
- An 8-byte trailing canary immediately after the user-requested size.

The overflow from the `set_cmnd()` backslash-processing loop writes past the
allocated buffer and corrupts the trailing canary. When the buffer is eventually
freed (or when any subsequent pointer validation runs the canary check stage),
the TSM detects `FreeResult::FreedWithCanaryCorruption`.

**Secondary detection: Bounds computation.**

If the TSM's `remaining_from()` function is queried during the `memcpy`/`strcpy`
operations that fill the buffer, the bounds computation will reveal that the
write exceeds `user_size`. The `heal_copy_bounds()` method would fire
`HealingAction::ClampSize`, clamping the copy to the actual allocation size.

**Tertiary detection: UpgradeToSafeVariant.**

If sudo's internal string concatenation routes through `strcpy()` in our shim,
the TSM can upgrade to a bounded variant, preventing the overflow entirely.

| TSM Feature | Applicable | Confidence |
|-------------|-----------|------------|
| Trailing canary | Yes | High -- overflow directly corrupts canary bytes |
| Bounds computation | Yes | Medium -- depends on whether copy routes through intercepted libc calls |
| ClampSize | Yes | Medium -- effective if memcpy/strcpy is intercepted |
| UpgradeToSafeVariant | Possible | Low -- depends on sudo's internal copy implementation |

#### LD_PRELOAD Feasibility

**Viability: High.**

sudo is a standard C binary that links dynamically against libc. All heap
operations (`malloc`, `free`, `realloc`) route through glibc symbols that we
intercept. The argument-parsing code uses standard C string operations that are
also interceptable.

**Caveat:** sudo is a setuid binary. On most Linux distributions,
`LD_PRELOAD` is ignored for setuid programs (the dynamic linker drops it).
For testing purposes, we must either:

1. Build sudo without the setuid bit and run the test as root.
2. Use a patched dynamic linker that honors `LD_PRELOAD` for the test binary.
3. Run inside a container where the test user is already root, making setuid
   irrelevant.

Option (3) is the recommended approach for CI.

#### Reproduction Complexity

**Low.** The build is trivial:

```bash
# Download and build vulnerable sudo
wget https://www.sudo.ws/dist/sudo-1.9.5p1.tar.gz
tar xzf sudo-1.9.5p1.tar.gz
cd sudo-1.9.5p1
./configure --prefix=/opt/sudo-vuln --disable-setuid
make -j$(nproc)

# Trigger with TSM LD_PRELOAD
LD_PRELOAD=/path/to/glibc_rust/target/release/libglibc_rs.so \
  /opt/sudo-vuln/bin/sudoedit -s '\' $(python3 -c 'print("A"*65536)')
```

The trigger is a single command-line invocation. No network services, no
crafted files, no multi-step setup. The test can assert that the TSM reports
canary corruption and/or fires ClampSize healing.

#### Source Availability

- **Repository:** https://www.sudo.ws/repos/sudo
- **Release tarball:** https://www.sudo.ws/dist/sudo-1.9.5p1.tar.gz
- **License:** ISC (permissive, no redistribution concerns for testing)

---

### CVE-2024-6197 -- curl/libcurl Stack UAF

| Field | Value |
|-------|-------|
| **CVE ID** | CVE-2024-6197 |
| **CVSS Score** | 7.5 (High) |
| **Disclosure Date** | 2024-07-24 |
| **Discoverer** | z2_ (reported to curl project 2024-06-19) |
| **Software** | curl / libcurl |
| **Vulnerable Versions** | 8.6.0 through 8.8.0 |
| **Target Version for Reproduction** | 8.6.0 |
| **Build Complexity** | Easy |
| **CWE Classification** | CWE-416 (Use After Free) -- specifically, free of stack memory |

#### Root Cause Analysis

The vulnerability exists in libcurl's ASN.1 parser, specifically in the
`utf8asn1str()` function used during TLS certificate processing. When this
function encounters an invalid field in an ASN.1 UTF-8 string, it calls
`free()` on a pointer that references a 4-byte local (stack-allocated) buffer
rather than a heap-allocated buffer.

The root cause is a code refactor introduced in curl 8.6.0 that changed the
buffer management logic. In the error path, the function fails to distinguish
between its small stack-based buffer (used for short strings) and a
dynamically allocated buffer (used for longer strings), passing the stack
address to `free()`.

The behavior after `free()` is called on a stack address depends on the
malloc implementation:
- glibc's malloc may add the stack address to its free list, corrupting
  the heap metadata.
- Some implementations crash immediately.
- In all cases, subsequent allocations may return pointers into the stack
  frame, enabling stack corruption.

#### Exploitation Mechanism

- **Attacker capability required:** Network position to serve a crafted TLS
  certificate (e.g., MITM, or control of a server curl connects to).
- **Trigger:** curl connects to a server presenting a TLS certificate with a
  specially crafted ASN.1 UTF-8 field that triggers the invalid-field error path.
- **Effect:** `free()` is called on a stack address, corrupting the allocator's
  internal state. Most likely outcome is a crash; code execution is theoretically
  possible.
- **Prerequisite:** curl must be built with GnuTLS, wolfSSL, Schannel, Secure
  Transport, or mbedTLS. Builds using OpenSSL are NOT vulnerable (OpenSSL has its
  own ASN.1 parser).

#### TSM Detection and Healing

**Primary detection: Page oracle rejects stack pointer.**

When `free()` is called with the stack address, the TSM's validation pipeline
runs:

1. **Bloom filter pre-check** (`bloom.rs`): The stack address was never inserted
   into the bloom filter. `might_contain()` returns `false` -- definitive proof
   this is not an arena allocation.

2. **Page oracle** (`page_oracle.rs`): The stack page is not in the two-level
   bitmap. `query()` returns `false`, confirming the address is not arena-owned.

3. **Arena lookup** (`arena.rs`): `lookup()` returns `None` (the address maps to
   no `ArenaSlot`).

4. **FreeResult::ForeignPointer** is returned by the arena's `free()` method.

**Primary healing: IgnoreForeignFree.**

The TSM fires `HealingAction::IgnoreForeignFree`, silently discarding the
invalid `free()` call. The stack buffer is never actually freed. The program
continues executing safely.

This is a textbook case for the foreign-free detection path. The TSM's
three-layer ownership check (bloom + page oracle + arena) ensures zero false
negatives: a stack pointer will never be mistakenly identified as an arena
allocation.

| TSM Feature | Applicable | Confidence |
|-------------|-----------|------------|
| Bloom filter (negative) | Yes | High -- stack address never inserted |
| Page oracle (negative) | Yes | High -- stack page never registered |
| Arena lookup (ForeignPointer) | Yes | High -- no ArenaSlot for stack address |
| IgnoreForeignFree | Yes | High -- directly applicable healing action |

#### LD_PRELOAD Feasibility

**Viability: High.**

curl is a standard dynamically-linked C binary. All `malloc`/`free`/`realloc`
calls route through libc symbols. The critical `free()` call on the stack buffer
is a direct call to libc's `free()`, which our LD_PRELOAD shim intercepts.

No setuid complications. No special linking requirements.

**Build note:** The vulnerable code path requires building curl with a non-OpenSSL
TLS backend. GnuTLS is the easiest choice on Linux:

```bash
apt-get install libgnutls28-dev
```

#### Reproduction Complexity

**Medium.** The trigger requires a TLS server presenting a crafted certificate.
Setup involves:

1. Build curl 8.6.0 with GnuTLS backend.
2. Generate a crafted X.509 certificate with a malformed ASN.1 UTF-8 field.
3. Run a local TLS server (e.g., `openssl s_server` or a Python script) that
   presents the crafted certificate.
4. Run curl against the local server with TSM LD_PRELOAD.

The certificate crafting is the most complex step, but existing proof-of-concept
tooling from the original disclosure can be adapted. A helper script to generate
the malformed certificate and stand up a test server should be part of the test
fixture.

```bash
# Build vulnerable curl with GnuTLS
wget https://curl.se/download/curl-8.6.0.tar.gz
tar xzf curl-8.6.0.tar.gz
cd curl-8.6.0
./configure --prefix=/opt/curl-vuln --with-gnutls --without-openssl
make -j$(nproc)

# Run with TSM (test server must be running on localhost:4433)
LD_PRELOAD=/path/to/glibc_rust/target/release/libglibc_rs.so \
  /opt/curl-vuln/bin/curl https://localhost:4433/ --insecure
```

#### Source Availability

- **Repository:** https://github.com/curl/curl
- **Release tarball:** https://curl.se/download/curl-8.6.0.tar.gz
- **License:** MIT/X-derivate (permissive)
- **Advisory:** https://curl.se/docs/CVE-2024-6197.html

---

### CVE-2024-56406 -- Perl tr/// Heap Overflow

| Field | Value |
|-------|-------|
| **CVE ID** | CVE-2024-56406 |
| **CVSS Score** | 8.6 (High) |
| **Disclosure Date** | 2025-04-14 (public advisory on oss-security) |
| **Discoverer** | Nathan Mills |
| **Software** | Perl |
| **Vulnerable Versions** | 5.34.x, 5.36.x, 5.38.x, 5.40.x (dev: 5.33.1 through 5.41.10) |
| **Target Version for Reproduction** | 5.38.2 or 5.40.0 |
| **Build Complexity** | Medium |
| **CWE Classification** | CWE-122 (Heap-based Buffer Overflow) |

#### Root Cause Analysis

The vulnerability is in Perl's transliteration operator implementation,
specifically in the `S_do_trans_invmap()` function in `doop.c`. When the `tr///`
operator's left-hand side contains non-ASCII bytes (values 0x80-0xFF) and the
target string has the UTF-8 flag set, the function miscalculates the output
buffer size.

The issue arises because:
1. The input string contains byte values > 0x7F.
2. The transliteration replacement may produce multi-byte UTF-8 sequences.
3. The destination buffer `d` is sized based on the assumption that output
   characters are the same width as input characters.
4. When non-ASCII bytes are replaced with characters requiring more UTF-8 bytes
   than the input, `d` overflows past the allocated buffer.

The overflow size scales linearly with the input string length, making it
straightforward to produce large overflows.

#### Exploitation Mechanism

- **Attacker capability required:** Ability to supply input to a Perl script
  that uses `tr///` on user-controlled data, or to execute Perl code directly.
- **Trigger (one-liner PoC):**
  ```
  perl -e '$_ = "\x{FF}" x 100000; tr/\xFF/\x{100}/;'
  ```
  Alternative trigger with UTF-8 source string:
  ```
  perl -e 'use utf8; my $s = "abc\x{100}"; $s =~ tr/\x80-\xff/X/;'
  ```
- **Effect:** Heap buffer overflow in Perl's internal string buffer. Causes
  crash (segfault) or potential arbitrary code execution.

#### TSM Detection and Healing

**Primary detection: Trailing canary corruption.**

Perl's internal string buffers (`SV` / `PV` slots) are allocated via `malloc()`.
When the TSM intercepts these allocations, each gets a trailing canary. The
`S_do_trans_invmap()` overflow writes past the allocated buffer and corrupts
the canary.

Detection occurs at `free()` time (when Perl deallocates or reallocates the
string) via `FreeResult::FreedWithCanaryCorruption`.

**Secondary detection: Bounds computation during realloc.**

If Perl calls `realloc()` on the overflowed buffer, the TSM can compare the
fingerprint's recorded `size` field against the actual write extent. The
fingerprint header stores the original `user_size` as a `u32`, enabling
after-the-fact size verification.

**Potential healing: ClampSize.**

If the TSM interposes on the internal `memcpy` or character-copy loop (unlikely
for Perl's internal byte-level loop), `ClampSize` could prevent the overflow.
However, Perl's transliteration uses direct pointer arithmetic rather than
libc string functions, so this healing path is unlikely to engage.

| TSM Feature | Applicable | Confidence |
|-------------|-----------|------------|
| Trailing canary | Yes | High -- heap overflow directly corrupts canary |
| Fingerprint size metadata | Yes | Medium -- useful for post-hoc size verification |
| Bounds computation | Possible | Low -- depends on Perl calling interceptable libc functions |
| ClampSize | Unlikely | Low -- Perl uses direct pointer writes, not libc memcpy |

#### LD_PRELOAD Feasibility

**Viability: High.**

Perl is a dynamically-linked C binary. All heap operations (`malloc`, `free`,
`realloc`, `calloc`) go through libc. The TSM will manage all of Perl's
internal string buffers, and the trailing canary will detect the overflow.

The one limitation is that the actual overflow occurs via direct pointer
increment (`*d++ = ...`) in Perl's compiled C code, not through a libc function
call. This means the TSM cannot prevent the overflow in real time -- it can
only detect it after the fact via canary corruption.

#### Reproduction Complexity

**Low.** The trigger is a single Perl one-liner:

```bash
# Build vulnerable Perl
wget https://www.cpan.org/src/5.0/perl-5.38.2.tar.gz
tar xzf perl-5.38.2.tar.gz
cd perl-5.38.2
./Configure -des -Dprefix=/opt/perl-vuln
make -j$(nproc)

# Trigger with TSM
LD_PRELOAD=/path/to/glibc_rust/target/release/libglibc_rs.so \
  /opt/perl-vuln/bin/perl -e '$_ = "\x{FF}" x 100000; tr/\xFF/\x{100}/;'
```

No network services, no crafted files. The test asserts canary corruption
is reported by the TSM.

**Build caveat:** Perl's `Configure` script is interactive by default; use
`-des` for non-interactive defaults. Build takes ~5 minutes on modern hardware.

#### Source Availability

- **Repository:** https://github.com/Perl/perl5
- **Release tarball:** https://www.cpan.org/src/5.0/perl-5.38.2.tar.gz
- **License:** Artistic License 2.0 / GPL v1+ (dual-licensed)
- **Advisory:** https://seclists.org/oss-sec/2025/q2/48

---

### CVE-2024-46461 -- VLC MMS Integer Overflow

| Field | Value |
|-------|-------|
| **CVE ID** | CVE-2024-46461 |
| **CVSS Score** | 7.5 (High) |
| **Disclosure Date** | 2024-10-01 |
| **Discoverer** | Andreas Fobian (Mantodea Security GmbH) |
| **Software** | VLC media player |
| **Vulnerable Versions** | 3.0.20 and earlier |
| **Target Version for Reproduction** | 3.0.20 |
| **Build Complexity** | Hard |
| **CWE Classification** | CWE-190 (Integer Overflow), CWE-122 (Heap-based Buffer Overflow) |

#### Root Cause Analysis

The vulnerability is in VLC's MMS (Microsoft Media Server) stream processing
module. An integer overflow occurs when computing the size of a buffer to be
allocated for incoming MMS stream data. The overflow causes a much smaller buffer
to be allocated than the actual data size. Subsequent code then fills the
undersized buffer with the full stream data, producing a heap buffer overflow.

The attack chain:
1. An MMS stream header contains a length field.
2. VLC computes `allocation_size = header_length * element_size`.
3. If `header_length` and `element_size` are crafted to produce an integer
   overflow, `allocation_size` wraps to a small value.
4. `malloc(allocation_size)` succeeds with a small buffer.
5. The subsequent data copy writes `header_length * element_size` bytes
   (the true, non-wrapped value) into the small buffer, overflowing it.

#### Exploitation Mechanism

- **Attacker capability required:** Ability to serve or inject a crafted MMS
  stream that VLC opens.
- **Trigger:** VLC opens an MMS URL or local file containing a crafted MMS
  stream with integer-overflowing length fields.
- **Effect:** Heap buffer overflow leading to crash (DoS) or potential code
  execution.

#### TSM Detection and Healing

**Primary detection: ClampSize on allocation.**

The TSM's `heal_copy_bounds()` system can detect when a copy operation attempts
to write more bytes than the destination allocation's `user_size`. If the copy
from the MMS stream routes through an intercepted `memcpy()`, the TSM computes
`remaining_from()` on the destination pointer, determines the write exceeds
bounds, and fires `HealingAction::ClampSize`.

**Secondary detection: Trailing canary corruption.**

Even if the copy does not route through an intercepted function, the overflow
will corrupt the trailing canary. Detection occurs at `free()` time.

**Potential prevention: Integer overflow detection in allocation size.**

If the TSM's `malloc()` shim validates that the requested size is reasonable
(e.g., not suspiciously small for the context), it could raise a flag. However,
the TSM currently does not perform contextual size validation at allocation
time -- it trusts the caller's requested size. The integer overflow occurs before
the `malloc()` call, so the TSM sees only the wrapped (small) value.

**Key insight:** The TSM cannot prevent the integer overflow itself (that happens
in VLC's code). But it can detect the consequence (overflow into canary) and
potentially heal the symptom (clamp the copy if routed through libc).

| TSM Feature | Applicable | Confidence |
|-------------|-----------|------------|
| Trailing canary | Yes | High -- overflow corrupts canary bytes |
| ClampSize (on copy) | Possible | Medium -- only if VLC uses intercepted memcpy for the fill |
| Bounds computation | Yes | Medium -- remaining_from() can detect oversized write |
| Integer overflow in malloc arg | No | N/A -- TSM trusts caller-provided size |

#### LD_PRELOAD Feasibility

**Viability: Medium.**

VLC is dynamically linked and its heap operations go through libc. However:

1. VLC loads many modules as shared libraries (plugins). All heap operations in
   plugins also route through libc, so LD_PRELOAD coverage is comprehensive.
2. The MMS module specifically uses standard `malloc`/`memcpy` patterns.
3. VLC's plugin loading and multimedia pipeline introduce complexity that could
   cause false positives from the TSM (many allocations, complex lifecycle).

#### Reproduction Complexity

**High.** VLC has a substantial dependency tree:

```bash
# Dependencies (Debian/Ubuntu)
apt-get install build-essential pkg-config \
  libavcodec-dev libavformat-dev libswscale-dev \
  libgcrypt-dev liblua5.2-dev libqt5-dev \
  protobuf-compiler flex bison

# Build VLC 3.0.20
wget https://get.videolan.org/vlc/3.0.20/vlc-3.0.20.tar.xz
tar xf vlc-3.0.20.tar.xz
cd vlc-3.0.20
./configure --prefix=/opt/vlc-vuln --disable-a52 --disable-nls
make -j$(nproc)
```

Additionally, triggering the vulnerability requires a crafted MMS stream file.
This means writing a binary generator for the malformed MMS data:

1. Construct an MMS stream header with overflow-inducing length fields.
2. Package it as a file or serve it via a local MMS server stub.
3. Launch VLC in headless mode against the crafted input.

```bash
LD_PRELOAD=/path/to/glibc_rust/target/release/libglibc_rs.so \
  /opt/vlc-vuln/bin/vlc --intf dummy --no-video --no-audio \
  mms://localhost:1755/crafted_stream
```

The MMS stream generation and VLC build complexity make this the most effort-intensive
candidate.

#### Source Availability

- **Repository:** https://code.videolan.org/videolan/vlc
- **Release tarball:** https://get.videolan.org/vlc/3.0.20/vlc-3.0.20.tar.xz
- **License:** GPL v2+ (no redistribution concerns for testing)
- **Advisory:** https://www.videolan.org/security/sb-vlc3021.html

---

### CVE-2025-49844 -- RediShell (Redis)

| Field | Value |
|-------|-------|
| **CVE ID** | CVE-2025-49844 |
| **CVSS Score** | 10.0 (Critical) |
| **Disclosure Date** | 2025-10-03 (patch release; originally demonstrated at Pwn2Own Berlin, May 2025) |
| **Discoverer** | Wiz Research |
| **Software** | Redis |
| **Vulnerable Versions** | All versions prior to patch (bug present for ~13 years in Lua interpreter) |
| **Target Version for Reproduction** | 7.4.1 or 7.4.2 |
| **Build Complexity** | Easy |
| **CWE Classification** | CWE-416 (Use After Free) |

#### Root Cause Analysis

The vulnerability is a use-after-free in Redis's embedded Lua scripting engine.
The bug has existed in the Lua interpreter integration for approximately 13
years. The root cause is in the Lua garbage collector's interaction with Redis's
object lifecycle:

1. An authenticated user sends a crafted Lua script via `EVAL` or `EVALSHA`.
2. The Lua garbage collector runs and incorrectly frees an object that is still
   referenced (a "live" object).
3. The freed memory is returned to the allocator's free list.
4. A subsequent allocation reuses the freed memory.
5. The original dangling pointer still references the old object, but the memory
   now contains attacker-controlled data (from the new allocation).
6. The attacker uses this type confusion to escape the Lua sandbox and execute
   arbitrary native code.

This is a classic UAF-to-sandbox-escape chain: the garbage collector creates a
dangling pointer, the attacker wins a race to reclaim the memory, and the type
confusion allows writing to arbitrary memory locations.

#### Exploitation Mechanism

- **Attacker capability required:** Authenticated Redis client (or access to an
  unauthenticated Redis instance -- Wiz estimates at least 60,000 such instances
  are Internet-exposed).
- **Trigger:** Send a crafted Lua script via the `EVAL` command that triggers
  specific garbage collection timing.
- **Effect:** Lua sandbox escape, arbitrary native code execution on the Redis
  host with the privileges of the Redis process.

#### TSM Detection and Healing

**Primary detection: Generational arena with quarantine.**

This is the TSM's strongest use case for UAF detection. When Redis (via Lua's
allocator, which calls `malloc`/`free`) frees the object:

1. The arena's `free()` method moves the slot to `SafetyState::Quarantined`.
2. The generation counter is incremented.
3. The allocation enters the quarantine queue (up to 64 MB / 65,536 entries).

When the attacker's subsequent allocation reclaims memory, it gets a *new* slot
with a *new* generation. The original dangling pointer, if validated through the
pipeline, hits `TemporalViolation`: the arena finds the slot but its state is
`Quarantined`, not `Valid`.

**Key mechanism:** The quarantine queue ensures the freed memory is not
immediately returned to the system allocator. The attacker's `malloc()` call
gets fresh memory from a different region, not the freed object's memory. This
breaks the UAF exploitation chain entirely -- the attacker cannot reclaim the
specific freed memory because it is held in quarantine.

**Secondary detection: Fingerprint generation mismatch.**

Even if quarantine is drained and the memory is reused, the generation counter
in the fingerprint header will not match. Any validation of the dangling pointer
will detect the generation mismatch.

**Healing path:**

If the Lua GC calls `free()` and then later code attempts to use the freed
pointer:
- The validation pipeline returns `TemporalViolation`.
- The healing engine can fire `ReturnSafeDefault` for read operations or
  block the operation entirely.

| TSM Feature | Applicable | Confidence |
|-------------|-----------|------------|
| Generational arena | Yes | High -- quarantine prevents memory reuse |
| Quarantine queue | Yes | High -- holds freed memory, blocking reclamation |
| Generation counter mismatch | Yes | High -- dangling pointer has stale generation |
| TemporalViolation detection | Yes | High -- freed/quarantined state detected in pipeline |
| ReturnSafeDefault | Yes | Medium -- applicable if the code checks return value |

#### LD_PRELOAD Feasibility

**Viability: High.**

Redis is a single C binary with minimal dependencies (it includes its own
copies of jemalloc, Lua, and hiredis). When built with the system allocator
(or when LD_PRELOAD overrides jemalloc's symbols), all `malloc`/`free`/`realloc`
calls route through our shim.

**Important build flag:** Redis must be built with `MALLOC=libc` to use the
system allocator rather than the bundled jemalloc:

```bash
make MALLOC=libc
```

Alternatively, our LD_PRELOAD can override jemalloc's symbols since they share
the same function names (`malloc`, `free`, etc.), but using the system allocator
is cleaner.

#### Reproduction Complexity

**Medium.** Redis builds trivially, but the exploit requires a crafted Lua
script that triggers specific GC timing:

```bash
# Build vulnerable Redis
wget https://github.com/redis/redis/archive/refs/tags/7.4.1.tar.gz
tar xzf 7.4.1.tar.gz
cd redis-7.4.1
make MALLOC=libc -j$(nproc)

# Start Redis with TSM
LD_PRELOAD=/path/to/glibc_rust/target/release/libglibc_rs.so \
  ./src/redis-server --protected-mode no &

# Send crafted Lua script
redis-cli EVAL "$(cat crafted_uaf_trigger.lua)" 0
```

The Lua trigger script is the complex part. Public exploit code exists
(e.g., https://github.com/raminfp/redis_exploit), but it must be adapted
for our specific testing scenario. For the CVE Arena, we need a script that
reliably triggers the UAF without requiring the sandbox escape -- we only need
to demonstrate that the TSM detects the temporal violation.

A simplified approach: write a Lua script that triggers GC in a way that
creates a dangling reference, then attempt to access the freed object. The TSM
should report `TemporalViolation` even without a full exploit chain.

#### Source Availability

- **Repository:** https://github.com/redis/redis
- **Release tarball:** https://github.com/redis/redis/archive/refs/tags/7.4.1.tar.gz
- **License:** RSALv2 / SSPLv1 (dual-licensed; acceptable for internal testing)
- **Advisory:** https://redis.io/blog/security-advisory-cve-2025-49844/
- **Public exploit:** https://github.com/raminfp/redis_exploit

---

## Feasibility Matrix

The following matrix scores each CVE across four dimensions on a 1-5 scale
(5 = best/easiest). The composite score uses equal weighting.

| CVE | Software | Build Difficulty | LD_PRELOAD Viability | Reproduction Confidence | TSM Coverage | Composite |
|-----|----------|:---:|:---:|:---:|:---:|:---:|
| CVE-2021-3156 | sudo | 5 (trivial) | 4 (setuid caveat) | 5 (one-liner trigger) | 4 (canary + bounds) | **4.50** |
| CVE-2024-6197 | curl | 5 (trivial) | 5 (no caveats) | 3 (needs TLS server + cert) | 5 (bloom + page oracle + foreign free) | **4.50** |
| CVE-2024-56406 | Perl | 4 (5-min build) | 5 (no caveats) | 5 (one-liner trigger) | 3 (canary only, no real-time prevention) | **4.25** |
| CVE-2025-49844 | Redis | 5 (trivial) | 5 (MALLOC=libc) | 3 (needs crafted Lua script) | 5 (quarantine + generation) | **4.50** |
| CVE-2024-46461 | VLC | 2 (many deps) | 4 (plugin complexity) | 2 (needs MMS stream generator) | 3 (canary + possible ClampSize) | **2.75** |

### Dimension Definitions

- **Build Difficulty:** How easy is it to compile the vulnerable version from
  source in a CI environment? (5 = `make` with no deps, 1 = complex dep chain)
- **LD_PRELOAD Viability:** How cleanly does LD_PRELOAD interception work?
  (5 = direct libc linkage, no caveats; 1 = static linking or dlopen bypasses)
- **Reproduction Confidence:** How reliably can we trigger the vulnerability in
  an automated test? (5 = deterministic one-liner; 1 = timing-dependent or
  needs complex multi-step setup)
- **TSM Coverage:** How many TSM mechanisms engage, and how strong is the
  detection? (5 = multiple independent detection paths; 1 = single weak signal)

---

## Recommended Priority Order

Based on the feasibility matrix and the diversity of TSM mechanisms exercised:

### Tier 1: Implement First

1. **CVE-2021-3156 (sudo)** -- Composite 4.50. Trivial build, deterministic
   trigger, exercises canary detection (the TSM's primary heap overflow defense).
   The setuid caveat is solved by running in a container. This is the "hello
   world" of the CVE Arena.

2. **CVE-2025-49844 (Redis)** -- Composite 4.50. Trivial build, exercises the
   generational arena and quarantine queue (the TSM's primary UAF defense).
   This is the highest-severity CVE (CVSS 10.0) and validates the TSM's most
   architecturally novel feature. Lua script crafting adds some complexity but
   public exploit code is available.

3. **CVE-2024-6197 (curl)** -- Composite 4.50. Exercises the foreign-pointer
   detection path (bloom + page oracle + IgnoreForeignFree) -- a unique detection
   mechanism not tested by the other candidates. The TLS server setup adds
   friction but is automatable.

### Tier 2: Implement Second

4. **CVE-2024-56406 (Perl)** -- Composite 4.25. Very easy trigger but exercises
   only canary detection (same mechanism as CVE-2021-3156). Include this for
   breadth -- it demonstrates the TSM detecting overflow in a different software
   ecosystem (scripting language runtime vs. system utility).

### Tier 3: Stretch Goal

5. **CVE-2024-46461 (VLC)** -- Composite 2.75. The build complexity and MMS
   stream crafting make this expensive for limited additional TSM coverage. Defer
   unless the team has bandwidth. The integer-overflow-to-heap-overflow chain is
   interesting but the TSM's response is identical to the direct-overflow cases.

---

## References

- [Qualys Advisory: CVE-2021-3156 Baron Samedit](https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit)
- [curl Advisory: CVE-2024-6197](https://curl.se/docs/CVE-2024-6197.html)
- [JFrog Analysis: CVE-2024-6197](https://jfrog.com/blog/curl-and-libcurl-uaf-cve-2024-6197/)
- [oss-security: CVE-2024-56406 Perl tr/// overflow](https://seclists.org/oss-sec/2025/q2/48)
- [CVE News: CVE-2024-56406 analysis](https://www.cve.news/cve-2024-56406/)
- [VideoLAN Security Advisory: CVE-2024-46461](https://www.videolan.org/security/sb-vlc3021.html)
- [Redis Security Advisory: CVE-2025-49844](https://redis.io/blog/security-advisory-cve-2025-49844/)
- [Wiz Research: RediShell CVE-2025-49844](https://www.wiz.io/blog/wiz-research-redis-rce-cve-2025-49844)
- [NVD: CVE-2025-49844](https://nvd.nist.gov/vuln/detail/CVE-2025-49844)
- [Public Exploit: redis_exploit (CVE-2025-49844)](https://github.com/raminfp/redis_exploit)
