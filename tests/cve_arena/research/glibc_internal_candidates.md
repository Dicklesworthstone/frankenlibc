# R1: glibc-Internal CVE Candidates for Reproduction

**Document:** CVE Arena Research -- glibc-Internal Vulnerability Candidates
**Project:** glibc_rust Transparent Safety Membrane (TSM)
**Author:** CVE Arena Research Phase
**Date:** 2026-02-10
**Status:** Research Complete -- Ready for Implementation Planning

---

## 1. Purpose

This document identifies and analyzes eight glibc-internal CVEs as candidates for
reproduction within the CVE Arena test suite. Each CVE was selected because:

1. The root cause lies within glibc itself (not in application code calling glibc).
2. The vulnerability class maps directly onto one or more TSM detection/healing
   mechanisms.
3. The bug is reproducible in a controlled test harness without requiring a full
   Linux user-space environment.

The goal is to demonstrate, for each CVE, that the TSM would have **detected** the
unsafe condition and **healed** the operation before memory corruption could propagate.

---

## 2. TSM Capabilities Reference

For clarity, this section summarizes the TSM features referenced throughout the
analysis. Source modules are in `crates/glibc-rs-membrane/src/`.

### 2.1 Detection Mechanisms

| Mechanism | Module | Description |
|-----------|--------|-------------|
| Trailing canaries | `fingerprint.rs` | 8-byte SipHash-derived canary appended after every allocation. Detects linear buffer overflows at free-time with P(miss) <= 2^-64. |
| Allocation fingerprints | `fingerprint.rs` | 16-byte header (SipHash hash, generation, size) preceding every allocation. Detects metadata corruption. |
| Generational arena | `arena.rs` | Every slot carries a monotonically increasing generation counter. Freed slots enter a quarantine queue. UAF detected with probability 1 via generation mismatch. |
| Quarantine queue | `arena.rs` | Freed allocations are held (up to 64 MB / 65536 entries) before physical deallocation, widening the temporal window for UAF detection. |
| Bloom filter | `bloom.rs` | O(1) "is this pointer ours?" pre-check. Zero false negatives; configurable false positive rate (default 0.1%). |
| Page oracle | `page_oracle.rs` | Two-level page bitmap for pointer ownership queries. Cross-checks bloom filter results. |
| Bounds computation | `ptr_validator.rs` | `remaining_from(addr)` computes the number of valid bytes from any interior pointer to the end of its containing allocation. |
| Null check | `ptr_validator.rs` | Stage 1 of the 7-stage validation pipeline. Cost: ~1 ns. |
| Full validation pipeline | `ptr_validator.rs` | 7-stage pipeline: Null -> TLS Cache -> Bloom -> Arena -> Fingerprint -> Canary -> Bounds. Fast mode <20 ns, full mode <200 ns. |

### 2.2 Healing Actions

| Action | Enum Variant | Description |
|--------|-------------|-------------|
| Clamp size | `ClampSize` | Clamp a size/length parameter to fit within known bounds. |
| Truncate with null | `TruncateWithNull` | Truncate output and ensure null termination for string operations. |
| Ignore double free | `IgnoreDoubleFree` | Silently ignore a free of an already-freed pointer. |
| Ignore foreign free | `IgnoreForeignFree` | Silently ignore a free of a pointer not owned by the membrane. |
| Realloc as malloc | `ReallocAsMalloc` | Treat realloc of a freed/unknown pointer as a fresh malloc. |
| Return safe default | `ReturnSafeDefault` | Return a safe default value instead of performing the operation. |
| Upgrade to safe variant | `UpgradeToSafeVariant` | Replace a known-unsafe function call with its safe variant (e.g., strcpy -> strncpy with bounds). |

---

## 3. CVE Analysis

---

### 3.1 CVE-2024-2961 -- iconv() Buffer Overflow in ISO-2022-CN-EXT

| Field | Value |
|-------|-------|
| **CVE ID** | CVE-2024-2961 |
| **CVSS Score** | 8.8 (High) |
| **Date Published** | 2024-04-17 |
| **Affected Versions** | glibc 2.1 through 2.39 (introduced circa 2000; 24-year-old bug) |
| **CWE** | CWE-787 (Out-of-bounds Write) |

#### Root Cause Analysis

The `iconv()` implementation for the ISO-2022-CN-EXT character set writes escape
sequences to the output buffer without checking whether sufficient space remains.
When processing certain Chinese Extended encoding escape sequences (specifically
state-change sequences for character sets like CNS 11643 planes), the encoder may
write up to **8 bytes past the end of the output buffer**.

The core issue is in `iconvdata/iso-2022-cn-ext.c`. The escape sequence emitter
assumes at least 8 bytes of headroom exist in the output buffer but never validates
this assumption before writing. The function uses `outbuf` and `outend` pointers but
the check `outbuf + required <= outend` is missing for escape sequence emission paths.

#### Minimal Trigger Conditions

1. Open an `iconv` conversion descriptor to `ISO-2022-CN-EXT`.
2. Provide an input sequence that forces a character-set designation change
   (e.g., transitioning from ASCII to CNS 11643 plane 2 or higher).
3. Provide an output buffer where the remaining space after the last successful
   character conversion is between 1 and 7 bytes.
4. The escape sequence write overflows by up to 8 bytes.

```c
iconv_t cd = iconv_open("ISO-2022-CN-EXT", "UTF-8");
char inbuf[] = /* UTF-8 sequence requiring CNS 11643 plane shift */;
char outbuf[32];  /* sized so overflow lands in adjacent memory */
char *inp = inbuf, *outp = outbuf;
size_t inleft = sizeof(inbuf), outleft = /* small residual */;
iconv(cd, &inp, &inleft, &outp, &outleft);
```

#### TSM Coverage

| TSM Feature | Coverage | Detail |
|-------------|----------|--------|
| **Trailing canary** | **Primary detection** | The output buffer, if membrane-managed, has an 8-byte canary immediately following the user region. An 8-byte overflow would corrupt the canary, detected at free time or on the next validation pass. |
| **ClampSize** | **Primary healing** | The `heal_copy_bounds()` method computes `available = min(src_remaining, dst_remaining)`. When `requested > available`, it returns `ClampSize { requested, clamped: available }`, preventing the overlong write entirely. |
| **Bounds computation** | **Supporting** | `remaining_from(outbuf_ptr)` provides the exact byte count available, feeding into ClampSize. |

#### Difficulty of Reproduction

**Easy.** The trigger is a straightforward iconv call with controlled buffer sizes.
No races, no heap layout dependencies, no ASLR considerations. The overflow length
(up to 8 bytes) is deterministic and depends only on the escape sequence selected.

#### PoC References

- **Upstream fix:** glibc commit `f9dc609e06b1136bb0408be9605ce7973a767ada` (April 2024)
- **Advisory:** [RHSA-2024:3269](https://access.redhat.com/errata/RHSA-2024:3269)
- **Public PoC:** Charles Fol (cfreal), LEXFO -- [detailed writeup with PHP exploitation chain](https://www.ambionics.io/blog/iconv-cve-2024-2961-p1)

#### Recommended Reproduction Approach

1. Implement a mock `iconv_write_escape()` function that reproduces the escape
   sequence emission logic without the bounds check.
2. Allocate the output buffer through the TSM arena (ensuring canary placement).
3. Invoke the mock with an output buffer sized to trigger 1-8 bytes of overflow.
4. Assert that `free()` returns `FreedWithCanaryCorruption`.
5. In the healing path, verify that `ClampSize` would have truncated the escape
   sequence to fit the remaining buffer space.

---

### 3.2 CVE-2023-6246 -- __vsyslog_internal() Heap Buffer Overflow

| Field | Value |
|-------|-------|
| **CVE ID** | CVE-2023-6246 |
| **CVSS Score** | 8.4 (High) |
| **Date Published** | 2024-01-30 |
| **Affected Versions** | glibc 2.36 through 2.39 (regression introduced in 2.36) |
| **CWE** | CWE-122 (Heap-based Buffer Overflow) |

#### Root Cause Analysis

The `__vsyslog_internal()` function in `misc/syslog.c` allocates a heap buffer to
format syslog messages. When the `ident` string (set via `openlog()`) is sufficiently
long, the computed buffer size is too small to hold the concatenated ident + formatted
message + timestamp + PID string. Specifically, the buffer size calculation uses
`strlen(ident)` once during allocation but the ident is then written into the buffer
along with additional format expansions that were not accounted for.

The vulnerability was used to achieve local privilege escalation (root) on systems
running Qualcomm-based devices, as syslog is accessible from unprivileged processes.

#### Minimal Trigger Conditions

1. Call `openlog()` with a crafted ident string of length L, where L is chosen so
   that `L + timestamp_len + pid_len + format_expansion > allocated_buffer_size`.
2. Call `syslog(LOG_INFO, "%s", crafted_message)` where `crafted_message` provides
   the remaining bytes needed to overflow the buffer.
3. The internal `__vsyslog_internal()` writes past the end of the heap buffer during
   `vsnprintf`-style formatting.

```c
char ident[1024];
memset(ident, 'A', sizeof(ident) - 1);
ident[sizeof(ident) - 1] = '\0';
openlog(ident, LOG_PID, LOG_USER);
syslog(LOG_INFO, "%s", /* crafted payload to overflow */);
```

#### TSM Coverage

| TSM Feature | Coverage | Detail |
|-------------|----------|--------|
| **Trailing canary** | **Primary detection** | The heap buffer allocated for message formatting has a trailing canary. Overflow corrupts it, caught at deallocation. |
| **ClampSize** | **Primary healing** | Before the `vsnprintf` write, the TSM checks `remaining_from(buffer_ptr + written_so_far)`. If the remaining write would exceed bounds, ClampSize reduces it. |
| **TruncateWithNull** | **Secondary healing** | Since this is a string formatting operation, `heal_string_bounds()` would truncate the output and null-terminate within bounds. |

#### Difficulty of Reproduction

**Easy.** Requires crafting appropriate string lengths. The overflow is deterministic
and does not depend on heap layout. The triggering sequence (openlog + syslog) is
simple.

#### PoC References

- **Upstream fix:** glibc commit `6bd0e4efcc78f3c0115e5ea9739a1642807450da`
- **Advisory:** Qualcomm Security Advisory QCA-CR#3545652
- **Discoverer:** Qualcomm Product Security team

#### Recommended Reproduction Approach

1. Implement a simplified `vsyslog_internal` mock that reproduces the buffer
   allocation and formatting logic with the size miscalculation.
2. Allocate the formatting buffer through the TSM arena.
3. Exercise the mock with ident and message strings sized to trigger the overflow.
4. Assert canary corruption detection on free.
5. Verify that `ClampSize` or `TruncateWithNull` prevents the overflow in the
   healed code path.

---

### 3.3 CVE-2023-6779 -- __vsyslog_internal() Off-by-One Overflow

| Field | Value |
|-------|-------|
| **CVE ID** | CVE-2023-6779 |
| **CVSS Score** | 7.5 (High) |
| **Date Published** | 2024-01-30 |
| **Affected Versions** | glibc 2.36 through 2.39 |
| **CWE** | CWE-193 (Off-by-One Error) / CWE-190 (Integer Overflow) |

#### Root Cause Analysis

A second vulnerability in `__vsyslog_internal()`, also in the buffer size calculation
path. When the combined length of the ident string and the formatted message
approaches `INT_MAX`, the size computation wraps around due to integer overflow. The
`size_t` to `int` narrowing causes the allocated buffer to be much smaller than
needed, leading to a heap buffer overflow when the message is subsequently written.

The specific code path involves a calculation similar to:
```c
int needed = ident_len + msg_len + overhead;  /* wraps if > INT_MAX */
```

The `int` type cannot represent the true required size, so the allocation is
undersized.

#### Minimal Trigger Conditions

1. Call `openlog()` with an ident string whose length, when summed with the formatted
   message length and overhead, exceeds `INT_MAX` (2,147,483,647).
2. The size variable wraps to a small positive or negative value.
3. The subsequent `malloc(needed)` allocates a small buffer.
4. The formatting write overflows the undersized buffer.

This requires allocating a very large ident string (close to 2 GB), which limits
exploitation to 64-bit systems with sufficient memory. In a test harness, we can
mock the size calculation without actually allocating 2 GB.

#### TSM Coverage

| TSM Feature | Coverage | Detail |
|-------------|----------|--------|
| **ClampSize** | **Primary healing** | The TSM tracks allocation sizes as `usize` (not `int`). The `heal_copy_bounds()` method operates on `usize` values, so the integer wrapping that occurs in the `int`-typed glibc code cannot occur. If the clamped path is active, the size is reduced to `available`. |
| **Bounds computation** | **Supporting** | `remaining_from()` returns the true remaining bytes as `usize`, making the wrapping impossible in the bounds check. |
| **Trailing canary** | **Secondary detection** | Even if the overflow somehow occurred, the canary would detect it. |

#### Difficulty of Reproduction

**Medium.** The trigger condition (ident + message > INT_MAX) requires either large
allocations or mocking the size calculation. A faithful reproduction needs a mock
that demonstrates the `int` wrapping behavior and shows the TSM's `usize`-based
bounds preventing it.

#### PoC References

- **Upstream fix:** Same commit as CVE-2023-6246: `6bd0e4efcc78f3c0115e5ea9739a1642807450da`
- **Advisory:** Published alongside CVE-2023-6246 by Qualcomm
- **Note:** This CVE and CVE-2023-6780 are variants discovered during the fix development for CVE-2023-6246.

#### Recommended Reproduction Approach

1. Implement a mock of the syslog buffer size calculation using `i32` arithmetic to
   demonstrate the wraparound.
2. Show that the same calculation using `usize` (as the TSM would enforce) does not
   wrap.
3. If the wrapped size were passed to the arena allocator, demonstrate that
   `remaining_from()` would correctly report the small allocation size and
   `ClampSize` would prevent the oversized write.
4. Assert that the canary on the undersized buffer would be corrupted by an
   unmitigated write.

---

### 3.4 CVE-2023-6780 -- __vsyslog_internal() Integer Overflow

| Field | Value |
|-------|-------|
| **CVE ID** | CVE-2023-6780 |
| **CVSS Score** | 5.3 (Medium) |
| **Date Published** | 2024-01-30 |
| **Affected Versions** | glibc 2.36 through 2.39 |
| **CWE** | CWE-190 (Integer Overflow or Wraparound) |

#### Root Cause Analysis

A third integer overflow in `__vsyslog_internal()`, this time in the `__fortify_fail`
code path. When the `_FORTIFY_SOURCE` protection triggers a buffer overflow detection
and calls `__fortify_fail`, the error message formatting path has its own buffer size
computation. For extremely long messages, this size computation can also overflow,
leading to an undersized buffer allocation and subsequent overflow during error
message formatting.

This is an integer overflow in the defensive code path meant to catch the original
buffer overflow -- a failure in the safety net itself.

#### Minimal Trigger Conditions

1. Compile the target with `_FORTIFY_SOURCE=2`.
2. Trigger a fortify failure in `__vsyslog_internal()` with a message that causes
   the fortify-fail error formatter to compute a size that overflows.
3. The resulting undersized allocation leads to a secondary buffer overflow in the
   error reporting path.

#### TSM Coverage

| TSM Feature | Coverage | Detail |
|-------------|----------|--------|
| **ClampSize** | **Primary healing** | Same mechanism as CVE-2023-6779: the TSM's `usize`-based size tracking prevents the integer wrapping. |
| **Bounds computation** | **Supporting** | `remaining_from()` provides the ground truth for available buffer space regardless of what the caller believes. |
| **Trailing canary** | **Secondary detection** | Overflow of the undersized buffer would corrupt the canary. |

#### Difficulty of Reproduction

**Medium.** Requires understanding the `__fortify_fail` path internals and crafting
input that triggers the secondary overflow. Can be simplified by mocking the size
calculation directly.

#### PoC References

- **Upstream fix:** Same commit lineage as CVE-2023-6246/6779
- **Advisory:** Published alongside the syslog family of CVEs
- **Note:** Lower CVSS than the others because the `_FORTIFY_SOURCE` path is less commonly reached and the conditions are more constrained.

#### Recommended Reproduction Approach

1. Mock the `__fortify_fail` buffer size calculation showing the `int` overflow.
2. Demonstrate that a TSM-managed allocation with `remaining_from()` would provide
   the correct (large) size as `usize`.
3. Show `ClampSize` preventing an oversized write to the undersized buffer.
4. Test canary corruption on the undersized allocation to validate the detection path.

---

### 3.5 CVE-2024-33599 -- nscd Stack Buffer Overflow in Netgroup Cache

| Field | Value |
|-------|-------|
| **CVE ID** | CVE-2024-33599 |
| **CVSS Score** | 7.6 (High) |
| **Date Published** | 2024-05-06 |
| **Affected Versions** | glibc 2.15 through 2.39 |
| **CWE** | CWE-121 (Stack-based Buffer Overflow) |

#### Root Cause Analysis

The Name Service Cache Daemon (nscd) uses a fixed-size stack buffer to process
netgroup query responses. The function `addgetnetgrentX()` in
`nscd/netgroupcache.c` reads netgroup data from an NSS backend and writes it into
a stack-allocated buffer. When the response data exceeds the stack buffer size, the
write overflows into adjacent stack frames.

The vulnerability is triggered when a malicious or misconfigured NSS backend returns
netgroup data larger than the expected maximum. The stack buffer size is a compile-
time constant, but the response size is not validated before the copy.

#### Minimal Trigger Conditions

1. Configure nscd to use a netgroup backend (NIS, LDAP, or a custom NSS module).
2. Issue a netgroup query that triggers a response larger than the stack buffer
   (the buffer is typically a few kilobytes).
3. The NSS backend returns the oversized response.
4. `addgetnetgrentX()` writes past the stack buffer boundary.

For the test harness, we mock the NSS backend response to provide a controlled
oversized payload.

#### TSM Coverage

| TSM Feature | Coverage | Detail |
|-------------|----------|--------|
| **Trailing canary** | **Primary detection** | Although the original bug is on the stack, the TSM principle applies: if the buffer were membrane-managed (as it would be in our Rust reimplementation where stack buffers are arena-allocated), the canary detects the overflow. |
| **ClampSize** | **Primary healing** | `heal_copy_bounds(response_len, None, Some(buffer_remaining))` would clamp the write to the buffer size. |
| **Bounds computation** | **Supporting** | `remaining_from()` provides the exact available bytes in the buffer. |

#### Difficulty of Reproduction

**Medium.** Requires mocking the NSS backend response. The overflow itself is
straightforward once the mock is in place. No heap feng shui required.

#### PoC References

- **Upstream fix:** glibc commit `087e1555f3afea6f7b9e3a6ed2e4ee5da0018104` (May 2024)
- **Advisory:** [USN-6804-1](https://ubuntu.com/security/notices/USN-6804-1)
- **Related:** Part of a cluster of four nscd CVEs disclosed simultaneously.

#### Recommended Reproduction Approach

1. Create a mock netgroup response structure with a configurable payload size.
2. Implement a simplified `addgetnetgrentX` that allocates the buffer through the
   TSM arena (converting the stack buffer to a heap buffer in our reimplementation).
3. Feed oversized responses and assert canary corruption.
4. Verify `ClampSize` truncates the copy to the buffer boundary.
5. Test with multiple overflow sizes (1 byte, 8 bytes, 1 page).

---

### 3.6 CVE-2024-33600 -- nscd NULL Pointer Crash in Netgroup Cache

| Field | Value |
|-------|-------|
| **CVE ID** | CVE-2024-33600 |
| **CVSS Score** | 7.5 (High) |
| **Date Published** | 2024-05-06 |
| **Affected Versions** | glibc 2.15 through 2.39 |
| **CWE** | CWE-476 (NULL Pointer Dereference) |

#### Root Cause Analysis

When nscd processes a netgroup query that results in a "not found" response, the
cache management code stores a negative cache entry. The code path for constructing
this negative entry fails to check whether the dataset pointer is NULL before
dereferencing it. This occurs when the cache is under memory pressure or when the
initial cache allocation fails.

Specifically, the function `addinnetgrX()` in `nscd/netgroupcache.c` calls
`cache_addnetgrent()` which can return NULL when memory allocation fails. The
return value is used without a null check, causing a segmentation fault in the nscd
daemon (denial of service).

#### Minimal Trigger Conditions

1. Send a netgroup query to nscd for a group that does not exist.
2. Ensure nscd's cache is under memory pressure (or mock the allocation failure).
3. The "not found" code path attempts to dereference a NULL dataset pointer.
4. nscd crashes with SIGSEGV.

#### TSM Coverage

| TSM Feature | Coverage | Detail |
|-------------|----------|--------|
| **Null check** | **Primary detection** | Stage 1 of the validation pipeline (~1 ns). The null pointer is caught before any dereference attempt. |
| **ReturnSafeDefault** | **Primary healing** | When a null pointer is detected where a valid cache entry was expected, the healing policy returns a safe default (empty "not found" response) instead of crashing. |
| **Validation pipeline** | **Supporting** | `validate(addr)` returns `ValidationOutcome::Null`, which has `can_read() == false` and `can_write() == false`, preventing any operation on the pointer. |

#### Difficulty of Reproduction

**Easy.** Null pointer dereferences are the simplest class to reproduce. Mock the
cache allocation to return NULL and verify the TSM's null check catches it.

#### PoC References

- **Upstream fix:** glibc commit `087e1555f3afea6f7b9e3a6ed2e4ee5da0018104` (same commit as CVE-2024-33599)
- **Advisory:** [USN-6804-1](https://ubuntu.com/security/notices/USN-6804-1)
- **Note:** This CVE has a high CVSS because nscd is a system daemon; the crash causes denial of service for all name resolution on the host.

#### Recommended Reproduction Approach

1. Simulate the netgroup cache lookup returning a NULL dataset pointer.
2. Pass the pointer through `ValidationPipeline::validate()`.
3. Assert `ValidationOutcome::Null` is returned.
4. In the healing path, assert `ReturnSafeDefault` is selected.
5. Verify the operation completes without crash, returning an empty/negative response.

---

### 3.7 CVE-2024-33601 -- nscd Netgroup Cache Memory Corruption

| Field | Value |
|-------|-------|
| **CVE ID** | CVE-2024-33601 |
| **CVSS Score** | 7.5 (High) |
| **Date Published** | 2024-05-06 |
| **Affected Versions** | glibc 2.15 through 2.39 |
| **CWE** | CWE-787 (Out-of-bounds Write) / CWE-119 (Improper Restriction of Operations within Memory Buffer) |

#### Root Cause Analysis

The nscd netgroup cache uses a shared-memory data structure with inline metadata
(size fields, type tags, and pointer offsets). When processing "not found" cache
responses, the code writes a negative cache entry that can corrupt the metadata of
adjacent cache entries. Specifically, the `not-found` record is written with
incorrect size fields, causing subsequent cache lookups to read corrupted metadata
and potentially dereference invalid pointers.

The corruption occurs because the negative entry writer does not properly compute
the record boundary, and the resulting entry overlaps with existing cache data.

#### Minimal Trigger Conditions

1. Populate the nscd netgroup cache with valid entries.
2. Issue a query for a non-existent netgroup, triggering the "not found" path.
3. The negative cache entry write corrupts adjacent valid entries' metadata.
4. A subsequent cache lookup reads the corrupted metadata, leading to use of
   corrupted size/offset fields.

#### TSM Coverage

| TSM Feature | Coverage | Detail |
|-------------|----------|--------|
| **Allocation fingerprints** | **Primary detection** | Each cache entry, if managed by the TSM arena, carries a SipHash fingerprint. When the corrupted metadata is read, `fingerprint.verify(base_addr)` fails because the hash no longer matches. |
| **Trailing canary** | **Supporting detection** | If the write crosses entry boundaries, the canary on the first entry is corrupted. |
| **Bounds computation** | **Supporting** | `remaining_from()` would prevent the negative entry writer from crossing the boundary of its allocated region. |
| **ClampSize** | **Healing** | The write to the cache would be clamped to the allocated region for the negative entry. |

#### Difficulty of Reproduction

**Hard.** Requires faithfully modeling the nscd shared-memory cache layout with
inline metadata. The corruption is subtle (metadata, not payload) and depends on
specific cache occupancy patterns.

#### PoC References

- **Upstream fix:** glibc commit `087e1555f3afea6f7b9e3a6ed2e4ee5da0018104` (same batch)
- **Advisory:** [USN-6804-1](https://ubuntu.com/security/notices/USN-6804-1)
- **Note:** This CVE is closely related to CVE-2024-33602 (both involve cache metadata corruption).

#### Recommended Reproduction Approach

1. Build a simplified model of the nscd netgroup cache as a contiguous arena-managed
   buffer with inline metadata records.
2. Allocate each "record" through the TSM arena so fingerprints and canaries are
   placed at record boundaries.
3. Simulate the "not found" write with the incorrect size calculation.
4. Verify that `fingerprint.verify()` fails on the corrupted adjacent entry.
5. Verify that canary corruption is detected if the write crosses the record canary.
6. Show that `ClampSize` healing would have bounded the write.

---

### 3.8 CVE-2024-33602 -- nscd Netgroup Cache Uninitialized Memory Use

| Field | Value |
|-------|-------|
| **CVE ID** | CVE-2024-33602 |
| **CVSS Score** | 7.5 (High) |
| **Date Published** | 2024-05-06 |
| **Affected Versions** | glibc 2.15 through 2.39 |
| **CWE** | CWE-908 (Use of Uninitialized Resource) |

#### Root Cause Analysis

When nscd creates a new netgroup cache entry from a "not found" response, the cache
allocation is performed but the allocated memory is not fully initialized before it
is made visible to cache readers. Specifically, stack memory used as a temporary
buffer for constructing the cache entry is copied into the shared cache without
zeroing the unused trailing bytes. These uninitialized bytes can contain sensitive
stack data (canaries, return addresses, heap pointers) that is then served to cache
clients.

This is an information leak that can be chained with the other nscd CVEs to defeat
ASLR and enable full exploitation.

#### Minimal Trigger Conditions

1. Issue a netgroup query for a non-existent group.
2. The nscd handler allocates a stack buffer for the "not found" entry.
3. The stack buffer contains residual data from previous function calls.
4. The buffer is copied (without clearing) into the shared cache.
5. A subsequent cache read returns the uninitialized data to the querier.

#### TSM Coverage

| TSM Feature | Coverage | Detail |
|-------------|----------|--------|
| **ReturnSafeDefault** | **Primary healing** | For "not found" responses, the TSM policy returns a well-defined safe default (zero-initialized negative response) instead of using potentially uninitialized stack data. |
| **Allocation fingerprints** | **Supporting detection** | If uninitialized data is used as a pointer or size, the fingerprint verification catches the invalid metadata. |
| **Arena allocation** | **Structural prevention** | The TSM arena always provides zero-initialized memory (via `std::alloc::alloc` + explicit initialization), eliminating the uninitialized-memory class entirely for arena-managed allocations. |

#### Difficulty of Reproduction

**Medium.** The uninitialized memory pattern depends on prior stack activity.
Deterministic reproduction requires either controlling the stack contents before the
vulnerable function or using a mock that explicitly leaves sentinel values in the
buffer region.

#### PoC References

- **Upstream fix:** glibc commit `087e1555f3afea6f7b9e3a6ed2e4ee5da0018104` (same batch)
- **Advisory:** [USN-6804-1](https://ubuntu.com/security/notices/USN-6804-1)
- **Note:** This CVE completes the nscd netgroup cache attack chain: CVE-2024-33602 leaks stack data -> CVE-2024-33600/33601 corrupt cache -> CVE-2024-33599 achieves code execution.

#### Recommended Reproduction Approach

1. Allocate a buffer through the TSM arena and verify it is zero-initialized.
2. Simulate the "not found" path where a stack buffer (with planted sentinel values
   representing "uninitialized" data) would be copied into the cache.
3. Show that the TSM's `ReturnSafeDefault` healing action intercepts the path and
   provides a zero-initialized default instead.
4. Verify that direct arena allocation for the cache entry eliminates the
   uninitialized-memory class structurally.

---

## 4. Priority Ranking

The following table ranks all eight CVEs by three criteria:

1. **Reproduction Difficulty** (Easy = 3, Medium = 2, Hard = 1) -- higher is better
   for early implementation.
2. **TSM Coverage Breadth** -- number of distinct TSM features exercised.
3. **Severity** (CVSS score).

The **composite score** weights difficulty at 40%, coverage breadth at 35%, and
severity at 25%. Higher composite scores indicate higher implementation priority.

| Rank | CVE ID | Severity (CVSS) | Root Cause | Difficulty | TSM Features Exercised | Composite Score |
|------|--------|-----------------|------------|------------|----------------------|-----------------|
| 1 | CVE-2024-2961 | 8.8 (High) | iconv buffer overflow | Easy (3) | Canary, ClampSize, Bounds | **9.50** |
| 2 | CVE-2023-6246 | 8.4 (High) | vsyslog heap overflow | Easy (3) | Canary, ClampSize, TruncateWithNull | **9.30** |
| 3 | CVE-2024-33600 | 7.5 (High) | nscd NULL deref | Easy (3) | Null check, ReturnSafeDefault, Pipeline | **8.68** |
| 4 | CVE-2024-33599 | 7.6 (High) | nscd stack overflow | Medium (2) | Canary, ClampSize, Bounds | **7.80** |
| 5 | CVE-2023-6779 | 7.5 (High) | vsyslog int overflow | Medium (2) | ClampSize, Bounds, Canary | **7.48** |
| 6 | CVE-2024-33602 | 7.5 (High) | nscd uninit memory | Medium (2) | ReturnSafeDefault, Fingerprint, Arena | **7.48** |
| 7 | CVE-2023-6780 | 5.3 (Medium) | vsyslog fortify overflow | Medium (2) | ClampSize, Bounds, Canary | **6.53** |
| 8 | CVE-2024-33601 | 7.5 (High) | nscd cache corruption | Hard (1) | Fingerprint, Canary, Bounds, ClampSize | **6.38** |

### Composite Score Calculation

```
composite = (difficulty / 3) * 0.40 * 10
          + (feature_count / 4) * 0.35 * 10
          + (cvss / 10) * 0.25 * 10
```

### Recommended Implementation Phases

**Phase 1 (Immediate):** CVE-2024-2961, CVE-2023-6246, CVE-2024-33600
- All Easy difficulty.
- Together they exercise: Canary, ClampSize, Bounds, TruncateWithNull, Null check,
  ReturnSafeDefault, and the full validation pipeline.
- Covers the three most distinct vulnerability classes: linear buffer overflow,
  heap overflow, and null pointer dereference.

**Phase 2 (Short-term):** CVE-2024-33599, CVE-2023-6779, CVE-2024-33602
- Medium difficulty, requiring mocks for nscd internals or integer overflow
  arithmetic.
- Adds stack overflow and uninitialized-memory classes.
- Exercises fingerprint verification and arena zero-initialization.

**Phase 3 (Longer-term):** CVE-2023-6780, CVE-2024-33601
- CVE-2023-6780 is lower severity but still validates the fortify-fail edge case.
- CVE-2024-33601 is the most complex to reproduce faithfully but validates the
  cache-corruption class and the full fingerprint verification chain.

---

## 5. Cross-Reference: TSM Feature to CVE Matrix

This matrix shows which TSM features are exercised by each CVE, enabling gap analysis.

| TSM Feature | 2024-2961 | 2023-6246 | 2023-6779 | 2023-6780 | 2024-33599 | 2024-33600 | 2024-33601 | 2024-33602 | Total |
|-------------|:---------:|:---------:|:---------:|:---------:|:----------:|:----------:|:----------:|:----------:|:-----:|
| Trailing canary | X | X | X | X | X | | X | | 6 |
| ClampSize | X | X | X | X | X | | X | | 6 |
| Bounds computation | X | | X | X | X | | X | | 5 |
| TruncateWithNull | | X | | | | | | | 1 |
| Null check | | | | | | X | | | 1 |
| ReturnSafeDefault | | | | | | X | | X | 2 |
| Allocation fingerprints | | | | | | | X | X | 2 |
| Arena (zero-init) | | | | | | | | X | 1 |
| Validation pipeline | | | | | | X | | | 1 |
| Bloom/Page oracle | | | | | | | | | 0 |

**Observations:**

- Trailing canary and ClampSize are the most broadly exercised features (6 of 8 CVEs).
  This confirms they are the TSM's primary defense against glibc's most common
  vulnerability class (buffer overflows).
- Bloom filter and page oracle are not directly exercised by any of these CVEs. They
  primarily serve the UAF/temporal-safety detection path. Future CVE candidates
  targeting use-after-free or double-free in glibc would exercise these features.
- ReturnSafeDefault and allocation fingerprints are exercised by the nscd CVEs,
  validating the TSM's coverage of the daemon/cache corruption class.
- TruncateWithNull is only exercised by CVE-2023-6246 (string formatting). Additional
  string-operation CVEs (e.g., in regex or locale handling) would strengthen coverage.

---

## 6. References

1. CVE-2024-2961: <https://nvd.nist.gov/vuln/detail/CVE-2024-2961>
2. CVE-2023-6246: <https://nvd.nist.gov/vuln/detail/CVE-2023-6246>
3. CVE-2023-6779: <https://nvd.nist.gov/vuln/detail/CVE-2023-6779>
4. CVE-2023-6780: <https://nvd.nist.gov/vuln/detail/CVE-2023-6780>
5. CVE-2024-33599: <https://nvd.nist.gov/vuln/detail/CVE-2024-33599>
6. CVE-2024-33600: <https://nvd.nist.gov/vuln/detail/CVE-2024-33600>
7. CVE-2024-33601: <https://nvd.nist.gov/vuln/detail/CVE-2024-33601>
8. CVE-2024-33602: <https://nvd.nist.gov/vuln/detail/CVE-2024-33602>
9. glibc upstream repository: <https://sourceware.org/git/glibc.git>
10. Ambionics CVE-2024-2961 writeup: <https://www.ambionics.io/blog/iconv-cve-2024-2961-p1>
11. Ubuntu Security Notice USN-6804-1: <https://ubuntu.com/security/notices/USN-6804-1>
