# Gemini Code Review Summary

## 2026-04-16 - Cross-cutting ABI and Concurrency Deep Dive

### Module: `crates/frankenlibc-abi/src/unistd_abi.rs` (and project-wide `std::fs` usage)

**Finding 5: Pervasive `std::fs` usage in ABI layer causing unbound re-entry and memory corruption (Critical)**
- **Location:** `crates/frankenlibc-abi/src/*.rs` (84+ occurrences across `unistd_abi.rs`, `resolv_abi.rs`, `pthread_abi.rs`, etc.)
- **Root Cause:** The ABI layer uses Rust's standard library file IO (`std::fs::read`, `std::fs::read_to_string`, `std::fs::File::open`, `std::fs::metadata`) to read system files like `/proc/self/auxv`, `/proc/meminfo`, `/proc/self/maps`, and config files like `/etc/resolv.conf`, `/etc/hosts`, etc.
- **Risk:** Rust's `std::fs` is built on top of the host `libc` (`open64`, `read`, `close`, `fstat`). Since FrankenLibC actively interposes these exact functions, calling `std::fs` from within an interposed function causes deep re-entry into the ABI layer. Furthermore, `std::fs::read_to_string` allocates heap memory (`Vec`/`String`). If this happens during early bootstrap, inside a signal handler, or while resolving an allocation policy, it will cause infinite recursion, deadlock, or use-after-free corruption.
- **Suggested Fix:** Replace ALL instances of `std::fs` and `std::io::BufReader` in the `frankenlibc-abi` crate with raw syscall wrappers (`frankenlibc_core::syscall::sys_open`, `sys_read`, `sys_close`) reading into stack-allocated buffers (e.g., `[u8; 1024]`). The ABI layer must be strictly self-contained and allocation-free when reading OS metadata.

### Module: `crates/frankenlibc-abi/src/malloc_abi.rs`

**Finding 6: Global `AtomicBool` reentry guards cause false sharing and serialization (Important)**
- **Location:** `native_libc_malloc`, `native_libc_calloc`, `native_libc_realloc`, `native_libc_free`
- **Root Cause:** To prevent re-entry into the host allocator during symbol resolution, the code uses a single process-wide `AtomicBool` (`NATIVE_MALLOC_REENTRY.compare_exchange(...)`). If a thread fails to acquire this global lock, it falls back to the fixed-size `bump_alloc`. 
- **Risk:** In a multi-threaded application, if Thread A is legitimately inside the host `malloc` (or symbol resolution), and Thread B calls `malloc` concurrently, Thread B will fail the `compare_exchange` and be forced into the static `bump_alloc` heap. This means concurrent allocations rapidly exhaust the 256MB bump heap, bypassing the host allocator entirely and eventually crashing the process with OOM.
- **Suggested Fix:** Re-entry tracking must be thread-local, not process-global. Since TLS might not be available during early bootstrap, use a two-tiered approach: a global boot phase flag (for before threads exist), and standard `#[thread_local]` or `core_self_tid()` checks afterward to allow concurrent host allocations.

### Module: `crates/frankenlibc-abi/src/stdio_abi.rs`

**Finding 7: Heap allocation inside `stdio` stream registry initialization (Important)**
- **Location:** `registry()` singleton initialization
- **Root Cause:** The lazy initialization uses `Box::new(Mutex::new(StreamRegistry::new()))`.
- **Risk:** `Box::new` invokes the global allocator. This initialization can be triggered the very first time a program calls `printf`, `fopen`, or any `stdio` function. If the global allocator is also heavily interposed or triggers tracing that calls `stdio`, this will result in a recursive call back to `registry()`, deadlocking the process on the `std::hint::spin_loop()`.
- **Suggested Fix:** Statically allocate the `StreamRegistry` using `OnceLock<Mutex<StreamRegistry>>` or `parking_lot::Mutex` without `Box::new`. Pre-compute the `HashMap` entries in a static context or use an array-backed slotmap for the standard streams to avoid any heap allocation during lazy `stdio` initialization.

## 2026-04-18 - Recent Commits & Diff Review

### Module: `crates/frankenlibc-abi/src/search_abi.rs`

**Finding 8: POSIX Parity Regression in `hsearch` (Critical)**
- **Location:** `HashTable::search` (commit 65a8f6e)
- **Root Cause:** The `ENTER` action was modified to overwrite existing data for an already-present key. The commit message incorrectly claims this matches POSIX.
- **Risk:** POSIX explicitly states for `hsearch`: "If action is ENTER and the item is found in the table, it is not overwritten." The commit changed `hsearch` to overwrite the existing entry, strictly violating the POSIX specification and recreating a known legacy bug (pre-glibc 2.3).
- **Suggested Fix:** Revert the data overwrite logic `if action == Action::ENTER { slot.data = item.data; }` when `keys_equal` matches. Revert the test in `search_abi_test.rs` to assert the data remains unchanged.

**Finding 10: Critical ABI signature mismatch in `twalk_r` callback leading to guaranteed SIGSEGV (Critical)**
- **Location:** `twalk_r` (line ~430)
- **Root Cause:** The Rust implementation of GNU's `twalk_r` assumes the callback takes 4 arguments: `action: unsafe extern "C" fn(*const c_void, c_int, c_int, *mut c_void)`. It calls it with `action(node_ptr, Visit::Preorder as c_int, level, closure)`. However, the C API for `twalk_r` specifies that the action callback takes only 3 arguments: `void (*action)(const void *nodep, VISIT which, void *closure)`.
- **Risk:** By passing 4 arguments from the Rust side to a C callback that expects 3, the 3rd argument in the C ABI (e.g., `rdx` on x86_64) will be populated by `level` (an integer), not `closure` (a pointer). When the C code tries to dereference `closure`, it will actually be dereferencing `level` (e.g., `0`, `1`, `2`), resulting in an immediate `SIGSEGV`.
- **Suggested Fix:** Remove the `level` parameter from both the `twalk_r` action signature and the internal `twalk_r_recursive` calls. Change the invocation to `action(node_ptr, Visit::Preorder as c_int, closure)` to perfectly match the GNU C API.

### Module: `crates/frankenlibc-abi/src/signal_abi.rs`

**Finding 9: Segfault vulnerability in `sigaltstack` wrapper (Critical)**
- **Location:** `sigaltstack` (uncommitted diff)
- **Root Cause:** The fast-path checks `let is_disable = !ss.is_null() && unsafe { (*ss).ss_flags } & libc::SS_DISABLE != 0;` before the raw syscall.
- **Risk:** `ss` is an untrusted user pointer. If an application provides an invalid pointer (e.g., `0x1`), `ss.is_null()` is false, but dereferencing `(*ss).ss_flags` will instantly crash the process with SIGSEGV. The raw syscall `sys_sigaltstack` natively validates pointers and gracefully returns `EFAULT`. By dereferencing it beforehand in the ABI wrapper, you introduce a crash vulnerability and violate the `EFAULT` C ABI standard.
- **Suggested Fix:** Do not blindly dereference `ss`. If you need to read it for the `SS_DISABLE` optimization, execute the raw `sys_sigaltstack` first and rely on the kernel's validation. If the syscall succeeds, then you know it's safe to read `old_ss` (if needed) or apply policy changes. Or, use a safe memory probe (`core_probe_read`) before checking the flag.

### Module: `crates/frankenlibc-abi/src/locale_abi.rs`

**Finding 11: Unbounded memory leak in `textdomain` and `bindtextdomain` (Important)**
- **Location:** `textdomain`, `bindtextdomain` (lines ~300-360)
- **Root Cause:** Both functions convert the input string to a `CString` via `CString::new`, and unconditionally push it into a `Vec<CString>` (`current.pool.push(owned)` or `bindings.pool.push(owned)`) on every invocation, never freeing older strings for the same domain.
- **Risk:** Any application that dynamically calls `textdomain()` or `bindtextdomain()` repeatedly over its lifetime will leak memory proportionally to the number of calls. While glibc maintains global strings, it does not leak unboundedly on repeated calls.
- **Suggested Fix:** Store exactly one `CString` per domain in `current_by_domain` (or globally for `textdomain`) and drop/replace the old one when a new one is set, rather than appending indefinitely to a `Vec`.

---
*End of Report*