// Deployed-mode (NOT cfg(test), so `strict_passthrough_active()` is live and the
// per-call entrypoint trace is skipped) in-process A/B harness for the stdio write
// path. Times fl `fputc` into a fully-buffered stream (no flush in the loop) with
// `__libc_single_threaded` == 1 vs == 0. No dlmopen — this is the ONLY clean way to
// measure deployed stdio perf here (the dlmopen `fputs_glibc_bench` hangs in this env,
// and any `cfg(test)` harness measures the test-only entrypoint-trace path, ~10x
// inflated). Run: cargo run -p frankenlibc-abi --example putc_ab --release
//
// MEASURED (cc, 2026-06-24): fputc 52-68 ns (lockskip) vs mutex ≈ 1.03-1.05x
// (lockcost ~2 ns); fgetc 63 ns; write/read = 0.83x. CONCLUSIONS:
// (1) fl stdio per-call ≈ 50-68 ns vs glibc ~3 ns ≈ ~20x — the real bd-hqo6b6 gap (the
//     "727 ns" from a cfg(test) probe was pure entrypoint-trace overhead, absent deployed).
// (2) The registry `std::sync::Mutex` (~2 ns) is NOT the cost — bd-hqo6b6's "registry
//     Mutex is the dominant cost" is WRONG; the single-threaded lock-skip is ~0-gain
//     (~1.04x) and was reverted (twice-confirmed).
// (3) READ ≈ WRITE (fgetc 63 ns ≈ fputc 53 ns) — NO write-specific lever; the cost is
//     COMMON per-call overhead: `canonical_stream_id` + the `decide()`/`observe()`
//     membrane + the `streams.get_mut(&FILE*-addr)` registry indirection (already a
//     custom `StreamIdHasher`, not SipHash) + `buffer_write`. Every focused suspect is
//     already-optimized or ~0-gain; the only lever left is ARCHITECTURAL: glibc's
//     FILE*-IS-the-stream direct reference (no per-call registry lookup, no membrane on
//     the hot path) — a multi-turn rearchitecture. Caveat: this harness runs in
//     MODE_UNRESOLVED (no bootstrap); fully-deployed MODE_STRICT may shave decide/observe.
use std::sync::atomic::Ordering;
use std::time::Instant;

fn main() {
    unsafe {
        let f = frankenlibc_abi::stdio_abi::fopen(
            b"/dev/null\0".as_ptr().cast(),
            b"w\0".as_ptr().cast(),
        );
        assert!(!f.is_null(), "fopen failed");
        // _IOFBF, 64 MiB: n below stays under it → no flush in the timed loop.
        assert_eq!(
            frankenlibc_abi::stdio_abi::setvbuf(f, std::ptr::null_mut(), 0, 64 << 20),
            0
        );
        let n: usize = 20_000_000;
        let flag = &frankenlibc_abi::glibc_internal_abi::__libc_single_threaded;

        let bench = || {
            for _ in 0..200_000 {
                frankenlibc_abi::stdio_abi::fputc(b'x' as i32, f);
            }
            frankenlibc_abi::stdio_abi::fflush(f);
            let t = Instant::now();
            for _ in 0..n {
                frankenlibc_abi::stdio_abi::fputc(b'x' as i32, f);
            }
            let ns = t.elapsed().as_nanos() as f64 / n as f64;
            frankenlibc_abi::stdio_abi::fflush(f);
            ns
        };

        flag.store(1, Ordering::Release);
        let fast = bench();
        flag.store(0, Ordering::Release);
        let slow = bench();
        flag.store(1, Ordering::Release);

        frankenlibc_abi::stdio_abi::fclose(f);

        // Read-path comparison: fgetc from /dev/zero (the read path my memory says was
        // optimized to ~2x faster than glibc). The fputc/fgetc asymmetry localizes the
        // write-path gap (membrane vs buffer vs dispatch).
        let r = frankenlibc_abi::stdio_abi::fopen(
            b"/dev/zero\0".as_ptr().cast(),
            b"r\0".as_ptr().cast(),
        );
        let getc_ns = if !r.is_null() {
            assert_eq!(
                frankenlibc_abi::stdio_abi::setvbuf(r, std::ptr::null_mut(), 0, 64 << 20),
                0
            );
            for _ in 0..200_000 {
                frankenlibc_abi::stdio_abi::fgetc(r);
            }
            let t = Instant::now();
            for _ in 0..n {
                std::hint::black_box(frankenlibc_abi::stdio_abi::fgetc(r));
            }
            let ns = t.elapsed().as_nanos() as f64 / n as f64;
            frankenlibc_abi::stdio_abi::fclose(r);
            ns
        } else {
            -1.0
        };

        println!(
            "PUTC_AB_DEPLOYED fputc={fast:.2}ns (lockskip) / {slow:.2}ns (mutex) = {:.2}x lockcost={:.2}ns | fgetc={getc_ns:.2}ns | write/read={:.2}x",
            slow / fast,
            slow - fast,
            fast / getc_ns
        );
    }
}
