// Deployed-mode (NOT cfg(test), so `strict_passthrough_active()` is live and the
// per-call entrypoint trace is skipped) in-process A/B harness for the stdio write
// path. Times fl `fputc` into a fully-buffered stream (no flush in the loop) with
// `__libc_single_threaded` == 1 vs == 0. No dlmopen — this is the ONLY clean way to
// measure deployed stdio perf here (the dlmopen `fputs_glibc_bench` hangs in this env,
// and any `cfg(test)` harness measures the test-only entrypoint-trace path, ~10x
// inflated). Run: cargo run -p frankenlibc-abi --example putc_ab --release
//
// MEASURED (cc, 2026-06-24, this worker): lockskip=67.56ns mutex=69.74ns = 1.03x,
// lockcost=2.19ns. CONCLUSIONS: (1) fl deployed fputc ~68 ns/call vs glibc ~3 ns ≈
// ~22x — the real bd-hqo6b6 gap (a clean number; the "727 ns" from a cfg(test) probe
// was pure entrypoint-trace overhead, absent deployed). (2) The registry `Mutex`
// (plain std, uncontended ~2 ns) is NOT the cost — bd-hqo6b6's "registry Mutex is the
// dominant cost" is WRONG; a single-threaded lock-skip is ~0-gain (1.03x) and was
// reverted. The ~66 ns lives in the rest of the per-call path: `canonical_stream_id`,
// `decide()`/`observe()` (if heals on), the `streams.get_mut(&FILE*-addr)` HashMap
// lookup, and `buffer_write`. That — especially replacing the HashMap-by-pointer with
// glibc's FILE*-IS-the-stream direct reference — is the real (multi-turn) lever.
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
        println!(
            "PUTC_AB_DEPLOYED lockskip={fast:.2}ns mutex={slow:.2}ns speedup={:.2}x lockcost={:.2}ns",
            slow / fast,
            slow - fast
        );
    }
}
