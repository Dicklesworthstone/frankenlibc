// reallocarray wrapper-tax isolation: reallocarray(p,1,S) does an overflow check
// then (currently) its OWN runtime_policy decide+observe before delegating to
// realloc — but realloc already does its own membrane handling, so that decide+
// observe is a redundant per-call tax. Measuring (reallocarray - realloc) on the
// SAME fl-owned pointer with a shrink-in-place S (realloc returns same ptr fast)
// isolates the wrapper cost: before the fix it includes decide+observe, after it
// is just the overflow check. glibc reallocarray shown for context.
use std::ffi::c_void;
use std::hint::black_box;
use std::time::Instant;

fn main() {
    unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen libc failed");
        type MallocFn = unsafe extern "C" fn(usize) -> *mut c_void;
        type RallocarrFn = unsafe extern "C" fn(*mut c_void, usize, usize) -> *mut c_void;
        let gl_malloc: MallocFn =
            std::mem::transmute::<*mut c_void, MallocFn>(libc::dlsym(h, b"malloc\0".as_ptr().cast()));
        let gl_reallocarray: RallocarrFn = std::mem::transmute::<*mut c_void, RallocarrFn>(
            libc::dlsym(h, b"reallocarray\0".as_ptr().cast()),
        );

        const S: usize = 4096; // shrink target that fits the 1 MiB block -> in-place fast realloc

        // fl-owned block for the fl arms.
        let mut fp = frankenlibc_abi::malloc_abi::malloc(1 << 20);
        assert!(!fp.is_null());
        // glibc-owned block for the glibc arm (allocators must not be mixed).
        let mut gp = gl_malloc(1 << 20);
        assert!(!gp.is_null());

        let iters = 5_000_000usize;

        // Warm up / stabilize (first realloc may adjust bookkeeping).
        for _ in 0..1000 {
            fp = frankenlibc_abi::malloc_abi::realloc(fp, S);
            fp = frankenlibc_abi::malloc_abi::realloc(fp, 1 << 20);
        }

        let t = Instant::now();
        for _ in 0..iters {
            fp = frankenlibc_abi::malloc_abi::realloc(black_box(fp), S);
        }
        let realloc_ns = t.elapsed().as_nanos() as f64 / iters as f64;

        let t = Instant::now();
        for _ in 0..iters {
            fp = frankenlibc_abi::stdlib_abi::reallocarray(black_box(fp), 1, S);
        }
        let rarr_ns = t.elapsed().as_nanos() as f64 / iters as f64;

        let t = Instant::now();
        for _ in 0..iters {
            gp = gl_reallocarray(black_box(gp), 1, S);
        }
        let gl_ns = t.elapsed().as_nanos() as f64 / iters as f64;

        let wrapper = (rarr_ns - realloc_ns).max(0.0);
        println!(
            "REALLOCARRAY realloc={realloc_ns:.1}ns reallocarray={rarr_ns:.1}ns glibc={gl_ns:.1}ns  \
             wrapper_tax(reallocarray-realloc)={wrapper:.1}ns",
        );

        frankenlibc_abi::malloc_abi::free(fp);
    }
}
