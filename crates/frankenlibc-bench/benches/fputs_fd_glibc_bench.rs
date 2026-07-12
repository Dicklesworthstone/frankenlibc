//! fputs to an fd-backed, FULL-buffered stream (/dev/null) — the COMMON case that hits
//! the lock-free fast_write fast path — deployed fl vs host glibc (dlmopen). Contrast
//! with fputs_glibc_bench, which uses fmemopen (mem-backed) and MISSES fast_write
//! (is_mem_backed() => false), so that bench measures the slow locked path, not this one.
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use std::os::raw::c_char;
use std::sync::OnceLock;
use std::time::Instant;

fn h() -> *mut libc::c_void {
    static H: OnceLock<usize> = OnceLock::new();
    *H.get_or_init(|| unsafe {
        let p = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!p.is_null());
        p as usize
    }) as *mut libc::c_void
}
fn dl<T: Copy>(n: &[u8]) -> T {
    let p = unsafe { libc::dlsym(h(), n.as_ptr().cast()) };
    assert!(!p.is_null(), "dlsym");
    unsafe { std::mem::transmute_copy::<usize, T>(&(p as usize)) }
}

type FopenFn = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut libc::c_void;
type SetvbufFn = unsafe extern "C" fn(*mut libc::c_void, *mut c_char, i32, usize) -> i32;
type FputsFn = unsafe extern "C" fn(*const c_char, *mut libc::c_void) -> i32;
type FflushFn = unsafe extern "C" fn(*mut libc::c_void) -> i32;

fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let r = q * (v.len() - 1) as f64;
    let (lo, hi) = (r.floor() as usize, r.ceil() as usize);
    if lo == hi {
        v[lo]
    } else {
        v[lo] * (1.0 - (r - lo as f64)) + v[hi] * (r - lo as f64)
    }
}

fn bench(c: &mut Criterion) {
    // glibc handles (own namespace).
    let g_fopen: FopenFn = dl(b"fopen\0");
    let g_setvbuf: SetvbufFn = dl(b"setvbuf\0");
    let g_fputs: FputsFn = dl(b"fputs\0");
    let g_fflush: FflushFn = dl(b"fflush\0");

    // fl handles (deployed abi).
    use frankenlibc_abi::stdio_abi as fl;

    let path = b"/dev/null\0".as_ptr() as *const c_char;
    let mode = b"w\0".as_ptr() as *const c_char;
    // Full-buffered, large buffer so writes accumulate (rare flush).
    let cap = 1 << 16;

    let gf = unsafe { g_fopen(path, mode) };
    assert!(!gf.is_null());
    unsafe {
        g_setvbuf(gf, std::ptr::null_mut(), libc::_IOFBF, cap);
    }
    let ff = unsafe { fl::fopen(path, mode) };
    assert!(!ff.is_null());
    unsafe {
        fl::setvbuf(ff, std::ptr::null_mut(), libc::_IOFBF, cap);
    }

    let mut grp = c.benchmark_group("fputs_fd");
    grp.sample_size(10);
    let it = 20000u64;
    for &n in &[8usize, 38, 200] {
        let s: Vec<u8> = std::iter::repeat(b'x')
            .take(n)
            .chain(std::iter::once(0))
            .collect();
        let sp = s.as_ptr() as *const c_char;
        // warm (populate fl write cache + buffers)
        unsafe {
            fl::fputs(sp, ff);
            g_fputs(sp, gf);
        }
        let (mut fs, mut gs) = (Vec::new(), Vec::new());
        for _ in 0..100 {
            let t = Instant::now();
            for _ in 0..it {
                black_box(unsafe { fl::fputs(black_box(sp), ff) });
            }
            unsafe {
                fl::fflush(ff);
            }
            fs.push(t.elapsed().as_nanos() as f64 / it as f64);
            let t = Instant::now();
            for _ in 0..it {
                black_box(unsafe { g_fputs(black_box(sp), gf) });
            }
            unsafe {
                g_fflush(gf);
            }
            gs.push(t.elapsed().as_nanos() as f64 / it as f64);
        }
        println!(
            "FPUTS_FD n={n} fl={:.2} glibc={:.2} fl/glibc={:.3}",
            pctl(&fs, 0.5),
            pctl(&gs, 0.5),
            pctl(&fs, 0.5) / pctl(&gs, 0.5)
        );
    }
    grp.bench_function("noop", |b| b.iter(|| black_box(1u8)));
    grp.finish();
}
criterion_group!(benches, bench);
criterion_main!(benches);
