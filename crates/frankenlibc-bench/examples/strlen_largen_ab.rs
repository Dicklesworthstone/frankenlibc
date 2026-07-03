//! Characterize fl strlen vs glibc strlen (dlmopen) across sizes — where does the
//! *kernel* (floor amortized) lose? The probe showed n=1024 at 1.89x; this maps the
//! full curve so a kernel change can be validated for no-regression at every size.
//!
//! Run: cargo run --release --example strlen_largen_ab --features abi-bench

use std::hint::black_box;
use std::time::Instant;

type StrlenFn = unsafe extern "C" fn(*const i8) -> usize;

unsafe fn dl(h: *mut libc::c_void, n: &[u8]) -> StrlenFn {
    let p = unsafe { libc::dlsym(h, n.as_ptr().cast()) };
    assert!(!p.is_null());
    unsafe { std::mem::transmute::<*mut libc::c_void, StrlenFn>(p) }
}

fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}

fn main() {
    let h = unsafe {
        libc::dlmopen(libc::LM_ID_NEWLM, b"libc.so.6\0".as_ptr().cast(), libc::RTLD_LAZY | libc::RTLD_LOCAL)
    };
    assert!(!h.is_null(), "dlmopen libc");
    let g_strlen: StrlenFn = unsafe { dl(h, b"strlen\0") };

    // Exhaustive correctness: fl strlen (strict path → scan_c_string, the tiered kernel)
    // must equal the true length at every alignment × length spanning head(≤32),
    // bridge(32-64), 64B tier(64-256), and 128B handoff(256+) and their boundaries.
    {
        let mut checks = 0u64;
        for align in 0..80usize {
            for len in 0..340usize {
                let mut buf = vec![0u8; align + len + 1 + 160];
                for k in 0..len {
                    buf[align + k] = 1 + ((align + k) % 200) as u8; // non-zero
                }
                buf[align + len] = 0;
                let sp = unsafe { buf.as_ptr().add(align) as *const i8 };
                let got = unsafe { frankenlibc_abi::string_abi::strlen(sp) };
                assert_eq!(got, len, "strlen align={align} len={len}");
                checks += 1;
            }
        }
        println!("correctness: {checks} (align×len) fl strlen == true length ✓");
    }

    // Page-safety: place strings ending just before an unmapped (PROT_NONE) page and
    // verify the tiered scan (which reads up to 32B past the NUL within its aligned
    // window) never faults. A fault crashes the process ⇒ test fails by crashing.
    unsafe {
        let pg = 4096usize;
        let base = libc::mmap(std::ptr::null_mut(), 2 * pg, libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0) as *mut u8;
        assert_ne!(base as isize, -1, "mmap");
        assert_eq!(libc::mprotect(base.add(pg) as *mut _, pg, libc::PROT_NONE), 0, "mprotect");
        let mut guarded = 0u64;
        // For every NUL position in the last 140 bytes of the mapped page, and every
        // start alignment 0..64 before it, strlen must stop at the NUL without reading
        // into the guard page.
        for nul_off in (pg - 140)..pg {
            for a in 0..64usize {
                if a > nul_off { continue; }
                let start = nul_off - a; // string of length `a`, NUL at nul_off
                for k in start..nul_off { base.add(k).write(b'z'); }
                base.add(nul_off).write(0);
                let got = frankenlibc_abi::string_abi::strlen(base.add(start) as *const i8);
                assert_eq!(got, a, "guard strlen nul_off={nul_off} a={a}");
                guarded += 1;
            }
        }
        libc::munmap(base as *mut _, 2 * pg);
        println!("page-safety: {guarded} guard-page strlens near PROT_NONE boundary ✓");
    }

    let sizes = [64usize, 128, 256, 512, 1024, 2048, 4096, 16384];
    for &n in &sizes {
        // Typical (non-128-aligned) buffer: a Vec is 8/16-aligned, offset by 8 bytes so
        // it is NOT 128-aligned (the common real-world case).
        let mut buf = vec![b'x'; n + 16];
        buf[n] = 0;
        let scp = unsafe { buf.as_ptr().add(0) as *const i8 };
        let lit = 20_000u64;
        let (mut fl, mut gl) = (Vec::new(), Vec::new());
        for r in 0..100 {
            if r % 2 == 0 {
                let t = Instant::now();
                for _ in 0..lit { black_box(unsafe { frankenlibc_abi::string_abi::strlen(scp) }); }
                fl.push(t.elapsed().as_nanos() as f64 / lit as f64);
                let t = Instant::now();
                for _ in 0..lit { black_box(unsafe { g_strlen(scp) }); }
                gl.push(t.elapsed().as_nanos() as f64 / lit as f64);
            } else {
                let t = Instant::now();
                for _ in 0..lit { black_box(unsafe { g_strlen(scp) }); }
                gl.push(t.elapsed().as_nanos() as f64 / lit as f64);
                let t = Instant::now();
                for _ in 0..lit { black_box(unsafe { frankenlibc_abi::string_abi::strlen(scp) }); }
                fl.push(t.elapsed().as_nanos() as f64 / lit as f64);
            }
        }
        let (f10, g10) = (pctl(&fl, 0.1), pctl(&gl, 0.1));
        println!(
            "STRLEN n={n:<6} p10: fl={f10:.2} glibc={g10:.2} fl/glibc={:.3}  {}",
            f10 / g10,
            if f10 <= g10 * 1.1 { "ok" } else { "LOSS" }
        );
    }
}
