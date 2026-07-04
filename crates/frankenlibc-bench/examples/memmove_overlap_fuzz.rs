//! Deterministic differential fuzz of fl memmove vs glibc memmove over a controlled grid
//! of (n, overlap shift, direction, alignment). Forces every alignment/shift combo within
//! one binary (rather than relying on heap-layout luck) — a permanent regression gate for
//! the overlap-copy paths (raw_avx_copy forward/backward peels + rep-movsb tier). Seeds and
//! compares only the touched window plus guard bytes so huge-n cases stay fast, and checks
//! the guard bytes to catch any over-write outside [dst, dst+n).
use std::hint::black_box;
type MFn = unsafe extern "C" fn(*mut u8, *const u8, usize) -> *mut u8;

fn main() {
    let h = unsafe {
        libc::dlmopen(libc::LM_ID_NEWLM, b"libc.so.6\0".as_ptr().cast(), libc::RTLD_LAZY | libc::RTLD_LOCAL)
    };
    assert!(!h.is_null());
    let g: MFn = unsafe { std::mem::transmute(libc::dlsym(h, b"memmove\0".as_ptr().cast())) };

    let cap = 600_000usize; // room for the rep-movsb path (>=128 KiB) + margins
    let layout = std::alloc::Layout::from_size_align(cap, 64).unwrap();
    let base_f = unsafe { std::alloc::alloc(layout) };
    let base_g = unsafe { std::alloc::alloc(layout) };
    assert!(!base_f.is_null() && !base_g.is_null());

    let byte = |i: usize| -> u8 { ((i as u32).wrapping_mul(2654435761) >> 13) as u8 };

    let mut checked = 0usize;
    let mut fails = 0usize;
    let mut first: Option<(usize, isize, usize, &'static str)> = None;

    // Run one case: src at `src_off`, dst at `dst_off`, `n` bytes. Seeds only the touched
    // window (+64 guard each side) and compares that window incl. the guards.
    let mut run = |src_off: usize, dst_off: usize, n: usize, tag: &'static str| {
        let lo = src_off.min(dst_off).saturating_sub(64);
        let hi = (src_off.max(dst_off) + n + 64).min(cap);
        for i in lo..hi {
            let v = byte(i);
            unsafe { *base_f.add(i) = v; *base_g.add(i) = v; }
        }
        unsafe {
            black_box(libc::memmove(base_f.add(dst_off) as *mut _, base_f.add(src_off) as *const _, n));
            black_box(g(base_g.add(dst_off), base_g.add(src_off), n));
        }
        checked += 1;
        let eq = (lo..hi).all(|i| unsafe { *base_f.add(i) == *base_g.add(i) });
        if !eq && first.is_none() {
            first = Some((n, dst_off as isize - src_off as isize, (src_off.max(dst_off) + n) & 31, tag));
        }
        if !eq { fails += 1; }
    };

    // Sweep 1: small/mid n, ALL base alignments, both overlap directions, shifts 1..=64.
    for base_off in 0..64usize {
        for &n in &[1usize, 8, 16, 31, 32, 33, 63, 64, 65, 120, 127, 128, 129, 132, 160, 200, 255, 256, 260, 384, 512, 600] {
            for shift in 1..=64usize {
                // backward: dst > src
                run(base_off, base_off + shift, n, "backward");
                // forward: src > dst
                run(base_off + shift, base_off, n, "forward");
            }
        }
    }

    // Sweep 2: large n (AVX loop + rep-movsb tier), a handful of alignments/shifts.
    for &n in &[1024usize, 4096, 16384, 65536, 131072, 262144] {
        for base_off in [0usize, 1, 7, 24, 31, 40, 63] {
            for &shift in &[1usize, 15, 24, 32, 33, 64, 96, 129] {
                run(base_off, base_off + shift, n, "backward-large");
                run(base_off + shift, base_off, n, "forward-large");
            }
        }
    }

    eprintln!("memmove overlap fuzz: checked={checked} fails={fails}");
    match first {
        Some((n, delta, top_head, tag)) => {
            eprintln!("  FIRST FAIL [{tag}]: n={n} dst-src={delta} top_head=(dst+n)&31={top_head}");
        }
        None => eprintln!("  ALL MATCH glibc"),
    }
    unsafe {
        std::alloc::dealloc(base_f, layout);
        std::alloc::dealloc(base_g, layout);
    }
    if fails != 0 { std::process::exit(1); }
}
