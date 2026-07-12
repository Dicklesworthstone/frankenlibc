//! Same-process A/B for the wcsspn/wcscspn/wcspbrk set-membership core. OLD
//! (`[bool; 128]` ASCII table — a 128-byte stack zero per call) vs NEW
//! (`[u64; 2]` 128-bit bitmap — 16-byte zero, glibc-style) vs host glibc
//! `wcsspn`, all in one process so per-worker load cancels in the ratios.
//!
//! The membrane fast path already removed the per-call decide/observe tax; this
//! isolates the residual core gap (fl was ~2.6x glibc at short inputs because the
//! 128-byte table init dominates when the accept set is small).
//!
//! Run: `cargo bench -p frankenlibc-bench --bench wcsspn_set_ab_bench`

use std::ffi::c_int;
use std::hint::black_box;
use std::sync::OnceLock;

use criterion::{Criterion, criterion_group, criterion_main};

type WcsspnFn = unsafe extern "C" fn(*const u32, *const u32) -> usize;

fn host_wcsspn() -> WcsspnFn {
    static HOST: OnceLock<usize> = OnceLock::new();
    let addr = *HOST.get_or_init(|| unsafe {
        let handle = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!handle.is_null(), "dlmopen libc.so.6");
        let sym = libc::dlsym(handle, b"wcsspn\0".as_ptr().cast());
        assert!(!sym.is_null(), "resolve glibc wcsspn");
        sym as usize
    });
    unsafe { std::mem::transmute::<usize, WcsspnFn>(addr) }
}

fn wlen(p: *const u32) -> usize {
    let mut i = 0;
    unsafe {
        while *p.add(i) != 0 {
            i += 1;
        }
    }
    i
}

// --- OLD: [bool; 128] ASCII table ------------------------------------------
struct OldSet<'a> {
    ascii: [bool; 128],
    rest: &'a [u32],
    has_nonascii: bool,
}
impl<'a> OldSet<'a> {
    unsafe fn new(set: *const u32, len: usize) -> Self {
        let mut ascii = [false; 128];
        let mut has_nonascii = false;
        for k in 0..len {
            let a = unsafe { *set.add(k) };
            if a < 128 {
                ascii[a as usize] = true;
            } else {
                has_nonascii = true;
            }
        }
        let rest = unsafe { std::slice::from_raw_parts(set, len) };
        Self {
            ascii,
            rest,
            has_nonascii,
        }
    }
    #[inline]
    fn contains(&self, c: u32) -> bool {
        if c < 128 {
            self.ascii[c as usize]
        } else {
            self.has_nonascii && self.rest.contains(&c)
        }
    }
}

// --- NEW: [u64; 2] 128-bit bitmap ------------------------------------------
struct NewSet<'a> {
    ascii: [u64; 2],
    rest: &'a [u32],
    has_nonascii: bool,
}
impl<'a> NewSet<'a> {
    unsafe fn new(set: *const u32, len: usize) -> Self {
        let mut ascii = [0u64; 2];
        let mut has_nonascii = false;
        for k in 0..len {
            let a = unsafe { *set.add(k) };
            if a < 128 {
                ascii[(a >> 6) as usize] |= 1u64 << (a & 63);
            } else {
                has_nonascii = true;
            }
        }
        let rest = unsafe { std::slice::from_raw_parts(set, len) };
        Self {
            ascii,
            rest,
            has_nonascii,
        }
    }
    #[inline]
    fn contains(&self, c: u32) -> bool {
        if c < 128 {
            (self.ascii[(c >> 6) as usize] >> (c & 63)) & 1 != 0
        } else {
            self.has_nonascii && self.rest.contains(&c)
        }
    }
}

unsafe fn spn_old(s: *const u32, accept: *const u32) -> usize {
    let alen = wlen(accept);
    let set = unsafe { OldSet::new(accept, alen) };
    let slen = wlen(s);
    let mut count = 0;
    for i in 0..slen {
        if set.contains(unsafe { *s.add(i) }) {
            count += 1;
        } else {
            break;
        }
    }
    count
}
unsafe fn spn_new(s: *const u32, accept: *const u32) -> usize {
    let alen = wlen(accept);
    let set = unsafe { NewSet::new(accept, alen) };
    let slen = wlen(s);
    let mut count = 0;
    for i in 0..slen {
        if set.contains(unsafe { *s.add(i) }) {
            count += 1;
        } else {
            break;
        }
    }
    count
}

fn wstr(n: usize) -> Vec<u32> {
    let mut v = vec![b'a' as u32; n];
    v.push(0);
    v
}

fn bench(c: &mut Criterion) {
    let glibc = host_wcsspn();
    // 'a' placed LAST so glibc's naive inner loop must scan the whole accept set
    // per element (defeats its match-first best case; fl's table stays O(1)).
    let accept: Vec<u32> = "bcdefa".chars().map(|ch| ch as u32).chain([0]).collect();
    let pset = accept.as_ptr();
    for &n in &[4usize, 16, 64, 256] {
        let s = wstr(n);
        let ps = s.as_ptr();
        // parity
        assert_eq!(unsafe { spn_old(ps, pset) }, n);
        assert_eq!(unsafe { spn_new(ps, pset) }, n);
        assert_eq!(unsafe { glibc(ps, pset) }, n);

        let mut grp = c.benchmark_group(format!("wcsspn_set_{n}"));
        grp.bench_function("old_bool128", |b| {
            b.iter(|| black_box(unsafe { spn_old(black_box(ps), black_box(pset)) }))
        });
        grp.bench_function("new_bitmap", |b| {
            b.iter(|| black_box(unsafe { spn_new(black_box(ps), black_box(pset)) }))
        });
        grp.bench_function("host_glibc", |b| {
            b.iter(|| black_box(unsafe { glibc(black_box(ps), black_box(pset)) }))
        });
        grp.finish();
    }
    let _ = black_box::<c_int>(0);
}

criterion_group!(benches, bench);
criterion_main!(benches);
