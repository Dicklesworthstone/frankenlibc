#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc memmove oracle + raw arenas

//! Differential regression gate for `memmove`'s OVERLAP paths (raw_avx_copy forward /
//! backward peels + the rep-movsb tier), vs host glibc.
//!
//! Background: `conformance_diff_wcs_copy::wmemmove_overlap` once failed in a build-flaky
//! way, which raised the question of whether the narrow `memmove` backward-AVX peel had a
//! layout-sensitive bug. This gate answers it deterministically: it forces every alignment
//! (`(dst+n)&31`, the peel selector) and every small overlap shift within ONE binary —
//! rather than relying on heap-layout luck — over both copy directions and sizes spanning
//! the byte tail, the 128-byte AVX loop, and the >=128 KiB rep-movsb tier. ~180k cases.
//!
//! Each case seeds two arenas identically, runs fl `memmove` (this binary's no-mangle
//! symbol) and glibc `memmove` (a fresh dlmopen namespace so it is the REAL libc, not fl),
//! then compares the touched window PLUS a 64-byte guard on each side (so an over-write
//! outside `[dst, dst+n)` is caught too).

type MFn = unsafe extern "C" fn(*mut u8, *const u8, usize) -> *mut u8;

struct Arena {
    f: *mut u8,
    g: *mut u8,
    cap: usize,
    layout: std::alloc::Layout,
    glibc: MFn,
}

impl Arena {
    fn new(cap: usize) -> Self {
        let layout = std::alloc::Layout::from_size_align(cap, 64).unwrap();
        let f = unsafe { std::alloc::alloc(layout) };
        let g = unsafe { std::alloc::alloc(layout) };
        assert!(!f.is_null() && !g.is_null());
        let h = unsafe {
            libc::dlmopen(
                libc::LM_ID_NEWLM,
                b"libc.so.6\0".as_ptr().cast(),
                libc::RTLD_LAZY | libc::RTLD_LOCAL,
            )
        };
        assert!(!h.is_null(), "dlmopen libc failed");
        let sym = unsafe { libc::dlsym(h, b"memmove\0".as_ptr().cast()) };
        assert!(!sym.is_null(), "dlsym memmove failed");
        let glibc: MFn = unsafe { std::mem::transmute(sym) };
        Arena {
            f,
            g,
            cap,
            layout,
            glibc,
        }
    }

    #[inline]
    fn byte(i: usize) -> u8 {
        ((i as u32).wrapping_mul(2_654_435_761) >> 13) as u8
    }

    /// Run one memmove case and return true iff fl matches glibc on the touched window
    /// (including a 64-byte guard on each side).
    fn case(&self, src_off: usize, dst_off: usize, n: usize) -> bool {
        let lo = src_off.min(dst_off).saturating_sub(64);
        let hi = (src_off.max(dst_off) + n + 64).min(self.cap);
        assert!(hi <= self.cap, "case out of arena");
        for i in lo..hi {
            let v = Self::byte(i);
            unsafe {
                *self.f.add(i) = v;
                *self.g.add(i) = v;
            }
        }
        unsafe {
            // fl memmove = this binary's no-mangle symbol.
            libc::memmove(
                self.f.add(dst_off) as *mut _,
                self.f.add(src_off) as *const _,
                n,
            );
            (self.glibc)(self.g.add(dst_off), self.g.add(src_off), n);
        }
        (lo..hi).all(|i| unsafe { *self.f.add(i) == *self.g.add(i) })
    }
}

impl Drop for Arena {
    fn drop(&mut self) {
        unsafe {
            std::alloc::dealloc(self.f, self.layout);
            std::alloc::dealloc(self.g, self.layout);
        }
    }
}

/// Small/mid sizes: ALL base alignments (0..64), both overlap directions, shifts 1..=64.
#[test]
fn memmove_overlap_small_mid_all_alignments() {
    let a = Arena::new(4096);
    let mut checked = 0usize;
    for base_off in 0..64usize {
        for &n in &[
            1usize, 8, 15, 16, 17, 31, 32, 33, 47, 63, 64, 65, 96, 120, 127, 128, 129, 132, 160,
            200, 255, 256, 260, 384, 512, 600,
        ] {
            for shift in 1..=64usize {
                // backward (dst > src) and forward (src > dst)
                assert!(
                    a.case(base_off, base_off + shift, n),
                    "backward mismatch n={n} shift={shift} base_off={base_off}"
                );
                assert!(
                    a.case(base_off + shift, base_off, n),
                    "forward mismatch n={n} shift={shift} base_off={base_off}"
                );
                checked += 2;
            }
        }
    }
    assert!(checked > 100_000, "expected a broad sweep, got {checked}");
}

/// Large sizes spanning the AVX loop and the rep-movsb tier (>=128 KiB), a handful of
/// alignments and shifts, both directions.
#[test]
fn memmove_overlap_large_sizes() {
    let a = Arena::new(600_000);
    for &n in &[1024usize, 4096, 16384, 65536, 131_072, 262_144] {
        for base_off in [0usize, 1, 7, 24, 31, 40, 63] {
            for &shift in &[1usize, 15, 24, 32, 33, 64, 96, 129] {
                assert!(
                    a.case(base_off, base_off + shift, n),
                    "backward-large mismatch n={n} shift={shift} base_off={base_off}"
                );
                assert!(
                    a.case(base_off + shift, base_off, n),
                    "forward-large mismatch n={n} shift={shift} base_off={base_off}"
                );
            }
        }
    }
}
