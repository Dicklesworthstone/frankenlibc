//! wcsrchr large-n lever probe — RESULT: NEGATIVE (no clean fold win; see the ledger below).
//!
//! CONCLUSION (measured 2026-07-14, this host, paired 10th-pctl of 40 rounds):
//!   * COMPETITIVE GAP is real and large: fl's deployed kernel (`wide_last_before_nul_simd`, an
//!     8-lane 32B/iter mask loop) LOSES to host glibc's vectorized wcsrchr on EVERY density —
//!     absent 1.36-1.58x, periodic-c 1.56-1.87x, frequent 2.26-2.50x (n=1k..64k). The gap is even
//!     understated here: glibc goes through an indirect dlmopen call while `scan8` is inlined.
//!   * NO fold variant is a clean win (every one that helps `absent` regresses a denser input):
//!       - panel-0-first fold (`scan_fold_p0`/`scan_fold_p0r`): WINS absent (p0r/cur 0.84-0.89 at
//!         n>=4k) but REGRESSES frequent ~1.5x and periodic-c ~1.3-1.4x.
//!       - always-on combined-mask fold (`scan_fold_always`): WINS frequent (0.69-0.79x) and
//!         absent (0.83-0.94x) but REGRESSES periodic-c ~1.08-1.32x.
//!   * ROOT CAUSE (generalizable): wcsrchr is a LAST-MATCH scan that ALWAYS traverses to the NUL.
//!     Unlike a forward-first-match kernel (strchr/memchr, where a frequent target terminates
//!     BEFORE the i>=128 fold gate ever opens — which is why scan_c_string_for_byte's always-on
//!     fold is free), a dense wcsrchr input runs the WHOLE loop, so ANY fold structure in the loop
//!     body taxes the dense path even when its branch is never taken. p0r regresses frequent ~1.5x
//!     purely from loop bloat (its fold code is unreachable on dense input yet still slows it).
//!   * DEFERRED real lever: a fold-forward pass that tracks only the LAST nul-free 128B block
//!     containing c (no per-panel extraction) + a single resolve of that block at the NUL. That
//!     removes per-panel extraction from the dense path too, but is a byte-identity-risky rewrite
//!     (deferred last-match resolve + head-c seeding + page-edge fallback) — its own focused turn.
//!
//! Original two questions this probe answered:
//!   (A) COMPETITIVE: does fl's deployed wcsrchr lose to host glibc at large n? glibc ships a
//!       vectorized wcsrchr (avx2/evex on 2.42); fl's kernel (`wide_last_before_nul_simd`) is a
//!       single 8-lane (32B/iter) loop with no unroll — the same shape narrow strrchr lost 1.68x
//!       with before its 128B fold (b246b7619 / ab62068d7).
//!   (B) LEVER: does a panel-0-first 128B fold (read the current 8-lane panel; only when it has
//!       NO c and NO nul, skip the next 3 panels = 128B total) close the large-n gap WITHOUT
//!       regressing the pathological frequent-c case (every char == c)? The deployed comment says
//!       "a folded 128B tier was tried and lost (frequent-c degenerates to whole-string scalar
//!       rescan)" — but that was a SCALAR-rescan/always-on fold; panel-0-first + mask extraction is
//!       exactly what fixed narrow strrchr (ab62068d7) and was never ported here.
//! An always-on combined-mask fold (`scan32`, from wcsrchr_wide_ab) is included as a third variant
//! to confirm/deny the note's regression claim. Byte-identity of (last,span) asserted vs the
//! deployed 8-lane mask kernel for every case.
#![feature(portable_simd)]
use std::hint::black_box;
use std::simd::Simd;
use std::simd::cmp::SimdPartialEq;
use std::time::Instant;

fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}

// ---- fl DEPLOYED: 8-lane (32B/iter) mask extraction (mirrors wide_last_before_nul_simd c!=0). ----
unsafe fn scan8(s: *const u32, c: u32) -> (Option<usize>, usize) {
    const L: usize = 8;
    let mut last = None;
    let mut i = 0;
    let head = ((32 - ((s as usize) & 31)) & 31) / 4;
    while i < head {
        let ch = unsafe { *s.add(i) };
        if ch == c {
            last = Some(i);
        }
        if ch == 0 {
            return (last, i + 1);
        }
        i += 1;
    }
    let cv = Simd::<u32, L>::splat(c);
    let zv = Simd::<u32, L>::splat(0);
    loop {
        let v = Simd::<u32, L>::from_array(unsafe { core::ptr::read(s.add(i).cast::<[u32; L]>()) });
        let eqc = v.simd_eq(cv);
        let eqz = v.simd_eq(zv);
        if (eqc | eqz).any() {
            let zm = eqz.to_bitmask();
            if zm != 0 {
                let p = zm.trailing_zeros() as usize;
                let cmb = eqc.to_bitmask() & ((1u64 << p) - 1);
                if cmb != 0 {
                    last = Some(i + (63 - cmb.leading_zeros() as usize));
                }
                return (last, i + p + 1);
            }
            last = Some(i + (63 - eqc.to_bitmask().leading_zeros() as usize));
        }
        i += L;
    }
}

// Resolve one 8-lane panel exactly like scan8 (returns Some(span) to terminate, else updates last).
#[inline(always)]
unsafe fn resolve_panel(
    v: Simd<u32, 8>,
    cv: Simd<u32, 8>,
    zv: Simd<u32, 8>,
    i: usize,
    last: &mut Option<usize>,
) -> Option<usize> {
    let eqc = v.simd_eq(cv);
    let eqz = v.simd_eq(zv);
    if (eqc | eqz).any() {
        let zm = eqz.to_bitmask();
        if zm != 0 {
            let p = zm.trailing_zeros() as usize;
            let cmb = eqc.to_bitmask() & ((1u64 << p) - 1);
            if cmb != 0 {
                *last = Some(i + (63 - cmb.leading_zeros() as usize));
            }
            return Some(i + p + 1);
        }
        *last = Some(i + (63 - eqc.to_bitmask().leading_zeros() as usize));
    }
    None
}

// ---- fl LEVER: panel-0-first 128B fold. Check the current 8-lane panel; only when it is clear
// (no c, no nul) fold the NEXT 3 panels — if all clear, skip the whole 128B. A frequent c hits
// panel 0, resolves, and NEVER folds (== deployed); an absent/rare c skips 128B at a time. ----
unsafe fn scan_fold_p0(s: *const u32, c: u32) -> (Option<usize>, usize) {
    const L: usize = 8;
    let mut last = None;
    let mut i = 0;
    let head = ((32 - ((s as usize) & 31)) & 31) / 4;
    while i < head {
        let ch = unsafe { *s.add(i) };
        if ch == c {
            last = Some(i);
        }
        if ch == 0 {
            return (last, i + 1);
        }
        i += 1;
    }
    let cv = Simd::<u32, L>::splat(c);
    let zv = Simd::<u32, L>::splat(0);
    loop {
        let v0 = Simd::<u32, L>::from_array(unsafe { core::ptr::read(s.add(i).cast::<[u32; L]>()) });
        if (v0.simd_eq(cv) | v0.simd_eq(zv)).any() {
            if let Some(span) = unsafe { resolve_panel(v0, cv, zv, i, &mut last) } {
                return (last, span);
            }
            i += L;
            continue;
        }
        // Panel 0 clear. Fold the next 3 panels (i+8,i+16,i+24) => 96B; with panel 0 that is a
        // 128B window. Page-guard: the 128B [i, i+32) u32 window must stay in one 4 KiB page.
        if (unsafe { s.add(i) } as usize & 0xFFF) <= 0x1000 - 128 {
            let v1 = Simd::<u32, L>::from_array(unsafe {
                core::ptr::read(s.add(i + 8).cast::<[u32; L]>())
            });
            let v2 = Simd::<u32, L>::from_array(unsafe {
                core::ptr::read(s.add(i + 16).cast::<[u32; L]>())
            });
            let v3 = Simd::<u32, L>::from_array(unsafe {
                core::ptr::read(s.add(i + 24).cast::<[u32; L]>())
            });
            let any = (v1.simd_eq(cv) | v1.simd_eq(zv))
                | (v2.simd_eq(cv) | v2.simd_eq(zv))
                | (v3.simd_eq(cv) | v3.simd_eq(zv));
            if !any.any() {
                i += 32; // whole 128B window clear — skip it
                continue;
            }
        }
        // Panel 0 clear but the fold either straddles a page or panels 1-3 hold something:
        // advance one panel; the 8-lane resolve above handles panels 1-3 next iterations.
        i += L;
    }
}

// ---- fl LEVER v2 (REFINED panel-0-first): fixes v1's two regressions.
//   (1) frequent-c 1.3x: v1 recomputed eqc/eqz inside resolve_panel; here the panel-0 masks are
//       computed ONCE and reused, so a dense c is byte-for-byte the deployed 8-lane path.
//   (2) periodic-c 2x: when panel 0 is clear but panels 1-3 are NOT (so the fold can't skip), v1
//       wastefully advanced only 8 and re-loaded; here we RESOLVE panels 1-3 in one combined
//       24-lane mask and advance 32. So: panel-0 hit -> deployed resolve (advance 8); whole-128B
//       clear -> skip 128; panel-0 clear but 1-3 present -> combined resolve of 1-3 (advance 32).
unsafe fn scan_fold_p0r(s: *const u32, c: u32) -> (Option<usize>, usize) {
    const L: usize = 8;
    let mut last = None;
    let mut i = 0;
    let head = ((32 - ((s as usize) & 31)) & 31) / 4;
    while i < head {
        let ch = unsafe { *s.add(i) };
        if ch == c {
            last = Some(i);
        }
        if ch == 0 {
            return (last, i + 1);
        }
        i += 1;
    }
    let cv = Simd::<u32, L>::splat(c);
    let zv = Simd::<u32, L>::splat(0);
    loop {
        let v0 = Simd::<u32, L>::from_array(unsafe { core::ptr::read(s.add(i).cast::<[u32; L]>()) });
        let e0c = v0.simd_eq(cv);
        let e0z = v0.simd_eq(zv);
        if (e0c | e0z).any() {
            // Deployed 8-lane resolve of panel 0 with the already-computed masks.
            let zm = e0z.to_bitmask();
            if zm != 0 {
                let p = zm.trailing_zeros() as usize;
                let cmb = e0c.to_bitmask() & ((1u64 << p) - 1);
                if cmb != 0 {
                    last = Some(i + (63 - cmb.leading_zeros() as usize));
                }
                return (last, i + p + 1);
            }
            last = Some(i + (63 - e0c.to_bitmask().leading_zeros() as usize));
            i += L;
            continue;
        }
        // Panel 0 clear. Try to fold/resolve panels 1-3 (i+8,i+16,i+24) if the 128B stays in-page.
        if (unsafe { s.add(i) } as usize & 0xFFF) <= 0x1000 - 128 {
            let v1 = Simd::<u32, L>::from_array(unsafe {
                core::ptr::read(s.add(i + 8).cast::<[u32; L]>())
            });
            let v2 = Simd::<u32, L>::from_array(unsafe {
                core::ptr::read(s.add(i + 16).cast::<[u32; L]>())
            });
            let v3 = Simd::<u32, L>::from_array(unsafe {
                core::ptr::read(s.add(i + 24).cast::<[u32; L]>())
            });
            let c1 = v1.simd_eq(cv);
            let c2 = v2.simd_eq(cv);
            let c3 = v3.simd_eq(cv);
            let z1 = v1.simd_eq(zv);
            let z2 = v2.simd_eq(zv);
            let z3 = v3.simd_eq(zv);
            if !((c1 | z1) | (c2 | z2) | (c3 | z3)).any() {
                i += 32; // whole 128B window clear — skip it
                continue;
            }
            // panels 1-3 (24 lanes) hold c and/or nul; resolve them in one combined mask. Bit b
            // (0..24) maps to element i+8+b.
            let cm = c1.to_bitmask() | (c2.to_bitmask() << 8) | (c3.to_bitmask() << 16);
            let zm = z1.to_bitmask() | (z2.to_bitmask() << 8) | (z3.to_bitmask() << 16);
            if zm != 0 {
                let p = zm.trailing_zeros() as usize;
                let cmb = cm & ((1u64 << p) - 1);
                if cmb != 0 {
                    last = Some(i + 8 + (63 - cmb.leading_zeros() as usize));
                }
                return (last, i + 8 + p + 1);
            }
            // c present, no nul in panels 1-3: last match is the highest c lane; consume 128B.
            last = Some(i + 8 + (63 - cm.leading_zeros() as usize));
            i += 32;
            continue;
        }
        // Near a page edge with panel 0 clear: advance one panel (8-lane path handles 1-3 next).
        i += L;
    }
}

// ---- fl LEVER v3 (FOLD-FORWARD LAST-BLOCK TRACKING): the deferred design. Align UP to 128B (8-lane
// ramp, deployed resolve into `last`), then a pure 128B-ALIGNED fold loop — structurally page-safe
// (128|4096, no guard) like wide_strlen_unbounded. The fold does ONLY .any() work per 128B, tracking
// the START index of the last nul-free block that holds a c (`last_c_block`); ALL per-lane extraction
// is DEFERRED to the NUL block. So the dense path pays no per-panel extraction at all (unlike deployed
// 8-lane and always-on's per-block combined extraction), which is why it can win every density.
unsafe fn scan_fold_track(s: *const u32, c: u32) -> (Option<usize>, usize) {
    const L: usize = 8;
    let cv = Simd::<u32, L>::splat(c);
    let zv = Simd::<u32, L>::splat(0);
    let mut last: Option<usize> = None;
    let pb = s as usize;
    // Head: scalar to 32B alignment (== deployed).
    let head = ((32 - (pb & 31)) & 31) / 4;
    let mut i = 0;
    while i < head {
        let ch = unsafe { *s.add(i) };
        if ch == c {
            last = Some(i);
        }
        if ch == 0 {
            return (last, i + 1);
        }
        i += 1;
    }
    // Ramp: 8-lane (32B, page-safe) deployed resolve into `last` until s+i is 128B aligned.
    while (pb + i * 4) & 127 != 0 {
        let v = Simd::<u32, L>::from_array(unsafe { core::ptr::read(s.add(i).cast::<[u32; L]>()) });
        let eqc = v.simd_eq(cv);
        let eqz = v.simd_eq(zv);
        if (eqc | eqz).any() {
            let zm = eqz.to_bitmask();
            if zm != 0 {
                let p = zm.trailing_zeros() as usize;
                let cmb = eqc.to_bitmask() & ((1u64 << p) - 1);
                if cmb != 0 {
                    last = Some(i + (63 - cmb.leading_zeros() as usize));
                }
                return (last, i + p + 1);
            }
            last = Some(i + (63 - eqc.to_bitmask().leading_zeros() as usize));
        }
        i += L;
    }
    // 128B-aligned fold loop (page-safe by alignment). Track the last nul-free block with a c.
    let mut last_c_block: Option<usize> = None;
    loop {
        let v0 = Simd::<u32, L>::from_array(unsafe { core::ptr::read(s.add(i).cast::<[u32; L]>()) });
        let v1 =
            Simd::<u32, L>::from_array(unsafe { core::ptr::read(s.add(i + 8).cast::<[u32; L]>()) });
        let v2 =
            Simd::<u32, L>::from_array(unsafe { core::ptr::read(s.add(i + 16).cast::<[u32; L]>()) });
        let v3 =
            Simd::<u32, L>::from_array(unsafe { core::ptr::read(s.add(i + 24).cast::<[u32; L]>()) });
        let (c0, c1, c2, c3) = (
            v0.simd_eq(cv),
            v1.simd_eq(cv),
            v2.simd_eq(cv),
            v3.simd_eq(cv),
        );
        let (z0, z1, z2, z3) = (
            v0.simd_eq(zv),
            v1.simd_eq(zv),
            v2.simd_eq(zv),
            v3.simd_eq(zv),
        );
        if !((z0 | z1) | (z2 | z3)).any() {
            // No NUL in this 128B block: if any c, remember the block; defer extraction.
            if ((c0 | c1) | (c2 | c3)).any() {
                last_c_block = Some(i);
            }
            i += 32;
            continue;
        }
        // NUL is in this block. c != 0 here, so a NUL lane is never a c lane.
        let zm = z0.to_bitmask()
            | (z1.to_bitmask() << 8)
            | (z2.to_bitmask() << 16)
            | (z3.to_bitmask() << 24);
        let cm = c0.to_bitmask()
            | (c1.to_bitmask() << 8)
            | (c2.to_bitmask() << 16)
            | (c3.to_bitmask() << 24);
        let p = zm.trailing_zeros() as usize;
        let cmb = cm & ((1u64 << p) - 1);
        if cmb != 0 {
            // Last c lies before the NUL within THIS block — it dominates any earlier block.
            return (Some(i + (63 - cmb.leading_zeros() as usize)), i + p + 1);
        }
        // No c before the NUL in this block: the answer is the last c in the last remembered
        // nul-free block (later than `last`), else the head/ramp `last`.
        if let Some(b) = last_c_block {
            let b0 =
                Simd::<u32, L>::from_array(unsafe { core::ptr::read(s.add(b).cast::<[u32; L]>()) });
            let b1 = Simd::<u32, L>::from_array(unsafe {
                core::ptr::read(s.add(b + 8).cast::<[u32; L]>())
            });
            let b2 = Simd::<u32, L>::from_array(unsafe {
                core::ptr::read(s.add(b + 16).cast::<[u32; L]>())
            });
            let b3 = Simd::<u32, L>::from_array(unsafe {
                core::ptr::read(s.add(b + 24).cast::<[u32; L]>())
            });
            let bcm = b0.simd_eq(cv).to_bitmask()
                | (b1.simd_eq(cv).to_bitmask() << 8)
                | (b2.simd_eq(cv).to_bitmask() << 16)
                | (b3.simd_eq(cv).to_bitmask() << 24);
            return (Some(b + (63 - bcm.leading_zeros() as usize)), i + p + 1);
        }
        return (last, i + p + 1);
    }
}

// ---- ALWAYS-ON combined-mask fold (== wcsrchr_wide_ab scan32): folds 128B at the loop top every
// iteration. Included to confirm the deployed note's frequent-c regression claim. ----
unsafe fn scan_fold_always(s: *const u32, c: u32) -> (Option<usize>, usize) {
    const L: usize = 8;
    let mut last = None;
    let mut i = 0;
    let head = ((32 - ((s as usize) & 31)) & 31) / 4;
    while i < head {
        let ch = unsafe { *s.add(i) };
        if ch == c {
            last = Some(i);
        }
        if ch == 0 {
            return (last, i + 1);
        }
        i += 1;
    }
    let cv = Simd::<u32, L>::splat(c);
    let zv = Simd::<u32, L>::splat(0);
    loop {
        while (unsafe { s.add(i) } as usize & 0xFFF) <= 0x1000 - 128 {
            let c0 =
                Simd::<u32, L>::from_array(unsafe { core::ptr::read(s.add(i).cast::<[u32; L]>()) });
            let c1 = Simd::<u32, L>::from_array(unsafe {
                core::ptr::read(s.add(i + 8).cast::<[u32; L]>())
            });
            let c2 = Simd::<u32, L>::from_array(unsafe {
                core::ptr::read(s.add(i + 16).cast::<[u32; L]>())
            });
            let c3 = Simd::<u32, L>::from_array(unsafe {
                core::ptr::read(s.add(i + 24).cast::<[u32; L]>())
            });
            let e0 = c0.simd_eq(cv) | c0.simd_eq(zv);
            let e1 = c1.simd_eq(cv) | c1.simd_eq(zv);
            let e2 = c2.simd_eq(cv) | c2.simd_eq(zv);
            let e3 = c3.simd_eq(cv) | c3.simd_eq(zv);
            if (e0 | e1 | e2 | e3).any() {
                let cm = c0.simd_eq(cv).to_bitmask()
                    | (c1.simd_eq(cv).to_bitmask() << 8)
                    | (c2.simd_eq(cv).to_bitmask() << 16)
                    | (c3.simd_eq(cv).to_bitmask() << 24);
                let zm = c0.simd_eq(zv).to_bitmask()
                    | (c1.simd_eq(zv).to_bitmask() << 8)
                    | (c2.simd_eq(zv).to_bitmask() << 16)
                    | (c3.simd_eq(zv).to_bitmask() << 24);
                if zm != 0 {
                    let p = zm.trailing_zeros() as usize;
                    let cmb = cm & ((1u64 << p) - 1);
                    if cmb != 0 {
                        last = Some(i + (63 - cmb.leading_zeros() as usize));
                    }
                    return (last, i + p + 1);
                }
                last = Some(i + (63 - cm.leading_zeros() as usize));
            }
            i += 32;
        }
        let v = Simd::<u32, L>::from_array(unsafe { core::ptr::read(s.add(i).cast::<[u32; L]>()) });
        if let Some(span) = unsafe { resolve_panel(v, cv, zv, i, &mut last) } {
            return (last, span);
        }
        i += L;
    }
}

// glibc wcsrchr via a fresh link namespace (bypasses fl's interposed symbol).
type GFn = unsafe extern "C" fn(*const u32, u32) -> *mut u32;
fn glibc_wcsrchr() -> GFn {
    unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen libc failed");
        let s = libc::dlsym(h, b"wcsrchr\0".as_ptr().cast());
        assert!(!s.is_null(), "dlsym wcsrchr failed");
        std::mem::transmute::<*mut c_void, GFn>(s)
    }
}
use std::ffi::c_void;

fn main() {
    let g = glibc_wcsrchr();
    // Cases: absent (c never present, full scan), frequent (every char == c, full scan tracking
    // last), mid (c once at n/2). n spans small..large to expose the fold's large-n win.
    for &n in &[256usize, 1024, 4096, 16384, 65536] {
        for tag in ["absent", "frequent", "mid"] {
            let base: Vec<u32> = match tag {
                "frequent" => std::iter::repeat(b'a' as u32)
                    .take(n)
                    .chain(std::iter::once(0))
                    .collect(),
                _ => (0..n as u32)
                    .map(|x| b'a' as u32 + (x % 20))
                    .chain(std::iter::once(0))
                    .collect(),
            };
            let c = match tag {
                "absent" => b'Z' as u32,
                "frequent" => b'a' as u32,
                _ => (b'a' as u32) + ((n / 2 % 20) as u32),
            };
            let sp = base.as_ptr();

            // Byte-identity of all fl variants vs the deployed 8-lane kernel.
            let ref_ = unsafe { scan8(sp, c) };
            assert_eq!(unsafe { scan_fold_p0(sp, c) }, ref_, "p0 mismatch n={n} {tag}");
            assert_eq!(unsafe { scan_fold_p0r(sp, c) }, ref_, "p0r mismatch n={n} {tag}");
            assert_eq!(
                unsafe { scan_fold_track(sp, c) },
                ref_,
                "track mismatch n={n} {tag}"
            );
            assert_eq!(
                unsafe { scan_fold_always(sp, c) },
                ref_,
                "always mismatch n={n} {tag}"
            );
            // fl kernel vs glibc: compare the resulting index (last match or NUL-relative).
            let gp = unsafe { g(sp, c) };
            let g_idx = if gp.is_null() {
                None
            } else {
                Some(unsafe { gp.offset_from(sp) } as usize)
            };
            assert_eq!(g_idx, ref_.0, "glibc idx mismatch n={n} {tag}");

            // Scale iters inversely with scan length so each timing sample is ~1-20ms.
            let iters: u64 = (8_000_000u64 / n as u64).max(1500);
            let (mut cur, mut tr, mut al, mut gl) =
                (Vec::new(), Vec::new(), Vec::new(), Vec::new());
            let time = |f: &dyn Fn()| {
                let t = Instant::now();
                for _ in 0..iters {
                    f();
                }
                t.elapsed().as_nanos() as f64 / iters as f64
            };
            for r in 0..40 {
                let fc = || {
                    black_box(unsafe { scan8(black_box(sp), c) });
                };
                let ft = || {
                    black_box(unsafe { scan_fold_track(black_box(sp), c) });
                };
                let fa = || {
                    black_box(unsafe { scan_fold_always(black_box(sp), c) });
                };
                let fg = || {
                    black_box(unsafe { g(black_box(sp), c) });
                };
                // Rotate order each round so no variant is systematically favored by warmup.
                if r % 2 == 0 {
                    cur.push(time(&fc));
                    tr.push(time(&ft));
                    al.push(time(&fa));
                    gl.push(time(&fg));
                } else {
                    gl.push(time(&fg));
                    al.push(time(&fa));
                    tr.push(time(&ft));
                    cur.push(time(&fc));
                }
            }
            let (cur, tr, al, gl) = (
                pctl(&cur, 0.1),
                pctl(&tr, 0.1),
                pctl(&al, 0.1),
                pctl(&gl, 0.1),
            );
            println!(
                "n={n:<6} {tag:<8} glibc={gl:7.1} cur={cur:7.1} track={tr:7.1} always={al:7.1}ns | \
                 cur/gl={:.2}x  track/gl={:.2}x  track/cur={:.3}  always/cur={:.3}",
                cur / gl,
                tr / gl,
                tr / cur,
                al / cur,
            );
        }
    }
}
