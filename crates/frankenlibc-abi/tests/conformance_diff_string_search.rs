#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc string-search oracle + raw pointer math

//! Differential + metamorphic harness for the SIMD-optimised string-search
//! family (bd-7xqyx8). Before this, strchr/strrchr/strchrnul had individual
//! diff gates but strstr/memmem/memchr/strcasestr/strpbrk/strspn/strcspn/
//! rawmemchr had NONE, and nothing cross-checked the family for internal
//! consistency.
//!
//! Two layers, no mocks:
//!   1. DIFFERENTIAL — for thousands of randomised inputs (varied alignment,
//!      length, byte alphabet, needle presence/position, and the empty/NUL edge
//!      cases that stress SIMD tail handling), fl's result OFFSET must equal the
//!      host glibc result offset, byte-for-byte.
//!   2. METAMORPHIC — cross-consistency invariants that must hold regardless of
//!      the implementation (strchr vs memchr vs strchrnul; strstr vs memmem;
//!      rawmemchr vs memchr; strspn/strcspn complementarity).
//!
//! Bare `extern "C"` names resolve to host glibc in the test binary (fl's
//! symbols are not no_mangle in test builds); fl is reached via the crate path.

use std::ffi::{c_char, c_int, c_void};

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn strstr(h: *const c_char, n: *const c_char) -> *mut c_char;
        pub fn strcasestr(h: *const c_char, n: *const c_char) -> *mut c_char;
        pub fn memmem(h: *const c_void, hl: usize, n: *const c_void, nl: usize) -> *mut c_void;
        pub fn memchr(s: *const c_void, c: c_int, n: usize) -> *mut c_void;
        pub fn strchr(s: *const c_char, c: c_int) -> *mut c_char;
        pub fn strrchr(s: *const c_char, c: c_int) -> *mut c_char;
        pub fn strchrnul(s: *const c_char, c: c_int) -> *mut c_char;
        pub fn strpbrk(s: *const c_char, a: *const c_char) -> *mut c_char;
        pub fn strspn(s: *const c_char, a: *const c_char) -> usize;
        pub fn strcspn(s: *const c_char, a: *const c_char) -> usize;
        pub fn strtok(s: *mut c_char, d: *const c_char) -> *mut c_char;
        pub fn strtok_r(s: *mut c_char, d: *const c_char, sp: *mut *mut c_char) -> *mut c_char;
        pub fn strsep(sp: *mut *mut c_char, d: *const c_char) -> *mut c_char;
    }
}

use frankenlibc_abi::string_abi as fl;

/// PAGE-SAFETY + correctness proof for the FUSED strstr (untracked haystack path).
/// mmap'd memory is not fl-malloc-tracked → `known_remaining` is None → the fused
/// page-chunked search runs. Place a NUL-terminated haystack ending at every offset
/// in the last 48 B of a mapped page whose successor is PROT_NONE, then strstr for a
/// present needle, an absent needle, and one whose match sits right at the tail —
/// require the exact glibc result and no SIGSEGV.
#[test]
fn strstr_fused_untracked_guard_page() {
    let page = 4096usize;
    unsafe {
        let base = libc::mmap(
            std::ptr::null_mut(),
            page * 2,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        assert_ne!(base, libc::MAP_FAILED, "mmap failed");
        let base = base.cast::<u8>();
        assert_eq!(
            libc::mprotect(base.add(page).cast(), page, libc::PROT_NONE),
            0
        );

        let needles: &[&[u8]] = &[b"ab\0", b"xyz\0", b"aab\0", b"zzz\0"];
        for back in 2..=48usize {
            let start = base.add(page - back);
            // Fill with a repeating pattern that contains "ab"/"aab" sometimes.
            for k in 0..(back - 1) {
                *start.add(k) = match k % 4 {
                    0 => b'a',
                    1 => b'a',
                    2 => b'b',
                    _ => b'c',
                };
            }
            *start.add(back - 1) = 0;
            for ndl in needles {
                let gp = g::strstr(start.cast(), ndl.as_ptr().cast());
                let fp = fl::strstr(start.cast(), ndl.as_ptr().cast());
                assert_eq!(
                    off(fp.cast(), start.cast()),
                    off(gp.cast(), start.cast()),
                    "strstr fused mismatch/overread back={back} needle={ndl:?}"
                );
            }
        }
        libc::munmap(base.cast(), page * 2);
    }
}

/// Offset of `p` from `base`, or -1 if `p` is NULL. Both impls operate on the
/// same buffer, so equal offsets ⟺ identical results.
fn off(p: *const c_void, base: *const c_void) -> isize {
    if p.is_null() {
        -1
    } else {
        (p as isize) - (base as isize)
    }
}

/// Deterministic xorshift64* PRNG — reproducible, no external entropy.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % (n as u64)) as usize
    }
    /// A byte drawn from a small alphabet of `alpha` distinct values (1..=255),
    /// so matches and repeats are frequent (stresses overlap/backtrack paths).
    fn byte(&mut self, alpha: u8) -> u8 {
        1 + (self.next() % (alpha as u64)) as u8
    }
}

/// Build a random NUL-terminated C string (no embedded NULs) plus its bytes.
fn rand_cstr(rng: &mut Rng, max_len: usize, alpha: u8) -> Vec<u8> {
    let len = rng.below(max_len + 1);
    let mut v: Vec<u8> = (0..len).map(|_| rng.byte(alpha)).collect();
    v.push(0);
    v
}

/// Build a random byte buffer that MAY contain embedded NULs (for mem* funcs).
fn rand_bytes(rng: &mut Rng, max_len: usize, alpha: u8) -> Vec<u8> {
    let len = rng.below(max_len + 1);
    (0..len)
        .map(|_| {
            // ~1/8 chance of an embedded NUL to exercise the mem* NUL handling.
            if rng.below(8) == 0 {
                0
            } else {
                rng.byte(alpha)
            }
        })
        .collect()
}

#[test]
fn strstr_memmem_strcasestr_match_glibc() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..6000 {
        let alpha = [2u8, 3, 5, 26][rng.below(4)];
        let hay = rand_cstr(&mut rng, 40, alpha);
        // Sometimes splice a copy of a haystack slice as the needle so it is
        // actually present at a known-ish position; sometimes fully random.
        let needle = if !hay.is_empty() && rng.below(2) == 0 && hay.len() > 1 {
            let hlen = hay.len() - 1; // exclude NUL
            let start = if hlen == 0 { 0 } else { rng.below(hlen) };
            let end = start + rng.below(hlen - start + 1);
            let mut n: Vec<u8> = hay[start..end].to_vec();
            n.push(0);
            n
        } else {
            rand_cstr(&mut rng, 6, alpha)
        };

        let g_ss = unsafe { g::strstr(hay.as_ptr().cast(), needle.as_ptr().cast()) };
        let f_ss = unsafe { fl::strstr(hay.as_ptr().cast(), needle.as_ptr().cast()) };
        assert_eq!(
            off(f_ss.cast(), hay.as_ptr().cast()),
            off(g_ss.cast(), hay.as_ptr().cast()),
            "strstr mismatch hay={hay:?} needle={needle:?}"
        );

        // strcasestr: same contract, ASCII-case-insensitive.
        let g_ci = unsafe { g::strcasestr(hay.as_ptr().cast(), needle.as_ptr().cast()) };
        let f_ci = unsafe { fl::strcasestr(hay.as_ptr().cast(), needle.as_ptr().cast()) };
        assert_eq!(
            off(f_ci.cast(), hay.as_ptr().cast()),
            off(g_ci.cast(), hay.as_ptr().cast()),
            "strcasestr mismatch hay={hay:?} needle={needle:?}"
        );

        // memmem over the byte bodies (excluding the NUL terminators).
        let hb = &hay[..hay.len().saturating_sub(1)];
        let nb = &needle[..needle.len().saturating_sub(1)];
        let g_mm = unsafe { g::memmem(hb.as_ptr().cast(), hb.len(), nb.as_ptr().cast(), nb.len()) };
        let f_mm =
            unsafe { fl::memmem(hb.as_ptr().cast(), hb.len(), nb.as_ptr().cast(), nb.len()) };
        assert_eq!(
            off(f_mm.cast(), hb.as_ptr().cast()),
            off(g_mm.cast(), hb.as_ptr().cast()),
            "memmem mismatch hay={hb:?} needle={nb:?}"
        );

        // METAMORPHIC: strstr presence ⟺ memmem presence at the same offset
        // (when the needle has no embedded NUL, which rand_cstr guarantees).
        assert_eq!(
            off(f_ss.cast(), hay.as_ptr().cast()),
            off(f_mm.cast(), hb.as_ptr().cast()),
            "strstr vs memmem disagree hay={hay:?} needle={needle:?}"
        );
    }
}

#[test]
fn strcasestr_ascii_casefold_cases_match_glibc() {
    let cases: &[(&[u8], &[u8])] = &[
        (b"AbCdEfGh\0", b"cDe\0"),
        (b"prefixNeedleSuffix\0", b"needLE\0"),
        (b"HTTPHeaderContent\0", b"header\0"),
        (b"MiXeD ascii CASE\0", b"ASCII case\0"),
        (b"no letters here 123\0", b"HERE 123\0"),
        (b"abcXYZ\0", b"xyz\0"),
        (b"abcXYZ\0", b"xYzq\0"),
        (b"Casefold tail\0", b"TAIL\0"),
        (b"short\0", b"LONGNEEDLE\0"),
        (b"empty needle\0", b"\0"),
    ];

    for (hay, needle) in cases {
        let g_ci = unsafe { g::strcasestr(hay.as_ptr().cast(), needle.as_ptr().cast()) };
        let f_ci = unsafe { fl::strcasestr(hay.as_ptr().cast(), needle.as_ptr().cast()) };
        assert_eq!(
            off(f_ci.cast(), hay.as_ptr().cast()),
            off(g_ci.cast(), hay.as_ptr().cast()),
            "strcasestr ASCII casefold mismatch hay={hay:?} needle={needle:?}"
        );
    }
}

#[test]
fn memchr_strchr_family_match_glibc() {
    let mut rng = Rng(0x1234_5678_9ABC_DEF0);
    for _ in 0..6000 {
        let alpha = [2u8, 4, 16][rng.below(3)];
        let s = rand_cstr(&mut rng, 48, alpha);
        let slen = s.len() - 1; // strlen
        // Search byte: bias toward bytes present in s and the NUL.
        let c: c_int = match rng.below(4) {
            0 => 0,
            1 if slen > 0 => s[rng.below(slen)] as c_int,
            _ => rng.byte(alpha) as c_int,
        };

        // strchr vs glibc.
        let gc = unsafe { g::strchr(s.as_ptr().cast(), c) };
        let fc = unsafe { fl::strchr(s.as_ptr().cast(), c) };
        assert_eq!(
            off(fc.cast(), s.as_ptr().cast()),
            off(gc.cast(), s.as_ptr().cast()),
            "strchr mismatch s={s:?} c={c}"
        );

        // strrchr vs glibc.
        let gr = unsafe { g::strrchr(s.as_ptr().cast(), c) };
        let fr = unsafe { fl::strrchr(s.as_ptr().cast(), c) };
        assert_eq!(
            off(fr.cast(), s.as_ptr().cast()),
            off(gr.cast(), s.as_ptr().cast()),
            "strrchr mismatch s={s:?} c={c}"
        );

        // strchrnul vs glibc (never NULL: returns NUL terminator when absent).
        let gn = unsafe { g::strchrnul(s.as_ptr().cast(), c) };
        let fn_ = unsafe { fl::strchrnul(s.as_ptr().cast(), c) };
        assert_eq!(
            off(fn_.cast(), s.as_ptr().cast()),
            off(gn.cast(), s.as_ptr().cast()),
            "strchrnul mismatch s={s:?} c={c}"
        );

        // memchr over the body INCLUDING the terminator so the c==0 case can be
        // located (matches strchr's NUL-finding behaviour).
        let n = slen + 1;
        let gm = unsafe { g::memchr(s.as_ptr().cast(), c, n) };
        let fm = unsafe { fl::memchr(s.as_ptr().cast(), c, n) };
        assert_eq!(
            off(fm.cast(), s.as_ptr().cast()),
            off(gm.cast(), s.as_ptr().cast()),
            "memchr mismatch s={s:?} c={c} n={n}"
        );

        // METAMORPHIC invariants (fl internal consistency):
        // strchr(s,c) == memchr(s,c,strlen+1) for the byte c.
        assert_eq!(
            off(fc.cast(), s.as_ptr().cast()),
            off(fm.cast(), s.as_ptr().cast()),
            "strchr vs memchr disagree s={s:?} c={c}"
        );
        // strchrnul == strchr when found, else points at the NUL terminator.
        let chrnul_off = off(fn_.cast(), s.as_ptr().cast());
        if !fc.is_null() {
            assert_eq!(chrnul_off, off(fc.cast(), s.as_ptr().cast()));
        } else {
            assert_eq!(chrnul_off, slen as isize, "strchrnul must point at NUL");
        }
        // strchr(s,0) is always the terminator.
        if c == 0 {
            assert_eq!(off(fc.cast(), s.as_ptr().cast()), slen as isize);
        }
    }
}

#[test]
fn strpbrk_strspn_strcspn_match_glibc() {
    let mut rng = Rng(0xDEAD_BEEF_CAFE_F00D);
    for _ in 0..6000 {
        let alpha = [2u8, 3, 8][rng.below(3)];
        let s = rand_cstr(&mut rng, 40, alpha);
        let set = rand_cstr(&mut rng, 6, alpha);

        let gp = unsafe { g::strpbrk(s.as_ptr().cast(), set.as_ptr().cast()) };
        let fp = unsafe { fl::strpbrk(s.as_ptr().cast(), set.as_ptr().cast()) };
        assert_eq!(
            off(fp.cast(), s.as_ptr().cast()),
            off(gp.cast(), s.as_ptr().cast()),
            "strpbrk mismatch s={s:?} set={set:?}"
        );

        let g_spn = unsafe { g::strspn(s.as_ptr().cast(), set.as_ptr().cast()) };
        let f_spn = unsafe { fl::strspn(s.as_ptr().cast(), set.as_ptr().cast()) };
        assert_eq!(f_spn, g_spn, "strspn mismatch s={s:?} set={set:?}");

        let g_csp = unsafe { g::strcspn(s.as_ptr().cast(), set.as_ptr().cast()) };
        let f_csp = unsafe { fl::strcspn(s.as_ptr().cast(), set.as_ptr().cast()) };
        assert_eq!(f_csp, g_csp, "strcspn mismatch s={s:?} set={set:?}");

        // METAMORPHIC: the prefix of `s` of length strcspn(s,set) contains no
        // char of `set`, and the char at that index (if < strlen) IS in `set`
        // and equals strpbrk's hit.
        let slen = s.len() - 1;
        if f_csp < slen {
            assert_eq!(
                off(fp.cast(), s.as_ptr().cast()),
                f_csp as isize,
                "strpbrk must hit the first reject char (= strcspn index)"
            );
        } else {
            assert!(fp.is_null(), "no reject char -> strpbrk NULL");
        }
    }
}

/// LONG-string + small-set differential for the FUSED early-stop span scanner
/// (bd-7xqyx8 follow-up): exercises the 128-byte folded tier (only reachable for
/// strings > 128 B) and varied head-alignment for `strspn`/`strcspn`/`strpbrk`
/// with 2..=4-byte accept/reject sets — the exact path the deployed strict mode
/// takes. Each `s` is built in a 64-byte-aligned page-interior buffer and probed
/// at every head offset 0..32 so the aligned-down + head-mask first load is
/// covered at all 32 residues.
#[test]
fn fused_span_long_strings_match_glibc() {
    let mut rng = Rng(0x1357_9BDF_2468_ACE0);
    for _ in 0..3000 {
        // Set size 2..=4 (the fused path); members from a tiny alphabet so a
        // member appears somewhere in a long run.
        let setlen = 2 + rng.below(3);
        let set: Vec<u8> = {
            let mut v: Vec<u8> = (0..setlen).map(|_| 1 + (rng.below(6) as u8)).collect();
            v.push(0);
            v
        };
        // Body length spanning the 32 B / 128 B tier boundaries; alphabet overlaps
        // the set sometimes (early stop) and sometimes not (scan to NUL).
        let blen = 96 + rng.below(220); // 96..=315
        let alpha = [2u8, 7, 12][rng.below(3)];
        // Over-allocate so we can slide the start to test every head residue.
        let mut buf: Vec<u8> = vec![0u8; blen + 64];
        let head = rng.below(32);
        for b in buf.iter_mut().skip(head).take(blen) {
            *b = 1 + (rng.next() % (alpha as u64)) as u8;
        }
        buf[head + blen] = 0; // NUL terminator
        let s = buf[head..].as_ptr();

        let g_spn = unsafe { g::strspn(s.cast(), set.as_ptr().cast()) };
        let f_spn = unsafe { fl::strspn(s.cast(), set.as_ptr().cast()) };
        assert_eq!(
            f_spn, g_spn,
            "strspn(long) mismatch head={head} blen={blen} set={set:?}"
        );

        let g_csp = unsafe { g::strcspn(s.cast(), set.as_ptr().cast()) };
        let f_csp = unsafe { fl::strcspn(s.cast(), set.as_ptr().cast()) };
        assert_eq!(
            f_csp, g_csp,
            "strcspn(long) mismatch head={head} blen={blen} set={set:?}"
        );

        let gp = unsafe { g::strpbrk(s.cast(), set.as_ptr().cast()) };
        let fp = unsafe { fl::strpbrk(s.cast(), set.as_ptr().cast()) };
        assert_eq!(
            off(fp.cast(), s.cast()),
            off(gp.cast(), s.cast()),
            "strpbrk(long) mismatch head={head} blen={blen} set={set:?}"
        );
    }
}

/// Differential gate for the SSE4.2 `pcmpistri` span probe (`span_probe_cmpistri`),
/// which answers `strspn`/`strcspn`/`strpbrk` for 5..=16-byte sets without the LUT
/// path's per-call setup. Every boundary the probe decides on is swept here, and
/// each must agree with live glibc:
///
///   * set length 4..=17 — 4 is below the probe's floor (tuned splat path), 16 is
///     the exact `pcmpistri` needle width (no terminator inside the register, so
///     the length comes from the byte *after* the load), 17 is the first width it
///     must decline;
///   * spans on both sides of the 128-byte probe budget, so the "resolved inside
///     the budget" and "fell through to the LUT path" branches are both exercised
///     and must produce the same answer;
///   * non-ASCII set bytes, which `pcmpistri` handles but the PSHUFB classifier
///     refuses — the two arms must still agree;
///   * strings and sets placed hard against a page end, which trips the probe's
///     page-cross guard into declining. Both guard branches must agree.
#[test]
fn cmpistri_span_probe_matches_glibc() {
    const PAGE: usize = 4096;
    let mut rng = Rng(0x0BAD_F00D_1234_5678);

    // A 4-page window, page-aligned in the interior, so a string can be laid out to
    // end exactly at a page boundary without ever reading unmapped memory.
    let backing = vec![0u8; PAGE * 5];
    let page0 = (backing.as_ptr() as usize).next_multiple_of(PAGE);

    for _ in 0..4000 {
        // The probe holds a bank of four 16-byte needles, so its behaviour changes at
        // every multiple of 16: a set of exactly 16/32/48 leaves the terminating needle
        // empty (it is dropped), 17/33/49 open a new one, and 65 is the first width the
        // bank refuses. Sample 4..=70 so all of those, plus both ends, are hit.
        let setlen = 4 + rng.below(67);
        // Half the sets draw from a small ASCII alphabet (so members actually occur
        // in `s`), half include bytes >= 0x80 to cover the non-ASCII case. The
        // alphabet is drawn WIDER than the widest set so a long set still leaves
        // non-members behind: a 70-byte set over 9 values would cover them all, and
        // both spans would then be trivially 0 or `blen` at every width.
        let non_ascii = rng.below(2) == 1;
        let mut set: Vec<u8> = (0..setlen)
            .map(|_| {
                if non_ascii && rng.below(3) == 0 {
                    0x80 + (rng.below(0x7F) as u8)
                } else {
                    1 + (rng.below(90) as u8)
                }
            })
            .collect();
        set.push(0);

        // Body length straddling the 128-byte probe budget.
        let blen = 1 + rng.below(300);
        // Haystack alphabets that variously sit inside, astride, and outside the set's
        // range, so each set width sees both an immediate stop and a long run.
        let alpha = [2u8, 6, 30, 91, 200][rng.below(5)];

        // Place the string either in the page interior or ending flush at a page
        // boundary, which forces a page-crossing 16-byte load partway through.
        let s_off = if rng.below(2) == 0 {
            PAGE + rng.below(64)
        } else {
            // NUL lands on the last byte of page 2.
            2 * PAGE - blen - 1 + rng.below(2)
        };
        // SAFETY: `backing` covers [page0, page0 + 4*PAGE); s_off + blen stays inside.
        let s = unsafe {
            let p = (page0 + s_off) as *mut u8;
            for i in 0..blen {
                *p.add(i) = 1 + (rng.next() % (alpha as u64)) as u8;
            }
            *p.add(blen) = 0;
            p as *const u8
        };

        // Place the set either in the interior or flush against a page end, so the
        // probe's set-load guard is exercised in both directions.
        let set_ptr = if rng.below(2) == 0 {
            set.as_ptr()
        } else {
            // SAFETY: writing set.len() bytes ending at the boundary of page 4.
            unsafe {
                let p = (page0 + 4 * PAGE - set.len()) as *mut u8;
                std::ptr::copy_nonoverlapping(set.as_ptr(), p, set.len());
                p as *const u8
            }
        };

        let ctx = || format!("setlen={setlen} blen={blen} s_off={s_off} set={set:?}");

        let g_spn = unsafe { g::strspn(s.cast(), set_ptr.cast()) };
        let f_spn = unsafe { fl::strspn(s.cast(), set_ptr.cast()) };
        assert_eq!(f_spn, g_spn, "strspn mismatch {}", ctx());

        let g_csp = unsafe { g::strcspn(s.cast(), set_ptr.cast()) };
        let f_csp = unsafe { fl::strcspn(s.cast(), set_ptr.cast()) };
        assert_eq!(f_csp, g_csp, "strcspn mismatch {}", ctx());

        let gp = unsafe { g::strpbrk(s.cast(), set_ptr.cast()) };
        let fp = unsafe { fl::strpbrk(s.cast(), set_ptr.cast()) };
        assert_eq!(
            off(fp.cast(), s.cast()),
            off(gp.cast(), s.cast()),
            "strpbrk mismatch {}",
            ctx()
        );
    }
}

/// Differential gate for the TOKENIZER family — `strtok`, `strtok_r`, `strsep` —
/// driven to exhaustion, comparing the WHOLE token stream against live glibc.
///
/// A single-call test cannot see the failure mode these functions actually have:
/// each of them carries a resume point across calls, and `strtok_r` keeps it in the
/// caller's `saveptr` while `strtok` keeps it in a thread-local. A fast path that
/// writes the wrong one still returns a correct FIRST token and only truncates the
/// stream afterwards — which is exactly the bug the `pcmpistri` widening introduced
/// and the existing per-function tests passed straight through.
///
/// Delimiter sets sweep 1..=20 bytes so the 5..=16 probe range, its two boundaries,
/// and the wider fallback are all covered, with leading, trailing, adjacent and
/// absent delimiters.
#[test]
fn tokenizer_family_token_streams_match_glibc() {
    fn fl_stream_strtok_r(src: &[u8], delim: &[u8]) -> Vec<Vec<u8>> {
        let mut buf = src.to_vec();
        let mut out = Vec::new();
        let mut save: *mut c_char = std::ptr::null_mut();
        unsafe {
            let mut t = fl::strtok_r(buf.as_mut_ptr().cast(), delim.as_ptr().cast(), &mut save);
            while !t.is_null() {
                out.push(std::ffi::CStr::from_ptr(t).to_bytes().to_vec());
                t = fl::strtok_r(std::ptr::null_mut(), delim.as_ptr().cast(), &mut save);
            }
        }
        out
    }
    fn g_stream_strtok_r(src: &[u8], delim: &[u8]) -> Vec<Vec<u8>> {
        let mut buf = src.to_vec();
        let mut out = Vec::new();
        let mut save: *mut c_char = std::ptr::null_mut();
        unsafe {
            let mut t = g::strtok_r(buf.as_mut_ptr().cast(), delim.as_ptr().cast(), &mut save);
            while !t.is_null() {
                out.push(std::ffi::CStr::from_ptr(t).to_bytes().to_vec());
                t = g::strtok_r(std::ptr::null_mut(), delim.as_ptr().cast(), &mut save);
            }
        }
        out
    }
    // `strsep` differs from strtok by design: it returns EMPTY fields between
    // adjacent delimiters instead of collapsing them, so it is compared to glibc's
    // strsep, never to the strtok streams.
    fn stream_strsep(src: &[u8], delim: &[u8], fl_side: bool) -> Vec<Vec<u8>> {
        let mut buf = src.to_vec();
        let mut cur = buf.as_mut_ptr().cast::<c_char>();
        let mut out = Vec::new();
        unsafe {
            loop {
                let t = if fl_side {
                    fl::strsep(&mut cur, delim.as_ptr().cast())
                } else {
                    g::strsep(&mut cur, delim.as_ptr().cast())
                };
                if t.is_null() {
                    break;
                }
                out.push(std::ffi::CStr::from_ptr(t).to_bytes().to_vec());
            }
        }
        out
    }

    let mut rng = Rng(0xFEED_FACE_5EED_1234);
    for _ in 0..3000 {
        // 1..=70 covers below, inside, and above the probe's 5..=64 window, and every
        // 16-byte needle boundary the bank steps across in between.
        let dlen = 1 + rng.below(70);
        let mut delim: Vec<u8> = (0..dlen).map(|_| 1 + (rng.below(22) as u8)).collect();
        delim.push(0);

        // Body from an alphabet that overlaps the delimiters, so delimiters land in
        // runs, at the head, and at the tail.
        let blen = 1 + rng.below(260);
        let alpha = [3u8, 8, 14, 25][rng.below(4)];
        let mut src: Vec<u8> = (0..blen)
            .map(|_| 1 + (rng.next() % alpha as u64) as u8)
            .collect();
        src.push(0);

        let ctx = || format!("dlen={dlen} blen={blen} delim={delim:?}");
        assert_eq!(
            fl_stream_strtok_r(&src, &delim),
            g_stream_strtok_r(&src, &delim),
            "strtok_r stream {}",
            ctx()
        );
        assert_eq!(
            stream_strsep(&src, &delim, true),
            stream_strsep(&src, &delim, false),
            "strsep stream {}",
            ctx()
        );

        // `strtok` carries its resume point in per-implementation global state, so
        // each stream is driven to exhaustion before the other starts.
        let fl_tok = {
            let mut buf = src.clone();
            let mut out = Vec::new();
            unsafe {
                let mut t = fl::strtok(buf.as_mut_ptr().cast(), delim.as_ptr().cast());
                while !t.is_null() {
                    out.push(std::ffi::CStr::from_ptr(t).to_bytes().to_vec());
                    t = fl::strtok(std::ptr::null_mut(), delim.as_ptr().cast());
                }
            }
            out
        };
        let g_tok = {
            let mut buf = src.clone();
            let mut out = Vec::new();
            unsafe {
                let mut t = g::strtok(buf.as_mut_ptr().cast(), delim.as_ptr().cast());
                while !t.is_null() {
                    out.push(std::ffi::CStr::from_ptr(t).to_bytes().to_vec());
                    t = g::strtok(std::ptr::null_mut(), delim.as_ptr().cast());
                }
            }
            out
        };
        assert_eq!(fl_tok, g_tok, "strtok stream {}", ctx());
    }
}

#[test]
fn rawmemchr_matches_memchr_when_present() {
    // rawmemchr assumes the byte IS present; cross-check against memchr.
    let mut rng = Rng(0x0BAD_C0DE_1337_4242);
    for _ in 0..4000 {
        let alpha = [2u8, 5, 12][rng.below(3)];
        let mut buf = rand_bytes(&mut rng, 40, alpha);
        // Guarantee a sentinel byte is present by appending it.
        let c = rng.byte(alpha);
        buf.push(c);
        let n = buf.len();
        let fm = unsafe { fl::memchr(buf.as_ptr().cast(), c as c_int, n) };
        let fr = unsafe { fl::rawmemchr(buf.as_ptr().cast(), c as c_int) };
        assert_eq!(
            off(fr, buf.as_ptr().cast()),
            off(fm, buf.as_ptr().cast()),
            "rawmemchr vs memchr disagree buf={buf:?} c={c}"
        );
    }
}

#[test]
fn empty_and_edge_cases_match_glibc() {
    // Empty haystack, empty needle, needle longer than haystack, single byte.
    let cases: &[(&[u8], &[u8])] = &[
        (b"\0", b"\0"),        // both empty
        (b"abc\0", b"\0"),     // empty needle -> haystack
        (b"\0", b"x\0"),       // empty haystack, non-empty needle
        (b"abc\0", b"abcd\0"), // needle longer
        (b"aaaa\0", b"aa\0"),  // overlapping repeats
        (b"abcabc\0", b"bca\0"),
        (b"x\0", b"x\0"),
    ];
    for (hay, needle) in cases {
        let g_ss = unsafe { g::strstr(hay.as_ptr().cast(), needle.as_ptr().cast()) };
        let f_ss = unsafe { fl::strstr(hay.as_ptr().cast(), needle.as_ptr().cast()) };
        assert_eq!(
            off(f_ss.cast(), hay.as_ptr().cast()),
            off(g_ss.cast(), hay.as_ptr().cast()),
            "strstr edge mismatch hay={hay:?} needle={needle:?}"
        );
        let hb = &hay[..hay.len() - 1];
        let nb = &needle[..needle.len() - 1];
        let g_mm = unsafe { g::memmem(hb.as_ptr().cast(), hb.len(), nb.as_ptr().cast(), nb.len()) };
        let f_mm =
            unsafe { fl::memmem(hb.as_ptr().cast(), hb.len(), nb.as_ptr().cast(), nb.len()) };
        assert_eq!(
            off(f_mm.cast(), hb.as_ptr().cast()),
            off(g_mm.cast(), hb.as_ptr().cast()),
            "memmem edge mismatch hay={hb:?} needle={nb:?}"
        );
    }
    // memchr with n==0 is always NULL.
    let buf = [1u8, 2, 3];
    assert!(unsafe { fl::memchr(buf.as_ptr().cast(), 1, 0) }.is_null());
    assert!(unsafe { g::memchr(buf.as_ptr().cast(), 1, 0) }.is_null());
}
