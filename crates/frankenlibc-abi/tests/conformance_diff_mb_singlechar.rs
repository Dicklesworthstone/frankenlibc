#![cfg(target_os = "linux")]

//! Differential conformance harness for the single-character multibyte
//! conversions `mblen(3)`, `mbtowc(3)`, and `wctomb(3)` across `"C"` and
//! `"C.UTF-8"` locales, `PROT_NONE` guard-page / `usize::MAX` length bounds,
//! metamorphic round-trip invariants, mutated-arm rejection, and isolated
//! `strict` + `hardened` subprocess execution.

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

use dlsym_oracle::host_fn;
use frankenlibc_abi::{errno_abi, locale_abi, wchar_abi as fl};
use std::ffi::{CStr, c_char, c_int};
use std::process::Command;
use std::sync::{Mutex, MutexGuard};

type MblenFn = unsafe extern "C" fn(*const c_char, usize) -> c_int;
type MbtowcFn = unsafe extern "C" fn(*mut i32, *const c_char, usize) -> c_int;
type WctombFn = unsafe extern "C" fn(*mut c_char, i32) -> c_int;
type SetlocaleFn = unsafe extern "C" fn(c_int, *const c_char) -> *mut c_char;
type ErrnoLocFn = unsafe extern "C" fn() -> *mut c_int;

struct HostMbApi {
    mblen: MblenFn,
    mbtowc: MbtowcFn,
    wctomb: WctombFn,
    setlocale: SetlocaleFn,
    errno_loc: ErrnoLocFn,
}

impl HostMbApi {
    fn resolve() -> Self {
        unsafe {
            Self {
                mblen: host_fn(c"mblen", fl::mblen as *const ()),
                mbtowc: host_fn(c"mbtowc", fl::mbtowc as *const ()),
                wctomb: host_fn(c"wctomb", fl::wctomb as *const ()),
                setlocale: host_fn(c"setlocale", locale_abi::setlocale as *const ()),
                errno_loc: host_fn(
                    c"__errno_location",
                    errno_abi::__errno_location as *const (),
                ),
            }
        }
    }

    fn clear_both_errnos(&self) {
        unsafe {
            *errno_abi::__errno_location() = 0;
            *(self.errno_loc)() = 0;
        }
    }

    fn errnos(&self) -> (c_int, c_int) {
        unsafe { (*errno_abi::__errno_location(), *(self.errno_loc)()) }
    }
}

static LOCALE_LOCK: Mutex<()> = Mutex::new(());

struct LocaleScope<'a> {
    _guard: MutexGuard<'a, ()>,
    host: HostMbApi,
}

impl<'a> LocaleScope<'a> {
    fn enter(locale: &CStr) -> Self {
        let guard = LOCALE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let host = HostMbApi::resolve();
        unsafe {
            let fl_loc = locale_abi::setlocale(libc::LC_CTYPE, locale.as_ptr());
            let lc_loc = (host.setlocale)(libc::LC_CTYPE, locale.as_ptr());
            assert!(
                !fl_loc.is_null() && !lc_loc.is_null(),
                "setlocale(LC_CTYPE, {locale:?}) failed: fl={fl_loc:p} host={lc_loc:p}"
            );
            let _ = fl::mbtowc(std::ptr::null_mut(), std::ptr::null(), 0);
            let _ = (host.mbtowc)(std::ptr::null_mut(), std::ptr::null(), 0);
        }
        Self {
            _guard: guard,
            host,
        }
    }
}

impl Drop for LocaleScope<'_> {
    fn drop(&mut self) {
        unsafe {
            let _ = locale_abi::setlocale(libc::LC_CTYPE, c"C".as_ptr());
            let _ = (self.host.setlocale)(libc::LC_CTYPE, c"C".as_ptr());
            let _ = fl::mbtowc(std::ptr::null_mut(), std::ptr::null(), 0);
            let _ = (self.host.mbtowc)(std::ptr::null_mut(), std::ptr::null(), 0);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MbObservation {
    rc: c_int,
    err: c_int,
    wc: i32,
    bytes: Vec<u8>,
}

fn check_mb_arm_parity(
    fl_obs: &MbObservation,
    host_obs: &MbObservation,
    context: &str,
) -> Result<(), String> {
    if fl_obs == host_obs {
        Ok(())
    } else {
        Err(format!("{context}: fl={fl_obs:?} host={host_obs:?}"))
    }
}

#[test]
fn diff_mblen_ascii_returns_one() {
    let scope = LocaleScope::enter(c"C");
    for &b in b"aZ0 !" {
        let buf = [b];
        scope.host.clear_both_errnos();
        let fl_r = unsafe { fl::mblen(buf.as_ptr(), 1) };
        let lc_r = unsafe { (scope.host.mblen)(buf.as_ptr().cast(), 1) };
        let (fl_e, lc_e) = scope.host.errnos();
        assert_eq!((fl_r, fl_e), (lc_r, lc_e), "mblen({b:#x})");
        assert_eq!((fl_r, fl_e), (1, 0));
    }
}

#[test]
fn diff_mblen_nul_returns_zero() {
    let scope = LocaleScope::enter(c"C");
    for n in [0usize, 1, usize::MAX] {
        let buf = [0u8];
        scope.host.clear_both_errnos();
        let fl_r = unsafe { fl::mblen(buf.as_ptr(), n) };
        let lc_r = unsafe { (scope.host.mblen)(buf.as_ptr().cast(), n) };
        let (fl_e, lc_e) = scope.host.errnos();
        assert_eq!((fl_r, fl_e), (lc_r, lc_e), "mblen(NUL, n={n})");
        assert_eq!((fl_r, fl_e), (0, 0));
    }
}

#[test]
fn diff_mblen_zero_n_returns_minus_one_without_eilseq() {
    let scope = LocaleScope::enter(c"C");
    let buf = b"a";
    scope.host.clear_both_errnos();
    let fl_r = unsafe { fl::mblen(buf.as_ptr(), 0) };
    let lc_r = unsafe { (scope.host.mblen)(buf.as_ptr().cast(), 0) };
    let (fl_e, lc_e) = scope.host.errnos();
    assert_eq!((fl_r, fl_e), (lc_r, lc_e), "mblen(n=0)");
    assert_eq!((fl_r, fl_e), (-1, 0));
}

#[test]
fn diff_mbtowc_zero_n_returns_minus_one_without_eilseq() {
    let scope = LocaleScope::enter(c"C");
    let buf = b"a";
    let mut fl_wc: i32 = -77;
    let mut lc_wc: i32 = -77;
    scope.host.clear_both_errnos();
    let fl_r = unsafe { fl::mbtowc((&mut fl_wc as *mut i32).cast(), buf.as_ptr(), 0) };
    let lc_r = unsafe { (scope.host.mbtowc)(&mut lc_wc, buf.as_ptr().cast(), 0) };
    let (fl_e, lc_e) = scope.host.errnos();
    assert_eq!((fl_r, fl_e, fl_wc), (lc_r, lc_e, lc_wc));
    assert_eq!((fl_r, fl_e, fl_wc), (-1, 0, -77));
}

#[test]
fn diff_mblen_and_mbtowc_and_wctomb_null_pointer_reports_stateless() {
    let scope = LocaleScope::enter(c"C");
    let fl_mblen = unsafe { fl::mblen(std::ptr::null(), 1) };
    let lc_mblen = unsafe { (scope.host.mblen)(std::ptr::null(), 1) };
    assert_eq!((fl_mblen, lc_mblen), (0, 0));

    let fl_mbtowc = unsafe { fl::mbtowc(std::ptr::null_mut(), std::ptr::null(), 1) };
    let lc_mbtowc = unsafe { (scope.host.mbtowc)(std::ptr::null_mut(), std::ptr::null(), 1) };
    assert_eq!((fl_mbtowc, lc_mbtowc), (0, 0));

    let fl_wctomb = unsafe { fl::wctomb(std::ptr::null_mut(), 0) };
    let lc_wctomb = unsafe { (scope.host.wctomb)(std::ptr::null_mut(), 0) };
    assert_eq!((fl_wctomb, lc_wctomb), (0, 0));
}

#[test]
fn diff_mbtowc_ascii_and_null_pwc_and_nul_parity() {
    let scope = LocaleScope::enter(c"C");
    for &b in b"A1~ " {
        let in_buf = [b];
        let mut fl_wc: i32 = -1;
        let mut lc_wc: i32 = -1;
        scope.host.clear_both_errnos();
        let fl_r = unsafe { fl::mbtowc((&mut fl_wc as *mut i32).cast(), in_buf.as_ptr(), 1) };
        let lc_r = unsafe { (scope.host.mbtowc)(&mut lc_wc, in_buf.as_ptr().cast(), 1) };
        let (fl_e, lc_e) = scope.host.errnos();
        assert_eq!((fl_r, fl_wc, fl_e), (lc_r, lc_wc, lc_e));
        assert_eq!((fl_r, fl_wc, fl_e), (1, b as i32, 0));
    }

    let in_buf = b"X";
    let fl_r = unsafe { fl::mbtowc(std::ptr::null_mut(), in_buf.as_ptr(), 1) };
    let lc_r = unsafe { (scope.host.mbtowc)(std::ptr::null_mut(), in_buf.as_ptr().cast(), 1) };
    assert_eq!((fl_r, lc_r), (1, 1));

    for n in [0usize, 1, usize::MAX] {
        let nul_buf = [0u8];
        let mut fl_wc: i32 = -1;
        let mut lc_wc: i32 = -1;
        let fl_r = unsafe { fl::mbtowc((&mut fl_wc as *mut i32).cast(), nul_buf.as_ptr(), n) };
        let lc_r = unsafe { (scope.host.mbtowc)(&mut lc_wc, nul_buf.as_ptr().cast(), n) };
        assert_eq!((fl_r, fl_wc), (lc_r, lc_wc));
        assert_eq!((fl_r, fl_wc), (0, 0));
    }
}

#[test]
fn diff_wctomb_ascii_and_nul_parity() {
    let scope = LocaleScope::enter(c"C");
    for wc in [0i32, b'a' as i32, b'Z' as i32, b'9' as i32, 0x7f] {
        let mut fl_buf = [0xffu8; 8];
        let mut lc_buf = [0xffu8; 8];
        scope.host.clear_both_errnos();
        let fl_r = unsafe { fl::wctomb(fl_buf.as_mut_ptr(), wc as u32) };
        let lc_r = unsafe { (scope.host.wctomb)(lc_buf.as_mut_ptr().cast(), wc) };
        let (fl_e, lc_e) = scope.host.errnos();
        assert_eq!((fl_r, fl_e), (lc_r, lc_e), "wctomb({wc:#x})");
        assert_eq!((fl_r, fl_e), (1, 0));
        assert_eq!(fl_buf[0], lc_buf[0]);
        assert_eq!(fl_buf[0] as i32, wc);
    }
}

#[test]
fn diff_c_locale_rejects_non_ascii_with_eilseq_across_all_three() {
    let scope = LocaleScope::enter(c"C");
    for wc in [0x80i32, 0xff, 0x4E2D, 0xD800, 0x10FFFF, -1] {
        let mut fl_buf = [0xa5u8; 8];
        let mut lc_buf = [0xa5u8; 8];
        scope.host.clear_both_errnos();
        let fl_r = unsafe { fl::wctomb(fl_buf.as_mut_ptr(), wc as u32) };
        let lc_r = unsafe { (scope.host.wctomb)(lc_buf.as_mut_ptr().cast(), wc) };
        let (fl_e, lc_e) = scope.host.errnos();
        assert_eq!(
            (fl_r, fl_e),
            (lc_r, lc_e),
            "C locale wctomb({wc:#x}) must match glibc exactly"
        );
        assert_eq!((fl_r, fl_e), (-1, libc::EILSEQ));
    }

    for byte in [0x80u8, 0xBF, 0xC2, 0xC3, 0xE2, 0xF0, 0xFF] {
        let buf = [byte];
        scope.host.clear_both_errnos();
        let fl_len = unsafe { fl::mblen(buf.as_ptr(), 1) };
        let lc_len = unsafe { (scope.host.mblen)(buf.as_ptr().cast(), 1) };
        let (fl_e, lc_e) = scope.host.errnos();
        assert_eq!((fl_len, fl_e), (lc_len, lc_e), "C locale mblen({byte:#x})");
        assert_eq!((fl_len, fl_e), (-1, libc::EILSEQ));

        let mut fl_wc: i32 = -55;
        let mut lc_wc: i32 = -55;
        scope.host.clear_both_errnos();
        let fl_mb = unsafe { fl::mbtowc((&mut fl_wc as *mut i32).cast(), buf.as_ptr(), 1) };
        let lc_mb = unsafe { (scope.host.mbtowc)(&mut lc_wc, buf.as_ptr().cast(), 1) };
        let (fl_e2, lc_e2) = scope.host.errnos();
        assert_eq!(
            (fl_mb, fl_e2, fl_wc),
            (lc_mb, lc_e2, lc_wc),
            "C locale mbtowc({byte:#x})"
        );
        assert_eq!((fl_mb, fl_e2, fl_wc), (-1, libc::EILSEQ, -55));
    }
}

#[test]
fn diff_utf8_locale_multibyte_state_and_guard_page_bounds() {
    let scope = LocaleScope::enter(c"C.UTF-8");

    // 1. Valid 1..=6 byte sequences in C.UTF-8 + rejection of surrogates and negative wchar_t.
    for wc in [
        0x007Fi32, 0x0080, 0x00E9, 0x07FF, 0x0800, 0x4E2D, 0xD7FF, 0xE000, 0x10FFFF, 0x110000,
    ] {
        let mut fl_buf = [0u8; 8];
        let mut lc_buf = [0u8; 8];
        scope.host.clear_both_errnos();
        let fl_r = unsafe { fl::wctomb(fl_buf.as_mut_ptr(), wc as u32) };
        let lc_r = unsafe { (scope.host.wctomb)(lc_buf.as_mut_ptr().cast(), wc) };
        let (fl_e, lc_e) = scope.host.errnos();
        assert_eq!(
            (fl_r, fl_e),
            (lc_r, lc_e),
            "C.UTF-8 wctomb({wc:#x}) ret/errno"
        );
        assert!(fl_r >= 1);
        let n = fl_r as usize;
        assert_eq!(&fl_buf[..n], &lc_buf[..n], "C.UTF-8 wctomb({wc:#x}) bytes");

        scope.host.clear_both_errnos();
        let fl_len = unsafe { fl::mblen(fl_buf.as_ptr(), usize::MAX) };
        let lc_len = unsafe { (scope.host.mblen)(lc_buf.as_ptr().cast(), usize::MAX) };
        assert_eq!((fl_len, lc_len), (fl_r, lc_r), "C.UTF-8 mblen({wc:#x})");

        let mut fl_wc: i32 = -1;
        let mut lc_wc: i32 = -1;
        scope.host.clear_both_errnos();
        let fl_mb =
            unsafe { fl::mbtowc((&mut fl_wc as *mut i32).cast(), fl_buf.as_ptr(), usize::MAX) };
        let lc_mb = unsafe { (scope.host.mbtowc)(&mut lc_wc, lc_buf.as_ptr().cast(), usize::MAX) };
        assert_eq!((fl_mb, fl_wc), (lc_mb, lc_wc));
        assert_eq!((fl_mb, fl_wc), (fl_r, wc));
    }

    for bad_wc in [0xD800i32, 0xDBFF, 0xDFFF, -1, i32::MIN] {
        let mut fl_buf = [0u8; 8];
        let mut lc_buf = [0u8; 8];
        scope.host.clear_both_errnos();
        let fl_r = unsafe { fl::wctomb(fl_buf.as_mut_ptr(), bad_wc as u32) };
        let lc_r = unsafe { (scope.host.wctomb)(lc_buf.as_mut_ptr().cast(), bad_wc) };
        let (fl_e, lc_e) = scope.host.errnos();
        assert_eq!(
            (fl_r, fl_e),
            (lc_r, lc_e),
            "C.UTF-8 bad wctomb({bad_wc:#x})"
        );
        assert_eq!((fl_r, fl_e), (-1, libc::EILSEQ));
    }

    // 2. Stateless mblen vs stateful LegacyWide mbtowc across split 2-byte UTF-8 ("é" = C3 A9).
    let e_acute = [0xC3u8, 0xA9];
    scope.host.clear_both_errnos();
    let fl_l1 = unsafe { fl::mblen(&e_acute[0], 1) };
    let lc_l1 = unsafe { (scope.host.mblen)((&e_acute[0] as *const u8).cast(), 1) };
    assert_eq!((fl_l1, lc_l1, scope.host.errnos()), (-1, -1, (0, 0)));

    scope.host.clear_both_errnos();
    let fl_l2 = unsafe { fl::mblen(&e_acute[1], 1) };
    let lc_l2 = unsafe { (scope.host.mblen)((&e_acute[1] as *const u8).cast(), 1) };
    assert_eq!(
        (fl_l2, lc_l2, scope.host.errnos()),
        (-1, -1, (libc::EILSEQ, libc::EILSEQ))
    );

    let mut fl_wc: i32 = -99;
    let mut lc_wc: i32 = -99;
    scope.host.clear_both_errnos();
    let fl_m1 = unsafe { fl::mbtowc((&mut fl_wc as *mut i32).cast(), &e_acute[0], 1) };
    let lc_m1 = unsafe { (scope.host.mbtowc)(&mut lc_wc, (&e_acute[0] as *const u8).cast(), 1) };
    assert_eq!(
        (fl_m1, lc_m1, fl_wc, lc_wc, scope.host.errnos()),
        (-1, -1, -99, -99, (0, 0))
    );

    scope.host.clear_both_errnos();
    let fl_m2 = unsafe { fl::mbtowc((&mut fl_wc as *mut i32).cast(), &e_acute[1], 1) };
    let lc_m2 = unsafe { (scope.host.mbtowc)(&mut lc_wc, (&e_acute[1] as *const u8).cast(), 1) };
    assert_eq!(
        (fl_m2, lc_m2, fl_wc, lc_wc, scope.host.errnos()),
        (1, 1, 0x00E9, 0x00E9, (0, 0))
    );

    // 3. Guard-page boundary check: a complete 2-byte UTF-8 sequence or an already-invalid
    // 2-byte prefix placed at `page_end - 2` before a `PROT_NONE` page must not fault even
    // when the caller supplies `n = usize::MAX` or `n = 16`.
    unsafe {
        let base = libc::mmap(
            std::ptr::null_mut(),
            8192,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        assert_ne!(base, libc::MAP_FAILED);
        assert_eq!(
            libc::mprotect(base.cast::<u8>().add(4096).cast(), 4096, libc::PROT_NONE),
            0
        );
        let tail2 = base.cast::<u8>().add(4094);

        *tail2 = 0xC3;
        *tail2.add(1) = 0xA9;
        scope.host.clear_both_errnos();
        let fl_g1 = fl::mblen(tail2, usize::MAX);
        let lc_g1 = (scope.host.mblen)(tail2.cast(), usize::MAX);
        let mut fl_gwc: i32 = -1;
        let mut lc_gwc: i32 = -1;
        let fl_g2 = fl::mbtowc((&mut fl_gwc as *mut i32).cast(), tail2, usize::MAX);
        let lc_g2 = (scope.host.mbtowc)(&mut lc_gwc, tail2.cast(), usize::MAX);
        assert_eq!((fl_g1, fl_g2, fl_gwc), (lc_g1, lc_g2, lc_gwc));
        assert_eq!((fl_g1, fl_g2, fl_gwc), (2, 2, 0x00E9));

        *tail2 = 0xE2;
        *tail2.add(1) = b' ';
        scope.host.clear_both_errnos();
        let fl_g3 = fl::mblen(tail2, 16);
        let lc_g3 = (scope.host.mblen)(tail2.cast(), 16);
        assert_eq!(
            (fl_g3, lc_g3, scope.host.errnos()),
            (-1, -1, (libc::EILSEQ, libc::EILSEQ))
        );

        scope.host.clear_both_errnos();
        let fl_g4 = fl::mbtowc((&mut fl_gwc as *mut i32).cast(), tail2, 16);
        let lc_g4 = (scope.host.mbtowc)(&mut lc_gwc, tail2.cast(), 16);
        assert_eq!(
            (fl_g4, lc_g4, scope.host.errnos()),
            (-1, -1, (libc::EILSEQ, libc::EILSEQ))
        );

        assert_eq!(libc::munmap(base, 8192), 0);
    }
}

/// Metamorphic invariant (explicitly distinct from oracle conformance):
/// For every scalar value accepted by `fl::wctomb` in `"C.UTF-8"`, `fl::mblen`
/// and `fl::mbtowc` over the exact emitted prefix recover the identical byte
/// length and codepoint, while truncating by 1 byte yields `-1` (`errno == 0`).
#[test]
fn metamorphic_wctomb_mbtowc_mblen_roundtrip_and_truncation() {
    let _scope = LocaleScope::enter(c"C.UTF-8");
    for wc in [1u32, 0x7F, 0x80, 0x3BB, 0x20AC, 0x4E2D, 0x1F600, 0x10FFFF] {
        let mut encoded = [0u8; 8];
        let n = unsafe { fl::wctomb(encoded.as_mut_ptr(), wc) };
        assert!((1..=4).contains(&n));
        let width = n as usize;

        let len = unsafe { fl::mblen(encoded.as_ptr(), width) };
        let mut decoded: u32 = 0;
        let mb_len = unsafe { fl::mbtowc(&mut decoded, encoded.as_ptr(), width) };
        assert_eq!((len, mb_len, decoded), (n, n, wc));

        if width > 1 {
            unsafe { *errno_abi::__errno_location() = 0 };
            let short_len = unsafe { fl::mblen(encoded.as_ptr(), width - 1) };
            let short_err = unsafe { *errno_abi::__errno_location() };
            assert_eq!((short_len, short_err), (-1, 0));
        }
    }
}

#[test]
fn mutated_mb_implementation_arm_is_rejected() {
    let reference = MbObservation {
        rc: 3,
        err: 0,
        wc: 0x4E2D,
        bytes: vec![0xE4, 0xB8, 0xAD],
    };
    assert!(check_mb_arm_parity(&reference, &reference, "identical").is_ok());

    let wrong_rc = MbObservation {
        rc: -1,
        ..reference.clone()
    };
    let wrong_errno = MbObservation {
        err: libc::EILSEQ,
        ..reference.clone()
    };
    let wrong_wc = MbObservation {
        wc: 0xFFFD,
        ..reference.clone()
    };
    let wrong_bytes = MbObservation {
        bytes: vec![0xE4, 0xB8, 0xAE],
        ..reference.clone()
    };
    assert!(check_mb_arm_parity(&wrong_rc, &reference, "mutated rc").is_err());
    assert!(check_mb_arm_parity(&wrong_errno, &reference, "mutated errno").is_err());
    assert!(check_mb_arm_parity(&wrong_wc, &reference, "mutated wc").is_err());
    assert!(check_mb_arm_parity(&wrong_bytes, &reference, "mutated bytes").is_err());
}

#[test]
fn mb_singlechar_strict_and_hardened_subprocess_and_measured_report() {
    if std::env::var("FL_MB_SINGLECHAR_SUBPROC").is_ok() {
        let mut comparisons = 0usize;
        let mut divergences = 0usize;
        for locale in [c"C", c"C.UTF-8"] {
            let scope = LocaleScope::enter(locale);
            for wc in [
                0i32,
                b'A' as i32,
                0x7F,
                0x80,
                0x00E9,
                0x4E2D,
                0xD800,
                0x10FFFF,
                -1,
            ] {
                let mut fl_buf = [0u8; 8];
                let mut lc_buf = [0u8; 8];
                scope.host.clear_both_errnos();
                let fl_rc = unsafe { fl::wctomb(fl_buf.as_mut_ptr(), wc as u32) };
                let lc_rc = unsafe { (scope.host.wctomb)(lc_buf.as_mut_ptr().cast(), wc) };
                let (fl_e, lc_e) = scope.host.errnos();
                let fl_obs = MbObservation {
                    rc: fl_rc,
                    err: fl_e,
                    wc,
                    bytes: if fl_rc > 0 {
                        fl_buf[..fl_rc as usize].to_vec()
                    } else {
                        Vec::new()
                    },
                };
                let lc_obs = MbObservation {
                    rc: lc_rc,
                    err: lc_e,
                    wc,
                    bytes: if lc_rc > 0 {
                        lc_buf[..lc_rc as usize].to_vec()
                    } else {
                        Vec::new()
                    },
                };
                comparisons += 1;
                if check_mb_arm_parity(&fl_obs, &lc_obs, "wctomb").is_err() {
                    divergences += 1;
                }
            }
        }
        assert!(
            comparisons >= 18,
            "expected measured comparisons, got {comparisons}"
        );
        assert_eq!(divergences, 0, "unexpected mb_singlechar divergences");
        eprintln!(
            "{{\"family\":\"libc mblen + mbtowc + wctomb\",\"reference\":\"glibc\",\"functions\":3,\"cases\":{comparisons},\"divergences\":{divergences}}}"
        );
        return;
    }

    for mode in ["strict", "hardened"] {
        let status = Command::new(std::env::current_exe().expect("current_exe"))
            .args([
                "--exact",
                "mb_singlechar_strict_and_hardened_subprocess_and_measured_report",
                "--nocapture",
            ])
            .env("FL_MB_SINGLECHAR_SUBPROC", "1")
            .env("FRANKENLIBC_MODE", mode)
            .env_remove("LD_PRELOAD")
            .status()
            .expect("spawn mb_singlechar child");
        assert!(
            status.success(),
            "mb_singlechar failed in mode={mode}: {status}"
        );
    }
}
