#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc wcsnlen oracle

//! Differential gate for wcsnlen (bd-li039w) — previously uncovered. wcsnlen
//! returns min(wcslen(s), maxlen): it scans at most `maxlen` wide chars and
//! never reads past a NUL. fl must match host glibc across maxlen below/at/above
//! the string length, including 0 and no-NUL-within-bound. No mocks.

use libc::wchar_t;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

/// The host arm is resolved with `dlsym`, not declared at link time. fl exports
/// this symbol into this test binary, so a link-time reference can bind to fl
/// and leave BOTH arms as fl -- green while comparing nothing (bd-v0388t). That
/// matters especially here: this gate covers a hand-written SIMD kernel, whose
/// whole risk is diverging from the scalar contract at a vector boundary.

type WcsnlenFn = unsafe extern "C" fn(*const wchar_t, usize) -> usize;

fn host_wcsnlen() -> WcsnlenFn {
    // SAFETY: signature matches GNU wcsnlen exactly.
    unsafe { dlsym_oracle::host_fn(c"wcsnlen", frankenlibc_abi::wchar_abi::wcsnlen as *const ()) }
}

#[test]
fn wcsnlen_matches_glibc() {
    // "hello\0" plus trailing non-NUL filler to exercise the unbounded case.
    let mut buf: Vec<wchar_t> = "hello".chars().map(|c| c as wchar_t).collect();
    buf.push(0);
    buf.extend("WORLD".chars().map(|c| c as wchar_t)); // junk after the NUL

    for maxlen in [0usize, 1, 3, 5, 6, 10, 50] {
        let g = unsafe { host_wcsnlen()(buf.as_ptr(), maxlen) };
        let f = unsafe { frankenlibc_abi::wchar_abi::wcsnlen(buf.as_ptr(), maxlen) };
        assert_eq!(f, g, "wcsnlen(maxlen={maxlen}): fl={f} glibc={g}");
    }

    // A buffer with NO NUL within the bound: wcsnlen must stop at maxlen.
    let nonul: Vec<wchar_t> = "abcdefgh".chars().map(|c| c as wchar_t).collect();
    for maxlen in [0usize, 1, 4, 8] {
        let g = unsafe { host_wcsnlen()(nonul.as_ptr(), maxlen) };
        let f = unsafe { frankenlibc_abi::wchar_abi::wcsnlen(nonul.as_ptr(), maxlen) };
        assert_eq!(f, g, "wcsnlen(no NUL, maxlen={maxlen}): fl={f} glibc={g}");
        assert_eq!(
            f, maxlen,
            "wcsnlen must return maxlen when no NUL within bound"
        );
    }

    // Empty string -> 0 regardless of maxlen.
    let empty: [wchar_t; 1] = [0];
    for maxlen in [0usize, 5] {
        let g = unsafe { host_wcsnlen()(empty.as_ptr(), maxlen) };
        let f = unsafe { frankenlibc_abi::wchar_abi::wcsnlen(empty.as_ptr(), maxlen) };
        assert_eq!(f, g, "wcsnlen(empty, maxlen={maxlen})");
        assert_eq!(f, 0);
    }
}

/// Bounds of 256+ elements. In the baseline x86-64 build, page-clamped spans of
/// 256+ elements run the AVX2 twin of the core wcsnlen on CPUs with AVX2 and its
/// baseline copy elsewhere; shorter spans (bound 255, or the head of a span that
/// starts near a page end) stay on the inline scan (bd-rc0923-epic-eeuy4f.13).
/// The filler elements are nonzero but contain zero BYTES (0x100, 0x1_0000,
/// 0x100_0000), so a scan that tested bytes instead of whole elements, or that
/// mishandled a panel or page edge, stops early. Every result must equal host
/// glibc and `min(NUL index, maxlen)`.
#[test]
fn wcsnlen_long_bounds_match_glibc() {
    const LEN: usize = 6 * 1024;
    let filler: [wchar_t; 7] = [0x100, 0x1_0000, 0x100_0000, -1, 0x61, 0x10_FFFF, 0x7f];
    let mut buf: Vec<wchar_t> = (0..LEN).map(|i| filler[i % filler.len()]).collect();
    let mut compared = 0usize;
    for start in [0usize, 1, 3, 17, 64, 1000] {
        let avail = LEN - start;
        for nul in [
            None,
            Some(0usize),
            Some(1),
            Some(63),
            Some(64),
            Some(255),
            Some(256),
            Some(257),
            Some(511),
            Some(1023),
            Some(1024),
            Some(1025),
            Some(2047),
            Some(4095),
        ] {
            if let Some(k) = nul {
                buf[start + k] = 0;
            }
            let mut bounds = vec![255usize, 256, 257, 300, 1024, 1025, 2048, 4096, avail];
            if nul.is_some() {
                // A terminator inside the buffer makes an unbounded ceiling legal.
                bounds.push(usize::MAX);
            }
            let p = buf[start..].as_ptr();
            for maxlen in bounds {
                let g = unsafe { host_wcsnlen()(p, maxlen) };
                let f = unsafe { frankenlibc_abi::wchar_abi::wcsnlen(p, maxlen) };
                let want = nul.map_or(maxlen, |k| k.min(maxlen));
                assert_eq!(
                    f, g,
                    "wcsnlen(start={start}, nul={nul:?}, maxlen={maxlen}): fl={f} glibc={g}"
                );
                assert_eq!(
                    f, want,
                    "wcsnlen(start={start}, nul={nul:?}, maxlen={maxlen}) must be min(NUL, maxlen)"
                );
                compared += 1;
            }
            if let Some(k) = nul {
                buf[start + k] = filler[(start + k) % filler.len()];
            }
        }
    }
    assert_eq!(compared, 6 * (9 + 13 * 10));
}
