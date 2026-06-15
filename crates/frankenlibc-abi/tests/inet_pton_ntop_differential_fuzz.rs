#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc inet_pton/inet_ntop oracle (libc, linked by std)

//! Randomized differential fuzzer for `inet_pton`/`inet_ntop` (AF_INET +
//! AF_INET6) vs host glibc. The inet subsystem has many fixed-case / edge /
//! metamorphic probes but NO randomized full-contract fuzzer — and IPv6 is
//! exactly where parity bugs hide: `inet_ntop`'s `::` longest-zero-run
//! compression (glibc only compresses runs >= 2, leftmost-longest, lowercase
//! hex, no leading zeros) and `inet_pton`'s acceptance of `::` placement,
//! embedded IPv4 tails, leading zeros, and overflow. This sweeps:
//!   - ntop6 over random 16-byte addresses with injected zero-runs (compression
//!     stress) — compares the exact output string;
//!   - ntop4 over random 4-byte addresses;
//!   - pton6/pton4 over canonical round-trips (host-ntop output fed back) AND
//!     random IPv6/IPv4-ish strings + garbage — compares the return value AND
//!     the written address bytes.

use std::ffi::{CString, c_char, c_int, c_void};

use frankenlibc_abi::inet_abi as fl;

unsafe extern "C" {
    fn inet_pton(af: c_int, src: *const c_char, dst: *mut c_void) -> c_int;
    fn inet_ntop(af: c_int, src: *const c_void, dst: *mut c_char, size: u32) -> *const c_char;
}

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 33) as u8
    }
}

/// `inet_ntop` via one implementation. Returns `Some(string)` on success (ptr
/// non-NULL) or `None` on failure.
unsafe fn ntop(
    f: unsafe extern "C" fn(c_int, *const c_void, *mut c_char, u32) -> *const c_char,
    af: c_int,
    src: &[u8],
) -> Option<String> {
    let mut buf = [0u8; 64];
    let r = unsafe {
        f(
            af,
            src.as_ptr() as *const c_void,
            buf.as_mut_ptr() as *mut c_char,
            buf.len() as u32,
        )
    };
    if r.is_null() {
        return None;
    }
    let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Some(String::from_utf8_lossy(&buf[..n]).into_owned())
}

/// `inet_pton` via one implementation. Returns `(ret, bytes_written)`; the bytes
/// are only meaningful when `ret == 1`, but we capture them regardless (glibc
/// leaves `dst` untouched on failure, and so must fl — compared only on success).
unsafe fn pton(
    f: unsafe extern "C" fn(c_int, *const c_char, *mut c_void) -> c_int,
    af: c_int,
    s: &CString,
    n: usize,
) -> (c_int, Vec<u8>) {
    let mut buf = vec![0u8; n];
    let r = unsafe { f(af, s.as_ptr(), buf.as_mut_ptr() as *mut c_void) };
    (r, buf)
}

/// Random IPv6-ish string: 0..=8 groups of 1..=5 hex digits joined by ':', with
/// an optional single `::`, an optional trailing embedded IPv4, and occasional
/// stray characters — to stress both the accept and reject paths.
fn gen_ipv6_string(r: &mut Lcg) -> String {
    let hexd = b"0123456789abcdefABCDEF";
    let mut parts: Vec<String> = Vec::new();
    let groups = (r.next() % 9) as usize;
    for _ in 0..groups {
        let len = 1 + (r.next() % 5) as usize;
        let mut g = String::new();
        for _ in 0..len {
            g.push(hexd[(r.next() % 22) as usize] as char);
        }
        parts.push(g);
    }
    let mut s = parts.join(":");
    // Optionally insert a "::" at a random position.
    if r.next() & 1 == 0 {
        let pos = (r.next() as usize) % (s.len() + 1);
        s.insert_str(pos, "::");
    }
    // Optionally append an embedded-IPv4 tail.
    if r.next().is_multiple_of(4) {
        let v4 = format!("{}.{}.{}.{}", r.byte(), r.byte(), r.byte(), r.byte());
        if !s.is_empty() && !s.ends_with(':') {
            s.push(':');
        }
        s.push_str(&v4);
    }
    // Occasional stray byte to exercise rejection.
    if r.next().is_multiple_of(8) {
        let stray_pool = *b"gz %/-x\t";
        let stray = stray_pool[(r.next() % 8) as usize];
        let pos = (r.next() as usize) % (s.len() + 1);
        s.insert(pos, stray as char);
    }
    s
}

#[test]
fn inet_pton_ntop_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0x9e37_79b9_7f4a_7c15);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    let record = |label: String, fl_s: String, host_s: String, divs: &mut Vec<String>| {
        if fl_s != host_s && divs.len() < 40 {
            divs.push(format!("{label}\n    fl   ={fl_s}\n    glibc={host_s}"));
        }
    };

    for _ in 0..40000 {
        // ---- inet_ntop AF_INET6: random 16 bytes with injected zero-runs. ----
        let mut a6 = [0u8; 16];
        for b in a6.iter_mut() {
            *b = r.byte();
        }
        // 65% of the time, zero out a random run to force `::` compression paths.
        if r.next() % 100 < 65 {
            let start = (r.next() as usize) % 16;
            let len = 1 + (r.next() as usize) % (16 - start);
            for b in &mut a6[start..start + len] {
                *b = 0;
            }
        }
        let (fln, hon) = unsafe {
            (
                ntop(fl::inet_ntop, libc::AF_INET6, &a6),
                ntop(inet_ntop, libc::AF_INET6, &a6),
            )
        };
        compared += 1;
        record(
            format!("ntop6 addr={a6:02x?}"),
            format!("{fln:?}"),
            format!("{hon:?}"),
            &mut divs,
        );

        // ---- inet_ntop AF_INET: random 4 bytes. ----
        let a4 = [r.byte(), r.byte(), r.byte(), r.byte()];
        let (fln4, hon4) = unsafe {
            (
                ntop(fl::inet_ntop, libc::AF_INET, &a4),
                ntop(inet_ntop, libc::AF_INET, &a4),
            )
        };
        compared += 1;
        record(
            format!("ntop4 addr={a4:02x?}"),
            format!("{fln4:?}"),
            format!("{hon4:?}"),
            &mut divs,
        );

        // ---- inet_pton AF_INET6: canonical round-trip (valid) + random. ----
        // Canonical: feed the host's own ntop output back through both ptons.
        for src in [hon.clone().unwrap_or_default(), gen_ipv6_string(&mut r)] {
            let Ok(cs) = CString::new(src.as_str()) else {
                continue;
            };
            let (flr, flb) = unsafe { pton(fl::inet_pton, libc::AF_INET6, &cs, 16) };
            let (hor, hob) = unsafe { pton(inet_pton, libc::AF_INET6, &cs, 16) };
            compared += 1;
            // Compare return value always; address bytes only when both succeeded.
            let fl_repr = if flr == 1 {
                format!("ret=1 {flb:02x?}")
            } else {
                format!("ret={flr}")
            };
            let host_repr = if hor == 1 {
                format!("ret=1 {hob:02x?}")
            } else {
                format!("ret={hor}")
            };
            record(format!("pton6 src={src:?}"), fl_repr, host_repr, &mut divs);
        }

        // ---- inet_pton AF_INET: canonical round-trip + random dotted. ----
        let v4src = if r.next() & 1 == 0 {
            hon4.clone().unwrap_or_default()
        } else {
            format!(
                "{}.{}.{}.{}",
                r.next() % 300,
                r.next() % 300,
                r.byte(),
                r.byte()
            )
        };
        if let Ok(cs) = CString::new(v4src.as_str()) {
            let (flr, flb) = unsafe { pton(fl::inet_pton, libc::AF_INET, &cs, 4) };
            let (hor, hob) = unsafe { pton(inet_pton, libc::AF_INET, &cs, 4) };
            compared += 1;
            let fl_repr = if flr == 1 {
                format!("ret=1 {flb:02x?}")
            } else {
                format!("ret={flr}")
            };
            let host_repr = if hor == 1 {
                format!("ret=1 {hob:02x?}")
            } else {
                format!("ret={hor}")
            };
            record(
                format!("pton4 src={v4src:?}"),
                fl_repr,
                host_repr,
                &mut divs,
            );
        }
    }

    assert!(
        divs.is_empty(),
        "inet_pton/ntop diverged from host glibc on {} cases (showing up to 40):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!(
        "inet_pton/ntop differential fuzz: {compared} comparisons, 0 divergences vs host glibc"
    );
}
