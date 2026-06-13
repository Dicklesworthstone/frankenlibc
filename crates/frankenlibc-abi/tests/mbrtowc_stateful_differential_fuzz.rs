//! Randomized live differential fuzzer for `mbrtowc` vs host glibc (C.UTF-8),
//! focused on the path the fixed `mbrtowc_differential_probe` never exercises:
//! STATEFUL continuation across calls with a carried `mbstate_t`. It feeds random
//! byte buffers (valid multi-byte chars interleaved with invalid/garbage bytes)
//! to `mbrtowc` in small 1–2 byte chunks, carrying a persistent state on each
//! side, and compares every call's classified return (NUL / EILSEQ / incomplete
//! / Ok(consumed-this-call, wc)). It also fuzzes one-shot decoding with a random
//! `n` length limit. The subtle behavior under test: a sequence split across
//! calls returns (size_t)-2 then, on completion, the number of bytes consumed
//! FROM THE FINAL CALL (not the whole char), with the state cleared.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc mbrtowc oracle (locale-dependent)

use std::ffi::c_int;

use frankenlibc_abi::wchar_abi as fl;

unsafe extern "C" {
    fn mbrtowc(
        pwc: *mut libc::wchar_t,
        s: *const libc::c_char,
        n: usize,
        ps: *mut libc::mbstate_t,
    ) -> usize;
    fn setlocale(category: c_int, locale: *const libc::c_char) -> *mut libc::c_char;
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum MbResult {
    Nul,
    Ileq,
    Incomplete,
    Ok(usize, u32),
    Other(usize),
}

fn classify(rc: usize, wc: libc::wchar_t) -> MbResult {
    if rc == 0 {
        MbResult::Nul
    } else if rc == usize::MAX {
        MbResult::Ileq
    } else if rc == usize::MAX - 1 {
        MbResult::Incomplete
    } else if rc <= 6 {
        MbResult::Ok(rc, wc as u32)
    } else {
        MbResult::Other(rc)
    }
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
    fn below(&mut self, n: usize) -> usize {
        (self.next() >> 11) as usize % n
    }
}

/// Encode a code point as UTF-8 (allowing the deliberately-invalid surrogate and
/// >U+10FFFF ranges, which a naive encoder must still be able to emit as bytes).
fn encode(cp: u32, out: &mut Vec<u8>) {
    if cp < 0x80 {
        out.push(cp as u8);
    } else if cp < 0x800 {
        out.push(0xC0 | (cp >> 6) as u8);
        out.push(0x80 | (cp & 0x3F) as u8);
    } else if cp < 0x10000 {
        out.push(0xE0 | (cp >> 12) as u8);
        out.push(0x80 | ((cp >> 6) & 0x3F) as u8);
        out.push(0x80 | (cp & 0x3F) as u8);
    } else if cp < 0x20_0000 {
        out.push(0xF0 | (cp >> 18) as u8);
        out.push(0x80 | ((cp >> 12) & 0x3F) as u8);
        out.push(0x80 | ((cp >> 6) & 0x3F) as u8);
        out.push(0x80 | (cp & 0x3F) as u8);
    } else if cp < 0x400_0000 {
        // Obsolete RFC 2279 5-byte form (non-overlong: cp >= 0x20_0000), which
        // glibc's C.UTF-8 still decodes and fl matches.
        out.push(0xF8 | (cp >> 24) as u8);
        out.push(0x80 | ((cp >> 18) & 0x3F) as u8);
        out.push(0x80 | ((cp >> 12) & 0x3F) as u8);
        out.push(0x80 | ((cp >> 6) & 0x3F) as u8);
        out.push(0x80 | (cp & 0x3F) as u8);
    } else {
        // Obsolete RFC 2279 6-byte form (non-overlong: cp >= 0x400_0000).
        out.push(0xFC | (cp >> 30) as u8);
        out.push(0x80 | ((cp >> 24) & 0x3F) as u8);
        out.push(0x80 | ((cp >> 18) & 0x3F) as u8);
        out.push(0x80 | ((cp >> 12) & 0x3F) as u8);
        out.push(0x80 | ((cp >> 6) & 0x3F) as u8);
        out.push(0x80 | (cp & 0x3F) as u8);
    }
}

fn gen_buf(r: &mut Lcg) -> Vec<u8> {
    let mut buf = Vec::new();
    let tokens = 1 + r.below(5);
    for _ in 0..tokens {
        match r.below(8) {
            // Valid-ish code point across every UTF-8 width, including the
            // obsolete 5/6-byte RFC 2279 forms (cp >= 0x20_0000) that glibc's
            // C.UTF-8 decodes and fl matches one-shot — now also reassembled
            // across incremental calls after the mbstate partial-region fix
            // (bd-kryp2k). Surrogate / >U+10FFFF ranges are handled identically
            // by fl and glibc.
            0 | 1 | 2 | 3 => {
                let cp = match r.below(8) {
                    0 => r.below(0x80) as u32,                     // ASCII (may include NUL)
                    1 => 0x80 + r.below(0x780) as u32,             // 2-byte
                    2 => 0x800 + r.below(0xF800) as u32,           // 3-byte (incl surrogates)
                    3 => 0x10000 + r.below(0x100000) as u32,       // 4-byte (incl >10FFFF)
                    4 => 0xD800 + r.below(0x800) as u32,           // surrogate range
                    5 => 0x110000 + r.below(0x1000) as u32,        // beyond max (still 4-byte)
                    6 => 0x20_0000 + r.below(0x3E0_0000) as u32,   // 5-byte (RFC 2279)
                    _ => 0x400_0000 + r.below(0x3C00_0000) as u32, // 6-byte (RFC 2279)
                };
                encode(cp, &mut buf);
            }
            // A raw (often invalid) byte: continuation bytes, never-leads, and
            // bare 5/6-byte leads (0xF8..=0xFD) — all in scope now.
            4 | 5 => {
                buf.push((r.next() & 0xFF) as u8);
            }
            // A bare lead byte with no continuation (truncation).
            6 => buf.push([0xC3, 0xE2, 0xF0, 0xC0, 0xFF, 0xFE][r.below(6)]),
            // A short run of continuation bytes.
            _ => {
                for _ in 0..(1 + r.below(2)) {
                    buf.push(0x80 | (r.next() & 0x3F) as u8);
                }
            }
        }
    }
    buf
}

fn fl_call(wc: &mut libc::wchar_t, s: &[u8], n: usize, st: &mut libc::mbstate_t) -> usize {
    unsafe {
        fl::mbrtowc(
            wc,
            s.as_ptr() as *const std::ffi::c_char,
            n,
            st as *mut libc::mbstate_t as *mut std::ffi::c_void,
        )
    }
}
fn host_call(wc: &mut libc::wchar_t, s: &[u8], n: usize, st: &mut libc::mbstate_t) -> usize {
    unsafe { mbrtowc(wc, s.as_ptr() as *const libc::c_char, n, st) }
}

#[test]
fn mbrtowc_stateful_differential_fuzz_vs_glibc() {
    let utf8 = c"C.UTF-8";
    let set = unsafe { setlocale(libc::LC_ALL, utf8.as_ptr()) };
    if set.is_null() {
        eprintln!("C.UTF-8 locale unavailable; skipping mbrtowc stateful fuzz");
        return;
    }

    let mut r = Lcg(0xb16b_00b5_dead_c0de);
    let mut divs: Vec<String> = Vec::new();
    let mut compared = 0u64;

    for _ in 0..100_000 {
        let buf = gen_buf(&mut r);
        if buf.is_empty() {
            continue;
        }

        // --- Mode A: one-shot decode with a random length limit `n`. ---
        {
            let n = r.below(buf.len() + 2); // may exceed for the "extra room" case
            let mut wf: libc::wchar_t = 0;
            let mut wh: libc::wchar_t = 0;
            let mut sf: libc::mbstate_t = unsafe { std::mem::zeroed() };
            let mut sh: libc::mbstate_t = unsafe { std::mem::zeroed() };
            let avail = n.min(buf.len());
            let f = classify(fl_call(&mut wf, &buf, avail, &mut sf), wf);
            let h = classify(host_call(&mut wh, &buf, avail, &mut sh), wh);
            compared += 1;
            if f != h && divs.len() < 30 {
                divs.push(format!(
                    "ONESHOT buf={buf:02x?} n={avail}  fl={f:?}  glibc={h:?}"
                ));
            }
        }

        // --- Mode B: incremental feed with a carried state. ---
        {
            let mut sf: libc::mbstate_t = unsafe { std::mem::zeroed() };
            let mut sh: libc::mbstate_t = unsafe { std::mem::zeroed() };
            let mut i = 0usize;
            let mut guard = 0;
            while i < buf.len() && guard < 64 {
                guard += 1;
                let chunk = 1 + r.below(2); // 1 or 2 bytes available this call
                let avail = chunk.min(buf.len() - i);
                let mut wf: libc::wchar_t = 0;
                let mut wh: libc::wchar_t = 0;
                let f = classify(fl_call(&mut wf, &buf[i..], avail, &mut sf), wf);
                let h = classify(host_call(&mut wh, &buf[i..], avail, &mut sh), wh);
                compared += 1;
                if f != h {
                    if divs.len() < 30 {
                        divs.push(format!(
                            "INCR buf={buf:02x?} at={i} navail={avail}  fl={f:?}  glibc={h:?}"
                        ));
                    }
                    break; // states are now out of sync; stop this buffer
                }
                // Advance by the (agreed) host outcome.
                match h {
                    MbResult::Ok(k, _) => i += k,
                    MbResult::Incomplete => i += avail, // all consumed into state
                    MbResult::Nul => i += 1,
                    MbResult::Ileq | MbResult::Other(_) => break,
                }
            }
        }
    }

    assert!(
        divs.is_empty(),
        "mbrtowc (stateful/oneshot) diverged from host glibc ({compared} compared):\n{}",
        divs.join("\n")
    );
    eprintln!("mbrtowc stateful fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
