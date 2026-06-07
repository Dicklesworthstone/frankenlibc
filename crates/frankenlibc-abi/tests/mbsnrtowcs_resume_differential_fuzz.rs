#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc mbsnrtowcs oracle (libc, linked by std)

//! Randomized live differential fuzzer for the RESUMABLE/stateful use of
//! `mbsnrtowcs` vs host glibc (C.UTF-8): a multibyte string is consumed across
//! MANY calls with a SHARED non-null mbstate and small random `nms` windows that
//! frequently end mid-character, so each call may store a partial sequence in
//! `ps` and the next must resume from it. The existing n_bounded probe is
//! fixed-case and passes a NULL `ps`, so it never exercises this path. We compare
//! the full per-call (return, *src offset, wide chars produced) sequence.

use std::ffi::{c_char, c_int, c_void};

use frankenlibc_abi::wchar_abi::mbsnrtowcs as fl_mbsnrtowcs;

unsafe extern "C" {
    fn mbsnrtowcs(
        dst: *mut libc::wchar_t,
        src: *mut *const c_char,
        nms: usize,
        len: usize,
        ps: *mut c_void,
    ) -> usize;
    fn setlocale(category: c_int, locale: *const c_char) -> *mut c_char;
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
    fn below(&mut self, n: u64) -> u64 {
        (self.next() >> 11) % n
    }
}

fn enc(cp: u32, out: &mut Vec<u8>) {
    match cp {
        0..=0x7F => out.push(cp as u8),
        0x80..=0x7FF => {
            out.push(0xC0 | (cp >> 6) as u8);
            out.push(0x80 | (cp & 0x3F) as u8);
        }
        0x800..=0xFFFF => {
            out.push(0xE0 | (cp >> 12) as u8);
            out.push(0x80 | ((cp >> 6) & 0x3F) as u8);
            out.push(0x80 | (cp & 0x3F) as u8);
        }
        _ => {
            out.push(0xF0 | (cp >> 18) as u8);
            out.push(0x80 | ((cp >> 12) & 0x3F) as u8);
            out.push(0x80 | ((cp >> 6) & 0x3F) as u8);
            out.push(0x80 | (cp & 0x3F) as u8);
        }
    }
}

fn gen_cp(r: &mut Lcg) -> u32 {
    let cp = match r.below(4) {
        0 => 1 + r.below(0x7F) as u32, // ASCII (non-NUL)
        1 => 0x80 + r.below(0x780) as u32,
        2 => 0x800 + r.below(0xF800) as u32,
        _ => 0x10000 + r.below(0x100000) as u32,
    };
    if (0xD800..=0xDFFF).contains(&cp) { 0x41 } else { cp }
}

/// One mbsnrtowcs call's observable result.
#[derive(PartialEq, Eq, Debug, Clone)]
struct Step {
    rc: i64,
    src_off: isize,
    wide: Vec<i64>,
}

/// Drive a full resumable conversion of `bytes` (NUL-terminated) through one
/// implementation, using the shared `nms` schedule, and return the per-call
/// sequence.
fn drive(
    f: unsafe extern "C" fn(*mut libc::wchar_t, *mut *const c_char, usize, usize, *mut c_void) -> usize,
    bytes: &[u8],
    schedule: &[usize],
) -> Vec<Step> {
    let start = bytes.as_ptr() as *const c_char;
    let mut src = start;
    let mut st = [0u8; 16];
    let mut out = Vec::new();
    let mut step = 0usize;
    loop {
        if src.is_null() {
            break;
        }
        let off = unsafe { src.offset_from(start) } as usize;
        if off >= bytes.len() {
            break;
        }
        let remaining = bytes.len() - off;
        let nms = schedule[step % schedule.len()].min(remaining).max(1);
        step += 1;
        let mut dst = [0i32; 64];
        let rc = unsafe {
            f(
                dst.as_mut_ptr() as *mut libc::wchar_t,
                &mut src as *mut *const c_char,
                nms,
                dst.len(),
                st.as_mut_ptr() as *mut c_void,
            )
        };
        let rc_i = rc as i64;
        let src_off = if src.is_null() {
            -1
        } else {
            unsafe { src.offset_from(start) }
        };
        let wide = if rc_i >= 0 {
            dst[..(rc_i as usize).min(dst.len())]
                .iter()
                .map(|&w| w as i64)
                .collect()
        } else {
            Vec::new()
        };
        out.push(Step { rc: rc_i, src_off, wide });
        if rc_i < 0 {
            break; // EILSEQ
        }
        if step > 2000 {
            break;
        }
    }
    out
}

#[test]
fn mbsnrtowcs_resume_differential_fuzz_vs_glibc() {
    unsafe { setlocale(libc::LC_ALL, c"C.UTF-8".as_ptr()) };
    let mut r = Lcg(0x6d62_736e_7273_0001);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    for _ in 0..60_000 {
        let nchars = 1 + r.below(6);
        let mut bytes = Vec::new();
        for _ in 0..nchars {
            enc(gen_cp(&mut r), &mut bytes);
            // Occasionally splice a raw (often invalid) byte mid-stream so the
            // EILSEQ path is exercised across the resume boundary.
            if r.below(6) == 0 {
                bytes.push((0x80 + r.below(0x80)) as u8);
            }
        }
        bytes.push(0); // NUL-terminate
        // Small windows force frequent mid-character splits; an occasional big
        // window consumes several characters at once.
        let sched: Vec<usize> = (0..8)
            .map(|_| if r.below(5) == 0 { 1 + r.below(12) as usize } else { 1 + r.below(4) as usize })
            .collect();

        let fl = drive(fl_mbsnrtowcs, &bytes, &sched);
        let host = drive(mbsnrtowcs, &bytes, &sched);
        compared += 1;
        if fl != host && divs.len() < 30 {
            divs.push(format!(
                "bytes={:02x?} sched={sched:?}\n    fl   ={fl:?}\n    glibc={host:?}",
                bytes
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "mbsnrtowcs resume diverged from host glibc on {} cases (showing up to 30):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!("mbsnrtowcs resume differential fuzz: {compared} strings, 0 divergences vs host glibc");
}
