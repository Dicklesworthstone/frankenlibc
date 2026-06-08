#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc snprintf oracle

//! Randomized differential fuzzer for printf POSITIONAL arguments (`%n$`,
//! `%n$*m$d`, `%n$.*m$d`) vs live host glibc snprintf. The existing conformance
//! has only ~4 fixed positional cases; argument reordering and positional
//! width/precision indexing (the classic bug nest) are otherwise untested.
//!
//! The argument vector is MIXED TYPE — positions 1 and 3 are ints, positions 2
//! and 4 are C strings — so reordering exercises fl's positional argument
//! type/size table (the part most likely to mishandle a pointer-sized arg
//! interleaved with ints). To stay strictly in-spec (so any divergence is a real
//! fl bug, not UB): every generated format is FULLY positional, references
//! positions 1..=K with no gaps (a permutation, so glibc learns every argument's
//! type), each position is printed with a conversion matching its real type, and
//! any positional width/precision references an INT position. Ints are small and
//! string lengths bounded so widths/precisions stay sane.

use std::ffi::{c_char, c_int};

use frankenlibc_abi::stdio_abi as fl;

unsafe extern "C" {
    fn snprintf(s: *mut c_char, n: usize, fmt: *const c_char, ...) -> c_int;
}

const STRINGS: [&[u8]; 4] = [b"\0", b"a\0", b"hello\0", b"WorldWide\0"];

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
        self.next() % n
    }
}

/// Positions are 1-based; odd positions (1,3) are ints, even (2,4) are strings.
fn is_int_pos(pos: usize) -> bool {
    pos % 2 == 1
}

/// Build a valid fully-positional mixed-type format. Returns the format plus the
/// two int values (for positions 1 and 3) and the two string indices (positions
/// 2 and 4).
fn gen_fmt(r: &mut Lcg) -> (Vec<u8>, [c_int; 2], [usize; 2]) {
    let ints = [(r.below(41) as i32) - 20, (r.below(41) as i32) - 20];
    let strs = [
        r.below(STRINGS.len() as u64) as usize,
        r.below(STRINGS.len() as u64) as usize,
    ];

    let k = 2 + r.below(3) as usize; // reference positions 1..=k, no gaps
    let mut perm: Vec<usize> = (1..=k).collect();
    for i in (1..k).rev() {
        let j = r.below((i + 1) as u64) as usize;
        perm.swap(i, j);
    }
    // Int positions available for positional width/precision (always includes 1).
    let int_positions: Vec<usize> = (1..=k).filter(|&p| is_int_pos(p)).collect();

    const ICONV: &[u8] = b"diouxX";
    let mut fmt = String::new();
    for &pos in &perm {
        let int_pos = is_int_pos(pos);
        fmt.push('%');
        fmt.push_str(&pos.to_string());
        fmt.push('$');
        // flags (well-defined for the chosen conversions; '#'/'0'/'+'/' ' only
        // for integers — for %s only '-' is meaningful, others are ignored
        // identically by both impls, but keep %s to '-' to avoid noise).
        if int_pos {
            for ch in ['-', '+', ' ', '#', '0'] {
                if r.below(3) == 0 {
                    fmt.push(ch);
                }
            }
        } else if r.below(2) == 0 {
            fmt.push('-');
        }
        // width: none | literal | positional(*m$ on an int position)
        match r.below(3) {
            0 => {}
            1 => fmt.push_str(&r.below(12).to_string()),
            _ => {
                let m = int_positions[r.below(int_positions.len() as u64) as usize];
                fmt.push('*');
                fmt.push_str(&m.to_string());
                fmt.push('$');
            }
        }
        // precision: none | .literal | .positional (.*m$ on an int position)
        match r.below(3) {
            0 => {}
            1 => {
                fmt.push('.');
                fmt.push_str(&r.below(12).to_string());
            }
            _ => {
                let m = int_positions[r.below(int_positions.len() as u64) as usize];
                fmt.push_str(".*");
                fmt.push_str(&m.to_string());
                fmt.push('$');
            }
        }
        if int_pos {
            fmt.push(ICONV[r.below(ICONV.len() as u64) as usize] as char);
        } else {
            fmt.push('s');
        }
        if r.below(2) == 0 {
            fmt.push('|');
        }
    }
    let mut bytes = fmt.into_bytes();
    bytes.push(0);
    (bytes, ints, strs)
}

fn fl_run(fmt: &[u8], ints: [c_int; 2], strs: [usize; 2]) -> (c_int, Vec<u8>) {
    let s1 = STRINGS[strs[0]].as_ptr() as *const c_char;
    let s3 = STRINGS[strs[1]].as_ptr() as *const c_char;
    let mut buf = vec![0u8; 256];
    let rc = unsafe {
        fl::snprintf(
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            fmt.as_ptr() as *const c_char,
            ints[0],
            s1,
            ints[1],
            s3,
        )
    };
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    buf.truncate(end);
    (rc, buf)
}

fn host_run(fmt: &[u8], ints: [c_int; 2], strs: [usize; 2]) -> (c_int, Vec<u8>) {
    let s1 = STRINGS[strs[0]].as_ptr() as *const c_char;
    let s3 = STRINGS[strs[1]].as_ptr() as *const c_char;
    let mut buf = vec![0u8; 256];
    let rc = unsafe {
        snprintf(
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            fmt.as_ptr() as *const c_char,
            ints[0],
            s1,
            ints[1],
            s3,
        )
    };
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    buf.truncate(end);
    (rc, buf)
}

#[test]
fn printf_positional_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0x9e37_79b9_7f4a_7c15);
    let mut divs: Vec<String> = Vec::new();
    let mut compared = 0u64;

    for _ in 0..200_000 {
        let (fmt, ints, strs) = gen_fmt(&mut r);
        let flr = fl_run(&fmt, ints, strs);
        let hostr = host_run(&fmt, ints, strs);
        compared += 1;
        if flr != hostr && divs.len() < 40 {
            divs.push(format!(
                "fmt={:?} ints={ints:?} strs={strs:?}\n    fl   = rc={} {:?}\n    glibc= rc={} {:?}",
                String::from_utf8_lossy(&fmt[..fmt.len() - 1]),
                flr.0,
                String::from_utf8_lossy(&flr.1),
                hostr.0,
                String::from_utf8_lossy(&hostr.1),
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "positional printf diverged from host glibc on some of {compared} cases (showing up to 40):\n{}",
        divs.join("\n")
    );
    eprintln!("positional printf fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
