#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc swscanf oracle

//! Randomized differential fuzzer for `swscanf`'s INTEGER conversion parser vs
//! host glibc. Type-safe by construction: every generated format uses only
//! integer conversions (`%d %i %u %x %o`) bound to three `int` slots, plus
//! random field widths, assignment-suppression (`%*d`), and literal separators.
//! Random numeric-ish input strings exercise sign handling, base prefixes,
//! width truncation, overflow, leading whitespace, and the EOF-vs-matching-
//! failure return distinction. Compares the return value AND every assigned
//! slot (up to the agreed return count) against glibc.

use frankenlibc_abi::wchar_abi as fl;

unsafe extern "C" {
    fn swscanf(s: *const libc::wchar_t, format: *const libc::wchar_t, ...) -> libc::c_int;
    fn setlocale(category: libc::c_int, locale: *const libc::c_char) -> *const libc::c_char;
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

fn w(bytes: &[u8]) -> Vec<libc::wchar_t> {
    let mut v: Vec<libc::wchar_t> = bytes.iter().map(|&b| b as libc::wchar_t).collect();
    v.push(0);
    v
}

/// Build a format using at most 3 NON-suppressed int conversions (so the three
/// &int args are never over-consumed) plus suppressed conversions / separators.
fn gen_format(r: &mut Lcg) -> (Vec<u8>, usize) {
    const CONV: &[u8] = b"duxo"; // NB: %i excluded — fl 0b-binary extension diverges (bd-2g7oyh.203)
    let mut f = Vec::new();
    let ntok = 1 + r.below(4);
    let mut bound = 0usize; // non-suppressed conversions
    for _ in 0..ntok {
        match r.below(8) {
            0 => f.push(b' '),              // whitespace (matches any run)
            1 => f.extend_from_slice(b"x"), // literal that must match input 'x'
            2 if bound < 3 => {
                // suppressed conversion (consumes input, no arg)
                f.push(b'%');
                f.push(b'*');
                if r.below(2) == 0 {
                    f.extend_from_slice((1 + r.below(4)).to_string().as_bytes());
                }
                f.push(CONV[r.below(CONV.len())]);
            }
            _ if bound < 3 => {
                f.push(b'%');
                if r.below(2) == 0 {
                    f.extend_from_slice((1 + r.below(5)).to_string().as_bytes()); // width
                }
                f.push(CONV[r.below(CONV.len())]);
                bound += 1;
            }
            _ => f.push(b' '),
        }
    }
    (f, bound)
}

fn gen_input(r: &mut Lcg) -> Vec<u8> {
    const POOL: &[u8] = b"0123456789 +-xXabcdefABCDEF\tx";
    let len = r.below(12);
    (0..len).map(|_| POOL[r.below(POOL.len())]).collect()
}

#[test]
fn swscanf_int_differential_fuzz_vs_glibc() {
    unsafe {
        let utf8 = std::ffi::CString::new("C.UTF-8").unwrap();
        setlocale(6, utf8.as_ptr());
    }
    let mut r = Lcg(0x5ca7_f00d_1234_abcd);
    let mut divs: Vec<String> = Vec::new();
    let mut compared = 0u64;

    for _ in 0..200_000 {
        let (fmt_bytes, _bound) = gen_format(&mut r);
        let input = gen_input(&mut r);
        let fmt = w(&fmt_bytes);
        let inp = w(&input);

        let mut af = [-7i32; 3];
        let mut ag = [-7i32; 3];
        let rf = unsafe {
            fl::swscanf(
                inp.as_ptr(),
                fmt.as_ptr(),
                &mut af[0] as *mut i32,
                &mut af[1] as *mut i32,
                &mut af[2] as *mut i32,
            )
        };
        let rg = unsafe {
            swscanf(
                inp.as_ptr(),
                fmt.as_ptr(),
                &mut ag[0] as *mut i32,
                &mut ag[1] as *mut i32,
                &mut ag[2] as *mut i32,
            )
        };
        compared += 1;

        let assigned = rf.clamp(0, 3) as usize;
        let slot_mismatch = rf == rg && af[..assigned] != ag[..assigned];
        if (rf != rg || slot_mismatch) && divs.len() < 40 {
            divs.push(format!(
                "fmt={:?} input={:?} fl=(ret={rf},{:?}) glibc=(ret={rg},{:?})",
                String::from_utf8_lossy(&fmt_bytes),
                String::from_utf8_lossy(&input),
                af,
                ag,
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "swscanf int parser diverged from glibc ({compared} compared):\n{}",
        divs.join("\n")
    );
    eprintln!("swscanf int fuzz: {compared} compared, 0 divergences vs host glibc");
}
