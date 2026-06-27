#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc sscanf oracle (libc)

//! Randomized live differential fuzzer for sscanf `%c` / `%Nc` (the character
//! conversion) vs host glibc. The existing `sscanf_differential_fuzz` does not
//! cover `%c` at all; its semantics differ from every other conversion — it
//! does NOT skip leading whitespace, writes exactly the matched bytes with NO
//! NUL terminator, and a field width reads up to that many characters. This
//! sweeps random `%[width]c%n` directives over random inputs (including
//! whitespace) and compares the return value, the matched bytes, and the `%n`
//! consumed count against the live glibc oracle.

use std::ffi::{CStr, CString, c_char, c_int};

use frankenlibc_abi::stdio_abi::sscanf as fl_sscanf;

unsafe extern "C" {
    fn sscanf(s: *const c_char, fmt: *const c_char, ...) -> c_int;
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
}

fn gen_fmt(r: &mut Lcg) -> String {
    let mut s = String::from("%");
    if r.next() & 1 == 0 {
        s.push_str(&(1 + r.next() % 6).to_string());
    }
    s.push_str("c%n");
    s
}

fn gen_input(r: &mut Lcg) -> Vec<u8> {
    const ALPHA: &[u8] = b"ab12XY.+ \t\n";
    let len = (r.next() % 12) as usize;
    (0..len)
        .map(|_| ALPHA[(r.next() as usize) % ALPHA.len()])
        .collect()
}

#[derive(PartialEq, Eq, Debug)]
struct Out {
    ret: c_int,
    matched: Option<Vec<u8>>,
    n: Option<c_int>,
}

fn run(is_fl: bool, input: &CStr, fmt: &CStr) -> Out {
    // Sentinel-filled buffer; %c writes exactly the matched bytes (no NUL), so
    // the consumed `%n` count tells us how many bytes are valid.
    let mut buf = [0xAAu8; 32];
    let mut n: c_int = -98765;
    let bp = buf.as_mut_ptr() as *mut c_char;
    let np = &mut n as *mut c_int;
    let ret = unsafe {
        if is_fl {
            fl_sscanf(input.as_ptr(), fmt.as_ptr(), bp, np)
        } else {
            sscanf(input.as_ptr(), fmt.as_ptr(), bp, np)
        }
    };
    let (matched, nn) = if ret == 1 {
        let cnt = (n.max(0) as usize).min(buf.len());
        (Some(buf[..cnt].to_vec()), Some(n))
    } else {
        (None, None)
    };
    Out { ret, matched, n: nn }
}

#[test]
fn sscanf_char_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0x0c4a_50a7_5ee0_0001);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    for _ in 0..200_000 {
        let fmt = gen_fmt(&mut r);
        let input = gen_input(&mut r);
        let (Ok(cfmt), Ok(cinput)) = (
            CString::new(fmt.as_str()),
            CString::new(input.clone()),
        ) else {
            continue;
        };
        let fl = run(true, &cinput, &cfmt);
        let host = run(false, &cinput, &cfmt);
        compared += 1;
        if fl != host && divs.len() < 40 {
            divs.push(format!(
                "fmt={fmt:?} input={:?}\n    fl   ={fl:?}\n    glibc={host:?}",
                String::from_utf8_lossy(&input)
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "sscanf %c parsing diverged from host glibc on {} cases (showing up to 40):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!("sscanf %c fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
