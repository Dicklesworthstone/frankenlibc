#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc asctime_r oracle (libc, linked by std)

//! Randomized differential fuzzer for `asctime_r` vs host glibc. asctime_r
//! formats a broken-down time into the classic 26-byte string and — in modern
//! glibc — returns NULL (EOVERFLOW) when the year would make the output exceed
//! the buffer. This sweeps random tm structs with valid name-index fields
//! (tm_wday in 0..=6, tm_mon in 0..=11) but a WIDE tm_year span (incl. the
//! ±boundary where glibc switches to NULL), comparing the exact output string
//! AND the NULL-return decision.

use frankenlibc_abi::time_abi::asctime_r as fl_asctime_r;

unsafe extern "C" {
    fn asctime_r(tm: *const libc::tm, buf: *mut std::ffi::c_char) -> *mut std::ffi::c_char;
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
    fn range(&mut self, lo: i64, hi: i64) -> i32 {
        (lo + (self.next() % (hi - lo + 1) as u64) as i64) as i32
    }
}

#[derive(PartialEq, Eq, Debug)]
struct Out {
    null: bool,
    s: Vec<u8>,
}

fn run(
    f: unsafe extern "C" fn(*const libc::tm, *mut std::ffi::c_char) -> *mut std::ffi::c_char,
    tm: &libc::tm,
) -> Out {
    let mut buf = [0u8; 64];
    let r = unsafe { f(tm, buf.as_mut_ptr() as *mut std::ffi::c_char) };
    if r.is_null() {
        Out {
            null: true,
            s: Vec::new(),
        }
    } else {
        let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        Out {
            null: false,
            s: buf[..n].to_vec(),
        }
    }
}

#[test]
fn asctime_r_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0x6173_6374_696d_0001);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    for _ in 0..200_000 {
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        tm.tm_sec = r.range(0, 60); // 60 = leap second
        tm.tm_min = r.range(0, 59);
        tm.tm_hour = r.range(0, 23);
        tm.tm_mday = r.range(1, 31);
        tm.tm_mon = r.range(0, 11);
        tm.tm_wday = r.range(0, 6);
        tm.tm_year = match r.next() % 4 {
            0 => r.range(-2100, 8200),  // around the lower & normal range
            1 => r.range(8000, 8200),   // near the +year boundary (year ~9999)
            2 => r.range(-2900, -2700), // near the -year boundary (year ~-999)
            _ => r.range(-30000, 1_000_000),
        };
        let fl = run(fl_asctime_r, &tm);
        let host = run(asctime_r, &tm);
        compared += 1;
        if fl != host && divs.len() < 40 {
            divs.push(format!(
                "year={} mon={} wday={} mday={} {}:{}:{}\n    fl   ={:?}\n    glibc={:?}",
                tm.tm_year + 1900,
                tm.tm_mon,
                tm.tm_wday,
                tm.tm_mday,
                tm.tm_hour,
                tm.tm_min,
                tm.tm_sec,
                String::from_utf8_lossy(&fl.s),
                String::from_utf8_lossy(&host.s),
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "asctime_r diverged from host glibc on {} cases (showing up to 40):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!("asctime_r differential fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
