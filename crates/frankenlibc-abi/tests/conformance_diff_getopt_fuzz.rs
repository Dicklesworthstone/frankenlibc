#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
//! Randomized live differential of fl `getopt` vs host glibc `getopt` over 8000
//! (optstring, argv) cases spanning every mode flag (`+`/`-`/`:` prefixes, `:`
//! and `::` argument specs, and combinations). Complements conformance_diff_getopt
//! (which pins hand-picked cases against hardcoded expectations) with broad
//! random coverage proving exact parity on the POSIX-specified observables:
//! the return-char sequence, optind, optarg, the in-place argv permutation, and
//! optopt ON ERROR (`?`/`:`).
//!
//! Two subtleties, both handled:
//!  * fl's getopt mirrors optind/optarg/optopt/opterr to the SAME host C symbols
//!    it interposes in release, so fl and glibc share that storage in this test
//!    binary. Runs are therefore NON-interleaved (all glibc, then all fl) so each
//!    engine owns the globals while it runs. Both treat optind==0 as the reinit
//!    signal, used to reset between cases.
//!  * optopt after a SUCCESSFUL return is POSIX-unspecified; glibc sets it to the
//!    option char mid-group while fl leaves it 0 (both conformant). It is only
//!    compared on error returns, where POSIX requires optopt = the offending char.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use frankenlibc_abi::unistd_abi::getopt as fl_getopt;

unsafe extern "C" {
    fn getopt(argc: c_int, argv: *const *mut c_char, optstring: *const c_char) -> c_int;
    static mut optarg: *mut c_char;
    static mut optind: c_int;
    static mut optopt: c_int;
    static mut opterr: c_int;
}

#[derive(PartialEq, Debug, Clone)]
struct Step { ret: i32, optopt: i32, optind: i32, optarg: Option<String> }

fn argv_order(av: &[*mut c_char]) -> Vec<String> {
    av.iter().filter(|p| !p.is_null())
      .map(|&p| unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()).collect()
}

fn run(tokens: &[CString], opts: &CString, fl: bool) -> (Vec<Step>, Vec<String>) {
    let mut av: Vec<*mut c_char> = tokens.iter().map(|c| c.as_ptr() as *mut c_char).collect();
    av.push(std::ptr::null_mut());
    let argc = tokens.len() as c_int;
    let mut steps = Vec::new();
    unsafe {
        optind = 0; opterr = 0; optarg = std::ptr::null_mut(); optopt = 0;
        loop {
            let r = if fl { fl_getopt(argc, av.as_ptr(), opts.as_ptr()) }
                    else { getopt(argc, av.as_ptr(), opts.as_ptr()) };
            if r == -1 { break; }
            let oa = if optarg.is_null() { None }
                     else { Some(CStr::from_ptr(optarg).to_string_lossy().into_owned()) };
            // optopt is specified only on error returns ('?'=63, ':'=58).
            let oo = if r == 63 || r == 58 { optopt } else { 0 };
            steps.push(Step { ret: r, optopt: oo, optind, optarg: oa });
            if steps.len() > 64 { break; }
        }
    }
    (steps, argv_order(&av))
}

#[test]
fn getopt_differential_fuzz_vs_glibc() {
    let pool = ["-a","-b","-c","-x","-ab","-bc","--","-","foo","bar","-afoo","val","-cval","-d","-a"];
    let optstrings = ["abc","a:bc","ab:c","a::bc","abcd:","+abc","-abc",":abc","+a:b",
                      "-a:b:",":a::b","abc:d::","ab","a:b:c:","+:ab:","-:a:b"];
    let mut seed: u64 = 0x12345678;
    let mut rng = || { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; seed };

    // Build the full case list first so glibc and fl see identical inputs.
    let mut cases: Vec<(CString, Vec<CString>)> = Vec::new();
    for _ in 0..8000 {
        let opts = CString::new(optstrings[(rng() as usize) % optstrings.len()]).unwrap();
        let ntok = 1 + (rng() as usize) % 6;
        let mut tokens = vec![CString::new("prog").unwrap()];
        for _ in 0..ntok { tokens.push(CString::new(pool[(rng() as usize) % pool.len()]).unwrap()); }
        cases.push((opts, tokens));
    }
    // Non-interleaved: all glibc first, then all fl.
    let host: Vec<_> = cases.iter().map(|(o, t)| run(t, o, false)).collect();
    let flr:  Vec<_> = cases.iter().map(|(o, t)| run(t, o, true)).collect();

    let mut div: Vec<String> = Vec::new();
    for (i, ((o, t), (h, f))) in cases.iter().zip(host.iter().zip(flr.iter())).enumerate() {
        if h != f && div.len() < 12 {
            let argv: Vec<&str> = t.iter().map(|c| c.to_str().unwrap()).collect();
            div.push(format!("[{i}] opts={:?} argv={:?}\n    host={:?}\n    fl  ={:?}",
                o.to_str().unwrap(), argv, h, f));
        }
    }
    let total = host.iter().zip(flr.iter()).filter(|(h, f)| h != f).count();
    assert!(total == 0, "getopt diverged in {total}/8000 cases:\n  {}", div.join("\n  "));
}
