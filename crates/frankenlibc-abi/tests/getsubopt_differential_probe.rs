//! Differential probe: frankenlibc getsubopt vs glibc getsubopt. Verifies the
//! return-index/value contract across recognized tokens, name=value, the
//! NULL-vs-empty value distinction (`name` -> *valuep==NULL; `name=` ->
//! *valuep=="" non-NULL), unrecognized suboptions (-1 with *valuep = whole
//! suboption), empty suboptions between commas, and trailing tokens. glibc
//! reference captured from a C probe.

use std::ffi::{CStr, CString, c_char};
use std::ptr;

use frankenlibc_abi::stdlib_abi;

#[test]
fn getsubopt_differential_battery() {
    let tok_ro = CString::new("ro").unwrap();
    let tok_rw = CString::new("rw").unwrap();
    let tok_bs = CString::new("bs").unwrap();
    let tok_empty = CString::new("empty").unwrap();
    let tokens: [*mut c_char; 5] = [
        tok_ro.as_ptr() as *mut c_char,
        tok_rw.as_ptr() as *mut c_char,
        tok_bs.as_ptr() as *mut c_char,
        tok_empty.as_ptr() as *mut c_char,
        ptr::null_mut(),
    ];

    // Mutable input buffer (getsubopt writes NULs in place).
    let mut input: Vec<u8> = b"ro,rw,bs=1024,unknown,empty=,=noval,,bs=,end\0".to_vec();
    let mut sub: *mut c_char = input.as_mut_ptr() as *mut c_char;
    let mut value: *mut c_char = ptr::null_mut();

    let mut got: Vec<String> = Vec::new();
    // Loop while the current suboption string is non-empty.
    while unsafe { *sub } != 0 {
        let r = unsafe { stdlib_abi::getsubopt(&mut sub, tokens.as_ptr(), &mut value) };
        let vstr = if value.is_null() {
            "(null)".to_string()
        } else {
            unsafe { CStr::from_ptr(value) }.to_string_lossy().into_owned()
        };
        got.push(format!("ret={r} value={vstr}"));
    }

    let glibc = [
        "ret=0 value=(null)",
        "ret=1 value=(null)",
        "ret=2 value=1024",
        "ret=-1 value=unknown",
        "ret=3 value=",
        "ret=-1 value==noval",
        "ret=-1 value=",
        "ret=2 value=",
        "ret=-1 value=end",
    ];

    let mut diffs = Vec::new();
    if got.len() != glibc.len() {
        diffs.push(format!("call count: frankenlibc={} glibc={}", got.len(), glibc.len()));
    }
    for (i, exp) in glibc.iter().enumerate() {
        match got.get(i) {
            Some(g) if g == exp => {}
            Some(g) => diffs.push(format!("call {i}: frankenlibc={g:?} glibc={exp:?}")),
            None => diffs.push(format!("call {i}: frankenlibc=<missing> glibc={exp:?}")),
        }
    }
    assert!(
        diffs.is_empty(),
        "getsubopt diverges from glibc in {} case(s):\n{}\nfull frankenlibc seq: {:?}",
        diffs.len(),
        diffs.join("\n"),
        got
    );
}
