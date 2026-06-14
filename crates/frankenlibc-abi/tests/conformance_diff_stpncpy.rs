#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
//! Isomorphism + golden gate for folding strncpy/stpncpy onto one shared scan
//! (strncpy_core). stpncpy was strncpy() then strnlen() over the just-written
//! destination — a second O(n) pass; it now returns the terminating-NUL offset
//! from the single copy scan. 200000 random (source, n vs srclen: truncate /
//! exact / NUL-pad, alignment) cases agree exactly with host glibc strncpy AND
//! stpncpy on the full written buffer [0..n] and the return pointer; a golden
//! sha256 of the stpncpy end offsets pins it.
use std::os::raw::c_char;
use frankenlibc_abi::string_abi as fa;
use sha2::{Digest,Sha256};
unsafe extern "C"{ fn strncpy(d:*mut c_char,s:*const c_char,n:usize)->*mut c_char; fn stpncpy(d:*mut c_char,s:*const c_char,n:usize)->*mut c_char; }
#[test]
fn strncpy_stpncpy_match_glibc() {
    let mut seed:u64=0x33;let mut rng=||{seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;seed};
    let mut h=Sha256::new();let mut div=0u32;
    for _ in 0..200000 {
        let slen=(rng()as usize)%120; let soff=(rng()as usize)%8;
        // n can be < slen (truncate), == slen, or > slen (pad with NUL)
        let n=(rng()as usize)%(slen+30);
        let body:Vec<u8>=(0..slen).map(|_|((rng()%94)+33)as u8).collect();
        let mut sback=vec![b'q';soff]; sback.extend_from_slice(&body); sback.push(0);
        let sp=unsafe{sback.as_ptr().add(soff)} as *const c_char;
        let cap=n+16;
        // strncpy: compare full written buffer [0..n] + return
        let mut d1=vec![0xAAu8;cap]; let mut d2=vec![0xAAu8;cap];
        let fr=unsafe{fa::strncpy(d1.as_mut_ptr() as *mut c_char,sp,n)};
        let gr=unsafe{strncpy(d2.as_mut_ptr() as *mut c_char,sp,n)};
        if (fr as usize-d1.as_ptr() as usize)!=(gr as usize-d2.as_ptr() as usize) || d1[..n]!=d2[..n] {
            div+=1; if div<=5{eprintln!("DIV strncpy slen={slen} n={n}");}
        }
        // stpncpy
        let mut e1=vec![0xAAu8;cap]; let mut e2=vec![0xAAu8;cap];
        let fe=unsafe{fa::stpncpy(e1.as_mut_ptr() as *mut c_char,sp,n)};
        let ge=unsafe{stpncpy(e2.as_mut_ptr() as *mut c_char,sp,n)};
        let (feo,geo)=(fe as usize-e1.as_ptr() as usize, ge as usize-e2.as_ptr() as usize);
        if feo!=geo || e1[..n]!=e2[..n] {
            div+=1; if div<=5{eprintln!("DIV stpncpy slen={slen} n={n} feo={feo} geo={geo}");}
        }
        h.update((feo as u64).to_le_bytes());
    }
    let hex:String=h.finalize().iter().map(|b|format!("{b:02x}")).collect();
    eprintln!("strncpy/stpncpy golden sha256: {hex}");
    assert_eq!(div, 0, "strncpy/stpncpy diverged from glibc in {div} cases");
    assert_eq!(
        hex,
        "08265033efc3f82da6ff9e99c4a57e6518d4f8757bb0b6cf7b02462ce35e37b9",
        "strncpy/stpncpy golden changed"
    );
}
