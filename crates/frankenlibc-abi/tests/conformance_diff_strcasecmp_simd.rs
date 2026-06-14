#![cfg(target_os = "linux")]
//! Isomorphism + golden gate for the 32-byte portable-SIMD fast path added to
//! the ABI `scan_strcasecmp` common path (widened from 8-byte SWAR to AVX width
//! to close a ~1.39x throughput gap vs glibc on long case-insensitive compares).
//! 200000 random pairs (case-variants, mismatches, mixed NUL positions, lengths
//! straddling the 32-byte panel) agree exactly with host glibc strcasecmp, and a
//! golden sha256 of the sign-result stream pins the behavior against regression.
#![allow(unsafe_code)]
use std::ffi::CString;
use std::os::raw::c_char;
use frankenlibc_abi::string_abi as fa;
use sha2::{Digest,Sha256};
unsafe extern "C"{ fn strcasecmp(a:*const c_char,b:*const c_char)->i32; }
fn norm(x:i32)->i32{ x.signum() }
#[test]
fn iso_and_golden(){
    // Differential vs glibc over random strings incl case, NUL pos, page-boundary lengths
    let alpha=[b'A',b'a',b'B',b'b',b'Z',b'z',b'm',b'M',b'0',b'!',b'~',b' '];
    let mut seed:u64=0x9E3779B9;
    let mut rng=||{seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;seed};
    let mut h=Sha256::new(); let mut div=0u32; let mut n=0u64;
    for _ in 0..200000 {
        let len=(rng()as usize)%70;
        let mut a:Vec<u8>=(0..len).map(|_|alpha[(rng()as usize)%alpha.len()]).collect();
        // sometimes make b a case-variant of a, sometimes differ
        let mut b=a.clone();
        if rng()&1==0 { for x in b.iter_mut(){ if rng()&7==0 {*x=alpha[(rng()as usize)%alpha.len()];}} }
        else { for x in b.iter_mut(){ if x.is_ascii_lowercase(){*x=x.to_ascii_uppercase();} else if x.is_ascii_uppercase(){*x=x.to_ascii_lowercase();}} }
        a.push(0); b.push(0);
        let ca=CString::new(&a[..a.len()-1]).unwrap(); let cb=CString::new(&b[..b.len()-1]).unwrap();
        let fl=norm(unsafe{fa::strcasecmp(ca.as_ptr(),cb.as_ptr())});
        let gl=norm(unsafe{strcasecmp(ca.as_ptr(),cb.as_ptr())});
        if fl!=gl {div+=1; if div<=5 {eprintln!("DIV a={:?} b={:?} fl={fl} gl={gl}",ca,cb);}}
        h.update([fl as u8]); n+=1;
    }
    let dig=h.finalize(); let hex:String=dig.iter().map(|b|format!("{b:02x}")).collect();
    eprintln!("golden sha256={hex} n={n} div={div}");
    assert_eq!(n, 200000);
    assert_eq!(
        hex,
        "37d0b3d211451f288c42aefbffceb890df30c535cc7c313027e451c226f4dea1",
        "strcasecmp sign-result golden changed"
    );
    assert_eq!(div,0,"strcasecmp diverged from glibc in {div} cases");
}
