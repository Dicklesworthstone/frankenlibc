//! Differential gate: SBCS codecs whose high (0x80-0xFF) tables were regenerated
//! byte-exact from the live host glibc to fix decode/encode divergences found by
//! a full-256 signature probe (ARMSCII-8 C1-control range, CP1255/MACCYRILLIC/MIK
//! wrong high-byte mappings). Each must now decode every byte 0x00..=0xFF and
//! encode every reachable codepoint identically to glibc.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
use frankenlibc_abi::iconv_abi as fl;
use std::ffi::{CString, c_char, c_int, c_void};
const RTLD_NOW: c_int = 2;
const INVALID: usize = usize::MAX;
unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}
type OpenFn = extern "C" fn(*const c_char, *const c_char) -> *mut c_void;
type CloseFn = extern "C" fn(*mut c_void) -> c_int;
type ConvFn = extern "C" fn(*mut c_void, *mut *mut c_char, *mut usize, *mut *mut c_char, *mut usize) -> usize;
struct G { open: OpenFn, close: CloseFn, conv: ConvFn }
fn g() -> G {
    unsafe {
        let h = dlopen(c"libc.so.6".as_ptr(), RTLD_NOW);
        assert!(!h.is_null());
        G { open: std::mem::transmute(dlsym(h, c"iconv_open".as_ptr())),
            close: std::mem::transmute(dlsym(h, c"iconv_close".as_ptr())),
            conv: std::mem::transmute(dlsym(h, c"iconv".as_ptr())) }
    }
}
fn gd(gg:&G,name:&str)->Vec<Option<u32>>{
    let cn=CString::new(name).unwrap();
    let cd=(gg.open)(c"UTF-32LE".as_ptr(),cn.as_ptr());
    assert!(cd as usize!=INVALID,"glibc rejects {name}");
    let v=(0u16..256).map(|b|{let mut inb=[b as u8];let mut o=[0u8;8];
        let mut ip=inb.as_mut_ptr() as *mut c_char;let mut il=1usize;
        let mut op=o.as_mut_ptr() as *mut c_char;let mut ol=8usize;
        let r=(gg.conv)(cd,&mut ip,&mut il,&mut op,&mut ol);
        if r==INVALID||il!=0{None}else{Some(u32::from_le_bytes([o[0],o[1],o[2],o[3]]))}}).collect();
    (gg.close)(cd);v
}
fn fd(name:&str)->Vec<Option<u32>>{
    let cn=CString::new(name).unwrap();
    let cd=unsafe{fl::iconv_open(c"UTF-32LE".as_ptr(),cn.as_ptr())};
    assert!(cd as usize!=INVALID&&!cd.is_null(),"fl rejects {name}");
    let v=(0u16..256).map(|b|{let mut inb=[b as u8];let mut o=[0u8;8];
        let mut ip=inb.as_mut_ptr() as *mut c_char;let mut il=1usize;
        let mut op=o.as_mut_ptr() as *mut c_char;let mut ol=8usize;
        let r=unsafe{fl::iconv(cd,&mut ip,&mut il,&mut op,&mut ol)};
        if r==INVALID||il!=0{None}else{Some(u32::from_le_bytes([o[0],o[1],o[2],o[3]]))}}).collect();
    unsafe{fl::iconv_close(cd)};v
}
fn ge(gg:&G,name:&str,cp:u32)->Option<Vec<u8>>{
    let c=char::from_u32(cp)?; let cn=CString::new(name).unwrap();
    let cd=(gg.open)(cn.as_ptr(),c"UTF-8".as_ptr()); assert!(cd as usize!=INVALID);
    let mut s=c.to_string().into_bytes(); let mut o=[0u8;8];
    let mut ip=s.as_mut_ptr() as *mut c_char;let mut il=s.len();
    let mut op=o.as_mut_ptr() as *mut c_char;let mut ol=8usize;
    let r=(gg.conv)(cd,&mut ip,&mut il,&mut op,&mut ol);(gg.close)(cd);
    (r!=INVALID&&il==0).then(||o[..8-ol].to_vec())
}
fn fe(name:&str,cp:u32)->Option<Vec<u8>>{
    let c=char::from_u32(cp)?; let cn=CString::new(name).unwrap();
    let cd=unsafe{fl::iconv_open(cn.as_ptr(),c"UTF-8".as_ptr())}; assert!(cd as usize!=INVALID&&!cd.is_null());
    let mut s=c.to_string().into_bytes(); let mut o=[0u8;8];
    let mut ip=s.as_mut_ptr() as *mut c_char;let mut il=s.len();
    let mut op=o.as_mut_ptr() as *mut c_char;let mut ol=8usize;
    let r=unsafe{fl::iconv(cd,&mut ip,&mut il,&mut op,&mut ol)};unsafe{fl::iconv_close(cd)};
    (r!=INVALID&&il==0).then(||o[..8-ol].to_vec())
}
const CODECS:&[&str]=&["ARMSCII-8","MACCYRILLIC","MIK","KOI8-U","CP864","CP1161","CSN_369103","CP856"];
#[test]
fn regenerated_sbcs_match_glibc(){
    let gg=g();
    for &name in CODECS {
        let d=fd(name);
        assert_eq!(d,gd(&gg,name),"{name} decode differs from glibc");
        for cp in d.iter().flatten().copied() {
            if cp<0x80 {continue;}
            assert_eq!(fe(name,cp),ge(&gg,name,cp),"{name} encode U+{cp:04X} differs");
        }
    }
}
