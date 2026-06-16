//! Differential gate: EUC-JP-MS (= EUCJP-OPEN / EUCJP-WIN), an EUC-JP superset
//! with NEC/IBM extensions (940 PUA cells in the 0x8F SS3 plane). Verified
//! byte-for-byte vs the live host glibc: decode of every 1-byte, 2-byte (0x8E +
//! 0xA1-0xFE leads) and 3-byte (0x8F SS3) sequence, encode of every reachable
//! code point, and that EUCJP-OPEN/EUCJP-WIN resolve to the same codec.
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
fn g() -> G { unsafe {
    let h = dlopen(c"libc.so.6".as_ptr(), RTLD_NOW); assert!(!h.is_null());
    G { open: std::mem::transmute(dlsym(h, c"iconv_open".as_ptr())),
        close: std::mem::transmute(dlsym(h, c"iconv_close".as_ptr())),
        conv: std::mem::transmute(dlsym(h, c"iconv".as_ptr())) } } }
// decode a byte slice -> (ok_flag, cp_or_remaining)
fn gdec(gg:&G,name:&str,b:&[u8])->(u8,u32){
    let cn=CString::new(name).unwrap();let cd=(gg.open)(c"UTF-32LE".as_ptr(),cn.as_ptr());
    assert!(cd as usize!=INVALID,"glibc rejects {name}");
    let mut s=b.to_vec();let mut o=[0u8;16];let mut ip=s.as_mut_ptr() as *mut c_char;let mut il=s.len();
    let mut op=o.as_mut_ptr() as *mut c_char;let mut ol=16usize;
    let r=(gg.conv)(cd,&mut ip,&mut il,&mut op,&mut ol);(gg.close)(cd);
    if r!=INVALID&&16-ol==4&&il==0 {(1,u32::from_le_bytes([o[0],o[1],o[2],o[3]]))} else {(0,il as u32)}
}
fn fdec(name:&str,b:&[u8])->(u8,u32){
    let cn=CString::new(name).unwrap();let cd=unsafe{fl::iconv_open(c"UTF-32LE".as_ptr(),cn.as_ptr())};
    assert!(cd as usize!=INVALID&&!cd.is_null(),"fl rejects {name}");
    let mut s=b.to_vec();let mut o=[0u8;16];let mut ip=s.as_mut_ptr() as *mut c_char;let mut il=s.len();
    let mut op=o.as_mut_ptr() as *mut c_char;let mut ol=16usize;
    let r=unsafe{fl::iconv(cd,&mut ip,&mut il,&mut op,&mut ol)};unsafe{fl::iconv_close(cd)};
    if r!=INVALID&&16-ol==4&&il==0 {(1,u32::from_le_bytes([o[0],o[1],o[2],o[3]]))} else {(0,il as u32)}
}
fn genc(gg:&G,cp:u32)->Option<Vec<u8>>{
    let c=char::from_u32(cp)?;let cd=(gg.open)(c"EUC-JP-MS".as_ptr(),c"UTF-8".as_ptr());assert!(cd as usize!=INVALID);
    let mut s=c.to_string().into_bytes();let mut o=[0u8;16];let mut ip=s.as_mut_ptr() as *mut c_char;let mut il=s.len();
    let mut op=o.as_mut_ptr() as *mut c_char;let mut ol=16usize;let r=(gg.conv)(cd,&mut ip,&mut il,&mut op,&mut ol);(gg.close)(cd);
    (r!=INVALID&&il==0).then(||o[..16-ol].to_vec())
}
fn fenc(cp:u32)->Option<Vec<u8>>{
    let c=char::from_u32(cp)?;let cd=unsafe{fl::iconv_open(c"EUC-JP-MS".as_ptr(),c"UTF-8".as_ptr())};assert!(cd as usize!=INVALID&&!cd.is_null());
    let mut s=c.to_string().into_bytes();let mut o=[0u8;16];let mut ip=s.as_mut_ptr() as *mut c_char;let mut il=s.len();
    let mut op=o.as_mut_ptr() as *mut c_char;let mut ol=16usize;let r=unsafe{fl::iconv(cd,&mut ip,&mut il,&mut op,&mut ol)};unsafe{fl::iconv_close(cd)};
    (r!=INVALID&&il==0).then(||o[..16-ol].to_vec())
}
#[test]
fn eucjpms_decode_matches_glibc(){
    let gg=g(); let n="EUC-JP-MS";
    for b in 0u16..256 { let i=[b as u8]; assert_eq!(fdec(n,&i),gdec(&gg,n,&i),"1b {b:#04x}"); }
    for a in 0x80u16..=0xFF { for b in 0u16..256 { let i=[a as u8,b as u8]; assert_eq!(fdec(n,&i),gdec(&gg,n,&i),"2b {a:#04x},{b:#04x}"); } }
    for b in 0xA0u16..=0xFF { for c in 0xA0u16..=0xFF { let i=[0x8F,b as u8,c as u8]; assert_eq!(fdec(n,&i),gdec(&gg,n,&i),"3b 8F,{b:#04x},{c:#04x}"); } }
}
#[test]
fn eucjpms_encode_matches_glibc(){
    let gg=g();
    for cp in 0u32..=0xFFFF { if (0xD800..=0xDFFF).contains(&cp){continue;} assert_eq!(fenc(cp),genc(&gg,cp),"enc U+{cp:04X}"); }
}
#[test]
fn eucjpms_aliases_resolve(){
    let gg=g();
    for name in ["EUC-JP-MS","EUCJP-MS","EUCJP-OPEN","EUCJP-WIN"] {
        let cn=CString::new(name).unwrap();
        let cd=unsafe{fl::iconv_open(c"UTF-8".as_ptr(),cn.as_ptr())};
        assert!(cd as usize!=INVALID&&!cd.is_null(),"fl rejects {name}");
        unsafe{fl::iconv_close(cd)};
        // 3-byte SS3 sample must decode identically across alias + glibc
        let s=[0x8Fu8,0xA2,0xAF];
        assert_eq!(fdec(name,&s),gdec(&gg,name,&s),"alias {name} 3b");
    }
}
