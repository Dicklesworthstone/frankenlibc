//! Differential gate: UTF-7-IMAP (RFC 3501 modified UTF-7) vs the live host glibc.
//! Shift-in is '&' (literal '&' is "&-"), the 63rd base64 char is ',', and all
//! printable ASCII except '&' is direct. Verified both directions over a battery
//! of strings (ASCII, '&', BMP, astral, controls, comma-base64 cases) plus a
//! split-buffer streaming decode.
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
fn gconv(gg:&G,to:&str,from:&str,inp:&[u8])->Option<Vec<u8>>{
    let (ct,cf)=(CString::new(to).unwrap(),CString::new(from).unwrap());
    let cd=(gg.open)(ct.as_ptr(),cf.as_ptr()); if cd as usize==INVALID {return None;}
    let mut s=inp.to_vec(); let mut o=vec![0u8;512];
    let mut ip=s.as_mut_ptr() as *mut c_char;let mut il=s.len();let mut op=o.as_mut_ptr() as *mut c_char;let mut ol=o.len();
    let r=(gg.conv)(cd,&mut ip,&mut il,&mut op,&mut ol);
    // flush (NULL inbuf) for stateful finalize
    let mut np:*mut c_char=std::ptr::null_mut(); let _=(gg.conv)(cd,&mut np,&mut 0usize,&mut op,&mut ol);
    (gg.close)(cd);
    if r==INVALID||il!=0 {Some(vec![0xDE,0xAD])} else {let n=o.len()-ol;o.truncate(n);Some(o)}
}
fn flconv(to:&str,from:&str,inp:&[u8])->Option<Vec<u8>>{
    let (ct,cf)=(CString::new(to).unwrap(),CString::new(from).unwrap());
    let cd=unsafe{fl::iconv_open(ct.as_ptr(),cf.as_ptr())}; if cd as usize==INVALID||cd.is_null(){return None;}
    let mut s=inp.to_vec(); let mut o=vec![0u8;512];
    let mut ip=s.as_mut_ptr() as *mut c_char;let mut il=s.len();let mut op=o.as_mut_ptr() as *mut c_char;let mut ol=o.len();
    let r=unsafe{fl::iconv(cd,&mut ip,&mut il,&mut op,&mut ol)};
    let mut np:*mut c_char=std::ptr::null_mut(); let _=unsafe{fl::iconv(cd,&mut np,&mut 0usize,&mut op,&mut ol)};
    unsafe{fl::iconv_close(cd)};
    if r==INVALID||il!=0 {Some(vec![0xDE,0xAD])} else {let n=o.len()-ol;o.truncate(n);Some(o)}
}
const SAMPLES:&[&str]=&[
    "A&B","héllo","日本","~/mail","INBOX.Drafts","&","&&","a+b/c,d","\u{1F600}z",
    "Mail & News","Списки","",":+,-","Café—Список&日",
];
#[test]
fn utf7imap_encode_matches_glibc(){
    let gg=g();
    for s in SAMPLES { let b=s.as_bytes();
        assert_eq!(flconv("UTF-7-IMAP","UTF-8",b),gconv(&gg,"UTF-7-IMAP","UTF-8",b),"encode {s:?}"); }
}
#[test]
fn utf7imap_decode_matches_glibc(){
    let gg=g();
    // Round-trip: encode via glibc then decode both, plus raw IMAP byte strings.
    for s in SAMPLES {
        if let Some(enc)=gconv(&gg,"UTF-7-IMAP","UTF-8",s.as_bytes()) {
            if enc==vec![0xDE,0xAD] {continue;}
            assert_eq!(flconv("UTF-8","UTF-7-IMAP",&enc),gconv(&gg,"UTF-8","UTF-7-IMAP",&enc),"decode of {s:?} -> {enc:02x?}");
        }
    }
    for raw in [&b"A&AOk-B"[..], b"&-", b"&ZeVnLA-", b"x&-y", b"&AAk-"] {
        assert_eq!(flconv("UTF-8","UTF-7-IMAP",raw),gconv(&gg,"UTF-8","UTF-7-IMAP",raw),"raw decode {raw:02x?}");
    }
}
#[test]
fn utf7imap_split_buffer_streaming(){
    // Decode "&ZeVnLA-" (日本) split at every position; fl must accumulate state.
    let gg=g();
    let full=b"x&ZeVnLA-y";
    let want=gconv(&gg,"UTF-8","UTF-7-IMAP",full).unwrap();
    for split in 1..full.len() {
        let cn=CString::new("UTF-7-IMAP").unwrap();
        let cd=unsafe{fl::iconv_open(c"UTF-8".as_ptr(),cn.as_ptr())};
        assert!(cd as usize!=INVALID&&!cd.is_null());
        let mut out=vec![0u8;512]; let mut op=out.as_mut_ptr() as *mut c_char; let mut ol=out.len();
        let mut got=Vec::new();
        for chunk in [&full[..split],&full[split..]] {
            let mut s=chunk.to_vec(); let mut ip=s.as_mut_ptr() as *mut c_char; let mut il=s.len();
            let _=unsafe{fl::iconv(cd,&mut ip,&mut il,&mut op,&mut ol)};
        }
        let mut np:*mut c_char=std::ptr::null_mut(); let _=unsafe{fl::iconv(cd,&mut np,&mut 0usize,&mut op,&mut ol)};
        let n=out.len()-ol; got.extend_from_slice(&out[..n]);
        unsafe{fl::iconv_close(cd)};
        assert_eq!(got,want,"split at {split}");
    }
}
