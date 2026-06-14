#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
//! Byte-stability gate for ecvt/fcvt after moving their float render off the
//! heap (format! -> stack StackStr). Pins exact digits + decpt + sign over
//! specials + 80k random doubles x ndigit; must stay identical.
use std::os::raw::{c_char,c_int};
use std::ffi::CStr;
use frankenlibc_abi::stdlib_abi as fs;
use sha2::{Digest,Sha256};
#[test]
fn ecvt_fcvt_golden_byte_stable(){
  let mut h=Sha256::new();
  let mut seed:u64=0xfeed; let mut rng=||{seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;seed};
  let specials=[0.0f64,-0.0,1.0,-1.0,3.14159265358979,2.5,0.1,123456.789,1e300,1e-300,
    9.9999e-5,999999.9,1e-4,1e6,1e308,1e-308,0.5,0.05,99.995,1.0/3.0];
  let mut n=0u64;
  let mut run=|v:f64,nd:i32|{
    let (mut dp,mut sg)=(Box::new(0i32),Box::new(0i32));
    let pe=unsafe{fs::ecvt(v,nd,dp.as_mut() as *mut c_int,sg.as_mut() as *mut c_int)};
    let se=if pe.is_null(){b"<n>".to_vec()}else{unsafe{CStr::from_ptr(pe)}.to_bytes().to_vec()};
    h.update(&se);h.update(&(*dp).to_le_bytes());h.update(&[*sg as u8]);
    let pf=unsafe{fs::fcvt(v,nd,dp.as_mut() as *mut c_int,sg.as_mut() as *mut c_int)};
    let sf=if pf.is_null(){b"<n>".to_vec()}else{unsafe{CStr::from_ptr(pf)}.to_bytes().to_vec()};
    h.update(&sf);h.update(&(*dp).to_le_bytes());h.update(&[*sg as u8]);
  };
  for &v in &specials { for nd in 0i32..20 { run(v,nd); n+=1; } }
  for _ in 0..80000 { let v=f64::from_bits(rng()); if !v.is_finite(){continue;} let nd=(rng()%20)as i32; run(v,nd); n+=1; }
  let hex:String=h.finalize().iter().map(|b|format!("{b:02x}")).collect();
  eprintln!("ECVT GOLDEN n={n} sha256={hex}");
  assert_eq!(n,80365);
  assert_eq!(hex,"f9f43caacc5d3fe2fb5ac1b5ed24e5135dc666677bb50630ceecf105153e306e","ecvt/fcvt output changed");
}
