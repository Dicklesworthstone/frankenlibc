//! Survey fl time functions vs glibc (dlmopen): gmtime_r, mktime, timegm, difftime.
//! Forward (time_t->tm) and inverse (tm->time_t) date math.
use std::hint::black_box; use std::time::Instant;
fn pctl(s:&[f64],q:f64)->f64{let mut v=s.to_vec();v.sort_by(|a,b|a.partial_cmp(b).unwrap());v[((q*(v.len()-1)as f64).round()as usize).min(v.len()-1)]}
type GmrFn=unsafe extern "C" fn(*const i64,*mut libc::tm)->*mut libc::tm;
type MkFn=unsafe extern "C" fn(*mut libc::tm)->i64;
fn bench2<A:Fn(),B:Fn()>(a:A,b:B)->(f64,f64){
  let(mut fa,mut fb)=(Vec::new(),Vec::new());
  for r in 0..50{
    if r%2==0{let t=Instant::now();a();fa.push(t.elapsed().as_nanos()as f64);let t=Instant::now();b();fb.push(t.elapsed().as_nanos()as f64);}
    else{let t=Instant::now();b();fb.push(t.elapsed().as_nanos()as f64);let t=Instant::now();a();fa.push(t.elapsed().as_nanos()as f64);}
  }
  (pctl(&fa,0.1),pctl(&fb,0.1))
}
fn tag(r:f64)->&'static str{ if r>1.25{"  <-- LOSS"}else if r<0.9{"  win"}else{"  ~par"} }
fn main(){
  let h=unsafe{libc::dlmopen(libc::LM_ID_NEWLM,b"libc.so.6\0".as_ptr().cast(),libc::RTLD_LAZY|libc::RTLD_LOCAL)};assert!(!h.is_null());
  macro_rules! sym{($n:literal,$t:ty)=>{unsafe{std::mem::transmute::<_,$t>(libc::dlsym(h,concat!($n,"\0").as_ptr().cast()))}}}
  let g_gmr:GmrFn=sym!("gmtime_r",GmrFn);
  let g_mk:MkFn=sym!("mktime",MkFn);
  let g_tg:MkFn=sym!("timegm",MkFn);
  use frankenlibc_abi::time_abi as ta;
  let iters=100_000u64;
  // sample epochs across a wide range
  let epochs:Vec<i64>=vec![0, 1_000_000, 1_600_000_000, 1_700_000_000, 951_782_400, 2_000_000_000, 100_000_000_000];
  // gmtime_r
  let(mut ff,mut gg)=(Vec::new(),Vec::new());
  for &e in &epochs{
    let mut ft:libc::tm=unsafe{std::mem::zeroed()}; let mut gt:libc::tm=unsafe{std::mem::zeroed()};
    let ftp=&mut ft as *mut libc::tm; let gtp=&mut gt as *mut libc::tm; let ep=&e as *const i64;
    let(f,g)=bench2(||{for _ in 0..iters{black_box(unsafe{ta::gmtime_r(black_box(ep),ftp)});}},
                    ||{for _ in 0..iters{black_box(unsafe{g_gmr(black_box(ep),gtp)});}});
    ff.push(f); gg.push(g);
  }
  let(f,g)=(pctl(&ff,0.5),pctl(&gg,0.5));
  println!("gmtime_r  fl={:6.2}ns glibc={:6.2}ns fl/glibc={:.3}{}",f/iters as f64,g/iters as f64,f/g,tag(f/g));
  // build a tm for the inverse fns (2023-11-14 12:00:00 UTC-ish)
  let mk_tm=||{ let mut t:libc::tm=unsafe{std::mem::zeroed()}; t.tm_year=123; t.tm_mon=10; t.tm_mday=14; t.tm_hour=12; t.tm_min=30; t.tm_sec=15; t.tm_isdst=0; t };
  // timegm (pure UTC inverse — no tz)
  let(f,g)=bench2(||{for _ in 0..iters{ let mut t=mk_tm(); black_box(unsafe{ta::timegm(black_box(&mut t))}); }},
                  ||{for _ in 0..iters{ let mut t=mk_tm(); black_box(unsafe{g_tg(black_box(&mut t))}); }});
  println!("timegm    fl={:6.2}ns glibc={:6.2}ns fl/glibc={:.3}{}",f/iters as f64,g/iters as f64,f/g,tag(f/g));
  // mktime (local tz — set UTC so both agree)
  unsafe{ std::env::set_var("TZ","UTC"); }
  let(f,g)=bench2(||{for _ in 0..iters{ let mut t=mk_tm(); black_box(unsafe{ta::mktime(black_box(&mut t))}); }},
                  ||{for _ in 0..iters{ let mut t=mk_tm(); black_box(unsafe{g_mk(black_box(&mut t))}); }});
  println!("mktime    fl={:6.2}ns glibc={:6.2}ns fl/glibc={:.3}{}",f/iters as f64,g/iters as f64,f/g,tag(f/g));
}
