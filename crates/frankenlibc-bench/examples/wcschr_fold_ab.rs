//! In-process A/B for wcschr's find_wide_or_nul fold (needle-OR-nul: min(x, x^t)==0 iff
//! x==0 or x==needle). CURRENT: 4x Simd<u32,64> (1024B block, 8 ymm/panel -> spill). ALTs:
//! 8x Simd<u32,8> (256B) and 16x (512B). Absent needle+nul buffer -> full scan.
#![feature(portable_simd)]
use std::hint::black_box; use std::time::Instant;
use std::simd::Simd; use std::simd::cmp::{SimdPartialEq, SimdOrd};
fn pctl(s:&[f64],q:f64)->f64{let mut v=s.to_vec();v.sort_by(|a,b|a.partial_cmp(b).unwrap());v[((q*(v.len()-1)as f64).round()as usize).min(v.len()-1)]}
// CURRENT: 4x Simd<u32,64> panels (1024B block)
fn scan64(s:&[u32],c:u32)->Option<usize>{
  let t=Simd::<u32,64>::splat(c); let z=Simd::<u32,64>::splat(0); let mut b=0;
  while b+256<=s.len(){
    let hit=|k:usize|{let p=Simd::<u32,64>::from_slice(&s[b+k*64..b+(k+1)*64]); p.simd_min(p^t)};
    if hit(0).simd_min(hit(1)).simd_min(hit(2).simd_min(hit(3))).simd_eq(z).any(){
      for j in b..b+256{ if s[j]==c||s[j]==0{return Some(j);} } }
    b+=256;
  }
  for j in b..s.len(){ if s[j]==c||s[j]==0{return Some(j);} } None
}
// ALT: panels x Simd<u32,8>
fn scan8(s:&[u32],c:u32,panels:usize)->Option<usize>{
  let t=Simd::<u32,8>::splat(c); let z=Simd::<u32,8>::splat(0); let blk=panels*8; let mut b=0;
  while b+blk<=s.len(){
    let mut folded={let p=Simd::<u32,8>::from_slice(&s[b..b+8]); p.simd_min(p^t)};
    for k in 1..panels{ let p=Simd::<u32,8>::from_slice(&s[b+k*8..b+(k+1)*8]); folded=folded.simd_min(p.simd_min(p^t)); }
    if folded.simd_eq(z).any(){ for j in b..b+blk{ if s[j]==c||s[j]==0{return Some(j);} } }
    b+=blk;
  }
  for j in b..s.len(){ if s[j]==c||s[j]==0{return Some(j);} } None
}
fn main(){
  for &n in &[256usize,1024,4096,16384]{
    let s:Vec<u32>=vec![b'a' as u32;n]; let c=b'z' as u32; // absent needle, no nul -> full scan
    assert_eq!(scan64(&s,c),scan8(&s,c,8),"m8 n={n}"); assert_eq!(scan64(&s,c),scan8(&s,c,16),"m16 n={n}");
    let iters=300_000u64; let(mut v64,mut v8,mut v16)=(Vec::new(),Vec::new(),Vec::new());
    for _ in 0..50{
      let t=Instant::now();for _ in 0..iters{black_box(scan64(black_box(&s),c));}v64.push(t.elapsed().as_nanos()as f64/iters as f64);
      let t=Instant::now();for _ in 0..iters{black_box(scan8(black_box(&s),c,8));}v8.push(t.elapsed().as_nanos()as f64/iters as f64);
      let t=Instant::now();for _ in 0..iters{black_box(scan8(black_box(&s),c,16));}v16.push(t.elapsed().as_nanos()as f64/iters as f64);
    }
    let(a,b,d)=(pctl(&v64,0.1),pctl(&v8,0.1),pctl(&v16,0.1));
    println!("wcschr-fold n={n:<6} 64lane(1024B)={a:6.1} 8x8(256B)={b:6.1} 16x8(512B)={d:6.1}  256/orig={:.3} 512/orig={:.3}",b/a,d/a);
  }
}
