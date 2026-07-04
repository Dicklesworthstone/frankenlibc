//! In-process A/B: OLD strcasecmp fold (simd_ge/simd_le+select, 32B/iter) vs NEW (guard-bit
//! arithmetic fold, 128B-unrolled). Same 'A'*n / 'a'*n data (folded-equal, full scan). Ratio
//! cancels worker. Proves whether the guard-bit fold + unroll actually beats the old fold.
#![feature(portable_simd)]
use std::hint::black_box; use std::time::Instant;
use std::simd::Simd; use std::simd::cmp::{SimdPartialEq, SimdPartialOrd}; use std::simd::Select as _;
fn pctl(s:&[f64],q:f64)->f64{let mut v=s.to_vec();v.sort_by(|a,b|a.partial_cmp(b).unwrap());v[((q*(v.len()-1)as f64).round()as usize).min(v.len()-1)]}
fn fold_old(v:Simd<u8,32>)->Simd<u8,32>{ let up=v.simd_ge(Simd::splat(b'A'))&v.simd_le(Simd::splat(b'Z')); up.select(v+Simd::splat(0x20),v) }
fn fold_new(v:Simd<u8,32>)->Simd<u8,32>{ let h=Simd::<u8,32>::splat(0x80); let g=v|h; let ga=(g-Simd::splat(0x41))&h; let gb=(g-Simd::splat(0x5B))&h; let asc=!v&h; let iu=ga&!gb&asc; v|(iu>>Simd::splat(2)) }
// OLD: 32B/iter, simd_ge/le fold
fn scan_old(a:&[u8],b:&[u8])->usize{ let n=a.len(); let z=Simd::<u8,32>::splat(0); let mut i=0;
  while i+32<=n{ let va=Simd::<u8,32>::from_slice(&a[i..i+32]); let vb=Simd::<u8,32>::from_slice(&b[i..i+32]);
    let f=(fold_old(va).simd_ne(fold_old(vb))|va.simd_eq(z)).to_bitmask(); if f==0{i+=32;continue;} return i+f.trailing_zeros() as usize; }
  while i<n{ if a[i].to_ascii_lowercase()!=b[i].to_ascii_lowercase()||a[i]==0{return i;} i+=1; } n }
// NEW: 128B unroll, guard-bit fold
fn scan_new(a:&[u8],b:&[u8])->usize{ let n=a.len(); let z=Simd::<u8,32>::splat(0);
  let hm=|off:usize|->u64{ let va=Simd::<u8,32>::from_slice(&a[off..off+32]); let vb=Simd::<u8,32>::from_slice(&b[off..off+32]); (fold_new(va).simd_ne(fold_new(vb))|va.simd_eq(z)).to_bitmask() };
  let mut i=0;
  while i+128<=n{ let f0=hm(i);let f1=hm(i+32);let f2=hm(i+64);let f3=hm(i+96);
    if f0|f1|f2|f3==0{i+=128;continue;}
    if f0!=0{return i+f0.trailing_zeros() as usize;} if f1!=0{return i+32+f1.trailing_zeros() as usize;}
    if f2!=0{return i+64+f2.trailing_zeros() as usize;} return i+96+f3.trailing_zeros() as usize; }
  while i+32<=n{ let f=hm(i); if f==0{i+=32;continue;} return i+f.trailing_zeros() as usize; }
  while i<n{ if a[i].to_ascii_lowercase()!=b[i].to_ascii_lowercase()||a[i]==0{return i;} i+=1; } n }
fn main(){
  for &n in &[64usize,256,1024]{
    let a=vec![b'A';n]; let b=vec![b'a';n];
    assert_eq!(scan_old(&a,&b),scan_new(&a,&b),"mismatch n={n}");
    let iters=1_000_000u64; let(mut ov,mut nv)=(Vec::new(),Vec::new());
    for r in 0..60{
      let o=||{let t=Instant::now();for _ in 0..iters{black_box(scan_old(black_box(&a),black_box(&b)));}t.elapsed().as_nanos()as f64/iters as f64};
      let nw=||{let t=Instant::now();for _ in 0..iters{black_box(scan_new(black_box(&a),black_box(&b)));}t.elapsed().as_nanos()as f64/iters as f64};
      if r%2==0{ov.push(o());nv.push(nw());}else{nv.push(nw());ov.push(o());}
    }
    let(o,nn)=(pctl(&ov,0.1),pctl(&nv,0.1));
    println!("casefold n={n:<5} OLD(ge/le)={o:6.1}ns NEW(guardbit+unroll)={nn:6.1}ns  new/old={:.3} ({:.2}x)",nn/o,o/nn);
  }
}
