//! In-process A/B for wcsncat's src-append: OLD (bounded NUL scan + 8-lane copy + 1 NUL)
//! vs NEW (fused single-pass 128B-tier ncopy + 1 NUL). Byte-identity asserted. The dst-end
//! scan is identical for both and omitted (append point only). Covers exact-fill (slen>=n)
//! and short-src (slen<n) — wcsncat appends min(strlen,n) real chars then ONE NUL (no pad).
#![feature(portable_simd)]
use std::hint::black_box; use std::time::Instant;
use std::simd::Simd; use std::simd::cmp::{SimdPartialEq, SimdOrd};
fn pctl(s:&[f64],q:f64)->f64{let mut v=s.to_vec();v.sort_by(|a,b|a.partial_cmp(b).unwrap());v[((q*(v.len()-1)as f64).round()as usize).min(v.len()-1)]}

#[inline] unsafe fn scan_n(src:*const u32,n:usize)->usize{
  let z=Simd::<u32,8>::splat(0); let mut i=0;
  while i+32<=n && (unsafe{src.add(i)} as usize & 0xFFF)<=0x1000-128 {
    let c0=Simd::<u32,8>::from_slice(unsafe{std::slice::from_raw_parts(src.add(i),8)});
    let c1=Simd::<u32,8>::from_slice(unsafe{std::slice::from_raw_parts(src.add(i+8),8)});
    let c2=Simd::<u32,8>::from_slice(unsafe{std::slice::from_raw_parts(src.add(i+16),8)});
    let c3=Simd::<u32,8>::from_slice(unsafe{std::slice::from_raw_parts(src.add(i+24),8)});
    if c0.simd_min(c1).simd_min(c2.simd_min(c3)).simd_eq(z).any(){
      for (k,c) in [c0,c1,c2,c3].iter().enumerate(){ let m=c.simd_eq(z).to_bitmask(); if m!=0{return i+k*8+m.trailing_zeros()as usize;} } }
    i+=32;
  }
  while i<n{ if unsafe{*src.add(i)}==0{return i;} i+=1; } n
}
#[inline] unsafe fn copy_8lane(dst:*mut u32,src:*const u32,count:usize){
  let mut i=0;
  while i+8<=count{ let v=Simd::<u32,8>::from_slice(unsafe{std::slice::from_raw_parts(src.add(i),8)}); v.copy_to_slice(unsafe{std::slice::from_raw_parts_mut(dst.add(i),8)}); i+=8; }
  while i<count{ unsafe{*dst.add(i)=*src.add(i)}; i+=1; }
}
// OLD deployed wcsncat src-append.
unsafe fn old(dst:*mut u32,src:*const u32,n:usize){
  let c=unsafe{scan_n(src,n)}; if c>0{ unsafe{copy_8lane(dst,src,c)}; } unsafe{*dst.add(c)=0};
}
// NEW fused ncopy (mirrors wide_fused_ncopy) + 1 NUL.
unsafe fn fused_ncopy(dst:*mut u32,src:*const u32,n:usize)->usize{
  let z=Simd::<u32,8>::splat(0); let mut i=0;
  while i+32<=n && (unsafe{src.add(i)} as usize & 0xFFF)<=0x1000-128 {
    let c0=Simd::<u32,8>::from_slice(unsafe{std::slice::from_raw_parts(src.add(i),8)});
    let c1=Simd::<u32,8>::from_slice(unsafe{std::slice::from_raw_parts(src.add(i+8),8)});
    let c2=Simd::<u32,8>::from_slice(unsafe{std::slice::from_raw_parts(src.add(i+16),8)});
    let c3=Simd::<u32,8>::from_slice(unsafe{std::slice::from_raw_parts(src.add(i+24),8)});
    if c0.simd_min(c1).simd_min(c2.simd_min(c3)).simd_eq(z).any(){
      for (k,c) in [c0,c1,c2,c3].iter().enumerate(){
        let m=c.simd_eq(z).to_bitmask();
        if m!=0{ let nul=i+k*8+m.trailing_zeros()as usize; for j in i+k*8..nul{ unsafe{*dst.add(j)=*src.add(j)}; } return nul; }
        c.copy_to_slice(unsafe{std::slice::from_raw_parts_mut(dst.add(i+k*8),8)});
      }
    }
    c0.copy_to_slice(unsafe{std::slice::from_raw_parts_mut(dst.add(i),8)});
    c1.copy_to_slice(unsafe{std::slice::from_raw_parts_mut(dst.add(i+8),8)});
    c2.copy_to_slice(unsafe{std::slice::from_raw_parts_mut(dst.add(i+16),8)});
    c3.copy_to_slice(unsafe{std::slice::from_raw_parts_mut(dst.add(i+24),8)});
    i+=32;
  }
  while i<n{ let c=unsafe{*src.add(i)}; if c==0{return i;} unsafe{*dst.add(i)=c}; i+=1; } n
}
unsafe fn new(dst:*mut u32,src:*const u32,n:usize){ let c=unsafe{fused_ncopy(dst,src,n)}; unsafe{*dst.add(c)=0}; }

fn main(){
  for &(n,slen) in &[(16usize,16usize),(64,64),(256,256),(1024,1024),(4096,4096),(64,40),(256,200),(1024,900)]{
    let mut src:Vec<u32>=(0..(slen.max(n)+8) as u32).map(|x|b'a' as u32+(x%26)).collect();
    if slen<src.len(){ src[slen]=0; }
    let sp=src.as_ptr();
    let mut d1=vec![7u32;n+8]; let mut d2=vec![7u32;n+8];
    unsafe{old(d1.as_mut_ptr(),sp,n); new(d2.as_mut_ptr(),sp,n);}
    let end=slen.min(n)+1;
    assert_eq!(&d1[..end],&d2[..end],"data n={n} slen={slen}");
    let iters=300_000u64; let(mut ov,mut nv)=(Vec::new(),Vec::new());
    let p1=d1.as_mut_ptr(); let p2=d2.as_mut_ptr();
    for r in 0..60{
      let o=||{let t=Instant::now();for _ in 0..iters{black_box(unsafe{old(black_box(p1),black_box(sp),n)});}t.elapsed().as_nanos()as f64/iters as f64};
      let nw=||{let t=Instant::now();for _ in 0..iters{black_box(unsafe{new(black_box(p2),black_box(sp),n)});}t.elapsed().as_nanos()as f64/iters as f64};
      if r%2==0{ov.push(o());nv.push(nw());}else{nv.push(nw());ov.push(o());}
    }
    let(o,nn)=(pctl(&ov,0.1),pctl(&nv,0.1));
    eprintln!("wcsncat n={n:<5} slen={slen:<5} OLD={o:7.2}ns fused={nn:7.2}ns  fused/old={:.3} ({:.2}x)",nn/o,o/nn);
  }
}
