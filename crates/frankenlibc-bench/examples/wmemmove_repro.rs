//! Repro of conformance_diff_wcs_copy::wmemmove_overlap failure (dom=8 so=2 n=33).
//! Prints fl::wmemmove output vs a reference memmove + host glibc (dlmopen).
use frankenlibc_abi::wchar_abi as fl;
type WFn = unsafe extern "C" fn(*mut i32, *const i32, usize) -> *mut i32;
fn main() {
    let (dom, so, n) = (8usize, 2usize, 33usize);
    let len = 41usize;
    let base: Vec<i32> = (0..len).map(|i| (i as i32) * 3 + 1).collect();
    // reference memmove
    let mut refb = base.clone();
    {
        let tmp: Vec<i32> = (0..n).map(|k| base[so + k]).collect();
        for k in 0..n {
            refb[dom + k] = tmp[k];
        }
    }
    // fl
    let mut fb = base.clone();
    unsafe {
        fl::wmemmove(
            fb.as_mut_ptr().add(dom) as *mut u32,
            fb.as_ptr().add(so) as *const u32,
            n,
        );
    }
    // glibc via dlmopen (fresh namespace = real libc symbol, not fl)
    let h = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    let g: WFn = unsafe { std::mem::transmute(libc::dlsym(h, b"wmemmove\0".as_ptr().cast())) };
    let mut gb = base.clone();
    unsafe {
        g(gb.as_mut_ptr().add(dom), gb.as_ptr().add(so), n);
    }
    eprintln!("ref  ={:?}", &refb);
    eprintln!("fl   ={:?}", &fb);
    eprintln!("glibc={:?}", &gb);
    eprintln!("fl==ref  : {}", fb == refb);
    eprintln!("fl==glibc: {}", fb == gb);

    // Isolate: is FL's memmove SYMBOL the culprit? Byte-equivalent overlap:
    // dst = base+dom*4 bytes, src = base+so*4 bytes, len = n*4 bytes.
    type MFn = unsafe extern "C" fn(*mut u8, *const u8, usize) -> *mut u8;
    let g_mm: MFn = unsafe { std::mem::transmute(libc::dlsym(h, b"memmove\0".as_ptr().cast())) };
    let bytes: Vec<u8> = base.iter().flat_map(|w| w.to_ne_bytes()).collect();
    let (dstb, srcb, lenb) = (dom * 4, so * 4, n * 4);
    // fl memmove via libc:: (resolves to fl no_mangle in this binary)
    let mut fm = bytes.clone();
    unsafe {
        libc::memmove(
            fm.as_mut_ptr().add(dstb) as *mut _,
            fm.as_ptr().add(srcb) as *const _,
            lenb,
        );
    }
    // glibc memmove
    let mut gm = bytes.clone();
    unsafe {
        g_mm(gm.as_mut_ptr().add(dstb), gm.as_ptr().add(srcb), lenb);
    }
    eprintln!("memmove fl==glibc: {}", fm == gm);
    if fm != gm {
        let fw: Vec<i32> = fm
            .chunks(4)
            .map(|c| i32::from_ne_bytes(c.try_into().unwrap()))
            .collect();
        eprintln!("  memmove fl (as i32)={:?}", fw);
    }
}
