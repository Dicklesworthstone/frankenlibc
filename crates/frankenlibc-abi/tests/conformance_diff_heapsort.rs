//! Correctness gate for the BSD `heapsort` integer fast lanes.
//!
//! `heapsort` is unstable and now routes integer keys through the same
//! verify-then-commit lanes as `qsort`. Because equal integer keys are
//! byte-identical, a fully sorted integer array is byte-unique, so fl heapsort
//! output must be byte-identical to glibc `qsort` for natural integer
//! comparators (lane committed) AND for unsigned/descending comparators (lane
//! verify fails -> in-place heap sort fallback). Covers widths 1/2/4/8 across
//! sizes spanning every lane threshold, over several distributions.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_core::stdlib::sort::heapsort as fl_heapsort;
use sha2::{Digest, Sha256};
use std::ffi::c_void;

macro_rules! cmp_pair {
    ($glname:ident, $flname:ident, $ty:ty, $ord:expr) => {
        extern "C" fn $glname(a: *const c_void, b: *const c_void) -> i32 {
            let x = unsafe { *(a as *const $ty) };
            let y = unsafe { *(b as *const $ty) };
            ($ord)(x, y)
        }
        fn $flname(a: &[u8], b: &[u8]) -> i32 {
            let x = <$ty>::from_ne_bytes(a.try_into().unwrap());
            let y = <$ty>::from_ne_bytes(b.try_into().unwrap());
            ($ord)(x, y)
        }
    };
}
cmp_pair!(gl_i8, fl_i8, i8, |x: i8, y: i8| (x as i32) - (y as i32));
cmp_pair!(gl_u8, fl_u8, u8, |x: u8, y: u8| (x as i32) - (y as i32));
cmp_pair!(gl_i16, fl_i16, i16, |x: i16, y: i16| x.cmp(&y) as i32);
cmp_pair!(gl_u16, fl_u16, u16, |x: u16, y: u16| x.cmp(&y) as i32);
cmp_pair!(gl_i32, fl_i32, i32, |x: i32, y: i32| x.cmp(&y) as i32);
cmp_pair!(gl_i32d, fl_i32d, i32, |x: i32, y: i32| y.cmp(&x) as i32);
cmp_pair!(gl_i64, fl_i64, i64, |x: i64, y: i64| x.cmp(&y) as i32);
cmp_pair!(gl_u64, fl_u64, u64, |x: u64, y: u64| x.cmp(&y) as i32);

fn mix(seed: u64, i: usize) -> u64 {
    let mut z = seed.wrapping_add((i as u64).wrapping_mul(0x9E3779B97F4A7C15));
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

type GlCmp = extern "C" fn(*const c_void, *const c_void) -> i32;

fn check(label: &str, bytes_in: &[u8], width: usize, fl_cmp: fn(&[u8], &[u8]) -> i32, gl_cmp: GlCmp) -> Vec<u8> {
    let n = bytes_in.len() / width;
    let mut fl_buf = bytes_in.to_vec();
    fl_heapsort(&mut fl_buf, width, fl_cmp);
    let mut gl_buf = bytes_in.to_vec();
    unsafe { libc::qsort(gl_buf.as_mut_ptr() as *mut c_void, n, width, Some(gl_cmp)); }
    assert_eq!(fl_buf, gl_buf, "{label}: heapsort diverges from glibc qsort (width={width}, n={n})");
    fl_buf
}

#[test]
fn heapsort_lanes_match_glibc_qsort() {
    let sizes = [255usize, 256, 257, 1024, 2049, 4096, 16385];
    let mut hasher = Sha256::new();

    for &n in &sizes {
        let seed = 0xC0DE_F00Du64 ^ (n as u64);
        let dists: [(&str, fn(u64, usize) -> u64); 4] = [
            ("rand", |s, i| mix(s, i)),
            ("dups", |s, i| mix(s, i) % 17),
            ("sorted", |_s, i| i as u64),
            ("revmix", |s, i| if i % 2 == 0 { mix(s, i) } else { (mix(s, i) as i64).wrapping_neg() as u64 }),
        ];
        for (tag, g) in &dists {
            let raw: Vec<u64> = (0..n).map(|i| g(seed, i)).collect();

            let img1: Vec<u8> = raw.iter().map(|&v| v as u8).collect();
            check(&format!("u8/{tag}/n{n}"), &img1, 1, fl_u8, gl_u8);
            check(&format!("i8/{tag}/n{n}"), &img1, 1, fl_i8, gl_i8);

            let img2: Vec<u8> = raw.iter().flat_map(|&v| (v as u16).to_ne_bytes()).collect();
            check(&format!("u16/{tag}/n{n}"), &img2, 2, fl_u16, gl_u16);
            check(&format!("i16/{tag}/n{n}"), &img2, 2, fl_i16, gl_i16);

            let img4: Vec<u8> = raw.iter().flat_map(|&v| (v as i32).to_ne_bytes()).collect();
            check(&format!("i32/{tag}/n{n}"), &img4, 4, fl_i32, gl_i32);
            check(&format!("i32desc/{tag}/n{n}"), &img4, 4, fl_i32d, gl_i32d);
            hasher.update(check(&format!("i32g/{tag}/n{n}"), &img4, 4, fl_i32, gl_i32));

            let img8: Vec<u8> = raw.iter().flat_map(|&v| (v as i64).to_ne_bytes()).collect();
            check(&format!("i64/{tag}/n{n}"), &img8, 8, fl_i64, gl_i64);
            check(&format!("u64/{tag}/n{n}"), &img8, 8, fl_u64, gl_u64);
        }
    }

    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    eprintln!("heapsort lanes golden sha256: {hex}");
}
