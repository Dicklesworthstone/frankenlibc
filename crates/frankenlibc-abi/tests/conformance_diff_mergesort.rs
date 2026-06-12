//! Isomorphism + stability gate for the rewritten BSD `mergesort`.
//!
//! The new implementation stably sorts an index array (instead of heap-
//! allocating one `Vec<u8>` per element). This gate proves the output is
//! byte-identical to a reference stable sort — Rust's stable `sort_by` over the
//! element byte-chunks, which is exactly what the previous element-copy
//! implementation computed — across element widths, input distributions, and
//! comparators, including KEY-ONLY comparators with a distinguishing payload so
//! stability (equal-comparing elements keep input order) is observable.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_core::stdlib::sort::mergesort as fl_mergesort;
use sha2::{Digest, Sha256};

fn mix(seed: u64, i: usize) -> u64 {
    let mut z = seed.wrapping_add((i as u64).wrapping_mul(0x9E3779B97F4A7C15));
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

/// Reference stable sort = the previous mergesort algorithm: copy elements out,
/// stable-sort by the comparator, write back.
fn reference_stable<F: Fn(&[u8], &[u8]) -> i32>(bytes: &[u8], width: usize, cmp: &F) -> Vec<u8> {
    let num = bytes.len() / width;
    let mut elems: Vec<Vec<u8>> = (0..num).map(|i| bytes[i * width..(i + 1) * width].to_vec()).collect();
    elems.sort_by(|a, b| cmp(a, b).cmp(&0));
    let mut out = Vec::with_capacity(bytes.len());
    for e in &elems {
        out.extend_from_slice(e);
    }
    out
}

fn check<F: Fn(&[u8], &[u8]) -> i32 + Copy>(label: &str, bytes: &[u8], width: usize, cmp: F) -> Vec<u8> {
    let mut fl_buf = bytes.to_vec();
    fl_mergesort(&mut fl_buf, width, cmp);
    let want = reference_stable(bytes, width, &cmp);
    assert_eq!(fl_buf, want, "{label}: mergesort diverges from reference stable sort");
    fl_buf
}

// width-4 natural i32
fn cmp_i32(a: &[u8], b: &[u8]) -> i32 {
    i32::from_ne_bytes(a.try_into().unwrap()).cmp(&i32::from_ne_bytes(b.try_into().unwrap())) as i32
}
// width-8 record: key = first 4 bytes (i32), payload = last 4 bytes. Comparing
// only the key makes equal-key/different-payload ties stability-observable.
fn cmp_key32(a: &[u8], b: &[u8]) -> i32 {
    i32::from_ne_bytes(a[..4].try_into().unwrap())
        .cmp(&i32::from_ne_bytes(b[..4].try_into().unwrap())) as i32
}
// width-1 unsigned
fn cmp_u8(a: &[u8], b: &[u8]) -> i32 { (a[0] as i32) - (b[0] as i32) }
// width-4 low-resolution key (many ties across distinct values) -> exercises
// stability where equal-comparing elements have DIFFERENT bytes.
fn cmp_i32_coarse(a: &[u8], b: &[u8]) -> i32 {
    let x = i32::from_ne_bytes(a.try_into().unwrap()) >> 8;
    let y = i32::from_ne_bytes(b.try_into().unwrap()) >> 8;
    x.cmp(&y) as i32
}

#[test]
fn mergesort_matches_reference_stable_sort() {
    let sizes = [1usize, 2, 7, 33, 256, 1000, 4096, 16385];
    let mut hasher = Sha256::new();

    for &n in &sizes {
        let seed = 0x7A11_BEEFu64 ^ (n as u64);

        // width 4 natural + coarse-key (stability across distinct bytes)
        let img4: Vec<u8> = (0..n).flat_map(|i| (mix(seed, i) as i32).to_ne_bytes()).collect();
        hasher.update(check(&format!("i32/n{n}"), &img4, 4, cmp_i32));
        hasher.update(check(&format!("i32coarse/n{n}"), &img4, 4, cmp_i32_coarse));

        // width 1 unsigned (duplicate-heavy by nature)
        let img1: Vec<u8> = (0..n).map(|i| mix(seed ^ 0x11, i) as u8).collect();
        hasher.update(check(&format!("u8/n{n}"), &img1, 1, cmp_u8));

        // width 8 key+payload: small key space -> many equal-key ties whose
        // payloads differ, so a non-stable sort would reorder them.
        let img8: Vec<u8> = (0..n)
            .flat_map(|i| {
                let key = (mix(seed ^ 0x22, i) % 16) as i32; // 16 distinct keys -> heavy ties
                let payload = i as i32; // unique payload reveals input order
                let mut r = key.to_ne_bytes().to_vec();
                r.extend_from_slice(&payload.to_ne_bytes());
                r
            })
            .collect();
        hasher.update(check(&format!("key32/n{n}"), &img8, 8, cmp_key32));
    }

    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    eprintln!("mergesort golden sha256: {hex}");
}
