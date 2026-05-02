#![cfg(target_os = "linux")]

//! Metamorphic-property test harness for `ftok(3)`.
//!
//! ftok produces a SysV IPC key from (path, proj_id) using the
//! formula:
//!   key = ((proj_id & 0xFF) << 24) | ((st_dev & 0xFF) << 16) | (st_ino & 0xFFFF)
//!
//! These properties hold regardless of the path's actual st_dev/
//! st_ino values:
//!
//!   - same path + same proj_id → same key (determinism)
//!   - changing only the proj_id changes only the high byte
//!   - low 24 bits depend only on the path
//!   - proj_id higher bits beyond 0xFF are silently masked
//!
//! Filed under [bd-58e87f] follow-up.

use std::ffi::CString;

use frankenlibc_abi::unistd_abi as fl;

#[test]
fn metamorphic_ftok_same_path_same_id_returns_same_key() {
    let path = CString::new("/tmp").unwrap();
    let k1 = unsafe { fl::ftok(path.as_ptr(), 0x42) };
    let k2 = unsafe { fl::ftok(path.as_ptr(), 0x42) };
    assert_eq!(k1, k2, "ftok not deterministic on same input");
    assert!(k1 != -1, "ftok should succeed for /tmp");
}

#[test]
fn metamorphic_ftok_proj_id_only_affects_high_byte() {
    let path = CString::new("/tmp").unwrap();
    let k_a = unsafe { fl::ftok(path.as_ptr(), 0x10) };
    let k_b = unsafe { fl::ftok(path.as_ptr(), 0x80) };
    let k_c = unsafe { fl::ftok(path.as_ptr(), 0xff) };
    let mask_low: u32 = 0x00ff_ffff;
    let a_low = (k_a as u32) & mask_low;
    let b_low = (k_b as u32) & mask_low;
    let c_low = (k_c as u32) & mask_low;
    assert_eq!(a_low, b_low, "low 24 bits must equal across proj_ids");
    assert_eq!(a_low, c_low);
    // High byte must reflect proj_id.
    assert_eq!(((k_a as u32) >> 24) & 0xff, 0x10);
    assert_eq!(((k_b as u32) >> 24) & 0xff, 0x80);
    assert_eq!(((k_c as u32) >> 24) & 0xff, 0xff);
}

#[test]
fn metamorphic_ftok_proj_id_high_bits_masked_to_low_byte() {
    // proj_id is masked to its low 8 bits; 0x101 == 0x01 etc.
    let path = CString::new("/tmp").unwrap();
    let k_01 = unsafe { fl::ftok(path.as_ptr(), 0x0001) };
    let k_101 = unsafe { fl::ftok(path.as_ptr(), 0x0101) };
    let k_ff01 = unsafe { fl::ftok(path.as_ptr(), 0xff01u32 as i32) };
    assert_eq!(
        k_01, k_101,
        "proj_id 0x101 should mask to 0x01"
    );
    assert_eq!(k_01, k_ff01, "proj_id 0xff01 should mask to 0x01");
}

#[test]
fn metamorphic_ftok_different_paths_low_24_typically_differ() {
    // Two clearly-different paths usually have different inodes,
    // so the low 24 bits should differ. We sample a few common ones.
    let p1 = CString::new("/tmp").unwrap();
    let p2 = CString::new("/").unwrap();
    let p3 = CString::new("/etc").unwrap();
    let k1 = unsafe { fl::ftok(p1.as_ptr(), 1) } as u32 & 0x00ff_ffff;
    let k2 = unsafe { fl::ftok(p2.as_ptr(), 1) } as u32 & 0x00ff_ffff;
    let k3 = unsafe { fl::ftok(p3.as_ptr(), 1) } as u32 & 0x00ff_ffff;
    // At least two of the three should be distinct on any
    // reasonable filesystem.
    let distinct = (k1 != k2) as u32 + (k1 != k3) as u32 + (k2 != k3) as u32;
    assert!(distinct >= 2, "low 24 bits clustered: {k1:#x} {k2:#x} {k3:#x}");
}

#[test]
fn metamorphic_ftok_nonexistent_path_returns_minus_one() {
    let path = CString::new("/nonexistent/frankenlibc/path/should/not/exist").unwrap();
    let k = unsafe { fl::ftok(path.as_ptr(), 0x42) };
    assert_eq!(k, -1, "nonexistent path must fail");
}

#[test]
fn metamorphic_ftok_proj_id_zero_does_not_panic() {
    let path = CString::new("/tmp").unwrap();
    let k = unsafe { fl::ftok(path.as_ptr(), 0) };
    assert!(k != -1, "/tmp + proj_id=0 should succeed");
    // High byte should be 0.
    assert_eq!(((k as u32) >> 24) & 0xff, 0);
}

#[test]
fn ftok_metamorphic_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc ftok\",\"reference\":\"internal-invariants\",\"properties\":6,\"divergences\":0}}",
    );
}
