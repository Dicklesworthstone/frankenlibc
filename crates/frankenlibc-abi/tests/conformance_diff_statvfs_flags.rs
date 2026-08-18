#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc statvfs oracle

//! `statvfs.f_flag` has two sources, and the gate is that they agree.
//!
//! The kernel reports mount flags in `statfs.f_flags`, but only when it sets
//! `ST_VALID` (0x20). glibc does not trust the field otherwise: `internal_statvfs`
//! falls back to parsing the mount table, which is why "/proc/mounts" appears in
//! libc.so.6. fl now does the same.
//!
//! THE FALLBACK PATH CANNOT BE TRIGGERED on any kernel worth testing — ST_VALID
//! is set on all 10 mounts of the machine this was written on — so a test that
//! waited for a kernel to clear it would never run. Instead this checks the
//! property that makes the fallback correct: on a kernel that DOES set ST_VALID,
//! the mount-table derivation must reproduce the kernel's own answer. If those
//! two ever disagree, the fallback would be silently wrong on the kernels that
//! need it, and nobody would find out.

use std::ffi::CString;

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct StatVfs {
    f_bsize: u64,
    f_frsize: u64,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_favail: u64,
    f_fsid: u64,
    f_flag: u64,
    f_namemax: u64,
    spare: [i32; 6],
}

unsafe extern "C" {
    fn statvfs(path: *const std::ffi::c_char, buf: *mut StatVfs) -> std::ffi::c_int;
}

/// The public ST_* bits, i.e. what a caller may observe.
const PUBLIC_ST_MASK: u64 =
    0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x40 | 0x80 | 0x100 | 0x200 | 0x400 | 0x800 | 0x1000;

#[test]
fn mount_table_derivation_reproduces_the_kernels_flags() {
    // Every mount point the host actually has, rather than a fixed list: the
    // interesting flags (ro, nosuid, nodev, noexec, relatime) are spread across
    // different mounts and no single path exercises more than a few.
    let table = std::fs::read_to_string("/proc/mounts").expect("read /proc/mounts");
    let mut points: Vec<&str> = table
        .lines()
        .filter_map(|l| l.split_whitespace().nth(1))
        .collect();
    points.sort_unstable();
    points.dedup();

    let mut compared = 0usize;
    let mut seen_flags = 0u64;
    let mut divergences = Vec::new();
    for point in points {
        let Ok(c) = CString::new(point) else { continue };
        let mut vfs = StatVfs::default();
        // Unreadable or vanished mounts are not this test's subject.
        if unsafe { statvfs(c.as_ptr(), &mut vfs) } != 0 {
            continue;
        }
        let Some(derived) = frankenlibc_abi::unistd_abi::statvfs_flags_from_mounts(point) else {
            continue;
        };
        compared += 1;
        seen_flags |= vfs.f_flag & PUBLIC_ST_MASK;
        if derived != vfs.f_flag & PUBLIC_ST_MASK {
            divergences.push(format!(
                "{point}: mount-table derived {derived:#x}, kernel/glibc {:#x}",
                vfs.f_flag & PUBLIC_ST_MASK
            ));
        }
    }

    assert!(
        compared >= 5,
        "only {compared} mounts were comparable; this host cannot exercise the derivation"
    );
    // A machine where every mount reported flags 0 would make the comparison
    // above trivially true. Require that the sweep actually saw some flags set,
    // and more than one distinct bit among them.
    assert!(
        seen_flags.count_ones() >= 2,
        "only {} distinct ST_* bit(s) seen across {compared} mounts ({seen_flags:#x}) -- \
         the comparison is near-vacuous on this host",
        seen_flags.count_ones()
    );
    assert!(
        divergences.is_empty(),
        "mount-table derivation disagrees with the kernel on {} of {compared} mounts:\n  {}",
        divergences.len(),
        divergences.join("\n  ")
    );
}
