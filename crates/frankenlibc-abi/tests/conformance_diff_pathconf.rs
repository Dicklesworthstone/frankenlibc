#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
//! Differential gate: fl `pathconf` must match glibc. _PC_2_SYMLINKS and the
//! record/allocation limits (_PC_REC_MIN_XFER_SIZE / _PC_REC_XFER_ALIGN /
//! _PC_ALLOC_SIZE_MIN, which glibc derives from statvfs f_bsize) used to fall
//! through to EINVAL (returning -1). _PC_FILESIZEBITS is now also covered: fl
//! maps it from the filesystem f_type magic (fs_filesizebits_for_type, mirroring
//! glibc __statfs_filesize_max), so it must match glibc on the test fs. bd-eqcn80.

use frankenlibc_abi::unistd_abi as fu;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_long};
unsafe extern "C" {
    fn pathconf(p: *const c_char, n: c_int) -> c_long;
}

#[test]
fn pathconf_matches_glibc() {
    let keys: &[(&str, c_int)] = &[
        ("_PC_LINK_MAX", libc::_PC_LINK_MAX),
        ("_PC_MAX_CANON", libc::_PC_MAX_CANON),
        ("_PC_MAX_INPUT", libc::_PC_MAX_INPUT),
        ("_PC_NAME_MAX", libc::_PC_NAME_MAX),
        ("_PC_PATH_MAX", libc::_PC_PATH_MAX),
        ("_PC_PIPE_BUF", libc::_PC_PIPE_BUF),
        ("_PC_CHOWN_RESTRICTED", libc::_PC_CHOWN_RESTRICTED),
        ("_PC_NO_TRUNC", libc::_PC_NO_TRUNC),
        ("_PC_VDISABLE", libc::_PC_VDISABLE),
        ("_PC_SYNC_IO", libc::_PC_SYNC_IO),
        ("_PC_REC_MIN_XFER_SIZE", libc::_PC_REC_MIN_XFER_SIZE),
        ("_PC_REC_XFER_ALIGN", libc::_PC_REC_XFER_ALIGN),
        ("_PC_ALLOC_SIZE_MIN", libc::_PC_ALLOC_SIZE_MIN),
        ("_PC_2_SYMLINKS", libc::_PC_2_SYMLINKS),
        ("_PC_FILESIZEBITS", libc::_PC_FILESIZEBITS),
    ];
    let path = CString::new("/tmp").unwrap();
    let mut div = Vec::new();
    for &(n, k) in keys {
        let f = unsafe { fu::pathconf(path.as_ptr(), k) };
        let g = unsafe { pathconf(path.as_ptr(), k) };
        if f != g {
            div.push(format!("{n}: fl={f} glibc={g}"));
        }
    }
    assert!(
        div.is_empty(),
        "pathconf divergences vs glibc ({}):\n  {}",
        div.len(),
        div.join("\n  ")
    );
}

#[test]
fn fpathconf_matches_glibc() {
    use std::os::raw::c_void;
    unsafe extern "C" {
        fn fpathconf(fd: c_int, n: c_int) -> c_long;
        fn open(p: *const c_char, fl: c_int) -> c_int;
        fn close(fd: c_int) -> c_int;
    }
    let _ = std::ptr::null::<c_void>();
    let p = CString::new("/tmp").unwrap();
    let fd = unsafe { open(p.as_ptr(), 0) };
    assert!(fd >= 0, "open(/tmp) failed");
    let keys: &[(&str, c_int)] = &[
        ("_PC_LINK_MAX", libc::_PC_LINK_MAX),
        ("_PC_NAME_MAX", libc::_PC_NAME_MAX),
        ("_PC_PATH_MAX", libc::_PC_PATH_MAX),
        ("_PC_PIPE_BUF", libc::_PC_PIPE_BUF),
        ("_PC_CHOWN_RESTRICTED", libc::_PC_CHOWN_RESTRICTED),
        ("_PC_NO_TRUNC", libc::_PC_NO_TRUNC),
        ("_PC_REC_MIN_XFER_SIZE", libc::_PC_REC_MIN_XFER_SIZE),
        ("_PC_REC_XFER_ALIGN", libc::_PC_REC_XFER_ALIGN),
        ("_PC_ALLOC_SIZE_MIN", libc::_PC_ALLOC_SIZE_MIN),
        ("_PC_2_SYMLINKS", libc::_PC_2_SYMLINKS),
        ("_PC_FILESIZEBITS", libc::_PC_FILESIZEBITS),
    ];
    let mut div = Vec::new();
    for &(n, k) in keys {
        let f = unsafe { fu::fpathconf(fd, k) };
        let g = unsafe { fpathconf(fd, k) };
        if f != g {
            div.push(format!("{n}: fl={f} glibc={g}"));
        }
    }
    unsafe { close(fd) };
    assert!(
        div.is_empty(),
        "fpathconf divergences vs glibc ({}):\n  {}",
        div.len(),
        div.join("\n  ")
    );
}

/// Seeded so "errno untouched" is distinguishable from "errno set to 0".
const SENTINEL_ERRNO: c_int = 4242;

/// Selectors glibc answers as INDETERMINATE: -1 with errno UNTOUCHED, as opposed
/// to an unknown selector, which is -1 with EINVAL.
///
/// `_PC_SYNC_IO` is in the value list above and has been since this gate was
/// written -- and that did not help, because both sides return -1 and the gate
/// compared only values. fl was reaching these through the EINVAL default, so it
/// told every caller "unknown selector" where glibc says "no limit defined".
/// Measured on live glibc 2.42 against ".", /tmp, /proc and /dev/shm: identical
/// on all four, so this is a per-selector fact, not a per-filesystem one.
///
/// _PC_REC_MIN_XFER_SIZE / _PC_REC_XFER_ALIGN / _PC_ALLOC_SIZE_MIN are
/// deliberately NOT here: glibc answers those from the filesystem block size.
/// The REC_* family splits, so each member is measured, not inferred.
///
/// `_PC_ASYNC_IO` WAS IN THIS LIST AND DID NOT BELONG. It is not indeterminate:
/// glibc decides it from the file type, returning 1 for regular files and block
/// devices. Every path this test drives is a DIRECTORY, where the answer really
/// is -1, so the wrong entry passed. See `async_io_depends_on_file_type`.
const INDETERMINATE_PC: &[(&str, c_int)] = &[
    ("_PC_SYNC_IO", libc::_PC_SYNC_IO),
    ("_PC_PRIO_IO", libc::_PC_PRIO_IO),
    ("_PC_SOCK_MAXBUF", libc::_PC_SOCK_MAXBUF),
    ("_PC_REC_INCR_XFER_SIZE", libc::_PC_REC_INCR_XFER_SIZE),
    ("_PC_REC_MAX_XFER_SIZE", libc::_PC_REC_MAX_XFER_SIZE),
    ("_PC_SYMLINK_MAX", libc::_PC_SYMLINK_MAX),
];

#[test]
fn indeterminate_pathconf_keys_preserve_errno() {
    // Several paths, because "indeterminate" must not turn out to be
    // "this filesystem happens to say -1".
    for dir in ["/tmp", ".", "/proc"] {
        let path = CString::new(dir).unwrap();
        for &(name, key) in INDETERMINATE_PC {
            let (g, g_errno) = unsafe {
                *libc::__errno_location() = SENTINEL_ERRNO;
                let r = pathconf(path.as_ptr(), key);
                (r, *libc::__errno_location())
            };
            // Host premise first: if glibc ever starts answering one of these,
            // this gate must fail loudly rather than keep asserting fl's -1.
            assert_eq!(g, -1, "host premise: glibc {name} on {dir} must be -1");
            assert_eq!(
                g_errno, SENTINEL_ERRNO,
                "host premise: glibc must leave errno untouched for {name} on {dir}"
            );

            let (f, f_errno) = unsafe {
                *libc::__errno_location() = SENTINEL_ERRNO;
                let r = fu::pathconf(path.as_ptr(), key);
                (r, *libc::__errno_location())
            };
            assert_eq!(f, g, "{name} on {dir}: fl={f} glibc={g}");
            assert_eq!(
                f_errno, SENTINEL_ERRNO,
                "fl must leave errno untouched for indeterminate {name} on {dir}: setting \
                 EINVAL reports an unknown selector, which is a different answer"
            );
        }
    }
}

/// `_PC_NAME_MAX` is per-FILESYSTEM, and the value that proves it is rare.
///
/// fl used to answer 255 from a constant table. That is correct on ext4, tmpfs,
/// proc, sysfs, cgroup2 and devtmpfs — every filesystem the other tests in this
/// file touch — and WRONG on squashfs, which reports 256. glibc returns statfs's
/// `f_namelen`; measured on the machine this was written against,
/// `pathconf(_PC_NAME_MAX)` equalled `statvfs.f_namemax` on all 12 paths tried
/// across 7 filesystem types.
///
/// So this test does not assert a number. It sweeps whatever filesystems the
/// host actually has, requires fl to match glibc on each, and reports whether a
/// DISCRIMINATING mount (one whose NAME_MAX is not 255) was present at all — a
/// pass without one does not prove the constant was removed.
#[test]
fn name_max_is_per_filesystem_not_a_constant() {
    let mut candidates: Vec<String> = ["/", "/tmp", "/proc", "/sys", "/dev/shm", "/dev", "/run"]
        .iter()
        .map(|s| (*s).to_string())
        .collect();

    // squashfs is the discriminating case on this host and it lives under
    // /snap/<name>/<rev>. Discover rather than hardcode: the revisions change.
    if let Ok(entries) = std::fs::read_dir("/snap") {
        for entry in entries.flatten().take(32) {
            if let Ok(revs) = std::fs::read_dir(entry.path()) {
                for rev in revs.flatten().take(4) {
                    let p = rev.path();
                    // Skip the "current" symlink; take numbered revisions.
                    if p.is_dir()
                        && p.file_name()
                            .and_then(|n| n.to_str())
                            .is_some_and(|n| n.chars().all(|c| c.is_ascii_digit()))
                    {
                        candidates.push(p.to_string_lossy().into_owned());
                    }
                }
            }
        }
    }

    let mut compared = 0usize;
    let mut discriminating = 0usize;
    let mut divergences = Vec::new();
    for dir in &candidates {
        let Ok(path) = CString::new(dir.as_str()) else {
            continue;
        };
        let g = unsafe { pathconf(path.as_ptr(), libc::_PC_NAME_MAX) };
        if g < 0 {
            continue; // path vanished or is not statfs-able; not this test's subject
        }
        let f = unsafe { fu::pathconf(path.as_ptr(), libc::_PC_NAME_MAX) };
        compared += 1;
        if g != 255 {
            discriminating += 1;
        }
        if f != g {
            divergences.push(format!("{dir}: fl={f} glibc={g}"));
        }
    }

    assert!(
        compared >= 4,
        "only {compared} paths were comparable -- this host cannot exercise the sweep"
    );
    // Not an assertion: a host with no squashfs (containers, minimal images)
    // legitimately has nothing that distinguishes 255-the-constant from
    // 255-the-measurement. Say so instead of implying coverage.
    if discriminating == 0 {
        println!(
            "pathconf _PC_NAME_MAX: {compared} paths compared, NONE with a NAME_MAX other than \
             255 -- a constant would also pass here, so this run does not prove the per-filesystem \
             lookup"
        );
    } else {
        println!(
            "pathconf _PC_NAME_MAX: {compared} paths compared, {discriminating} with a NAME_MAX \
             other than 255 -- the per-filesystem lookup is genuinely exercised"
        );
    }
    assert!(
        divergences.is_empty(),
        "_PC_NAME_MAX divergences vs glibc ({} of {compared}):\n  {}",
        divergences.len(),
        divergences.join("\n  ")
    );
}

/// `_PC_2_SYMLINKS` is per-FILESYSTEM, and — unlike `_PC_NAME_MAX` — this host
/// has NO filesystem that discriminates.
///
/// glibc statfs's the path and returns 0 for ten `f_type` magics
/// (QNX4, DEVPTS, MSDOS/FAT, ROMFS, ADFS, EFS x2, BFS, CRAMFS, NTFS), 1
/// otherwise. fl returned a constant 1. None of those ten is mounted on a
/// typical dev box, so a sweep over the mounted filesystems shows a uniform 1
/// and CANNOT catch the divergence — the list was read out of libc.so.6's
/// pathconf comparison tree instead.
///
/// So this test does two different things, and the second is the real one:
///   1. fl must match glibc on every mounted filesystem (weak here, by
///      construction — everything answers 1);
///   2. DEVPTS is the one magic in glibc's list that a normal Linux box
///      actually mounts, at /dev/pts. That makes it the single available
///      discriminating case, and it is asserted directly.
#[test]
fn two_symlinks_is_per_filesystem_not_a_constant() {
    let mut compared = 0usize;
    let mut divergences = Vec::new();
    for dir in [
        "/", "/tmp", "/proc", "/sys", "/dev", "/dev/shm", "/run", "/dev/pts",
    ] {
        let Ok(path) = CString::new(dir) else {
            continue;
        };
        let g = unsafe { pathconf(path.as_ptr(), libc::_PC_2_SYMLINKS) };
        if g < 0 {
            continue;
        }
        let f = unsafe { fu::pathconf(path.as_ptr(), libc::_PC_2_SYMLINKS) };
        compared += 1;
        if f != g {
            divergences.push(format!("{dir}: fl={f} glibc={g}"));
        }
    }
    assert!(compared >= 4, "only {compared} paths comparable");
    assert!(
        divergences.is_empty(),
        "_PC_2_SYMLINKS divergences vs glibc ({} of {compared}):\n  {}",
        divergences.len(),
        divergences.join("\n  ")
    );

    // The discriminating case, called out so a reader knows which line carries
    // the weight. /dev/pts is devpts (DEVPTS_SUPER_MAGIC 0x1cd1), one of the ten
    // magics glibc answers 0 for. A constant-1 implementation fails HERE and
    // nowhere else on this machine.
    let devpts = CString::new("/dev/pts").unwrap();
    let g = unsafe { pathconf(devpts.as_ptr(), libc::_PC_2_SYMLINKS) };
    if g < 0 {
        println!("/dev/pts not available -- the discriminating case was not exercised");
        return;
    }
    assert_eq!(
        g, 0,
        "host premise: glibc must report _PC_2_SYMLINKS=0 on devpts, got {g}"
    );
    let f = unsafe { fu::pathconf(devpts.as_ptr(), libc::_PC_2_SYMLINKS) };
    assert_eq!(
        f, 0,
        "fl must report _PC_2_SYMLINKS=0 on devpts -- a constant 1 fails exactly here"
    );
}

/// `_PC_LINK_MAX` across every mounted filesystem, not just /tmp.
///
/// fl derives this from `statfs.f_type` and always has — the shape was right.
/// The DATA was wrong: the table asserted PROC_SUPER_MAGIC and SYSFS_MAGIC map
/// to 1, where glibc reports its default 127. `/proc` and `/sys` are mounted on
/// every Linux box, so this was a live divergence that the one-path gate above
/// could not see because it only ever asked /tmp (tmpfs, where fl's answer
/// happened to equal the default).
///
/// A correct-shaped implementation with a wrong table is the failure mode this
/// test exists for, which is why it sweeps mounts instead of checking a value.
#[test]
fn link_max_matches_glibc_on_every_mounted_filesystem() {
    let mut dirs: Vec<String> = [
        "/",
        "/tmp",
        "/proc",
        "/sys",
        "/sys/fs/cgroup",
        "/dev",
        "/dev/shm",
        "/dev/pts",
        "/run",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    if let Ok(entries) = std::fs::read_dir("/snap") {
        for entry in entries.flatten().take(8) {
            if let Ok(revs) = std::fs::read_dir(entry.path()) {
                for rev in revs.flatten().take(2) {
                    let p = rev.path();
                    if p.is_dir()
                        && p.file_name()
                            .and_then(|n| n.to_str())
                            .is_some_and(|n| n.chars().all(|c| c.is_ascii_digit()))
                    {
                        dirs.push(p.to_string_lossy().into_owned());
                    }
                }
            }
        }
    }

    let mut compared = 0usize;
    let mut distinct = std::collections::BTreeSet::new();
    let mut divergences = Vec::new();
    for dir in &dirs {
        let Ok(path) = CString::new(dir.as_str()) else {
            continue;
        };
        let g = unsafe { pathconf(path.as_ptr(), libc::_PC_LINK_MAX) };
        if g < 0 {
            continue;
        }
        let f = unsafe { fu::pathconf(path.as_ptr(), libc::_PC_LINK_MAX) };
        compared += 1;
        distinct.insert(g);
        if f != g {
            divergences.push(format!("{dir}: fl={f} glibc={g}"));
        }
    }

    assert!(compared >= 6, "only {compared} paths comparable");
    // More than one distinct answer means the sweep actually crossed a
    // filesystem boundary that matters; a run where everything returns 127
    // would pass against a table that is entirely wrong.
    assert!(
        distinct.len() >= 2,
        "every path reported the same _PC_LINK_MAX ({distinct:?}) -- this run cannot \
         distinguish a correct table from a constant"
    );
    assert!(
        divergences.is_empty(),
        "_PC_LINK_MAX divergences vs glibc ({} of {compared}):\n  {}",
        divergences.len(),
        divergences.join("\n  ")
    );
}

/// MINIX is deliberately mounted in a private mount namespace: its `LINK_MAX`
/// value distinguishes the statfs dispatch from FrankenLibC's POSIX fallback,
/// while the namespace's teardown leaves no mount or image in the worker.
///
/// The parent starts a fresh copy of this test under `unshare --mount`; only
/// the child creates and mounts the image.  This gives the differential a live
/// glibc oracle without relying on a host's pre-existing mount layout.
#[test]
fn link_max_matches_glibc_on_loopback_minix() {
    const CHILD_ENV: &str = "FRANKENLIBC_PATHCONF_MINIX_CHILD";

    if std::env::var_os(CHILD_ENV).is_none() {
        let output = std::process::Command::new("unshare")
            .args(["--mount", "--propagation", "private"])
            .env(CHILD_ENV, "1")
            .arg(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "link_max_matches_glibc_on_loopback_minix",
                "--nocapture",
            ])
            .output()
            .expect("unshare must be available on the root oracle worker");
        assert!(
            output.status.success(),
            "private-namespace MINIX oracle failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        return;
    }

    let root =
        std::env::temp_dir().join(format!("frankenlibc-pathconf-minix-{}", std::process::id()));
    let image = root.join("minix.img");
    let mountpoint = root.join("mount");
    std::fs::create_dir_all(&mountpoint).expect("private oracle workspace");
    std::fs::File::create(&image)
        .expect("MINIX image")
        .set_len(4 * 1024 * 1024)
        .expect("size MINIX image");

    let image_path = image.to_str().expect("UTF-8 image path");
    let mut format = ["/usr/sbin/mkfs.minix", "/sbin/mkfs.minix", "mkfs.minix"]
        .into_iter()
        .find(|program| std::path::Path::new(program).is_file())
        .map(std::process::Command::new)
        .unwrap_or_else(|| {
            let mut command = std::process::Command::new("mkfs");
            command.args(["-t", "minix"]);
            command
        });
    let format = format
        .args(["-1", image_path])
        .output()
        .expect("a MINIX mkfs frontend must be available on the root oracle worker");
    assert!(
        format.status.success(),
        "MINIX mkfs failed: {}",
        String::from_utf8_lossy(&format.stderr)
    );

    let mount = std::process::Command::new("mount")
        .args([
            "-t",
            "minix",
            "-o",
            "loop",
            image_path,
            mountpoint.to_str().expect("UTF-8 mount path"),
        ])
        .output()
        .expect("mount must be available on the root oracle worker");
    assert!(
        mount.status.success(),
        "mounting private MINIX image failed: {}",
        String::from_utf8_lossy(&mount.stderr)
    );

    let path = CString::new(mountpoint.to_string_lossy().as_bytes()).expect("mount path");
    let host = unsafe { pathconf(path.as_ptr(), libc::_PC_LINK_MAX) };
    let fl = unsafe { fu::pathconf(path.as_ptr(), libc::_PC_LINK_MAX) };
    assert!(
        host >= 0,
        "host pathconf on mounted MINIX must succeed: {host}"
    );
    assert_eq!(fl, host, "MINIX _PC_LINK_MAX: fl={fl} glibc={host}");
}

/// `_PC_ASYNC_IO` is decided by the FILE TYPE, not by the filesystem and not by
/// a constant.
///
/// This test exists because a previous change put `_PC_ASYNC_IO` in this file's
/// indeterminate list, asserting it is always -1 with errno preserved — and the
/// assertion PASSED, because every path that list is driven with (`/tmp`, `.`,
/// `/proc`) is a directory, and directories really are -1. Regular files and
/// block devices are 1.
///
/// glibc's rule, from the jump-table target at pathconf+0x239:
///     (st_mode & S_IFMT) is S_IFREG or S_IFBLK -> 1, everything else -> -1
/// The `and $0xdf,%ah` in that sequence is what folds S_IFREG in alongside
/// S_IFBLK, which is why the two types share an answer.
///
/// So the cases are chosen by TYPE, and each type is asserted against the host
/// before fl, because the point is the discrimination and not the number.
#[test]
fn async_io_depends_on_file_type() {
    // (path, what it should be, why it is here)
    let cases: &[(&str, &str)] = &[
        ("/etc/hostname", "regular file"),
        ("/tmp", "directory"),
        ("/dev/null", "character device"),
        ("/dev/loop0", "block device"),
    ];

    let mut kinds = std::collections::BTreeSet::new();
    let mut compared = 0usize;
    for &(path, kind) in cases {
        let Ok(c) = CString::new(path) else { continue };
        let g = unsafe { pathconf(c.as_ptr(), libc::_PC_ASYNC_IO) };
        // A missing /dev/loop0 (containers often lack one) is not a failure;
        // it just costs the block-device half of the discrimination.
        if unsafe { libc::access(c.as_ptr(), libc::F_OK) } != 0 {
            println!("{path} ({kind}) absent -- not exercised");
            continue;
        }
        let f = unsafe { fu::pathconf(c.as_ptr(), libc::_PC_ASYNC_IO) };
        compared += 1;
        kinds.insert(g);
        assert_eq!(f, g, "_PC_ASYNC_IO on {path} ({kind}): fl={f} glibc={g}");
    }

    assert!(
        compared >= 3,
        "only {compared} of the file types were available"
    );
    // The whole point is that the answer VARIES. If every available path gave
    // the same answer, a constant would pass and this test would be theatre.
    assert!(
        kinds.len() >= 2,
        "every path reported the same _PC_ASYNC_IO ({kinds:?}) -- a constant \
         implementation would pass, so this run proves nothing"
    );
}

/// An unknown selector is rejected before glibc touches the pathname.
///
/// This is deliberately a missing pathname: a naive implementation which
/// probes the path before validating `name` returns `ENOENT`, making an unknown
/// selector indistinguishable from a valid query on a missing file.  glibc
/// instead returns `EINVAL` for the bad selector.  The host assertion comes
/// first so the test does not turn a local observation into the contract.
#[test]
fn invalid_selector_precedes_missing_path_lookup() {
    const INVALID_SELECTOR: c_int = c_int::MAX;
    let missing = CString::new("/definitely/not/a/frankenlibc/path").unwrap();

    let (host, host_errno) = unsafe {
        *libc::__errno_location() = SENTINEL_ERRNO;
        let value = pathconf(missing.as_ptr(), INVALID_SELECTOR);
        (value, *libc::__errno_location())
    };
    assert_eq!(host, -1, "host must reject an unknown pathconf selector");
    assert_eq!(
        host_errno,
        libc::EINVAL,
        "host must validate the selector before attempting the missing path"
    );

    let (fl, fl_errno) = unsafe {
        *libc::__errno_location() = SENTINEL_ERRNO;
        let value = fu::pathconf(missing.as_ptr(), INVALID_SELECTOR);
        (value, *libc::__errno_location())
    };
    assert_eq!(fl, host, "unknown selector return value");
    assert_eq!(
        fl_errno, host_errno,
        "fl must reject an unknown selector before pathname lookup; a stat-first implementation \
         incorrectly reports ENOENT here"
    );
}
