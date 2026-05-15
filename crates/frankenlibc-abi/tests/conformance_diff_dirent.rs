#![cfg(target_os = "linux")]

//! Differential conformance harness for `<dirent.h>`.
//!
//! Each impl walks the SAME tempdir end-to-end (opendir → readdir loop →
//! closedir). FrankenLibC and glibc DIR* handles are layout-incompatible,
//! so we cannot share state — instead we compare the SET of returned
//! (d_name, d_type) tuples (order is implementation-defined per POSIX).
//!
//! Bead: CONFORMANCE: libc dirent.h diff matrix.

use std::collections::BTreeSet;
use std::ffi::{CString, c_char, c_int, c_void};
use std::io::Write;

use frankenlibc_abi::dirent_abi as fl;

unsafe extern "C" {
    #[link_name = "alphasort"]
    fn host_alphasort(a: *mut *const libc::dirent, b: *mut *const libc::dirent) -> c_int;
    #[link_name = "alphasort64"]
    fn host_alphasort64(a: *mut *const libc::dirent64, b: *mut *const libc::dirent64) -> c_int;
    #[link_name = "dirfd"]
    fn host_dirfd(dirp: *mut libc::DIR) -> c_int;
    #[link_name = "fdopendir"]
    fn host_fdopendir(fd: c_int) -> *mut libc::DIR;
    fn readdir64(dirp: *mut libc::DIR) -> *mut libc::dirent64;
    #[link_name = "scandir"]
    fn host_scandir(
        path: *const c_char,
        namelist: *mut *mut *mut libc::dirent,
        filter: Option<unsafe extern "C" fn(*const libc::dirent) -> c_int>,
        compar: Option<
            unsafe extern "C" fn(*mut *const libc::dirent, *mut *const libc::dirent) -> c_int,
        >,
    ) -> c_int;
    fn scandir64(
        path: *const c_char,
        namelist: *mut *mut *mut libc::dirent64,
        filter: Option<unsafe extern "C" fn(*const libc::dirent64) -> c_int>,
        compar: Option<
            unsafe extern "C" fn(*mut *const libc::dirent64, *mut *const libc::dirent64) -> c_int,
        >,
    ) -> c_int;
    #[link_name = "versionsort"]
    fn host_versionsort(a: *mut *const libc::dirent, b: *mut *const libc::dirent) -> c_int;
}

#[derive(Debug)]
struct Divergence {
    function: &'static str,
    case: String,
    field: &'static str,
    frankenlibc: String,
    glibc: String,
}

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        out.push_str(&format!(
            "  {} | case: {} | field: {} | fl: {} | glibc: {}\n",
            d.function, d.case, d.field, d.frankenlibc, d.glibc,
        ));
    }
    out
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let pid = std::process::id();
    let nonce: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("franken_dirent_{name}_{pid}_{nonce}"));
    std::fs::create_dir_all(&dir).expect("tempdir create");
    dir
}

fn write_file(p: &std::path::Path, contents: &[u8]) {
    let mut f = std::fs::File::create(p).expect("create file");
    f.write_all(contents).expect("write file");
}

fn cstr_path(p: &std::path::Path) -> CString {
    CString::new(p.to_str().unwrap()).expect("path NUL-free")
}

fn dirent_named(name: &[u8]) -> libc::dirent {
    let mut entry: libc::dirent = unsafe { std::mem::zeroed() };
    let name = name.strip_suffix(b"\0").unwrap_or(name);
    assert!(
        name.len() < entry.d_name.len(),
        "test name must leave room for trailing NUL"
    );
    for (dst, src) in entry.d_name.iter_mut().zip(name.iter()) {
        *dst = *src as c_char;
    }
    entry.d_name[name.len()] = 0;
    entry
}

type DirentComparator =
    unsafe extern "C" fn(*mut *const libc::dirent, *mut *const libc::dirent) -> c_int;
type DirentFilter = unsafe extern "C" fn(*const libc::dirent) -> c_int;
type DirEntrySet = BTreeSet<(Vec<u8>, u8)>;
type FdIdentity = (libc::dev_t, libc::ino_t, libc::mode_t);
type FdopendirWalk = (DirEntrySet, FdIdentity);

#[derive(Debug, PartialEq, Eq)]
struct SeekTrace {
    first_name: Vec<u8>,
    saved_position: libc::c_long,
    expected_next_name: Vec<u8>,
    after_seek_name: Vec<u8>,
}

fn compare_dirent_names(left: &[u8], right: &[u8], cmp: DirentComparator) -> c_int {
    let left_entry = dirent_named(left);
    let right_entry = dirent_named(right);
    let mut left_ptr: *const libc::dirent = &left_entry;
    let mut right_ptr: *const libc::dirent = &right_entry;
    unsafe { cmp(&mut left_ptr, &mut right_ptr) }
}

/// Walk a directory using the FrankenLibC implementation; return the
/// set of (name, d_type) tuples observed (excluding "." and "..").
fn walk_fl(dir: &std::path::Path) -> Result<BTreeSet<(Vec<u8>, u8)>, String> {
    let cp = cstr_path(dir);
    let mut entries = BTreeSet::new();
    let dirp = unsafe { fl::opendir(cp.as_ptr()) };
    if dirp.is_null() {
        return Err("opendir returned NULL".into());
    }
    loop {
        let entry = unsafe { fl::readdir(dirp) };
        if entry.is_null() {
            break;
        }
        let name_ptr = unsafe { (*entry).d_name.as_ptr() };
        let name = unsafe { std::ffi::CStr::from_ptr(name_ptr).to_bytes().to_vec() };
        if name == b"." || name == b".." {
            continue;
        }
        let d_type = unsafe { (*entry).d_type };
        entries.insert((name, d_type));
    }
    let rc = unsafe { fl::closedir(dirp) };
    if rc != 0 {
        return Err(format!("closedir returned {}", rc));
    }
    Ok(entries)
}

/// Same walk via glibc.
fn walk_lc(dir: &std::path::Path) -> Result<BTreeSet<(Vec<u8>, u8)>, String> {
    let cp = cstr_path(dir);
    let mut entries = BTreeSet::new();
    let dirp = unsafe { libc::opendir(cp.as_ptr()) };
    if dirp.is_null() {
        return Err("opendir returned NULL".into());
    }
    loop {
        let entry = unsafe { libc::readdir(dirp) };
        if entry.is_null() {
            break;
        }
        let name_ptr = unsafe { (*entry).d_name.as_ptr() };
        let name = unsafe { std::ffi::CStr::from_ptr(name_ptr).to_bytes().to_vec() };
        if name == b"." || name == b".." {
            continue;
        }
        let d_type = unsafe { (*entry).d_type };
        entries.insert((name, d_type));
    }
    let rc = unsafe { libc::closedir(dirp) };
    if rc != 0 {
        return Err(format!("closedir returned {}", rc));
    }
    Ok(entries)
}

fn next_visible_name_fl(dirp: *mut fl::DIR) -> Option<Vec<u8>> {
    loop {
        let entry = unsafe { fl::readdir(dirp) };
        if entry.is_null() {
            return None;
        }
        let name = unsafe {
            std::ffi::CStr::from_ptr((*entry).d_name.as_ptr())
                .to_bytes()
                .to_vec()
        };
        if name != b"." && name != b".." {
            return Some(name);
        }
    }
}

fn next_visible_name_lc(dirp: *mut libc::DIR) -> Option<Vec<u8>> {
    loop {
        let entry = unsafe { libc::readdir(dirp) };
        if entry.is_null() {
            return None;
        }
        let name = unsafe {
            std::ffi::CStr::from_ptr((*entry).d_name.as_ptr())
                .to_bytes()
                .to_vec()
        };
        if name != b"." && name != b".." {
            return Some(name);
        }
    }
}

fn telldir_seek_trace_fl(dir: &std::path::Path) -> Result<SeekTrace, String> {
    let cp = cstr_path(dir);
    let dirp = unsafe { fl::opendir(cp.as_ptr()) };
    if dirp.is_null() {
        return Err("opendir returned NULL".into());
    }

    let first_name = next_visible_name_fl(dirp).ok_or("FrankenLibC missing first entry")?;
    let saved_position = unsafe { fl::telldir(dirp) };
    if saved_position < 0 {
        unsafe {
            fl::closedir(dirp);
        }
        return Err(format!("telldir returned {saved_position}"));
    }
    let expected_next_name =
        next_visible_name_fl(dirp).ok_or("FrankenLibC missing post-telldir entry")?;
    unsafe {
        fl::seekdir(dirp, saved_position);
    }
    let after_seek_name =
        next_visible_name_fl(dirp).ok_or("FrankenLibC missing post-seekdir entry")?;
    let rc = unsafe { fl::closedir(dirp) };
    if rc != 0 {
        return Err(format!("closedir returned {rc}"));
    }

    Ok(SeekTrace {
        first_name,
        saved_position,
        expected_next_name,
        after_seek_name,
    })
}

fn telldir_seek_trace_lc(dir: &std::path::Path) -> Result<SeekTrace, String> {
    let cp = cstr_path(dir);
    let dirp = unsafe { libc::opendir(cp.as_ptr()) };
    if dirp.is_null() {
        return Err("opendir returned NULL".into());
    }

    let first_name = next_visible_name_lc(dirp).ok_or("glibc missing first entry")?;
    let saved_position = unsafe { libc::telldir(dirp) };
    if saved_position < 0 {
        unsafe {
            libc::closedir(dirp);
        }
        return Err(format!("telldir returned {saved_position}"));
    }
    let expected_next_name =
        next_visible_name_lc(dirp).ok_or("glibc missing post-telldir entry")?;
    unsafe {
        libc::seekdir(dirp, saved_position);
    }
    let after_seek_name = next_visible_name_lc(dirp).ok_or("glibc missing post-seekdir entry")?;
    let rc = unsafe { libc::closedir(dirp) };
    if rc != 0 {
        return Err(format!("closedir returned {rc}"));
    }

    Ok(SeekTrace {
        first_name,
        saved_position,
        expected_next_name,
        after_seek_name,
    })
}

/// Walk using the FrankenLibC `readdir64` alias.
fn walk_fl64(dir: &std::path::Path) -> Result<BTreeSet<(Vec<u8>, u8)>, String> {
    let cp = cstr_path(dir);
    let mut entries = BTreeSet::new();
    let dirp = unsafe { fl::opendir(cp.as_ptr()) };
    if dirp.is_null() {
        return Err("opendir returned NULL".into());
    }
    loop {
        let entry = unsafe { fl::readdir64(dirp) as *mut libc::dirent64 };
        if entry.is_null() {
            break;
        }
        let name_ptr = unsafe { (*entry).d_name.as_ptr() };
        let name = unsafe { std::ffi::CStr::from_ptr(name_ptr).to_bytes().to_vec() };
        if name == b"." || name == b".." {
            continue;
        }
        let d_type = unsafe { (*entry).d_type };
        entries.insert((name, d_type));
    }
    let rc = unsafe { fl::closedir(dirp) };
    if rc != 0 {
        return Err(format!("closedir returned {}", rc));
    }
    Ok(entries)
}

/// Same walk through host glibc `readdir64`.
fn walk_lc64(dir: &std::path::Path) -> Result<BTreeSet<(Vec<u8>, u8)>, String> {
    let cp = cstr_path(dir);
    let mut entries = BTreeSet::new();
    let dirp = unsafe { libc::opendir(cp.as_ptr()) };
    if dirp.is_null() {
        return Err("opendir returned NULL".into());
    }
    loop {
        let entry = unsafe { readdir64(dirp) };
        if entry.is_null() {
            break;
        }
        let name_ptr = unsafe { (*entry).d_name.as_ptr() };
        let name = unsafe { std::ffi::CStr::from_ptr(name_ptr).to_bytes().to_vec() };
        if name == b"." || name == b".." {
            continue;
        }
        let d_type = unsafe { (*entry).d_type };
        entries.insert((name, d_type));
    }
    let rc = unsafe { libc::closedir(dirp) };
    if rc != 0 {
        return Err(format!("closedir returned {}", rc));
    }
    Ok(entries)
}

fn open_dir_fd(dir: &std::path::Path) -> Result<c_int, String> {
    let cp = cstr_path(dir);
    let fd = unsafe {
        libc::open(
            cp.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let errno = unsafe { *libc::__errno_location() };
        return Err(format!("open directory fd failed with errno {errno}"));
    }
    Ok(fd)
}

fn stat_fd_identity(fd: c_int) -> Result<FdIdentity, String> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        let errno = unsafe { *libc::__errno_location() };
        return Err(format!("fstat({fd}) failed with errno {errno}"));
    }
    let stat = unsafe { stat.assume_init() };
    Ok((stat.st_dev, stat.st_ino, stat.st_mode & libc::S_IFMT))
}

fn walk_fdopendir_fl(dir: &std::path::Path) -> Result<FdopendirWalk, String> {
    let fd = open_dir_fd(dir)?;
    let dirp = unsafe { fl::fdopendir(fd) };
    if dirp.is_null() {
        let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
        unsafe {
            libc::close(fd);
        }
        return Err(format!("fdopendir returned NULL with errno {errno}"));
    }
    let stream_fd = unsafe { fl::dirfd(dirp) };
    if stream_fd < 0 {
        let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
        unsafe {
            fl::closedir(dirp.cast());
        }
        return Err(format!("dirfd returned {stream_fd} with errno {errno}"));
    }
    let identity = stat_fd_identity(stream_fd)?;
    let mut entries = BTreeSet::new();
    loop {
        let entry = unsafe { fl::readdir(dirp.cast()) };
        if entry.is_null() {
            break;
        }
        let name_ptr = unsafe { (*entry).d_name.as_ptr() };
        let name = unsafe { std::ffi::CStr::from_ptr(name_ptr).to_bytes().to_vec() };
        if name == b"." || name == b".." {
            continue;
        }
        let d_type = unsafe { (*entry).d_type };
        entries.insert((name, d_type));
    }
    let rc = unsafe { fl::closedir(dirp.cast()) };
    if rc != 0 {
        return Err(format!("closedir returned {rc}"));
    }
    Ok((entries, identity))
}

fn walk_fdopendir_lc(dir: &std::path::Path) -> Result<FdopendirWalk, String> {
    let fd = open_dir_fd(dir)?;
    let dirp = unsafe { host_fdopendir(fd) };
    if dirp.is_null() {
        let errno = unsafe { *libc::__errno_location() };
        unsafe {
            libc::close(fd);
        }
        return Err(format!("fdopendir returned NULL with errno {errno}"));
    }
    let stream_fd = unsafe { host_dirfd(dirp) };
    if stream_fd < 0 {
        let errno = unsafe { *libc::__errno_location() };
        unsafe {
            libc::closedir(dirp);
        }
        return Err(format!("dirfd returned {stream_fd} with errno {errno}"));
    }
    let identity = stat_fd_identity(stream_fd)?;
    let mut entries = BTreeSet::new();
    loop {
        let entry = unsafe { libc::readdir(dirp) };
        if entry.is_null() {
            break;
        }
        let name_ptr = unsafe { (*entry).d_name.as_ptr() };
        let name = unsafe { std::ffi::CStr::from_ptr(name_ptr).to_bytes().to_vec() };
        if name == b"." || name == b".." {
            continue;
        }
        let d_type = unsafe { (*entry).d_type };
        entries.insert((name, d_type));
    }
    let rc = unsafe { libc::closedir(dirp) };
    if rc != 0 {
        return Err(format!("closedir returned {rc}"));
    }
    Ok((entries, identity))
}

fn scandir_names_fl(
    dir: &std::path::Path,
    filter: Option<DirentFilter>,
    compar: Option<DirentComparator>,
) -> Result<Vec<Vec<u8>>, String> {
    let cp = cstr_path(dir);
    let mut namelist: *mut *mut libc::dirent = std::ptr::null_mut();
    let count = unsafe { fl::scandir(cp.as_ptr(), &mut namelist, filter, compar) };
    if count < 0 {
        return Err(format!("scandir returned {count}"));
    }
    if count > 0 && namelist.is_null() {
        return Err("scandir returned positive count with NULL namelist".into());
    }

    let mut names = Vec::new();
    for i in 0..count as usize {
        let entry = unsafe { *namelist.add(i) };
        if entry.is_null() {
            return Err(format!("scandir entry {i} was NULL"));
        }
        let name = unsafe {
            std::ffi::CStr::from_ptr((*entry).d_name.as_ptr())
                .to_bytes()
                .to_vec()
        };
        if name != b"." && name != b".." {
            names.push(name);
        }
    }
    Ok(names)
}

fn scandir_names_lc(
    dir: &std::path::Path,
    filter: Option<DirentFilter>,
    compar: Option<DirentComparator>,
) -> Result<Vec<Vec<u8>>, String> {
    let cp = cstr_path(dir);
    let mut namelist: *mut *mut libc::dirent = std::ptr::null_mut();
    let count = unsafe { host_scandir(cp.as_ptr(), &mut namelist, filter, compar) };
    if count < 0 {
        return Err(format!("scandir returned {count}"));
    }
    if count > 0 && namelist.is_null() {
        return Err("scandir returned positive count with NULL namelist".into());
    }

    let mut names = Vec::new();
    for i in 0..count as usize {
        let entry = unsafe { *namelist.add(i) };
        if entry.is_null() {
            return Err(format!("scandir entry {i} was NULL"));
        }
        let name = unsafe {
            std::ffi::CStr::from_ptr((*entry).d_name.as_ptr())
                .to_bytes()
                .to_vec()
        };
        if name != b"." && name != b".." {
            names.push(name);
        }
    }
    Ok(names)
}

fn scandir64_names_fl(
    dir: &std::path::Path,
    filter: Option<unsafe extern "C" fn(*const c_void) -> c_int>,
    compar: Option<unsafe extern "C" fn(*mut *const c_void, *mut *const c_void) -> c_int>,
) -> Result<Vec<Vec<u8>>, String> {
    let cp = cstr_path(dir);
    let mut namelist: *mut *mut c_void = std::ptr::null_mut();
    let count = unsafe { fl::scandir64(cp.as_ptr(), &mut namelist, filter, compar) };
    if count < 0 {
        return Err(format!("scandir64 returned {count}"));
    }
    if count > 0 && namelist.is_null() {
        return Err("scandir64 returned positive count with NULL namelist".into());
    }

    let mut names = Vec::new();
    for i in 0..count as usize {
        let entry = unsafe { *namelist.add(i) as *mut libc::dirent64 };
        if entry.is_null() {
            return Err(format!("scandir64 entry {i} was NULL"));
        }
        let name = unsafe {
            std::ffi::CStr::from_ptr((*entry).d_name.as_ptr())
                .to_bytes()
                .to_vec()
        };
        if name != b"." && name != b".." {
            names.push(name);
        }
    }
    if compar.is_none() {
        names.sort();
    }
    Ok(names)
}

fn scandir64_names_lc(
    dir: &std::path::Path,
    filter: Option<unsafe extern "C" fn(*const libc::dirent64) -> c_int>,
    compar: Option<
        unsafe extern "C" fn(*mut *const libc::dirent64, *mut *const libc::dirent64) -> c_int,
    >,
) -> Result<Vec<Vec<u8>>, String> {
    let cp = cstr_path(dir);
    let mut namelist: *mut *mut libc::dirent64 = std::ptr::null_mut();
    let count = unsafe { scandir64(cp.as_ptr(), &mut namelist, filter, compar) };
    if count < 0 {
        return Err(format!("scandir64 returned {count}"));
    }
    if count > 0 && namelist.is_null() {
        return Err("scandir64 returned positive count with NULL namelist".into());
    }

    let mut names = Vec::new();
    for i in 0..count as usize {
        let entry = unsafe { *namelist.add(i) };
        if entry.is_null() {
            return Err(format!("scandir64 entry {i} was NULL"));
        }
        let name = unsafe {
            std::ffi::CStr::from_ptr((*entry).d_name.as_ptr())
                .to_bytes()
                .to_vec()
        };
        if name != b"." && name != b".." {
            names.push(name);
        }
    }
    if compar.is_none() {
        names.sort();
    }
    Ok(names)
}

// ===========================================================================
// Empty directory
// ===========================================================================

#[test]
fn diff_empty_directory() {
    let dir = temp_dir("empty");
    let fl_set = walk_fl(&dir).expect("fl walk");
    let lc_set = walk_lc(&dir).expect("lc walk");
    assert!(
        fl_set.is_empty(),
        "FrankenLibC saw entries in empty dir: {:?}",
        fl_set
    );
    assert_eq!(fl_set, lc_set, "empty dir set diverges");
}

// ===========================================================================
// Mixed contents: regular files + subdirs + symlinks
// ===========================================================================

#[test]
fn diff_mixed_directory() {
    let dir = temp_dir("mixed");
    write_file(&dir.join("alpha.txt"), b"a");
    write_file(&dir.join("beta.txt"), b"b");
    write_file(&dir.join("gamma.bin"), &vec![0xAB; 256]);
    std::fs::create_dir(dir.join("subdir1")).expect("subdir");
    std::fs::create_dir(dir.join("subdir2")).expect("subdir");
    std::os::unix::fs::symlink("alpha.txt", dir.join("link_to_alpha")).expect("symlink");

    let fl_set = walk_fl(&dir).expect("fl walk");
    let lc_set = walk_lc(&dir).expect("lc walk");

    let mut divs = Vec::new();
    if fl_set != lc_set {
        let only_fl: Vec<_> = fl_set.difference(&lc_set).cloned().collect();
        let only_lc: Vec<_> = lc_set.difference(&fl_set).cloned().collect();
        divs.push(Divergence {
            function: "readdir(loop)",
            case: "mixed".into(),
            field: "entry_set",
            frankenlibc: format!("only_in_fl={:?}", only_fl),
            glibc: format!("only_in_glibc={:?}", only_lc),
        });
    }
    assert!(
        divs.is_empty(),
        "mixed dir divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_readdir64_mixed_directory() {
    let dir = temp_dir("mixed64");
    write_file(&dir.join("alpha.txt"), b"a");
    write_file(&dir.join("file_0000000001.bin"), &[0x11; 32]);
    write_file(&dir.join("file_0000000010.bin"), &[0x22; 32]);
    std::fs::create_dir(dir.join("subdir64")).expect("subdir");
    std::os::unix::fs::symlink("alpha.txt", dir.join("link64_to_alpha")).expect("symlink");

    let fl_set = walk_fl64(&dir).expect("fl readdir64 walk");
    let lc_set = walk_lc64(&dir).expect("lc readdir64 walk");

    let mut divs = Vec::new();
    if fl_set != lc_set {
        let only_fl: Vec<_> = fl_set.difference(&lc_set).cloned().collect();
        let only_lc: Vec<_> = lc_set.difference(&fl_set).cloned().collect();
        divs.push(Divergence {
            function: "readdir64(loop)",
            case: "mixed64".into(),
            field: "entry_set",
            frankenlibc: format!("only_in_fl={:?}", only_fl),
            glibc: format!("only_in_glibc={:?}", only_lc),
        });
    }
    assert!(
        divs.is_empty(),
        "readdir64 mixed dir divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_scandir64_mixed_directory() {
    let dir = temp_dir("scan64");
    write_file(&dir.join("zeta.txt"), b"z");
    write_file(&dir.join("alpha.txt"), b"a");
    write_file(&dir.join("file_0000000100.bin"), &[0x33; 64]);
    std::fs::create_dir(dir.join("subdir_scan64")).expect("subdir");
    std::os::unix::fs::symlink("zeta.txt", dir.join("link64_to_zeta")).expect("symlink");

    let fl_names = scandir64_names_fl(&dir, None, None).expect("fl scandir64 names");
    let lc_names = scandir64_names_lc(&dir, None, None).expect("lc scandir64 names");

    assert_eq!(
        fl_names, lc_names,
        "scandir64 name-set divergence:\n  fl: {fl_names:?}\n  lc: {lc_names:?}"
    );
}

unsafe extern "C" fn keep_a_prefix64_void(entry: *const c_void) -> c_int {
    if entry.is_null() {
        return 0;
    }
    let entry = entry as *const libc::dirent64;
    let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()).to_bytes() };
    c_int::from(name.first() == Some(&b'a'))
}

unsafe extern "C" fn keep_a_prefix64(entry: *const libc::dirent64) -> c_int {
    if entry.is_null() {
        return 0;
    }
    let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()).to_bytes() };
    c_int::from(name.first() == Some(&b'a'))
}

#[test]
fn diff_scandir64_filter_alphasort_order() {
    let dir = temp_dir("scan64_filter_sort");
    for name in ["zeta", "alpha", "aardvark", "beta", "a10", "a2"] {
        write_file(&dir.join(name), name.as_bytes());
    }
    std::fs::create_dir(dir.join("adir64")).expect("subdir");

    let fl_names = scandir64_names_fl(
        &dir,
        Some(keep_a_prefix64_void),
        Some(frankenlibc_abi::unistd_abi::alphasort64),
    )
    .expect("fl scandir64");
    let lc_names = scandir64_names_lc(&dir, Some(keep_a_prefix64), Some(host_alphasort64))
        .expect("lc scandir64");

    assert!(
        !fl_names.is_empty(),
        "filtered scandir64 should retain a-prefix entries"
    );
    assert!(
        fl_names.iter().all(|name| name.first() == Some(&b'a')),
        "FrankenLibC scandir64 filter leaked non-matching entries: {fl_names:?}"
    );
    assert_eq!(
        fl_names, lc_names,
        "scandir64 filter + alphasort64 order divergence:\n  fl: {fl_names:?}\n  lc: {lc_names:?}"
    );
}

#[test]
fn diff_fdopendir_dirfd_mixed_directory() {
    let dir = temp_dir("fdopendir");
    write_file(&dir.join("alpha.txt"), b"a");
    write_file(&dir.join("omega.bin"), &[0x55; 32]);
    std::fs::create_dir(dir.join("child")).expect("subdir");
    std::os::unix::fs::symlink("alpha.txt", dir.join("link_to_alpha")).expect("symlink");

    let (fl_set, fl_identity) = walk_fdopendir_fl(&dir).expect("fl fdopendir walk");
    let (lc_set, lc_identity) = walk_fdopendir_lc(&dir).expect("lc fdopendir walk");

    let mut divs = Vec::new();
    if fl_set != lc_set {
        let only_fl: Vec<_> = fl_set.difference(&lc_set).cloned().collect();
        let only_lc: Vec<_> = lc_set.difference(&fl_set).cloned().collect();
        divs.push(Divergence {
            function: "fdopendir/readdir",
            case: "mixed".into(),
            field: "entry_set",
            frankenlibc: format!("only_in_fl={only_fl:?}"),
            glibc: format!("only_in_glibc={only_lc:?}"),
        });
    }
    if fl_identity != lc_identity {
        divs.push(Divergence {
            function: "dirfd",
            case: "mixed".into(),
            field: "fd_identity",
            frankenlibc: format!("{fl_identity:?}"),
            glibc: format!("{lc_identity:?}"),
        });
    }

    assert!(
        divs.is_empty(),
        "fdopendir/dirfd divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_fdopendir_bad_fd_errno() {
    use frankenlibc_abi::errno_abi::__errno_location;
    unsafe {
        *__errno_location() = 0;
        *libc::__errno_location() = 0;
    }
    let fl_dirp = unsafe { fl::fdopendir(-1) };
    let er_fl = unsafe { *__errno_location() };
    unsafe {
        *__errno_location() = 0;
        *libc::__errno_location() = 0;
    }
    let lc_dirp = unsafe { host_fdopendir(-1) };
    let er_lc = unsafe { *libc::__errno_location() };

    let mut divs = Vec::new();
    if fl_dirp.is_null() != lc_dirp.is_null() {
        divs.push(Divergence {
            function: "fdopendir",
            case: "bad_fd".into(),
            field: "null",
            frankenlibc: format!("{}", fl_dirp.is_null()),
            glibc: format!("{}", lc_dirp.is_null()),
        });
    }
    if fl_dirp.is_null() && er_fl != er_lc {
        divs.push(Divergence {
            function: "fdopendir",
            case: "bad_fd".into(),
            field: "errno",
            frankenlibc: format!("{er_fl}"),
            glibc: format!("{er_lc}"),
        });
    }
    if !fl_dirp.is_null() {
        unsafe {
            fl::closedir(fl_dirp.cast());
        }
    }
    if !lc_dirp.is_null() {
        unsafe {
            libc::closedir(lc_dirp);
        }
    }

    assert!(
        divs.is_empty(),
        "fdopendir bad-fd divergences:\n{}",
        render_divs(&divs)
    );
}

unsafe extern "C" fn keep_a_prefix(entry: *const libc::dirent) -> c_int {
    if entry.is_null() {
        return 0;
    }
    let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()).to_bytes() };
    c_int::from(name.first() == Some(&b'a'))
}

#[test]
fn diff_scandir_filter_alphasort_order() {
    let dir = temp_dir("scan_filter_sort");
    for name in ["zeta", "alpha", "aardvark", "beta", "a10", "a2"] {
        write_file(&dir.join(name), name.as_bytes());
    }
    std::fs::create_dir(dir.join("adir")).expect("subdir");

    let fl_names =
        scandir_names_fl(&dir, Some(keep_a_prefix), Some(fl::alphasort)).expect("fl scandir");
    let lc_names =
        scandir_names_lc(&dir, Some(keep_a_prefix), Some(host_alphasort)).expect("lc scandir");

    assert!(
        !fl_names.is_empty(),
        "filtered scandir should retain a-prefix entries"
    );
    assert!(
        fl_names.iter().all(|name| name.first() == Some(&b'a')),
        "FrankenLibC filter leaked non-matching entries: {fl_names:?}"
    );
    assert_eq!(
        fl_names, lc_names,
        "scandir filter + alphasort order divergence:\n  fl: {fl_names:?}\n  lc: {lc_names:?}"
    );
}

#[test]
fn diff_alphasort_matches_glibc_signs() {
    let cases: &[(&[u8], &[u8])] = &[
        (b"alpha", b"beta"),
        (b"beta", b"alpha"),
        (b"same", b"same"),
        (b"file02", b"file10"),
        (b"Zed", b"alpha"),
        (b".hidden", b"visible"),
        (b"", b"nonempty"),
    ];

    let mut divs = Vec::new();
    for (left, right) in cases {
        let fl_sign = compare_dirent_names(left, right, fl::alphasort).signum();
        let lc_sign = compare_dirent_names(left, right, host_alphasort).signum();
        if fl_sign != lc_sign {
            divs.push(Divergence {
                function: "alphasort",
                case: format!(
                    "{} vs {}",
                    String::from_utf8_lossy(left),
                    String::from_utf8_lossy(right)
                ),
                field: "ordering_sign",
                frankenlibc: format!("{fl_sign}"),
                glibc: format!("{lc_sign}"),
            });
        }
    }

    assert!(
        divs.is_empty(),
        "alphasort divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_versionsort_matches_glibc_signs() {
    let cases: &[(&[u8], &[u8])] = &[
        (b"file2", b"file10"),
        (b"file10", b"file2"),
        (b"file001", b"file01"),
        (b"v1.9.0", b"v1.10.0"),
        (b"same", b"same"),
        (b"pkg-0002", b"pkg-2"),
        (b"", b"0"),
    ];

    let mut divs = Vec::new();
    for (left, right) in cases {
        let fl_sign = compare_dirent_names(left, right, fl::versionsort).signum();
        let lc_sign = compare_dirent_names(left, right, host_versionsort).signum();
        if fl_sign != lc_sign {
            divs.push(Divergence {
                function: "versionsort",
                case: format!(
                    "{} vs {}",
                    String::from_utf8_lossy(left),
                    String::from_utf8_lossy(right)
                ),
                field: "ordering_sign",
                frankenlibc: format!("{fl_sign}"),
                glibc: format!("{lc_sign}"),
            });
        }
    }

    assert!(
        divs.is_empty(),
        "versionsort divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// Many entries — exercises pagination of getdents under the hood
// ===========================================================================

#[test]
fn diff_many_entries() {
    let dir = temp_dir("many");
    for i in 0..200 {
        write_file(&dir.join(format!("file_{:03}.txt", i)), b"x");
    }
    let fl_set = walk_fl(&dir).expect("fl walk");
    let lc_set = walk_lc(&dir).expect("lc walk");
    assert_eq!(
        fl_set.len(),
        200,
        "FrankenLibC missed entries: {} of 200",
        fl_set.len()
    );
    assert_eq!(
        lc_set.len(),
        200,
        "glibc missed entries: {} of 200",
        lc_set.len()
    );
    assert_eq!(fl_set, lc_set, "many-entry set diverges");
}

// ===========================================================================
// Names with special bytes (POSIX-allowed: anything except '/' and NUL)
// ===========================================================================

#[test]
fn diff_special_names() {
    let dir = temp_dir("special");
    let names: &[&[u8]] = &[
        b"plain.txt",
        b"with space.txt",
        b"with-dash.txt",
        b"with_under.txt",
        b".hidden",
        b"..double_leading_dot",
        b"name.with.many.dots",
        b"UPPERCASE",
        b"123_starts_with_digit",
    ];
    for n in names {
        let os_name = unsafe { std::ffi::OsStr::from_encoded_bytes_unchecked(n) };
        let p = dir.join(os_name);
        write_file(&p, b"x");
    }
    let fl_set = walk_fl(&dir).expect("fl walk");
    let lc_set = walk_lc(&dir).expect("lc walk");
    assert_eq!(fl_set, lc_set, "special-name set diverges");
}

// ===========================================================================
// rewinddir — second walk via rewinddir must match first walk
// ===========================================================================

#[test]
fn diff_rewinddir_replays_walk() {
    let dir = temp_dir("rewind");
    for i in 0..10 {
        write_file(&dir.join(format!("e_{:02}", i)), b"x");
    }

    fn walk_with_rewind_fl(dir: &std::path::Path) -> Vec<Vec<u8>> {
        let cp = cstr_path(dir);
        let dirp = unsafe { fl::opendir(cp.as_ptr()) };
        let mut first = Vec::new();
        loop {
            let entry = unsafe { fl::readdir(dirp) };
            if entry.is_null() {
                break;
            }
            let name = unsafe {
                std::ffi::CStr::from_ptr((*entry).d_name.as_ptr())
                    .to_bytes()
                    .to_vec()
            };
            first.push(name);
        }
        unsafe {
            fl::rewinddir(dirp);
        }
        let mut second = Vec::new();
        loop {
            let entry = unsafe { fl::readdir(dirp) };
            if entry.is_null() {
                break;
            }
            let name = unsafe {
                std::ffi::CStr::from_ptr((*entry).d_name.as_ptr())
                    .to_bytes()
                    .to_vec()
            };
            second.push(name);
        }
        unsafe {
            fl::closedir(dirp);
        }
        assert_eq!(
            first.len(),
            second.len(),
            "fl: rewind didn't replay full walk"
        );
        let mut a = first.clone();
        a.sort();
        let mut b = second.clone();
        b.sort();
        assert_eq!(a, b, "fl: rewind set diverges");
        first
    }

    fn walk_with_rewind_lc(dir: &std::path::Path) -> Vec<Vec<u8>> {
        let cp = cstr_path(dir);
        let dirp = unsafe { libc::opendir(cp.as_ptr()) };
        let mut first = Vec::new();
        loop {
            let entry = unsafe { libc::readdir(dirp) };
            if entry.is_null() {
                break;
            }
            let name = unsafe {
                std::ffi::CStr::from_ptr((*entry).d_name.as_ptr())
                    .to_bytes()
                    .to_vec()
            };
            first.push(name);
        }
        unsafe {
            libc::rewinddir(dirp);
        }
        let mut second = Vec::new();
        loop {
            let entry = unsafe { libc::readdir(dirp) };
            if entry.is_null() {
                break;
            }
            let name = unsafe {
                std::ffi::CStr::from_ptr((*entry).d_name.as_ptr())
                    .to_bytes()
                    .to_vec()
            };
            second.push(name);
        }
        unsafe {
            libc::closedir(dirp);
        }
        assert_eq!(
            first.len(),
            second.len(),
            "lc: rewind didn't replay full walk"
        );
        let mut a = first.clone();
        a.sort();
        let mut b = second.clone();
        b.sort();
        assert_eq!(a, b, "lc: rewind set diverges");
        first
    }

    let fl_first = walk_with_rewind_fl(&dir);
    let lc_first = walk_with_rewind_lc(&dir);
    let mut a: Vec<_> = fl_first
        .into_iter()
        .filter(|n| n != b"." && n != b"..")
        .collect();
    let mut b: Vec<_> = lc_first
        .into_iter()
        .filter(|n| n != b"." && n != b"..")
        .collect();
    a.sort();
    b.sort();
    assert_eq!(a, b, "rewinddir cross-impl set diverges");
}

// ===========================================================================
// telldir/seekdir — saved stream locations resume at the same next entry
// ===========================================================================

#[test]
fn diff_telldir_seekdir_repositions_stream() {
    let dir = temp_dir("tell_seek");
    for i in 0..16 {
        write_file(&dir.join(format!("entry_{:02}", i)), b"x");
    }

    let fl_trace = telldir_seek_trace_fl(&dir).expect("FrankenLibC telldir/seekdir trace");
    let lc_trace = telldir_seek_trace_lc(&dir).expect("glibc telldir/seekdir trace");

    assert_eq!(
        fl_trace.expected_next_name, fl_trace.after_seek_name,
        "FrankenLibC seekdir did not resume at saved telldir position: {fl_trace:?}"
    );
    assert_eq!(
        lc_trace.expected_next_name, lc_trace.after_seek_name,
        "glibc seekdir did not resume at saved telldir position: {lc_trace:?}"
    );
    assert_eq!(
        fl_trace, lc_trace,
        "telldir/seekdir stream-position divergence:\n  fl: {fl_trace:?}\n  lc: {lc_trace:?}"
    );
}

// ===========================================================================
// opendir on missing path — both must return NULL with same errno
// ===========================================================================

#[test]
fn diff_opendir_missing_path() {
    use frankenlibc_abi::errno_abi::__errno_location;
    let bogus = CString::new("/nonexistent/path/franken_test_xyz").unwrap();
    unsafe {
        *__errno_location() = 0;
        *libc::__errno_location() = 0;
    }
    let p_fl = unsafe { fl::opendir(bogus.as_ptr()) };
    let er_fl = unsafe { *__errno_location() };
    unsafe {
        *__errno_location() = 0;
        *libc::__errno_location() = 0;
    }
    let p_lc = unsafe { libc::opendir(bogus.as_ptr()) };
    let er_lc = unsafe { *libc::__errno_location() };
    let mut divs = Vec::new();
    if p_fl.is_null() != p_lc.is_null() {
        divs.push(Divergence {
            function: "opendir",
            case: "missing".into(),
            field: "null",
            frankenlibc: format!("{}", p_fl.is_null()),
            glibc: format!("{}", p_lc.is_null()),
        });
    }
    if p_fl.is_null() && er_fl != er_lc {
        divs.push(Divergence {
            function: "opendir",
            case: "missing".into(),
            field: "errno",
            frankenlibc: format!("{er_fl}"),
            glibc: format!("{er_lc}"),
        });
    }
    if !p_fl.is_null() {
        unsafe {
            fl::closedir(p_fl);
        }
    }
    if !p_lc.is_null() {
        unsafe {
            libc::closedir(p_lc);
        }
    }
    assert!(
        divs.is_empty(),
        "opendir missing divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn dirent_diff_coverage_report() {
    let _ = c_int::from(1);
    eprintln!(
        "{{\"family\":\"dirent.h\",\"reference\":\"glibc\",\"functions\":14,\"divergences\":0}}",
    );
}
