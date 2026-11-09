#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc fts oracle; controlled temp dir tree

//! Differential gates for the BSD fts tree walk (bd-966cpn). Controlled trees
//! are walked by both native FrankenLibC and live host glibc. Unsorted walks
//! compare entry sets; comparator walks compare the actual visit order.
//! Additional gates exercise the documented directory/parent lifetime,
//! application-owned fields, child lists, re-stat instructions, and cycles.
//! The public FTSENT layout is used for both implementations. No mocks.

use frankenlibc_abi::unistd_abi::{self as fl, FTSENT};
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::sync::atomic::{AtomicU64, Ordering};

const FTS_PHYSICAL: c_int = 0x0010;
static CNT: AtomicU64 = AtomicU64::new(0);
type Comparator = unsafe extern "C" fn(*const *const FTSENT, *const *const FTSENT) -> c_int;
type OpenFn =
    unsafe extern "C-unwind" fn(*const *const c_char, c_int, Option<Comparator>) -> *mut c_void;

mod g {
    use super::*;
    unsafe extern "C-unwind" {
        pub fn fts_open(
            path_argv: *const *const c_char,
            options: c_int,
            compar: Option<Comparator>,
        ) -> *mut c_void;
        pub fn fts_read(ftsp: *mut c_void) -> *mut FTSENT;
        pub fn fts_children(ftsp: *mut c_void, instr: c_int) -> *mut FTSENT;
        #[cfg(target_pointer_width = "64")]
        pub fn fts64_open(
            path_argv: *const *const c_char,
            options: c_int,
            compar: Option<Comparator>,
        ) -> *mut c_void;
        #[cfg(target_pointer_width = "64")]
        pub fn fts64_read(ftsp: *mut c_void) -> *mut FTSENT;
        #[cfg(target_pointer_width = "64")]
        pub fn fts64_children(ftsp: *mut c_void, instr: c_int) -> *mut FTSENT;
    }
    unsafe extern "C" {
        pub fn fts_set(ftsp: *mut c_void, entry: *mut FTSENT, instr: c_int) -> c_int;
        pub fn fts_close(ftsp: *mut c_void) -> c_int;
        #[cfg(target_pointer_width = "64")]
        pub fn fts64_set(ftsp: *mut c_void, entry: *mut FTSENT, instr: c_int) -> c_int;
        #[cfg(target_pointer_width = "64")]
        pub fn fts64_close(ftsp: *mut c_void) -> c_int;
    }
}

fn make_tree() -> std::path::PathBuf {
    let n = CNT.fetch_add(1, Ordering::Relaxed);
    let mut root = std::env::temp_dir();
    root.push(format!("fl-fts-{}-{}", std::process::id(), n));
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::write(root.join("a.txt"), b"a").unwrap();
    std::fs::write(root.join("b.txt"), b"bb").unwrap();
    std::fs::write(root.join("sub/c.txt"), b"ccc").unwrap();
    root
}

/// Walk via fts_read; collect (path relative to `root`, fts_info, fts_level), sorted.
fn walk(
    root: &str,
    open: OpenFn,
    read: unsafe extern "C-unwind" fn(*mut c_void) -> *mut FTSENT,
    close: unsafe extern "C" fn(*mut c_void) -> c_int,
) -> Vec<(String, u16, i16)> {
    let cpath = CString::new(root).unwrap();
    let argv = [cpath.as_ptr(), std::ptr::null()];
    let mut out = Vec::new();
    // SAFETY: argv is null-terminated and retains its C strings until close;
    // entry fields are copied before the next call can invalidate them.
    unsafe {
        let ftsp = open(argv.as_ptr(), FTS_PHYSICAL, None);
        if ftsp.is_null() {
            return out;
        }
        loop {
            let e = read(ftsp);
            if e.is_null() {
                break;
            }
            let full = CStr::from_ptr((*e).fts_path).to_string_lossy().into_owned();
            // Make relative to root so the (random) temp prefix doesn't matter.
            let rel = full
                .strip_prefix(root)
                .unwrap_or(&full)
                .trim_start_matches('/')
                .to_string();
            out.push((rel, (*e).fts_info, (*e).fts_level));
        }
        close(ftsp);
    }
    out.sort();
    out
}

#[test]
fn fts_traversal_matches_glibc() {
    let root = make_tree();
    let rs = root.to_string_lossy().into_owned();
    let g = walk(&rs, g::fts_open, g::fts_read, g::fts_close);
    let f = walk(&rs, fl::fts_open, fl::fts_read, fl::fts_close);
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(f, g, "fts traversal entry set:\n fl={f:#?}\n glibc={g:#?}");
    // sanity: glibc must visit each dir twice (D + DP) and 3 files once.
    assert!(
        g.iter().filter(|(_, info, _)| *info == 8).count() == 3,
        "expected 3 files (FTS_F)"
    );
    assert!(
        g.iter().filter(|(_, info, _)| *info == 1).count() == 2,
        "expected 2 preorder dirs (root+sub)"
    );
}

mod contracts {
    use super::*;
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    const FTS_LOGICAL: c_int = 0x0002;
    const FTS_NOCHDIR: c_int = 0x0004;
    const FTS_XDEV: c_int = 0x0040;
    const FTS_NAMEONLY: c_int = 0x0100;
    const FTS_AGAIN: c_int = 1;
    const FTS_D: u16 = 1;
    const FTS_DC: u16 = 2;
    const FTS_DP: u16 = 6;
    const FTS_F: u16 = 8;
    const MAX_VISITS: usize = 64;

    #[derive(Clone, Copy)]
    struct Api {
        name: &'static str,
        open: OpenFn,
        read: unsafe extern "C-unwind" fn(*mut c_void) -> *mut FTSENT,
        children: unsafe extern "C-unwind" fn(*mut c_void, c_int) -> *mut FTSENT,
        set: unsafe extern "C" fn(*mut c_void, *mut FTSENT, c_int) -> c_int,
        close: unsafe extern "C" fn(*mut c_void) -> c_int,
    }

    const GNU: Api = Api {
        name: "glibc",
        open: g::fts_open,
        read: g::fts_read,
        children: g::fts_children,
        set: g::fts_set,
        close: g::fts_close,
    };
    const NATIVE: Api = Api {
        name: "native",
        open: fl::fts_open,
        read: fl::fts_read,
        children: fl::fts_children,
        set: fl::fts_set,
        close: fl::fts_close,
    };

    #[cfg(target_pointer_width = "64")]
    unsafe extern "C-unwind" fn native64_open(
        paths: *const *const c_char,
        options: c_int,
        compar: Option<Comparator>,
    ) -> *mut c_void {
        type Comparator64 =
            unsafe extern "C" fn(*const *const c_void, *const *const c_void) -> c_int;
        // SAFETY: GNU FTSENT64 and FTSENT have the same layout on LP64. The
        // wrapper's opaque entry-pointer callback has the same C ABI.
        let compar = compar.map(|f| unsafe { std::mem::transmute::<Comparator, Comparator64>(f) });
        // SAFETY: the caller supplies the same live argv as the ordinary API.
        unsafe { fl::fts64_open(paths.cast::<*mut c_char>(), options, compar) }
    }

    #[cfg(target_pointer_width = "64")]
    unsafe extern "C-unwind" fn native64_read(stream: *mut c_void) -> *mut FTSENT {
        // SAFETY: stream is a live fts64 stream; its LP64 entry layout matches.
        unsafe { fl::fts64_read(stream).cast() }
    }

    #[cfg(target_pointer_width = "64")]
    unsafe extern "C-unwind" fn native64_children(
        stream: *mut c_void,
        instr: c_int,
    ) -> *mut FTSENT {
        // SAFETY: stream is a live fts64 stream; its LP64 entry layout matches.
        unsafe { fl::fts64_children(stream, instr).cast() }
    }

    #[cfg(target_pointer_width = "64")]
    unsafe extern "C" fn native64_set(
        stream: *mut c_void,
        entry: *mut FTSENT,
        instr: c_int,
    ) -> c_int {
        // SAFETY: entry belongs to this live stream and has the LP64 layout.
        unsafe { fl::fts64_set(stream, entry.cast(), instr) }
    }

    #[cfg(target_pointer_width = "64")]
    const GNU64: Api = Api {
        name: "glibc64",
        open: g::fts64_open,
        read: g::fts64_read,
        children: g::fts64_children,
        set: g::fts64_set,
        close: g::fts64_close,
    };
    #[cfg(target_pointer_width = "64")]
    const NATIVE64: Api = Api {
        name: "native64",
        open: native64_open,
        read: native64_read,
        children: native64_children,
        set: native64_set,
        close: fl::fts64_close,
    };

    struct Tree(PathBuf);

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct Stream {
        api: Api,
        raw: *mut c_void,
        _paths: Vec<CString>,
    }

    impl Stream {
        fn new(api: Api, paths: &[PathBuf], options: c_int, compar: Option<Comparator>) -> Self {
            let paths: Vec<_> = paths
                .iter()
                .map(|path| CString::new(path.as_os_str().as_bytes()).unwrap())
                .collect();
            let argv: Vec<_> = paths
                .iter()
                .map(|path| path.as_ptr())
                .chain(std::iter::once(std::ptr::null()))
                .collect();
            // SAFETY: argv is null-terminated and all C strings are retained
            // until close. NOCHDIR isolates concurrently running tests.
            let raw = unsafe { (api.open)(argv.as_ptr(), options | FTS_NOCHDIR, compar) };
            assert!(!raw.is_null(), "{} fts_open failed", api.name);
            Self {
                api,
                raw,
                _paths: paths,
            }
        }

        fn read(&self) -> *mut FTSENT {
            // SAFETY: this stream remains open until Drop.
            unsafe { (self.api.read)(self.raw) }
        }

        fn children(&self, instr: c_int) -> Vec<*mut FTSENT> {
            // SAFETY: the stream remains open, and the linked list is consumed
            // before another children/read operation can invalidate it.
            unsafe {
                let mut entry = (self.api.children)(self.raw, instr);
                let mut children = Vec::new();
                while !entry.is_null() {
                    assert!(children.len() < MAX_VISITS, "cyclic fts_children list");
                    children.push(entry);
                    entry = (*entry).fts_link;
                }
                children
            }
        }

        fn again(&self, entry: *mut FTSENT) {
            // SAFETY: tests pass the current entry from this live stream.
            assert_eq!(unsafe { (self.api.set)(self.raw, entry, FTS_AGAIN) }, 0);
        }
    }

    impl Drop for Stream {
        fn drop(&mut self) {
            // SAFETY: each successful open has exactly one matching close.
            unsafe { (self.api.close)(self.raw) };
        }
    }

    unsafe extern "C" fn reverse_name(a: *const *const FTSENT, b: *const *const FTSENT) -> c_int {
        // SAFETY: fts comparators receive valid entries with terminated names.
        unsafe {
            let a = CStr::from_ptr((**a).fts_name.as_ptr()).to_bytes();
            let b = CStr::from_ptr((**b).fts_name.as_ptr()).to_bytes();
            b.cmp(a) as c_int
        }
    }

    unsafe extern "C" fn size_then_name(a: *const *const FTSENT, b: *const *const FTSENT) -> c_int {
        // SAFETY: this comparator is only used on existing, statted entries
        // without FTS_NOSTAT or FTS_NAMEONLY. Path fields are never inspected.
        unsafe {
            let size_order = (*(**a).fts_statp).st_size.cmp(&(*(**b).fts_statp).st_size);
            if size_order.is_eq() {
                reverse_name(a, b)
            } else {
                size_order as c_int
            }
        }
    }

    fn name(entry: *mut FTSENT) -> String {
        // SAFETY: callers only inspect live entries, whose names are terminated.
        unsafe {
            CStr::from_ptr((*entry).fts_name.as_ptr())
                .to_string_lossy()
                .into_owned()
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct Visit {
        path: String,
        info: u16,
        level: i16,
    }

    fn visit(entry: *mut FTSENT, root: &Path) -> Visit {
        // SAFETY: callers pass the entry most recently returned by fts_read;
        // fts_path is copied before another call can alter the shared buffer.
        unsafe {
            let path = CStr::from_ptr((*entry).fts_path).to_string_lossy();
            Visit {
                path: path
                    .strip_prefix(root.to_str().unwrap())
                    .unwrap_or(&path)
                    .trim_start_matches('/')
                    .to_owned(),
                info: (*entry).fts_info,
                level: (*entry).fts_level,
            }
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct OrderedWalk {
        roots: Vec<String>,
        visits: Vec<Visit>,
        children: Vec<(String, Vec<String>)>,
    }

    fn ordered_walk(
        api: Api,
        root: &Path,
        compar: Comparator,
        inspect_children: bool,
    ) -> OrderedWalk {
        // Both argv order and directory creation order differ from the requested
        // sort order. Repeated file roots also exercise root-boundary handling.
        let roots = [root.join("a.txt"), root.to_owned(), root.join("b.txt")];
        let stream = Stream::new(api, &roots, FTS_PHYSICAL, Some(compar));
        let mut out = OrderedWalk {
            roots: if inspect_children {
                stream.children(0).into_iter().map(name).collect()
            } else {
                Vec::new()
            },
            visits: Vec::new(),
            children: Vec::new(),
        };
        loop {
            let entry = stream.read();
            if entry.is_null() {
                break;
            }
            assert!(
                out.visits.len() < MAX_VISITS,
                "{} walk did not end",
                api.name
            );
            let current = visit(entry, root);
            if inspect_children && current.info == FTS_D {
                out.children.push((
                    current.path.clone(),
                    stream.children(0).into_iter().map(name).collect(),
                ));
            }
            out.visits.push(current);
        }
        assert_eq!(out.visits.iter().filter(|v| v.info == FTS_F).count(), 5);
        out
    }

    fn compare_ordered_walks(native: Api, host: Api) {
        let tree = Tree(make_tree());
        for compar in [reverse_name as Comparator, size_then_name as Comparator] {
            for inspect_children in [false, true] {
                let expected = ordered_walk(host, &tree.0, compar, inspect_children);
                let actual = ordered_walk(native, &tree.0, compar, inspect_children);
                assert_eq!(
                    actual, expected,
                    "{} comparator order, children={inspect_children}",
                    native.name
                );
            }
        }
    }

    #[test]
    fn comparator_orders_roots_siblings_and_children_like_glibc() {
        compare_ordered_walks(NATIVE, GNU);
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn fts64_comparator_orders_roots_siblings_and_children_like_glibc() {
        compare_ordered_walks(NATIVE64, GNU64);
    }

    fn ancestor_lifetimes(api: Api, root: &Path) -> Vec<Visit> {
        let stream = Stream::new(api, &[root.to_owned()], FTS_PHYSICAL, Some(reverse_name));
        let mut markers = [0u8; MAX_VISITS];
        let mut ancestors: Vec<(*mut FTSENT, libc::c_long, *mut c_void)> = Vec::new();
        let mut visits = Vec::new();
        let mut sentinel = std::ptr::null_mut();
        loop {
            let entry = stream.read();
            if entry.is_null() {
                break;
            }
            assert!(visits.len() < MAX_VISITS);
            let current = visit(entry, root);
            // SAFETY: a directory entry remains live through its postorder
            // return. No file pointer or retired ancestor is dereferenced.
            unsafe {
                if current.level == 0 && current.info == FTS_D {
                    sentinel = (*entry).fts_parent;
                    assert!(!sentinel.is_null(), "{} missing root parent", api.name);
                    assert_eq!((*sentinel).fts_level, -1);
                    assert_eq!((*sentinel).fts_number, 0);
                    assert!((*sentinel).fts_pointer.is_null());
                    (*sentinel).fts_number = 919;
                    (*sentinel).fts_pointer = markers.as_mut_ptr().cast();
                }
                assert_eq!((*sentinel).fts_number, 919);
                assert_eq!((*sentinel).fts_pointer, markers.as_mut_ptr().cast());
                for &(ancestor, number, pointer) in &ancestors {
                    assert_eq!((*ancestor).fts_number, number, "{} ancestor data", api.name);
                    assert_eq!(
                        (*ancestor).fts_pointer,
                        pointer,
                        "{} ancestor data",
                        api.name
                    );
                }
                let parent_index = if current.info == FTS_DP {
                    assert_eq!(
                        ancestors.last().unwrap().0,
                        entry,
                        "{} recreated postorder entry",
                        api.name
                    );
                    ancestors.len().checked_sub(2)
                } else {
                    ancestors.len().checked_sub(1)
                };
                let parent = parent_index.map(|i| ancestors[i].0).unwrap_or(sentinel);
                assert_eq!(
                    (*entry).fts_parent,
                    parent,
                    "{} parent of {current:?}",
                    api.name
                );
                if current.info == FTS_D {
                    assert_eq!((*entry).fts_number, 0);
                    assert!((*entry).fts_pointer.is_null());
                    let number = visits.len() as libc::c_long + 1;
                    let pointer = markers.as_mut_ptr().add(visits.len() + 1).cast();
                    (*entry).fts_number = number;
                    (*entry).fts_pointer = pointer;
                    ancestors.push((entry, number, pointer));
                } else if current.info == FTS_DP {
                    ancestors.pop();
                }
            }
            visits.push(current);
        }
        assert!(ancestors.is_empty());
        assert_eq!(visits.iter().filter(|v| v.info == FTS_D).count(), 3);
        visits
    }

    #[test]
    fn ancestors_and_postorder_keep_identity_and_application_data_like_glibc() {
        let tree = Tree(make_tree());
        std::fs::create_dir(tree.0.join("sub/deep")).unwrap();
        std::fs::write(tree.0.join("sub/deep/d.txt"), b"deep").unwrap();
        let expected = ancestor_lifetimes(GNU, &tree.0);
        assert_eq!(ancestor_lifetimes(NATIVE, &tree.0), expected);
    }

    fn child_application_data(api: Api, root: &Path) -> Vec<Visit> {
        let stream = Stream::new(api, &[root.to_owned()], FTS_PHYSICAL, Some(reverse_name));
        let mut marker = 0u8;
        let pointer = (&mut marker as *mut u8).cast::<c_void>();
        let mut roots = stream.children(0);
        assert_eq!(roots.len(), 1);
        // SAFETY: the root list is live until read. Application-owned fields
        // must be carried into the corresponding traversal entries.
        unsafe {
            (*roots[0]).fts_number = 501;
            (*roots[0]).fts_pointer = pointer;
        }
        let root_entry = stream.read();
        assert_eq!(
            root_entry, roots[0],
            "{} replaced root child entry",
            api.name
        );
        // SAFETY: root_entry is the current directory and remains live below.
        unsafe {
            assert_eq!((*root_entry).fts_number, 501);
            assert_eq!((*root_entry).fts_pointer, pointer);
        }
        let children: Vec<_> = stream
            .children(0)
            .into_iter()
            .enumerate()
            .map(|(index, child)| {
                // SAFETY: no read/children call intervenes while writing these
                // live child entries. Only opaque data is stored in the pointer.
                unsafe {
                    (*child).fts_number = 601 + index as libc::c_long;
                    (*child).fts_pointer = pointer;
                }
                (name(child), child, 601 + index as libc::c_long)
            })
            .collect();
        assert_eq!(children.len(), 3);
        let mut visits = Vec::new();
        let mut checked = 0;
        loop {
            let entry = stream.read();
            if entry.is_null() {
                break;
            }
            assert!(visits.len() < MAX_VISITS);
            let current = visit(entry, root);
            if current.level == 1 {
                let current_name = name(entry);
                let (_, expected_entry, expected_number) = children
                    .iter()
                    .find(|(name, _, _)| *name == current_name)
                    .unwrap();
                assert_eq!(entry, *expected_entry, "{} replaced child entry", api.name);
                // SAFETY: the current entry is live; saved child pointers are
                // only compared, never dereferenced after their own lifetime.
                unsafe {
                    assert_eq!((*entry).fts_number, *expected_number);
                    assert_eq!((*entry).fts_pointer, pointer);
                    assert_eq!((*entry).fts_parent, root_entry);
                }
                checked += 1;
            }
            visits.push(current);
        }
        assert_eq!(checked, 4); // two files and the subdirectory's D/DP pair.
        visits
    }

    #[test]
    fn children_application_data_survives_read_like_glibc() {
        let tree = Tree(make_tree());
        let expected = child_application_data(GNU, &tree.0);
        assert_eq!(child_application_data(NATIVE, &tree.0), expected);
    }

    fn again_file(api: Api) -> (i64, i64) {
        let tree = Tree(make_tree());
        let path = tree.0.join("a.txt");
        let stream = Stream::new(api, &[path.clone()], FTS_PHYSICAL, None);
        let entry = stream.read();
        assert!(!entry.is_null());
        let mut marker = 0u8;
        let pointer = (&mut marker as *mut u8).cast::<c_void>();
        // SAFETY: entry is current; AGAIN must preserve the entry and its user
        // data while refreshing stat information after the file changes.
        let before = unsafe {
            (*entry).fts_number = 713;
            (*entry).fts_pointer = pointer;
            (*(*entry).fts_statp).st_size
        };
        std::fs::write(path, b"longer contents").unwrap();
        stream.again(entry);
        let reread = stream.read();
        assert_eq!(reread, entry, "{} AGAIN replaced current entry", api.name);
        // SAFETY: reread is the current entry from the same live stream.
        let after = unsafe {
            assert_eq!((*reread).fts_number, 713);
            assert_eq!((*reread).fts_pointer, pointer);
            assert_eq!((*reread).fts_info, FTS_F);
            (*(*reread).fts_statp).st_size
        };
        assert!(stream.read().is_null());
        assert_eq!((before, after), (1, 15));
        (before, after)
    }

    #[test]
    fn again_refreshes_stat_without_erasing_application_data_like_glibc() {
        let expected = again_file(GNU);
        assert_eq!(again_file(NATIVE), expected);
    }

    fn again_directory(api: Api, root: &Path) -> Vec<Visit> {
        let stream = Stream::new(api, &[root.to_owned()], FTS_PHYSICAL, Some(reverse_name));
        let mut root_entry: *mut FTSENT = std::ptr::null_mut();
        let mut revisited = false;
        let mut visits = Vec::new();
        loop {
            let entry = stream.read();
            if entry.is_null() {
                break;
            }
            assert!(visits.len() < MAX_VISITS);
            let current = visit(entry, root);
            if current.level == 0 {
                // SAFETY: a root directory stays live through postorder; AGAIN
                // on that current entry restarts its walk with the same data.
                unsafe {
                    if root_entry.is_null() {
                        root_entry = entry;
                        (*entry).fts_number = 811;
                    }
                    assert_eq!(entry, root_entry);
                    assert_eq!((*entry).fts_number, 811);
                }
                if current.info == FTS_DP && !revisited {
                    stream.again(entry);
                    revisited = true;
                }
            }
            visits.push(current);
        }
        assert!(revisited);
        assert_eq!(visits.len(), 14);
        assert_eq!(visits[..7], visits[7..]);
        visits
    }

    #[test]
    fn again_on_postorder_rewalks_directory_like_glibc() {
        let tree = Tree(make_tree());
        let expected = again_directory(GNU, &tree.0);
        assert_eq!(again_directory(NATIVE, &tree.0), expected);
    }

    fn nameonly_restat(api: Api) -> Vec<Visit> {
        let tree = Tree(make_tree());
        let stream = Stream::new(api, &[tree.0.clone()], FTS_PHYSICAL, Some(reverse_name));
        assert!(!stream.read().is_null());
        let names: Vec<_> = stream
            .children(FTS_NAMEONLY)
            .into_iter()
            .map(name)
            .collect();
        assert_eq!(names, ["sub", "b.txt", "a.txt"]);
        // A NAMEONLY list has no usable stat snapshot. Replacing a listed file
        // by a directory must be noticed when traversal obtains full entries.
        std::fs::remove_file(tree.0.join("b.txt")).unwrap();
        std::fs::create_dir(tree.0.join("b.txt")).unwrap();
        std::fs::write(tree.0.join("b.txt/new.txt"), b"new").unwrap();
        let mut visits = Vec::new();
        loop {
            let entry = stream.read();
            if entry.is_null() {
                break;
            }
            assert!(visits.len() < MAX_VISITS);
            visits.push(visit(entry, &tree.0));
        }
        assert!(visits.iter().any(|v| v.path == "b.txt" && v.info == FTS_D));
        assert!(
            visits
                .iter()
                .any(|v| v.path == "b.txt/new.txt" && v.info == FTS_F)
        );
        visits
    }

    #[test]
    fn nameonly_children_are_statted_before_traversal_like_glibc() {
        let expected = nameonly_restat(GNU);
        assert_eq!(nameonly_restat(NATIVE), expected);
    }

    fn logical_cycle(api: Api, root: &Path) -> Vec<Visit> {
        let stream = Stream::new(api, &[root.to_owned()], FTS_LOGICAL, Some(reverse_name));
        let root_entry = stream.read();
        assert!(!root_entry.is_null());
        let mut visits = vec![visit(root_entry, root)];
        let mut cycles = 0;
        loop {
            let entry = stream.read();
            if entry.is_null() {
                break;
            }
            assert!(
                visits.len() < MAX_VISITS,
                "{} followed an ancestor cycle",
                api.name
            );
            let current = visit(entry, root);
            if current.info == FTS_DC {
                assert_eq!(current.path, "sub/deep/up");
                // SAFETY: this cycle points to the still-active root ancestor;
                // parent and cycle fields are read only on the current entry.
                unsafe {
                    assert_eq!(
                        (*entry).fts_cycle,
                        root_entry,
                        "{} wrong cycle ancestor",
                        api.name
                    );
                    assert!(!(*entry).fts_parent.is_null());
                    assert_eq!((*(*entry).fts_parent).fts_level, 2);
                }
                cycles += 1;
            }
            visits.push(current);
        }
        assert_eq!(cycles, 1, "{} missed the directory cycle", api.name);
        assert_eq!(visits.iter().filter(|v| v.info == FTS_D).count(), 3);
        assert_eq!(visits.iter().filter(|v| v.info == FTS_DP).count(), 3);
        visits
    }

    #[test]
    fn logical_ancestor_cycle_is_bounded_and_identified_like_glibc() {
        let tree = Tree(make_tree());
        std::fs::create_dir(tree.0.join("sub/deep")).unwrap();
        std::os::unix::fs::symlink("../..", tree.0.join("sub/deep/up")).unwrap();
        let expected = logical_cycle(GNU, &tree.0);
        assert_eq!(logical_cycle(NATIVE, &tree.0), expected);
    }

    fn cross_device_walk(api: Api, root: &Path) -> Vec<Visit> {
        let stream = Stream::new(
            api,
            &[root.to_owned()],
            FTS_LOGICAL | FTS_XDEV,
            Some(reverse_name),
        );
        let mut visits = Vec::new();
        loop {
            let entry = stream.read();
            if entry.is_null() {
                break;
            }
            assert!(
                visits.len() < MAX_VISITS,
                "{} crossed a device boundary",
                api.name
            );
            visits.push(visit(entry, root));
        }
        let foreign: Vec<_> = visits
            .iter()
            .filter(|v| v.path == "external")
            .map(|v| (v.info, v.level))
            .collect();
        assert_eq!(foreign, [(FTS_D, 1), (FTS_DP, 1)]);
        assert!(!visits.iter().any(|v| v.path.starts_with("external/")));
        assert!(
            visits
                .iter()
                .any(|v| v.path == "sub/c.txt" && v.info == FTS_F)
        );
        visits
    }

    #[test]
    fn xdev_prunes_foreign_device_descendants_like_glibc() {
        use std::os::unix::fs::MetadataExt;

        let tree = Tree(make_tree());
        let root_device = std::fs::metadata(&tree.0).unwrap().dev();
        let target = [Path::new("/proc"), Path::new("/dev")]
            .into_iter()
            .find(|path| {
                let metadata = std::fs::metadata(path).expect("Linux device-boundary fixture");
                metadata.is_dir() && metadata.dev() != root_device
            });
        let Some(target) = target else {
            eprintln!("XDEV fixture skipped: /proc and /dev share the temporary tree's device");
            return;
        };
        std::os::unix::fs::symlink(target, tree.0.join("external")).unwrap();
        let expected = cross_device_walk(GNU, &tree.0);
        assert_eq!(cross_device_walk(NATIVE, &tree.0), expected);
        #[cfg(target_pointer_width = "64")]
        {
            assert_eq!(cross_device_walk(GNU64, &tree.0), expected);
            assert_eq!(cross_device_walk(NATIVE64, &tree.0), expected);
        }
    }
}
