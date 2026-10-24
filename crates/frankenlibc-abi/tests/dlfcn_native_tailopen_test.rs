//! Optimized dlopen and returned opener pointers retain the plugin search context.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
use frankenlibc_abi::dlfcn_abi as dl;
use frankenlibc_core::elf::ElfLoader;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type Open = unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void;
const SOURCE: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
__attribute__((noinline)) void *tail_open(const char *name,int flags) { return dlopen(name,flags); }
void *direct_open(void) { return (void *)dlopen; }
void *dynamic_open(const char *version) {
    return version ? dlvsym(RTLD_DEFAULT,"dlopen",version) : dlsym(RTLD_DEFAULT,"dlopen");
}
void *borrow_open(void *(*fn)(const char *,int),const char *name,int flags) {
    void *p=fn(name,flags); __asm__ __volatile__("" : "+r"(p)); return p;
}
"#;

fn build(input: &Path, output: &Path, got: bool, root: bool) {
    let mut cc = Command::new("cc");
    cc.args([
        "-shared",
        "-fPIC",
        "-nostdlib",
        "-O2",
        "-fno-builtin",
        "-U_FORTIFY_SOURCE",
        "-D_FORTIFY_SOURCE=0",
    ]);
    if got {
        cc.arg("-fno-plt");
    }
    if root {
        cc.arg("-Wl,-rpath,$ORIGIN");
    }
    let result = cc.arg(input).arg("-o").arg(output).output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let object = ElfLoader::new(0)
        .parse(&std::fs::read(output).unwrap())
        .unwrap();
    assert!(object.needed_libraries.is_empty());
    if root {
        let out = Command::new("objdump")
            .args(["-d", "--no-show-raw-insn", "--disassemble=tail_open"])
            .arg(output)
            .output()
            .unwrap();
        assert!(out.status.success());
        let code = String::from_utf8(out.stdout).unwrap();
        assert!(
            code.contains("jmp"),
            "must exercise actual sibling jump: {code}"
        );
        assert!(!code.contains("\tret"));
    }
}

struct Fixture {
    dir: PathBuf,
}
impl Fixture {
    fn new(got: bool) -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "frankenlibc-tailopen-{}-{stamp}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).unwrap();
        for (side, value) in [("left", 31), ("right", 47)] {
            let folder = dir.join(side);
            std::fs::create_dir(&folder).unwrap();
            let source = folder.join("root.c");
            std::fs::write(&source, SOURCE).unwrap();
            build(&source, &folder.join("libroot.so"), got, true);
            let child = folder.join("child.c");
            std::fs::write(
                &child,
                format!("int child_value(void) {{ return {value}; }}\n"),
            )
            .unwrap();
            build(&child, &folder.join("libchild.so"), got, false);
        }
        Self { dir }
    }
    fn root(&self, side: &str) -> Library {
        Library::open_path(&self.dir.join(side).join("libroot.so"))
    }
}
struct Library(*mut c_void);
impl Library {
    fn open_path(path: &Path) -> Self {
        let path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: terminated compiler-created path and valid flags.
        Self::take(unsafe { dl::dlopen(path.as_ptr(), libc::RTLD_NOW) })
    }
    fn take(handle: *mut c_void) -> Self {
        assert!(!handle.is_null(), "open failed");
        assert!(dl::native_dso_handle_for_tests(handle), "host fallback");
        Self(handle)
    }
    fn symbol(&self, name: &CStr) -> *mut c_void {
        // SAFETY: library retains its handle while every returned pointer is used.
        let p = unsafe { dl::dlsym(self.0, name.as_ptr()) };
        assert!(!p.is_null(), "{name:?}");
        p
    }
    fn opener(&self) -> Open {
        // SAFETY: the C function is exactly void *(const char *,int).
        unsafe { std::mem::transmute(self.symbol(c"tail_open")) }
    }
    fn value(&self) -> c_int {
        // SAFETY: child_value is the generated no-argument int function.
        let f: unsafe extern "C" fn() -> c_int =
            unsafe { std::mem::transmute(self.symbol(c"child_value")) };
        unsafe { f() }
    }
}
impl Drop for Library {
    fn drop(&mut self) {
        // SAFETY: all calls have returned before a handle is closed.
        assert_eq!(unsafe { dl::dlclose(self.0) }, 0);
    }
}
fn isolated(name: &str, body: fn()) {
    if std::env::var_os("FL_TAILOPEN_CHILD").is_some() {
        body();
        return;
    }
    for mode in ["strict", "hardened"] {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("FL_TAILOPEN_CHILD", "1")
            .env("FRANKENLIBC_MODE", mode)
            .env_remove("LD_PRELOAD")
            .spawn()
            .unwrap();
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "{name}/{mode}: {status}");
                break;
            }
            if start.elapsed() > Duration::from_secs(45) {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("{name}: timeout");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[test]
fn tail_open_uses_origin_runpath_and_preserves_one_loaded_identity() {
    isolated(
        "tail_open_uses_origin_runpath_and_preserves_one_loaded_identity",
        || {
            for got in [false, true] {
                let f = Fixture::new(got);
                let left = f.root("left");
                let right = f.root("right");
                for (root, expected) in [(&left, 31), (&right, 47)] {
                    let open = root.opener();
                    // SAFETY: exact entry signature, terminated names, retained root.
                    unsafe {
                        let child = Library::take(open(c"libchild.so".as_ptr(), libc::RTLD_NOW));
                        assert_eq!(child.value(), expected);
                        let again = Library::take(open(
                            c"$ORIGIN/libchild.so".as_ptr(),
                            libc::RTLD_NOW | libc::RTLD_NOLOAD,
                        ));
                        assert_eq!(again.0, child.0);
                        assert!(dl::dlerror().is_null());
                        assert!(open(c"definitely_missing.so".as_ptr(), libc::RTLD_NOW).is_null());
                        assert!(!dl::dlerror().is_null());
                        assert!(open(c"libchild.so".as_ptr(), 0x40000000).is_null());
                        assert!(!dl::dlerror().is_null());
                    }
                }
            }
        },
    );
}

#[test]
fn returned_openers_keep_their_origin_but_real_native_callers_override_it() {
    isolated(
        "returned_openers_keep_their_origin_but_real_native_callers_override_it",
        || {
            let f = Fixture::new(true);
            let left = f.root("left");
            let right = f.root("right");
            // SAFETY: exact compiled function signatures and retained root objects.
            unsafe {
                let direct: unsafe extern "C" fn() -> *mut c_void =
                    std::mem::transmute(left.symbol(c"direct_open"));
                let dynamic: unsafe extern "C" fn(*const c_char) -> *mut c_void =
                    std::mem::transmute(left.symbol(c"dynamic_open"));
                let p = direct();
                assert_eq!(dynamic(std::ptr::null()), p);
                assert_eq!(dynamic(c"GLIBC_2.34".as_ptr()), p);
                assert!(dynamic(c"GLIBC_PRIVATE".as_ptr()).is_null());
                assert!(!dl::dlerror().is_null());
                let open: Open = std::mem::transmute(p);
                let child = Library::take(open(c"libchild.so".as_ptr(), libc::RTLD_NOW));
                assert_eq!(child.value(), 31);
                let borrow: unsafe extern "C" fn(Open, *const c_char, c_int) -> *mut c_void =
                    std::mem::transmute(right.symbol(c"borrow_open"));
                let other = Library::take(borrow(open, c"libchild.so".as_ptr(), libc::RTLD_NOW));
                assert_eq!(other.value(), 47);
                assert_ne!(child.0, other.0);
            }
        },
    );
}

#[test]
fn concurrent_tail_opens_do_not_mix_search_paths_or_rewrite_loaded_metadata() {
    isolated(
        "concurrent_tail_opens_do_not_mix_search_paths_or_rewrite_loaded_metadata",
        || {
            let f = Fixture::new(false);
            let left = f.root("left");
            let right = f.root("right");
            // Replace the loaded root pathname with an image whose RUNPATH is wrong.
            // dlopen must use the immutable original origin, not current file bytes.
            std::fs::rename(
                f.dir.join("left/libroot.so"),
                f.dir.join("left/saved-root.so"),
            )
            .unwrap();
            let replacement = Command::new("cc")
                .args(["-shared", "-fPIC", "-nostdlib", "-O2"])
                .arg(format!("-Wl,-rpath,{}", f.dir.join("right").display()))
                .arg(f.dir.join("right/root.c"))
                .arg("-o")
                .arg(f.dir.join("left/libroot.so"))
                .output()
                .unwrap();
            assert!(
                replacement.status.success(),
                "{}",
                String::from_utf8_lossy(&replacement.stderr)
            );
            std::thread::scope(|scope| {
                for (root, expected) in [(&left, 31), (&right, 47), (&left, 31), (&right, 47)] {
                    let open = root.opener();
                    scope.spawn(move || {
                        for _ in 0..12 {
                            // SAFETY: parent retains roots; each child handle is independently owned.
                            let child = Library::take(unsafe {
                                open(c"$ORIGIN/libchild.so".as_ptr(), libc::RTLD_NOW)
                            });
                            assert_eq!(child.value(), expected);
                        }
                    });
                }
            });
            // A child opened dynamically is not owned by the caller's explicit handle.
            let child =
                Library::take(unsafe { left.opener()(c"libchild.so".as_ptr(), libc::RTLD_NOW) });
            drop(left);
            assert_eq!(child.value(), 31);
            drop(child);
        },
    );
}
