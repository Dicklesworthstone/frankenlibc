#![cfg(all(target_os = "linux", target_env = "gnu", target_pointer_width = "64"))]

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

use frankenlibc_abi::{locale_abi, string_abi, unistd_abi};
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;

type Glob = unsafe extern "C" fn(
    *const c_char,
    c_int,
    Option<unsafe extern "C" fn(*const c_char, c_int) -> c_int>,
    *mut c_void,
) -> c_int;
type GlobFree = unsafe extern "C" fn(*mut c_void);

fn expand(glob: Glob, free: GlobFree, pattern: &CStr, flags: i32) -> (i32, Vec<Vec<u8>>) {
    let mut g: libc::glob_t = unsafe { std::mem::zeroed() };
    let ptr = (&raw mut g).cast();
    let rc = unsafe { glob(pattern.as_ptr(), flags, None, ptr) };
    let paths = (0..g.gl_pathc)
        .map(|i| unsafe { CStr::from_ptr(*g.gl_pathv.add(i)).to_bytes().to_vec() })
        .collect();
    unsafe { free(ptr) };
    (rc, paths)
}

#[test]
fn glob_matches_and_orders_paths_in_the_selected_locale() {
    // This integration binary owns its process locale. Neither provider's
    // result may be re-sorted before comparison.
    let providers = [
        (
            c"glob",
            c"globfree",
            string_abi::glob as Glob,
            string_abi::globfree as GlobFree,
        ),
        (
            c"glob64",
            c"globfree64",
            unistd_abi::glob64 as Glob,
            unistd_abi::globfree64 as GlobFree,
        ),
    ]
    .map(|(name, free_name, candidate, free)| {
        let host: Glob = unsafe { dlsym_oracle::host_fn(name, candidate as *const ()) };
        let host_free: GlobFree = unsafe { dlsym_oracle::host_fn(free_name, free as *const ()) };
        (name, candidate, free, host, host_free)
    });
    let host_setlocale: unsafe extern "C" fn(c_int, *const c_char) -> *mut c_char =
        unsafe { dlsym_oracle::host_fn(c"setlocale", locale_abi::setlocale as *const ()) };
    let dir = std::env::temp_dir().join(format!("fl-glob-locale-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    for name in ["é", "a", "Z", "Å", "b", "ü", "z"] {
        std::fs::create_dir(dir.join(name)).unwrap();
        std::fs::write(dir.join(name).join("é"), b"").unwrap();
    }

    for locale in [c"C", c"C.UTF-8", c"en_US.UTF-8"] {
        if unsafe { host_setlocale(libc::LC_ALL, locale.as_ptr()) }.is_null() {
            assert_eq!(locale, c"en_US.UTF-8", "required locale missing");
            continue;
        }
        assert!(!unsafe { locale_abi::setlocale(libc::LC_ALL, locale.as_ptr()) }.is_null());
        for (pattern, flags) in [
            ("?", 0),
            ("[[:alpha:]]", 0),
            ("[[=a=]]", 0),
            ("[a-z]", 0),
            ("?/?", 0),
            ("*", 0),
            ("?", libc::GLOB_NOSORT),
            ("{z*,*}", libc::GLOB_BRACE),
        ] {
            let pattern = CString::new(dir.join(pattern).as_os_str().as_bytes()).unwrap();
            for (name, candidate, free, host, host_free) in providers {
                let expected = expand(host, host_free, &pattern, flags);
                let actual = expand(candidate, free, &pattern, flags);
                assert_eq!(actual, expected, "{name:?} {locale:?} {pattern:?} {flags:#x}");
            }
        }
    }
    std::fs::remove_dir_all(dir).unwrap();
}
