#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc getenv/putenv oracle; shared process environ

//! Differential gate for getenv / putenv (bd-93orbb) — these fundamental
//! functions had no differential gate. fl and glibc read the SAME process
//! environ, so getenv must agree for every name (existing, PATH, missing,
//! empty). putenv is checked for cross-impl interop: a variable inserted via
//! fl::putenv must be observable through glibc::getenv (and vice-versa), proving
//! fl writes the shared environ in glibc's layout, plus the return code.
//!
//! The host arms are resolved with `common/dlsym_oracle` rather than declared at
//! link time: fl exports `getenv` and `putenv` into this same test binary, so a
//! link-time declaration is only an oracle while the linker happens to choose
//! libc.so.6 (bd-v0388t, bd-reality-202609-lx578q.7).
//!
//! THE `environ` ALIASES. glibc exports `environ`, `_environ` and `__environ`,
//! and a program may read any of them directly — walking the array is how a
//! child process builds its environment and how shell-style code enumerates it.
//! `getenv` agreeing with glibc is therefore not sufficient: the ARRAY a caller
//! walks has to be current too. The arms below check that for every alias, in
//! both providers, through the same array-walk a C program would do.

use std::ffi::{CStr, CString, c_char, c_int};
use std::sync::{LazyLock, Mutex};

use frankenlibc_abi::stdlib_abi as fl;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

type Getenv = unsafe extern "C" fn(*const c_char) -> *mut c_char;
type Putenv = unsafe extern "C" fn(*mut c_char) -> c_int;

// SAFETY (both statics): the declared types are the C prototypes of these
// symbols, and `host_fn` rejects a resolution that lands on fl's own definition.
static HOST_GETENV: LazyLock<Getenv> =
    LazyLock::new(|| unsafe { dlsym_oracle::host_fn(c"getenv", fl::getenv as *const ()) });
static HOST_PUTENV: LazyLock<Putenv> =
    LazyLock::new(|| unsafe { dlsym_oracle::host_fn(c"putenv", fl::putenv as *const ()) });

/// Strings handed to `putenv`, which stores the CALLER's pointer rather than
/// copying: they must stay valid for as long as the variable exists in the
/// environment. This is the explicit owner for them, so nothing is leaked.
static PUTENV_STRINGS: LazyLock<Mutex<Vec<CString>>> = LazyLock::new(|| Mutex::new(Vec::new()));

/// Move a string into the process-lifetime store and return the pointer
/// `putenv` may retain.
fn retained_for_putenv(s: CString) -> *mut c_char {
    let mut store = PUTENV_STRINGS
        .lock()
        .expect("putenv store is never poisoned");
    let ptr = s.as_ptr() as *mut c_char;
    store.push(s);
    ptr
}

fn host_getenv() -> Getenv {
    *HOST_GETENV
}
fn host_putenv() -> Putenv {
    *HOST_PUTENV
}

fn g_get(name: &str) -> Option<String> {
    let c = CString::new(name).unwrap();
    let p = unsafe { (host_getenv())(c.as_ptr()) };
    if p.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    }
}
fn f_get(name: &str) -> Option<String> {
    let c = CString::new(name).unwrap();
    let p = unsafe { frankenlibc_abi::stdlib_abi::getenv(c.as_ptr()) };
    if p.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    }
}

/// Serializes the three tests below.
///
/// All three mutate PROCESS-GLOBAL state — the environ array and the pointer it
/// hangs from — so running them concurrently is a data race on data no lock of
/// theirs protects. That is not hypothetical: with them parallel, the alias test's
/// ownership transfer landed between another test's `set_var` and its `getenv`,
/// and the chunked census caught the result (`glibc getenv must see fl::putenv`
/// failing in one run and passing in another, bd-reality-202609-lx578q.7).
/// Holding this for the whole test makes the mutations strictly ordered, which is
/// the property each of them assumes.
static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn getenv_matches_glibc() {
    let _serial = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // A var we control, set via the platform setenv (writes the shared environ).
    unsafe { std::env::set_var("FL_GETENV_PROBE", "value-42") };
    for name in [
        "FL_GETENV_PROBE",
        "PATH",
        "HOME",
        "PWD",
        "NO_SUCH_VAR_QZX",
        "",
        "FL_GETENV_PROBE=",
    ] {
        assert_eq!(
            f_get(name),
            g_get(name),
            "getenv({name:?}): fl={:?} glibc={:?}",
            f_get(name),
            g_get(name)
        );
    }
}

#[test]
fn putenv_then_getenv_cross_impl() {
    let _serial = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // Insert via fl::putenv; both impls' getenv must see it (shared environ).
    // putenv keeps the caller's pointer in environ, so the string is moved into
    // a process-lifetime store rather than leaked.
    let s1 = retained_for_putenv(CString::new("FL_PUTENV_A=alpha").unwrap());
    let rc_fl = unsafe { frankenlibc_abi::stdlib_abi::putenv(s1) };
    assert_eq!(rc_fl, 0, "fl::putenv should succeed");
    assert_eq!(
        g_get("FL_PUTENV_A"),
        Some("alpha".to_string()),
        "glibc getenv must see fl::putenv"
    );
    assert_eq!(
        f_get("FL_PUTENV_A"),
        Some("alpha".to_string()),
        "fl getenv must see fl::putenv"
    );

    // Insert via glibc putenv; fl::getenv must see it.
    let s2 = retained_for_putenv(CString::new("FL_PUTENV_B=beta").unwrap());
    let rc_g = unsafe { (host_putenv())(s2) };
    assert_eq!(rc_g, 0, "glibc putenv should succeed");
    assert_eq!(
        f_get("FL_PUTENV_B"),
        g_get("FL_PUTENV_B"),
        "fl/glibc getenv agree after glibc putenv"
    );
    assert_eq!(f_get("FL_PUTENV_B"), Some("beta".to_string()));
}

// ---------------------------------------------------------------------------
// The exported `environ` aliases
// ---------------------------------------------------------------------------

/// Resolve one of glibc's exported `environ` variables and return the ADDRESS OF
/// THE VARIABLE (so `*addr` is the array pointer a C program would see).
///
/// # Safety
///
/// `name` must name one of `environ`, `_environ`, `__environ`, all of which
/// glibc exports as `char **` variables.
unsafe fn host_environ_var(name: &CStr) -> *mut *mut *mut c_char {
    // SAFETY: dlopen/dlsym are loader plumbing; the handle is released below.
    unsafe {
        let h = libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW);
        assert!(!h.is_null(), "libc.so.6 must be openable");
        let sym = libc::dlsym(h, name.as_ptr());
        libc::dlclose(h);
        assert!(!sym.is_null(), "glibc must export {name:?}");
        sym as *mut *mut *mut c_char
    }
}

/// Walk an environ array exactly as a C program would, and report whether it
/// carries `name=`.
///
/// # Safety
///
/// `envp` must be a NULL-terminated array of NUL-terminated C strings, or NULL.
unsafe fn array_has(envp: *mut *mut c_char, name: &str) -> bool {
    if envp.is_null() {
        return false;
    }
    let mut i = 0isize;
    loop {
        // SAFETY: the array is NULL-terminated, so the walk stops at a real
        // entry rather than running off the end.
        let e = unsafe { *envp.offset(i) };
        if e.is_null() {
            return false;
        }
        let bytes = unsafe { CStr::from_ptr(e) }.to_bytes();
        if bytes.len() > name.len()
            && bytes[name.len()] == b'='
            && bytes[..name.len()] == *name.as_bytes()
        {
            return true;
        }
        i += 1;
    }
}

/// fl's three exported aliases, read through the Rust paths that back the
/// exported symbols.
fn fl_alias_array(name: &str) -> *mut *mut c_char {
    unsafe {
        match name {
            "environ" => frankenlibc_abi::glibc_internal_abi::environ,
            "_environ" => frankenlibc_abi::glibc_internal_abi::_environ,
            "__environ" => frankenlibc_abi::glibc_internal_abi::__environ,
            other => panic!("unknown alias {other}"),
        }
    }
}

#[test]
fn environ_aliases_track_the_live_environment_like_glibc() {
    let _serial = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let fl_aliases = ["environ", "_environ", "__environ"];

    // A test binary starts through the HOST `__libc_start_main`, so fl's own
    // startup publication never runs here — and the aliases would read as
    // unpublished for a reason that has nothing to do with conformance. Drive
    // the same step `init_environment_globals` ends with, so this measures fl's
    // published state rather than the harness's startup path.
    frankenlibc_abi::stdlib_abi::take_environ_ownership();

    // Host glibc must satisfy this first. If the reference implementation does
    // not keep its own aliases current then the gate below would be asserting a
    // standard nobody follows, so the control runs before the comparison.
    for name in fl_aliases {
        let var = unsafe { host_environ_var(CString::new(name).unwrap().as_c_str()) };
        let arr = unsafe { *var };
        assert!(!arr.is_null(), "glibc {name} must be non-null");
        assert!(
            unsafe { array_has(arr, "PATH") },
            "glibc {name} must expose the process environment"
        );
    }

    // Insert a variable through fl, then require that EVERY alias of both
    // providers shows it. glibc updates all three because they are one storage
    // location; fl cannot alias three Rust statics to one address, so what is
    // asserted here is the observable contract instead: walking any of the three
    // must reveal the variable that getenv returns.
    let key = format!("FL_ENVIRON_ALIAS_{}", std::process::id());
    let entry = CString::new(format!("{key}=alias-1")).unwrap();
    let rc = unsafe {
        frankenlibc_abi::stdlib_abi::setenv(
            CString::new(key.as_str()).unwrap().as_ptr(),
            c"alias-1".as_ptr(),
            1,
        )
    };
    assert_eq!(rc, 0, "fl::setenv must succeed");
    assert_eq!(f_get(&key), Some("alias-1".to_string()));
    assert_eq!(g_get(&key), Some("alias-1".to_string()));

    let mut stale: Vec<String> = Vec::new();
    for name in fl_aliases {
        let arr = fl_alias_array(name);
        assert!(!arr.is_null(), "fl {name} must be published");
        if !unsafe { array_has(arr, &key) } {
            stale.push(format!("fl {name}"));
        }
    }
    for name in fl_aliases {
        let var = unsafe { host_environ_var(CString::new(name).unwrap().as_c_str()) };
        if !unsafe { array_has(*var, &key) } {
            stale.push(format!("glibc {name}"));
        }
    }

    // Clean up before asserting, so a failure does not leak the probe into the
    // remaining tests of this binary.
    let _ = unsafe {
        frankenlibc_abi::stdlib_abi::unsetenv(CString::new(key.as_str()).unwrap().as_ptr())
    };

    assert!(
        stale.is_empty(),
        "these environ aliases do not expose a variable that getenv returns, so a \
         caller that walks the array cannot see the live environment (glibc keeps \
         all three current): {}",
        stale.join(", ")
    );
}
