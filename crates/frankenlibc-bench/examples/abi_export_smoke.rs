//! Does a program that LOADS FrankenLibC actually reach FrankenLibC's code?
//!
//! `abi_disasm_probe` answers a narrower question — is the symbol in `.dynsym`?
//! That is a fact about the object, and it is what proved the nine exports added
//! for bd-6xstqa exist. It does not show that a loader resolves them, or that
//! what runs when you call one is FrankenLibC's implementation rather than
//! glibc's. Those are the properties the campaign actually cares about, and
//! nothing checked them: the conformance suite runs in DEBUG, where
//! `#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]` compiles the export
//! away entirely, so no existing test can see an export at all.
//!
//! This driver `dlopen`s the release cdylib and, for each named symbol,
//! establishes three things in order:
//!
//!   1. `dlsym` resolves it out of the FrankenLibC object;
//!   2. the resolved address lies INSIDE that object, checked with `dladdr` —
//!      not merely non-null, because a handle that failed to define the symbol
//!      can still hand back a match from an already-loaded glibc;
//!   3. calling it produces the right answer.
//!
//! Step 2 is the one that matters. `dladdr` reporting a different object is
//! exactly how an "export works" claim would be wrong while every other signal
//! looked green.
//!
//! RTLD_LOCAL, deliberately: the point is to exercise the object's own export
//! table, not to interpose the process.

use std::ffi::{c_char, c_int, c_void, CString};

const RTLD_NOW: c_int = 2;
const RTLD_LOCAL: c_int = 0;

#[repr(C)]
struct DlInfo {
    dli_fname: *const c_char,
    dli_fbase: *mut c_void,
    dli_sname: *const c_char,
    dli_saddr: *mut c_void,
}

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlerror() -> *const c_char;
    fn dladdr(addr: *const c_void, info: *mut DlInfo) -> c_int;
}

fn target_dir() -> String {
    std::env::var("FRANKENLIBC_BENCH_TARGET_DIR")
        .or_else(|_| std::env::var("CARGO_TARGET_DIR"))
        .unwrap_or_else(|_| "target".to_owned())
}

fn shared_object() -> String {
    format!("{}/release/libfrankenlibc_abi.so", target_dir())
}

/// Build the cdylib before reading it.
///
/// `cargo run --example` builds the example and the abi RLIB; the cdylib is a
/// separate target nothing in that command requires, and the target dir persists
/// per worker — so without this the driver tests whatever the last run left
/// behind. That mistake has been made twice in this campaign already
/// (bd-incumbent-stale-fl-artifact-pph3a1, and then again by the disasm probe on
/// its first outing).
fn build_cdylib() {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let status = std::process::Command::new(&cargo)
        .args(["build", "--quiet", "--profile", "release", "-p", "frankenlibc-abi"])
        .env("CARGO_TARGET_DIR", target_dir())
        .status()
        .expect("build the FrankenLibC cdylib");
    assert!(status.success(), "cdylib build failed");
}

fn last_dlerror() -> String {
    let message = unsafe { dlerror() };
    if message.is_null() {
        return "(no dlerror)".to_owned();
    }
    unsafe { std::ffi::CStr::from_ptr(message) }
        .to_string_lossy()
        .into_owned()
}

/// The object a resolved address actually belongs to.
fn owning_object(address: *mut c_void) -> Option<String> {
    let mut info = DlInfo {
        dli_fname: std::ptr::null(),
        dli_fbase: std::ptr::null_mut(),
        dli_sname: std::ptr::null(),
        dli_saddr: std::ptr::null_mut(),
    };
    let ok = unsafe { dladdr(address.cast_const(), &mut info) };
    if ok == 0 || info.dli_fname.is_null() {
        return None;
    }
    Some(
        unsafe { std::ffi::CStr::from_ptr(info.dli_fname) }
            .to_string_lossy()
            .into_owned(),
    )
}

fn main() {
    build_cdylib();
    let object = shared_object();

    let path = CString::new(object.clone()).expect("object path");
    let handle = unsafe { dlopen(path.as_ptr(), RTLD_NOW | RTLD_LOCAL) };
    if handle.is_null() {
        println!("EXPORT_SMOKE_UNAVAILABLE object={object} dlerror={}", last_dlerror());
        std::process::exit(2);
    }
    println!("EXPORT_SMOKE_OBJECT path={object}");

    // The nine names fixed for bd-6xstqa, plus controls. `memcpy` was exported
    // all along and must pass; `definitely_not_a_libc_symbol` must NOT resolve,
    // so a run that reported everything green would be visibly broken.
    let fixed = [
        "strchr", "strcpy", "strncpy", "wcsstr", "cospi", "dprintf", "freopen",
        "posix_spawn_file_actions_addclose", "vfprintf",
    ];
    let controls_present = ["memcpy", "strlen"];
    let control_absent = "definitely_not_a_libc_symbol";

    let mut resolved = 0usize;
    let mut foreign = 0usize;
    let mut missing = 0usize;

    for symbol in fixed.iter().chain(controls_present.iter()) {
        let name = CString::new(*symbol).expect("symbol name");
        let address = unsafe { dlsym(handle, name.as_ptr()) };
        if address.is_null() {
            missing += 1;
            println!("EXPORT_SMOKE symbol={symbol} status=unresolved");
            continue;
        }
        match owning_object(address) {
            Some(owner) if owner.contains("frankenlibc") => {
                resolved += 1;
                println!("EXPORT_SMOKE symbol={symbol} status=ok owner=frankenlibc");
            }
            Some(owner) => {
                // Resolved, but to somebody else's implementation.
                foreign += 1;
                println!("EXPORT_SMOKE symbol={symbol} status=FOREIGN owner={owner}");
            }
            None => {
                foreign += 1;
                println!("EXPORT_SMOKE symbol={symbol} status=owner_unknown");
            }
        }
    }

    let absent = CString::new(control_absent).expect("control name");
    let absent_address = unsafe { dlsym(handle, absent.as_ptr()) };
    println!(
        "EXPORT_SMOKE control symbol={control_absent} resolved={}",
        !absent_address.is_null()
    );

    // Behaviour, not just presence: call the one whose campaign this began with.
    let strchr_name = CString::new("strchr").expect("strchr");
    let strchr_address = unsafe { dlsym(handle, strchr_name.as_ptr()) };
    if !strchr_address.is_null() {
        let strchr: extern "C" fn(*const c_char, c_int) -> *const c_char =
            unsafe { std::mem::transmute(strchr_address) };
        let haystack = CString::new("abcdef").expect("haystack");
        let hit = strchr(haystack.as_ptr(), b'd' as c_int);
        let miss = strchr(haystack.as_ptr(), b'z' as c_int);
        let offset = if hit.is_null() {
            -1
        } else {
            (hit as isize) - (haystack.as_ptr() as isize)
        };
        println!(
            "EXPORT_SMOKE call symbol=strchr found_offset={offset} miss_is_null={}",
            miss.is_null()
        );
        assert_eq!(offset, 3, "strchr returned the wrong position");
        assert!(miss.is_null(), "strchr found a byte that is not there");
    }

    println!(
        "EXPORT_SMOKE_SUMMARY resolved={resolved} foreign={foreign} missing={missing} \
         control_absent_resolved={}",
        !absent_address.is_null()
    );

    // A green run must have found every symbol in FrankenLibC and must NOT have
    // resolved the control.
    assert_eq!(missing, 0, "some symbols did not resolve");
    assert_eq!(foreign, 0, "some symbols resolved outside FrankenLibC");
    assert!(
        absent_address.is_null(),
        "the absent control resolved, so this driver cannot tell present from absent"
    );
    println!("EXPORT_SMOKE_OK");
}
