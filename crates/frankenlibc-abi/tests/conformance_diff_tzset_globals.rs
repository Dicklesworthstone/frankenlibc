#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc tzset oracle; mutates process-global TZ

//! Differential gate for the public timezone globals `tzset()` publishes
//! (bd-vxpc1y).
//!
//! glibc's `tzset()` always populates `tzname`, `timezone` and `daylight`, and
//! `tzname[0]` in particular is never NULL — `tzset(); puts(tzname[0])` is a
//! common idiom that would dereference NULL otherwise. fl left the globals at
//! their zero-initialised NULL. The fix (8daab4a96) publishes the UTC values,
//! but nothing ever asserted them: `tzset` appears in a dozen test files purely
//! as setup, and `tzname` appears only as part of another test's NAME.
//!
//! SCOPE, deliberately: fl is UTC-only by design, so this file does NOT compare
//! the two implementations under an arbitrary TZ — glibc would report EST for
//! America/New_York and fl would report UTC, and that divergence is a known
//! design limitation, not this bead. Asserting it here would make the gate fail
//! for a reason it does not own. What IS compared, byte for byte against live
//! glibc, is the UTC case, where the two must agree exactly; and what is
//! asserted unconditionally is the property the bug was about — the globals are
//! populated and `tzname[0]` is a readable, non-NULL, non-empty string
//! regardless of TZ.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::sync::Mutex;

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}

/// TZ and the timezone globals are process-wide; the harness runs tests in
/// parallel threads.
static TZ_LOCK: Mutex<()> = Mutex::new(());

type TzsetFn = extern "C" fn();

fn libc_handle() -> *mut c_void {
    let h = unsafe { dlopen(c"libc.so.6".as_ptr(), 2 /* RTLD_NOW */) };
    assert!(!h.is_null(), "dlopen(libc.so.6) failed");
    h
}

/// glibc's `tzset`, reached by dlsym and asserted distinct from fl's — the
/// plain `extern "C"` route would bind to fl's own symbol in a release test
/// build, where `no_mangle` is active, and compare fl against itself.
fn glibc_tzset() -> TzsetFn {
    let h = libc_handle();
    let s = unsafe { dlsym(h, c"tzset".as_ptr()) };
    assert!(!s.is_null(), "dlsym(tzset) failed");
    assert_ne!(
        s as usize,
        frankenlibc_abi::time_abi::tzset as *const () as usize,
        "tzset resolved to fl's own symbol — the arms are not distinct"
    );
    unsafe { std::mem::transmute::<*mut c_void, TzsetFn>(s) }
}

/// Read a `char *[2]` global out of live glibc, plus the two `long`/`int` ones.
fn glibc_globals() -> (String, String, i64, c_int) {
    let h = libc_handle();
    unsafe {
        let tzname = dlsym(h, c"tzname".as_ptr()).cast::<*const c_char>();
        let timezone = dlsym(h, c"timezone".as_ptr()).cast::<i64>();
        let daylight = dlsym(h, c"daylight".as_ptr()).cast::<c_int>();
        assert!(
            !tzname.is_null() && !timezone.is_null() && !daylight.is_null(),
            "dlsym on a timezone global failed"
        );
        (cstr(*tzname), cstr(*tzname.add(1)), *timezone, *daylight)
    }
}

fn fl_globals() -> (String, String, i64, c_int) {
    unsafe {
        (
            cstr(frankenlibc_abi::glibc_internal_abi::tzname[0]),
            cstr(frankenlibc_abi::glibc_internal_abi::tzname[1]),
            frankenlibc_abi::glibc_internal_abi::timezone as i64,
            frankenlibc_abi::glibc_internal_abi::daylight,
        )
    }
}

/// Render a `char *` that MUST be non-NULL. A NULL here is the bug itself, so
/// it is reported as such rather than papered over with a placeholder.
fn cstr(p: *const c_char) -> String {
    assert!(
        !p.is_null(),
        "a tzname entry was NULL; `tzset(); puts(tzname[0])` would segfault here"
    );
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

fn set_tz(value: Option<&str>) {
    unsafe {
        match value {
            Some(v) => {
                let k = CString::new("TZ").unwrap();
                let v = CString::new(v).unwrap();
                libc::setenv(k.as_ptr(), v.as_ptr(), 1);
            }
            None => {
                let k = CString::new("TZ").unwrap();
                libc::unsetenv(k.as_ptr());
            }
        }
    }
}

#[test]
fn tzset_publishes_utc_globals_like_glibc() {
    let _g = TZ_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let saved = std::env::var("TZ").ok();

    set_tz(Some("UTC"));
    glibc_tzset()();
    let g = glibc_globals();
    unsafe { frankenlibc_abi::time_abi::tzset() };
    let f = fl_globals();

    set_tz(saved.as_deref());
    glibc_tzset()();

    assert_eq!(
        f, g,
        "TZ=UTC: fl and glibc must publish identical timezone globals \
         (tzname[0], tzname[1], timezone, daylight); fl={f:?} glibc={g:?}"
    );
    // Assert what the ORACLE produced, not only that the arms agree: if both
    // stopped publishing anything meaningful the equality above would hold.
    assert_eq!(
        g.0, "UTC",
        "glibc should report UTC as tzname[0] under TZ=UTC, got {:?}",
        g.0
    );
    assert_eq!(g.2, 0, "UTC has no offset from UTC");
    assert_eq!(g.3, 0, "UTC observes no DST");
}

#[test]
fn tzset_always_leaves_tzname_zero_a_readable_string() {
    // The property the bug was actually about, asserted independently of any
    // particular TZ: after tzset(), tzname[0] must be dereferenceable and
    // non-empty. This is what `tzset(); puts(tzname[0])` relies on, and it held
    // for NO value of TZ before the fix, because the globals stayed at their
    // zero-initialised NULL.
    //
    // Values chosen to include one fl does not implement (fl is UTC-only): the
    // requirement is that tzname[0] is a valid string, NOT that it names the
    // right zone, so an unsupported zone must still not produce NULL.
    let _g = TZ_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let saved = std::env::var("TZ").ok();

    for tz in [Some("UTC"), Some("America/New_York"), Some(""), None] {
        set_tz(tz);
        unsafe { frankenlibc_abi::time_abi::tzset() };

        // cstr() asserts non-NULL, which is the core of this bead.
        let (name0, name1, _, daylight) = fl_globals();
        assert!(
            !name0.is_empty(),
            "TZ={tz:?}: tzname[0] must be a non-empty string, got {name0:?}"
        );
        assert!(
            !name1.is_empty(),
            "TZ={tz:?}: tzname[1] must be a non-empty string, got {name1:?}"
        );
        assert!(
            daylight == 0 || daylight == 1,
            "TZ={tz:?}: daylight must be a 0/1 flag, got {daylight}"
        );
    }

    set_tz(saved.as_deref());
    glibc_tzset()();
}

#[test]
fn tzset_keeps_the_underscored_aliases_in_step() {
    // glibc exports both `tzname`/`timezone`/`daylight` and the `__`-prefixed
    // aliases, and a program may read either. fl publishes them as separate
    // statics rather than as aliases of one another, so a fix that updated only
    // the public set would still leave __tzname[0] NULL — the same crash, one
    // symbol over. Nothing else asserts this.
    let _g = TZ_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe { frankenlibc_abi::time_abi::tzset() };

    unsafe {
        for i in 0..2 {
            let public = frankenlibc_abi::glibc_internal_abi::tzname[i];
            let alias = frankenlibc_abi::glibc_internal_abi::__tzname[i];
            assert!(!alias.is_null(), "__tzname[{i}] is NULL");
            assert_eq!(
                cstr(public),
                cstr(alias),
                "tzname[{i}] and __tzname[{i}] disagree"
            );
        }
        // Read through raw pointers: `assert_eq!` takes references, and Rust
        // 2024 rejects a shared reference to a mutable static.
        let tz = *(&raw const frankenlibc_abi::glibc_internal_abi::timezone);
        let tz_alias = *(&raw const frankenlibc_abi::glibc_internal_abi::__timezone);
        assert_eq!(tz, tz_alias, "timezone and __timezone disagree");

        let dl = *(&raw const frankenlibc_abi::glibc_internal_abi::daylight);
        let dl_alias = *(&raw const frankenlibc_abi::glibc_internal_abi::__daylight);
        assert_eq!(dl, dl_alias, "daylight and __daylight disagree");
    }
}
