//! Promotion order, not mmap order, defines the native global symbol scope.
//! Every case runs against both glibc and the native ABI in fresh processes.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::{CStr, CString, c_int, c_void};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenlibc_abi::dlfcn_abi;

const PROVIDER: &str = r#"
int gp_function(void) { return VALUE; }
__thread int gp_tls = VALUE * 10;
static int implementation(void) { return VALUE * 100; }
static int (*resolver(void))(void) { return implementation; }
int gp_ifunc(void) __attribute__((ifunc("resolver")));
static int (*zero_resolver(void))(void) { return 0; }
int gp_zero(void) __attribute__((ifunc("zero_resolver")));
"#;
const CONSUMER: &str = r#"
extern int gp_function(void);
extern __thread int gp_tls;
extern int gp_ifunc(void);
int gp_observe(void) { return gp_function() + gp_tls + gp_ifunc(); }
"#;

fn checked(command: &mut Command) {
    let output = command.output().expect("execute required C compiler");
    assert!(output.status.success(), "{command:?}: {}\n{}",
        String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
}

fn compile(root: &Path, name: &str, source: &str, extra: &[&str]) {
    fs::write(root.join(format!("{name}.c")), source).unwrap();
    let mut command = Command::new("cc");
    command.current_dir(root).args([
        "-shared", "-fPIC", "-nostdlib", "-fno-stack-protector",
        "-Wl,--hash-style=both", "-Wl,-z,now", "-Wl,-z,relro",
        "-Wl,-rpath,$ORIGIN", "-Wl,--version-script=versions.map",
    ]).arg(format!("-Wl,-soname,lib{name}.so"))
        .arg(format!("{name}.c")).args(extra)
        .arg("-o").arg(format!("lib{name}.so"));
    checked(&mut command);
}

fn fixtures(root: &Path) {
    fs::create_dir_all(root).unwrap();
    fs::write(root.join("versions.map"), "GP_1 { global: gp_*; local: *; };\n").unwrap();
    compile(root, "gp_a", PROVIDER, &["-DVALUE=1"]);
    compile(root, "gp_b", PROVIDER, &["-DVALUE=2"]);
    compile(root, "gp_consumer", CONSUMER, &[]);
    compile(root, "gp_linked", CONSUMER, &["-Wl,--no-as-needed", "-L.", "-lgp_a"]);
    compile(root, "gp_group", "int gp_anchor(void) { return 7; }",
        &["-Wl,--no-as-needed", "-L.", "-lgp_a"]);
    compile(root, "gp_invalid", "extern int gp_missing(void); int gp_bad(void) { return gp_missing(); }", &[]);
}

struct Loader { native: bool }
impl Loader {
    fn error(&self) -> String {
        // SAFETY: each backend owns its NUL-terminated dlerror buffer.
        let message = unsafe {
            if self.native { dlfcn_abi::dlerror() } else { libc::dlerror().cast_const() }
        };
        if message.is_null() { return "no error".into(); }
        unsafe { CStr::from_ptr(message) }.to_string_lossy().into_owned()
    }

    fn try_open(&self, root: &Path, name: &str, flags: c_int) -> *mut c_void {
        let path = CString::new(root.join(format!("lib{name}.so")).as_os_str().as_bytes()).unwrap();
        // SAFETY: valid pathname and supported flags; each reference is closed.
        unsafe {
            if self.native { dlfcn_abi::dlopen(path.as_ptr(), flags) }
            else { libc::dlopen(path.as_ptr(), flags) }
        }
    }

    fn open(&self, root: &Path, name: &str, flags: c_int) -> *mut c_void {
        let handle = self.try_open(root, name, flags);
        assert!(!handle.is_null(), "{name}: {}", self.error());
        assert_eq!(dlfcn_abi::native_dso_handle_for_tests(handle), self.native,
            "a native case must not silently fall back to the host");
        handle
    }

    fn lookup(&self, handle: *mut c_void, name: &CStr, version: Option<&CStr>) -> (*mut c_void, bool) {
        // SAFETY: fixture handles remain open and both strings are terminated.
        unsafe {
            if self.native { let _ = dlfcn_abi::dlerror(); }
            else { let _ = libc::dlerror(); }
            let address = match (self.native, version) {
                (true, None) => dlfcn_abi::dlsym(handle, name.as_ptr()),
                (true, Some(version)) => dlfcn_abi::dlvsym(handle, name.as_ptr(), version.as_ptr()),
                (false, None) => libc::dlsym(handle, name.as_ptr()),
                (false, Some(version)) => libc::dlvsym(handle, name.as_ptr(), version.as_ptr()),
            };
            let failed = if self.native { !dlfcn_abi::dlerror().is_null() }
                else { !libc::dlerror().is_null() };
            (address, failed)
        }
    }

    fn function(&self, handle: *mut c_void, name: &CStr, version: Option<&CStr>) -> c_int {
        let (address, failed) = self.lookup(handle, name, version);
        assert!(!failed && !address.is_null(), "function lookup {name:?}");
        // SAFETY: our C fixture defines the named function as int(void),
        // and its provider is not closed until this call has returned.
        let function: unsafe extern "C" fn() -> c_int = unsafe { std::mem::transmute(address) };
        unsafe { function() }
    }

    fn main_handle(&self) -> *mut c_void {
        // SAFETY: NULL selects the main-program handle with valid flags.
        let handle = unsafe {
            if self.native { dlfcn_abi::dlopen(std::ptr::null(), libc::RTLD_NOW) }
            else { libc::dlopen(std::ptr::null(), libc::RTLD_NOW) }
        };
        assert!(!handle.is_null(), "main handle: {}", self.error());
        handle
    }

    fn value(&self, handle: *mut c_void) -> c_int {
        // SAFETY: the fixture exports int gp_observe(void), and its owning
        // handle remains live throughout lookup and the call.
        let address = unsafe {
            if self.native { dlfcn_abi::dlsym(handle, c"gp_observe".as_ptr()) }
            else { libc::dlsym(handle, c"gp_observe".as_ptr()) }
        };
        assert!(!address.is_null(), "lookup: {}", self.error());
        let function: unsafe extern "C" fn() -> c_int = unsafe { std::mem::transmute(address) };
        unsafe { function() }
    }

    fn close(&self, handle: *mut c_void) {
        // SAFETY: consumes one successful open, after all calls have returned.
        let result = unsafe {
            if self.native { dlfcn_abi::dlclose(handle) } else { libc::dlclose(handle) }
        };
        assert_eq!(result, 0, "close: {}", self.error());
    }
}

fn scenario(loader: &Loader, root: &Path, case: &str) {
    if case == "main_lookup" { main_lookup(loader, root); return; }
    if case == "null_ifunc" {
        let handle = loader.open(root, "gp_a", libc::RTLD_NOW);
        assert_eq!(loader.lookup(handle, c"gp_zero", None), (std::ptr::null_mut(), false));
        assert_eq!(loader.lookup(handle, c"gp_zero", Some(c"GP_1")), (std::ptr::null_mut(), false));
        assert_eq!(loader.lookup(handle, c"gp_zero", Some(c"GP_MISSING")), (std::ptr::null_mut(), true));
        loader.close(handle);
        return;
    }
    let global = libc::RTLD_NOW | libc::RTLD_GLOBAL;
    let promote = global | libc::RTLD_NOLOAD;
    let a = loader.open(root, "gp_a", if case == "repeat" { global } else { libc::RTLD_NOW });
    let b = loader.open(root, "gp_b", global);
    let mut extra = Vec::new();
    match case {
        "group" => extra.push(loader.open(root, "gp_group", global)),
        "rollback" => {
            assert!(loader.try_open(root, "gp_invalid", global).is_null());
            let _ = loader.error();
            extra.push(loader.open(root, "gp_a", promote));
        }
        "promotion" | "repeat" | "deepbind" => {
            extra.push(loader.open(root, "gp_a", promote));
            // A second promotion must neither duplicate nor reorder globals.
            extra.push(loader.open(root, "gp_a", promote));
        }
        _ => panic!("unknown case {case}"),
    }
    let deepbind = case == "deepbind";
    let consumer = loader.open(root, if deepbind { "gp_linked" } else { "gp_consumer" },
        libc::RTLD_NOW | if deepbind { libc::RTLD_DEEPBIND } else { 0 });
    let expected = if deepbind || case == "repeat" { 111 } else { 222 };
    assert_eq!(loader.value(consumer), expected, "{case}: ordinary, TLS and IFUNC providers");
    loader.close(b);
    // Relocation edges must retain the selected provider after its public
    // reference closes. Promotion only changes lookup, not that lifetime rule.
    assert_eq!(loader.value(consumer), expected, "{case}: provider lifetime");
    loader.close(consumer);
    let replacement = loader.open(root, "gp_consumer", libc::RTLD_NOW);
    assert_eq!(loader.value(replacement), 111, "{case}: surviving global after unload");
    loader.close(replacement);
    for handle in extra.into_iter().rev() { loader.close(handle); }
    loader.close(a);
}

fn main_lookup(loader: &Loader, root: &Path) {
    let main = loader.main_handle();
    let a = loader.open(root, "gp_a", libc::RTLD_NOW);
    assert_eq!(loader.lookup(main, c"gp_function", None), (std::ptr::null_mut(), true),
        "LOCAL objects must stay invisible to the main handle");
    assert_eq!(loader.function(a, c"gp_function", None), 1);
    let b = loader.open(root, "gp_b", libc::RTLD_NOW | libc::RTLD_GLOBAL);
    assert_eq!(loader.function(main, c"gp_function", None), 2);
    assert_eq!(loader.function(main, c"gp_function", Some(c"GP_1")), 2);
    assert_eq!(loader.lookup(main, c"gp_function", Some(c"GP_MISSING")), (std::ptr::null_mut(), true));
    let promoted = loader.open(root, "gp_a", libc::RTLD_NOW | libc::RTLD_GLOBAL | libc::RTLD_NOLOAD);
    assert_eq!(loader.function(main, c"gp_function", None), 2, "late promotion must append");
    assert_eq!(loader.function(main, c"gp_ifunc", Some(c"GP_1")), 200);
    assert_eq!(loader.lookup(main, c"gp_zero", None), (std::ptr::null_mut(), false));
    assert_eq!(loader.lookup(main, c"gp_zero", Some(c"GP_1")), (std::ptr::null_mut(), false));
    let (tls, failed) = loader.lookup(main, c"gp_tls", Some(c"GP_1"));
    assert!(!failed && !tls.is_null());
    assert_eq!(tls, loader.lookup(b, c"gp_tls", None).0);
    // SAFETY: gp_tls is an initialized int in this thread's live module.
    assert_eq!(unsafe { *tls.cast::<c_int>() }, 20);
    let main_address = main as usize;
    let native = loader.native;
    let other_tls = std::thread::spawn(move || {
        let loader = Loader { native };
        let (address, failed) = loader.lookup(main_address as *mut c_void, c"gp_tls", None);
        assert!(!failed && !address.is_null());
        // SAFETY: the parent retains both providers until this thread joins.
        unsafe {
            assert_eq!(*address.cast::<c_int>(), 20);
            *address.cast::<c_int>() = 91;
        }
        address as usize
    }).join().expect("TLS lookup thread");
    assert_ne!(other_tls, tls as usize, "each thread needs its own TLS block");
    assert_eq!(unsafe { *tls.cast::<c_int>() }, 20);
    loader.close(b);
    // Unlike RTLD_DEFAULT, lookup through an explicit main handle must not
    // make the provider a permanent dependency of the calling executable.
    assert_eq!(loader.function(main, c"gp_function", None), 1);
    assert_eq!(loader.function(main, c"gp_ifunc", Some(c"GP_1")), 100);
    loader.close(promoted);
    loader.close(a);
    assert_eq!(loader.lookup(main, c"gp_function", None), (std::ptr::null_mut(), true));
    loader.close(main);
}

#[test]
fn native_global_promotion_matches_host() {
    if let Ok(case) = std::env::var("FRANKEN_GLOBAL_CASE") {
        let root = PathBuf::from(std::env::var_os("FRANKEN_GLOBAL_ROOT").unwrap());
        let loader = Loader { native: std::env::var("FRANKEN_GLOBAL_BACKEND").unwrap() == "native" };
        scenario(&loader, &root, &case);
        return;
    }
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let root = std::env::temp_dir().join(format!("franken-global-{}-{stamp}", std::process::id()));
    fixtures(&root);
    let mut cases = vec!["promotion", "repeat", "group", "deepbind", "rollback", "null_ifunc"];
    if cfg!(feature = "standalone") { cases.push("main_lookup"); }
    for case in cases {
        for backend in ["host", "native"] {
            let output = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "native_global_promotion_matches_host", "--nocapture"])
                .env("FRANKEN_GLOBAL_CASE", case).env("FRANKEN_GLOBAL_ROOT", &root)
                .env("FRANKEN_GLOBAL_BACKEND", backend)
                .output().expect("run isolated oracle/native case");
            assert!(output.status.success(), "{backend}/{case}: {}\n{}",
                String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed;"),
                "{backend}/{case}: a zero-test child is not evidence");
        }
    }
}
