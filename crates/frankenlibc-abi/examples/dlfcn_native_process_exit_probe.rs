//! Actual main-thread/worker process termination, not a libtest worker exit.
//! Every native child asserts native handles before it executes fixture code.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "../tests/common/dlsym_oracle.rs"]
mod dlsym_oracle;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux {
    use std::ffi::{CString, c_char, c_int, c_void};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitCode, Stdio};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    use frankenlibc_abi::dlfcn_abi::{dlclose, dlopen, dlsym, native_dso_handle_for_tests};
    use super::dlsym_oracle;

    #[derive(Clone, Copy)]
    enum Loader { Native, Host }
    impl Loader {
        fn load(self, path: &Path, flags: c_int) -> *mut c_void {
            let name = CString::new(path.as_os_str().as_bytes()).unwrap();
            let handle = unsafe { match self {
                Self::Native => dlopen(name.as_ptr(), flags),
                Self::Host => {
                    let f: unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void =
                        dlsym_oracle::host_fn(c"dlopen", dlopen as *const ());
                    f(name.as_ptr(), flags)
                }
            }};
            assert!(!handle.is_null(), "process fixture failed to load: {path:?}");
            if matches!(self, Self::Native) {
                assert!(native_dso_handle_for_tests(handle), "host fallback is not native process exit");
            }
            handle
        }
        fn close(self, handle: *mut c_void) {
            let result = unsafe { match self {
                Self::Native => dlclose(handle),
                Self::Host => {
                    let f: unsafe extern "C" fn(*mut c_void) -> c_int =
                        dlsym_oracle::host_fn(c"dlclose", dlclose as *const ());
                    f(handle)
                }
            }};
            assert_eq!(result, 0);
        }
        fn terminate(self, handle: *mut c_void, status: c_int) -> ! {
            let address = unsafe { match self {
                Self::Native => dlsym(handle, c"terminate".as_ptr()),
                Self::Host => {
                    let f: unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void =
                        dlsym_oracle::host_fn(c"dlsym", dlsym as *const ());
                    f(handle, c"terminate".as_ptr())
                }
            }};
            assert!(!address.is_null());
            let f: unsafe extern "C" fn(c_int) -> ! = unsafe { std::mem::transmute(address) };
            unsafe { f(status) }
        }
    }

    const SINK: &str = r#"
        void record_event(long n) {
            char byte = (char)n; long result;
            __asm__ volatile("syscall" : "=a"(result) : "0"(1L), "D"(1L),
                "S"(&byte), "d"(1L) : "rcx", "r11", "memory");
        }
    "#;
    const LEAF: &str = r#"
        extern void record_event(long);
        __attribute__((constructor)) static void init(void) { record_event('L'); }
        __attribute__((destructor)) static void fini(void) { record_event('l'); }
    "#;
    const ROOT: &str = r#"
        extern void record_event(long);
        __attribute__((constructor)) static void init(void) { record_event('R'); }
        __attribute__((destructor)) static void fini(void) { record_event('r'); }
    "#;
    const CPP: &str = r#"
        extern "C" void record_event(long);
        struct Object { Object() { record_event('C'); } ~Object() { record_event('D'); } } object;
        __attribute__((destructor)) static void fini(void) { record_event('F'); }
    "#;
    const TLS: &str = r#"
        extern void record_event(long);
        extern int __cxa_atexit(void (*)(void *), void *, void *);
        extern int __cxa_thread_atexit_impl(void (*)(void *), void *, void *);
        static char token; __thread long value = 'T';
        static void thread_fini(void *p) { record_event(value); value = 'U'; }
        static void static_fini(void *p) { record_event(value); }
        __attribute__((constructor)) static void init(void) {
            if (__cxa_thread_atexit_impl(thread_fini, 0, &token) != 0) record_event('!');
            if (__cxa_atexit(static_fini, 0, &token) != 0) record_event('!');
        }
        __attribute__((destructor)) static void fini(void) { record_event(value); }
    "#;
    const COLD_TLS: &str = r#"
        extern void record_event(long); __thread long value = 'K';
        __attribute__((destructor)) static void fini(void) { record_event(value); }
    "#;
    const RECURSIVE: &str = r#"
        extern void record_event(long); extern void exit(int);
        extern int __cxa_atexit(void (*)(void *), void *, void *); static char token;
        static void older(void *p) { record_event('A'); }
        static void newer(void *p) { record_event('B'); exit(31); }
        __attribute__((constructor)) static void init(void) {
            __cxa_atexit(older, 0, &token); __cxa_atexit(newer, 0, &token);
        }
        __attribute__((destructor)) static void fini(void) { record_event('F'); }
    "#;
    const REGISTERING: &str = r#"
        extern void record_event(long);
        extern int __cxa_atexit(void (*)(void *), void *, void *); static char token;
        static void added(void *p) { record_event('C'); }
        static void older(void *p) { record_event('A'); }
        static void newer(void *p) { record_event('B'); __cxa_atexit(added, 0, &token); }
        __attribute__((constructor)) static void init(void) {
            __cxa_atexit(older, 0, &token); __cxa_atexit(newer, 0, &token);
        }
        __attribute__((destructor)) static void fini(void) { record_event('F'); }
    "#;
    const FINI_REGISTERING: &str = r#"
        extern void record_event(long);
        extern int __cxa_atexit(void (*)(void *), void *, void *);
        static void added(void *p) { record_event('Q'); }
        __attribute__((destructor)) static void fini(void) {
            record_event('F'); if (__cxa_atexit(added, 0, 0) != 0) record_event('!');
        }
    "#;
    const NULL_OWNER: &str = r#"
        extern void record_event(long);
        extern int __cxa_atexit(void (*)(void *), void *, void *);
        static void added(void *p) { record_event('Q'); }
        __attribute__((constructor)) static void init(void) { __cxa_atexit(added, 0, 0); }
        __attribute__((destructor)) static void fini(void) { record_event('F'); }
    "#;

    struct Case {
        name: &'static str, source: &'static str, cpp: bool, dependency: bool,
        mode: &'static str, function: &'static str, gnu2: bool,
        expected: &'static str, status: i32, native_only: bool,
    }
    fn cases() -> Vec<Case> {
        let base = |name, source, mode, expected| Case {
            name, source, mode, expected, cpp: false, dependency: false,
            function: "", gnu2: false, status: 17, native_only: false,
        };
        vec![
            Case { dependency: true, ..base("plain-return", ROOT, "return", "LRMrl") },
            Case { dependency: true, ..base("plain-host-exit", ROOT, "host-exit", "LRMrl") },
            Case { dependency: true, function: "exit", ..base("plain-native-exit", ROOT, "call", "LRMrl") },
            Case { dependency: true, ..base("nodelete-return", ROOT, "nodelete", "LRMrl") },
            Case { dependency: true, ..base("closed-return", ROOT, "closed", "LRrlM") },
            Case { cpp: true, ..base("cpp-return", CPP, "return", "CMDF") },
            Case { cpp: true, function: "exit", ..base("cpp-native-exit", CPP, "call", "CMDF") },
            base("tls-return", TLS, "return", "MTUU"),
            Case { gnu2: true, ..base("tlsdesc-return", TLS, "return", "MTUU") },
            base("tls-worker-host-exit", TLS, "worker-host-exit", "MTUU"),
            Case { function: "exit", ..base("tls-worker-native-exit", TLS, "worker-call", "MTUU") },
            base("cold-tls-fini", COLD_TLS, "return", "MK"),
            Case { gnu2: true, ..base("cold-tlsdesc-fini", COLD_TLS, "return", "MK") },
            Case { function: "_Exit", ..base("immediate-exit", TLS, "call", "M") },
            Case { function: "_exit", ..base("underscore-exit", TLS, "call", "M") },
            Case { function: "quick_exit", ..base("quick-exit", TLS, "call", "M") },
            Case { status: 31, ..base("recursive-exit", RECURSIVE, "host-exit", "MBAF") },
            base("registration-during-exit", REGISTERING, "return", "MBCAF"),
            base("registration-during-fini", FINI_REGISTERING, "return", "MFQ"),
            Case { native_only: true, ..base("null-owner-retention", NULL_OWNER, "closed", "MQF") },
        ]
    }

    fn compile(dir: &Path, name: &str, source: &str, cpp: bool, deps: &[&Path], gnu2: bool) -> PathBuf {
        let input = dir.join(format!("{name}.{}", if cpp { "cc" } else { "c" }));
        let output = dir.join(format!("{name}.so"));
        std::fs::write(&input, source).unwrap();
        let mut cmd = Command::new(if cpp { "c++" } else { "cc" });
        cmd.args(["-shared", "-fPIC", "-Wl,--build-id=none", "-Wl,--no-as-needed"]);
        if cpp { cmd.args(["-nodefaultlibs", "-fno-exceptions", "-fno-rtti", "-fno-gnu-unique"]); }
        else { cmd.arg("-nostdlib"); }
        if gnu2 { cmd.arg("-mtls-dialect=gnu2"); }
        let result = cmd.arg(&input).args(deps).arg("-o").arg(&output).output().unwrap();
        assert!(result.status.success(), "fixture compilation failed: {}", String::from_utf8_lossy(&result.stderr));
        output
    }

    fn run_child(loader: Loader, path: PathBuf, mode: String) -> ExitCode {
        if let Some(next) = mode.strip_prefix("worker-") {
            let next = next.to_owned();
            return std::thread::spawn(move || run_child(loader, path, next)).join().unwrap();
        }
        let flags = libc::RTLD_NOW | if mode == "nodelete" { libc::RTLD_NODELETE } else { 0 };
        let handle = loader.load(&path, flags);
        if matches!(mode.as_str(), "nodelete" | "closed") { loader.close(handle); }
        // Unbuffered boundary marker: this does not invoke the candidate.
        assert_eq!(unsafe { libc::write(1, b"M".as_ptr().cast(), 1) }, 1);
        match mode.as_str() {
            "host-exit" => std::process::exit(17),
            "call" => loader.terminate(handle, 17),
            _ => ExitCode::from(17),
        }
    }

    pub fn run() -> ExitCode {
        let args = std::env::args().skip(1).collect::<Vec<_>>();
        if args.first().map(String::as_str) == Some("--child") {
            assert_eq!(args.len(), 4);
            let loader = if args[1] == "native" { Loader::Native } else { Loader::Host };
            return run_child(loader, PathBuf::from(&args[3]), args[2].clone());
        }
        let only = if args.first().map(String::as_str) == Some("--only") { Some(args[1].as_str()) } else { None };
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("fl-process-exit-{}-{stamp}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sink = compile(&dir, "sink", SINK, false, &[], false);
        let leaf = compile(&dir, "leaf", LEAF, false, &[&sink], false);
        let mut count = 0;
        for case in cases().into_iter().filter(|case| only.is_none_or(|name| name == case.name)) {
            let mut source = case.source.to_owned();
            if !case.function.is_empty() {
                let linkage = if case.cpp { "extern \"C\"" } else { "extern" };
                let definition = if case.cpp { "extern \"C\"" } else { "" };
                source.push_str(&format!("\n{linkage} void {0}(int); {definition} void terminate(int n) {{ {0}(n); }}", case.function));
            }
            let deps = if case.dependency { vec![leaf.as_path(), sink.as_path()] } else { vec![sink.as_path()] };
            let path = compile(&dir, case.name, &source, case.cpp, &deps, case.gnu2);
            for loader in ["host", "native"] {
                if loader == "host" && case.native_only { continue; }
                let mut child = Command::new(std::env::current_exe().unwrap())
                    .args(["--child", loader, case.mode]).arg(&path)
                    .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
                let deadline = Instant::now() + Duration::from_secs(30);
                loop {
                    if child.try_wait().unwrap().is_some() { break; }
                    if Instant::now() >= deadline {
                        child.kill().unwrap(); let _ = child.wait();
                        panic!("process-exit child deadlocked: {loader} {}", case.name);
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                let result = child.wait_with_output().unwrap();
                assert_eq!(result.status.code(), Some(case.status), "process-exit status mismatch: {loader} {}: {}",
                    case.name, String::from_utf8_lossy(&result.stderr));
                assert_eq!(result.stdout, case.expected.as_bytes(), "native process-exit trace mismatch: {loader} {}: {}",
                    case.name, String::from_utf8_lossy(&result.stderr));
                count += 1;
                println!("process-exit {loader} {} status={} trace={}", case.name, case.status, case.expected);
            }
        }
        assert!(count > 0, "no process-exit scenarios selected");
        println!("native-process-exit: {count} scenarios passed");
        ExitCode::SUCCESS
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn main() -> std::process::ExitCode { linux::run() }
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() { panic!("native process-exit probe requires x86-64 Linux"); }
