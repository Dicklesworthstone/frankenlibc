#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::{CStr, CString, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use frankenlibc_abi::dlfcn_abi::{
    dlclose, dlopen, dlsym, native_dso_handle_for_tests,
};
use frankenlibc_core::elf::ElfLoader;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

#[derive(Clone, Copy)]
enum Loader {
    Host,
    Native,
}

impl Loader {
    fn try_open(self, path: &Path, flags: c_int) -> *mut c_void {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: a live NUL-terminated pathname and the public loader ABI.
        let handle = unsafe {
            match self {
                Self::Native => dlopen(path.as_ptr(), flags),
                Self::Host => {
                    let open: unsafe extern "C" fn(*const libc::c_char, c_int) -> *mut c_void =
                        dlsym_oracle::host_fn(c"dlopen", dlopen as *const ());
                    open(path.as_ptr(), flags)
                }
            }
        };
        if !handle.is_null() && matches!(self, Self::Native) {
            assert!(native_dso_handle_for_tests(handle), "host fallback is not native initialization");
        }
        handle
    }

    fn open(self, path: &Path, flags: c_int) -> *mut c_void {
        let handle = self.try_open(path, libc::RTLD_NOW | flags);
        assert!(!handle.is_null(), "initialization fixture must load: {}", path.display());
        handle
    }

    fn close(self, handle: *mut c_void) {
        // SAFETY: each call releases exactly one successful open reference.
        let result = unsafe {
            match self {
                Self::Native => dlclose(handle),
                Self::Host => {
                    let close: unsafe extern "C" fn(*mut c_void) -> c_int =
                        dlsym_oracle::host_fn(c"dlclose", dlclose as *const ());
                    close(handle)
                }
            }
        };
        assert_eq!(result, 0);
    }

    fn symbol(self, handle: *mut c_void, name: &CStr) -> *mut c_void {
        // SAFETY: successful open reference and a NUL-terminated symbol name.
        let address = unsafe {
            match self {
                Self::Native => dlsym(handle, name.as_ptr()),
                Self::Host => {
                    let symbol: unsafe extern "C" fn(*mut c_void, *const libc::c_char) -> *mut c_void =
                        dlsym_oracle::host_fn(c"dlsym", dlsym as *const ());
                    symbol(handle, name.as_ptr())
                }
            }
        };
        assert!(!address.is_null(), "missing {name:?}");
        address
    }

    fn resident(self, path: &Path) -> bool {
        let handle = self.try_open(path, libc::RTLD_NOW | libc::RTLD_NOLOAD);
        if handle.is_null() {
            false
        } else {
            self.close(handle);
            true
        }
    }
}

/// Run each lifecycle scenario through both loaders in isolated processes.
/// A deadlock or constructor crash must fail the parent rather than hang CI.
/// Timeout is enforced outside the process which might deadlock in dlopen.
fn child_case(name: &str) -> Option<Loader> {
    if std::env::var("FL_INITFIRST_CHILD").as_deref() == Ok(name) {
        return Some(match std::env::var("FL_INITFIRST_LOADER").unwrap().as_str() {
            "host" => Loader::Host,
            "native" => Loader::Native,
            other => panic!("unknown loader {other}"),
        });
    }
    for loader in ["host", "native"] {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("FL_INITFIRST_CHILD", name).env("FL_INITFIRST_LOADER", loader)
            .env_remove("LD_DYNAMIC_WEAK").spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "{loader} initialization child failed: {status}");
                break;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                let _ = child.wait();
                panic!("{loader} initialization child deadlocked: {name}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    None
}

struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("fl_initfirst_{}_{stamp}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Self { dir }
    }

    fn compile(&self, name: &str, source: &str, flags: &[&str]) -> PathBuf {
        let input = self.dir.join(format!("{name}.cc"));
        let output = self.dir.join(format!("{name}.so"));
        std::fs::write(&input, source).unwrap();
        let result = Command::new("g++")
            .args(["-std=c++17", "-O2", "-shared", "-fPIC", "-nostdlib",
                   "-fno-exceptions", "-fno-rtti", "-Wl,--build-id=none"])
            .args(flags).arg(&input).arg("-o").arg(&output).output().unwrap();
        assert!(result.status.success(), "C++ fixture failed: {}", String::from_utf8_lossy(&result.stderr));
        let bytes = std::fs::read(&output).unwrap();
        let object = ElfLoader::new(0).parse(&bytes).unwrap();
        assert!(!object.program_headers.is_empty());
        output
    }
}

// GNU initialization-priority regression scenarios. Every DSO remains -nostdlib, so a native pass cannot be host fallback.
impl Fixture {
    fn lifecycle_sink(&self) -> PathBuf {
        self.compile("sink", r#"extern "C" {
            char fixture_events[128]; unsigned fixture_event_count;
            void (*fixture_init_hook)(int);
            void fixture_emit(int tag) {
                if (fixture_event_count < sizeof(fixture_events)-1) {
                    fixture_events[fixture_event_count++] = (char)tag;
                    fixture_events[fixture_event_count] = 0;
                }
                if (fixture_init_hook) fixture_init_hook(tag);
            }
        }"#, &["-Wl,-soname,sink.so"])
    }

    fn lifecycle_dso(&self, name: &str, tag: char, deps: &[&str], first: bool, bad: bool) -> PathBuf {
        let mut flags = vec![
            format!("-L{}", self.dir.display()), "-Wl,--no-as-needed".into(),
            "-Wl,-rpath,$ORIGIN".into(), format!("-Wl,-soname,{name}.so"),
        ];
        flags.extend(deps.iter().map(|name| format!("-l:{name}.so")));
        flags.push("-l:sink.so".into());
        if first { flags.push("-Wl,-z,initfirst".into()); }
        let unresolved = if bad {
            "extern int fixture_missing_initfirst; int *missing() { return &fixture_missing_initfirst; }"
        } else { "" };
        let source = format!(r#"extern "C" {{
            void fixture_emit(int);
            __attribute__((constructor)) static void start() {{ fixture_emit('{tag}'); }}
            __attribute__((destructor)) static void finish() {{ fixture_emit('{}'); }}
            {unresolved}
        }}"#, tag.to_ascii_lowercase());
        let refs = flags.iter().map(String::as_str).collect::<Vec<_>>();
        let path = self.compile(name, &source, &refs);
        // Inspect emitted runtime metadata, not merely compiler flags.
        let bytes = std::fs::read(&path).unwrap();
        let object = ElfLoader::new(0).parse(&bytes).unwrap();
        let mut initfirst = false;
        for header in &object.program_headers {
            if header.p_type != frankenlibc_core::elf::ProgramType::Dynamic { continue; }
            let start = usize::try_from(header.p_offset).unwrap();
            let len = usize::try_from(header.p_filesz).unwrap();
            for entry in bytes[start..start+len].chunks_exact(16) {
                let tag = i64::from_le_bytes(entry[..8].try_into().unwrap());
                let flags = u64::from_le_bytes(entry[8..].try_into().unwrap());
                if tag == 0 { break; }
                if tag == 0x6fff_fffb { initfirst |= flags & 0x20 != 0; }
            }
        }
        assert_eq!(initfirst, first, "fixture must really emit DF_1_INITFIRST");
        path
    }

    fn lifecycle_chain(&self, marked: &[&str]) -> PathBuf {
        self.lifecycle_dso("leaf", 'L', &[], marked.contains(&"leaf"), false);
        self.lifecycle_dso("middle", 'M', &["leaf"], marked.contains(&"middle"), false);
        self.lifecycle_dso("root", 'R', &["middle"], marked.contains(&"root"), false)
    }
}

fn events(loader: Loader, sink: *mut c_void) -> String {
    let address = loader.symbol(sink, c"fixture_events");
    // SAFETY: sink is kept open, emits at most 127 bytes, and always terminates.
    unsafe { CStr::from_ptr(address.cast()) }.to_str().unwrap().to_owned()
}

fn priority_case(loader: Loader, marked: &[&str], expected: &str) {
    let f = Fixture::new();
    let sink = loader.open(&f.lifecycle_sink(), 0);
    let path = f.lifecycle_chain(marked);
    let root = loader.open(&path, 0);
    assert_eq!(events(loader, sink), expected);
    // Reopening the same image must not run ANY constructor again.
    let again = loader.open(&path, 0);
    assert_eq!(events(loader, sink), expected);
    loader.close(again);
    assert_eq!(events(loader, sink), expected);
    loader.close(root);
    // Measured glibc behavior: FINI is still consumer-before-provider even
    // when INITFIRST changed the order in which their constructors ran.
    assert_eq!(events(loader, sink), format!("{expected}rml"));
    assert!(!loader.resident(&path));
    loader.close(sink);
}

#[test]
fn native_initfirst_unmarked_dependency_order_is_unchanged() {
    let Some(loader) = child_case("native_initfirst_unmarked_dependency_order_is_unchanged") else { return; };
    priority_case(loader, &[], "LMR");
}

#[test]
fn native_initfirst_root_runs_before_its_dependencies() {
    let Some(loader) = child_case("native_initfirst_root_runs_before_its_dependencies") else { return; };
    priority_case(loader, &["root"], "RLM");
}

#[test]
fn native_initfirst_dependency_runs_before_its_own_dependencies() {
    let Some(loader) = child_case("native_initfirst_dependency_runs_before_its_own_dependencies") else { return; };
    priority_case(loader, &["middle"], "MLR");
}

#[test]
fn native_initfirst_last_newly_mapped_marked_object_wins() {
    let Some(loader) = child_case("native_initfirst_last_newly_mapped_marked_object_wins") else { return; };
    priority_case(loader, &["root", "middle"], "MLR");
}

#[test]
fn native_initfirst_resident_dependency_is_not_reinitialized() {
    let Some(loader) = child_case("native_initfirst_resident_dependency_is_not_reinitialized") else { return; };
    let f = Fixture::new();
    let sink = loader.open(&f.lifecycle_sink(), 0);
    let path = f.lifecycle_chain(&["leaf"]);
    let leaf = loader.open(&f.dir.join("leaf.so"), 0);
    assert_eq!(events(loader, sink), "L");
    let root = loader.open(&path, 0);
    assert_eq!(events(loader, sink), "LMR");
    loader.close(root);
    assert_eq!(events(loader, sink), "LMRrm");
    loader.close(leaf);
    assert_eq!(events(loader, sink), "LMRrml");
    loader.close(sink);
}

#[test]
fn native_initfirst_failed_load_never_runs_or_leaks_priority() {
    let Some(loader) = child_case("native_initfirst_failed_load_never_runs_or_leaks_priority") else { return; };
    let f = Fixture::new();
    let sink = loader.open(&f.lifecycle_sink(), 0);
    let bad = f.lifecycle_dso("bad", 'X', &[], true, true);
    assert!(loader.try_open(&bad, libc::RTLD_NOW).is_null());
    assert_eq!(events(loader, sink), "");
    let path = f.lifecycle_chain(&[]);
    let root = loader.open(&path, 0);
    assert_eq!(events(loader, sink), "LMR");
    loader.close(root);
    assert_eq!(events(loader, sink), "LMRrml");
    assert!(!loader.resident(&bad));
    loader.close(sink);
}

thread_local! {
    static INITFIRST_REOPEN: std::cell::RefCell<Option<(Loader, PathBuf)>> = const { std::cell::RefCell::new(None) };
}
static INITFIRST_REOPENED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

unsafe extern "C" fn initfirst_reopen(tag: c_int) {
    if tag != 'R' as c_int { return; }
    // Drop the borrow before loader reentry, which could execute callbacks.
    let action = INITFIRST_REOPEN.with(|state| state.borrow_mut().take());
    if let Some((loader, path)) = action {
        let handle = loader.open(&path, 0);
        loader.close(handle);
        INITFIRST_REOPENED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[test]
fn native_initfirst_recursive_reopen_runs_each_constructor_once() {
    let Some(loader) = child_case("native_initfirst_recursive_reopen_runs_each_constructor_once") else { return; };
    let f = Fixture::new();
    let sink = loader.open(&f.lifecycle_sink(), 0);
    let path = f.lifecycle_chain(&["root"]);
    INITFIRST_REOPEN.with(|state| *state.borrow_mut() = Some((loader, path.clone())));
    let hook = loader.symbol(sink, c"fixture_init_hook")
        .cast::<Option<unsafe extern "C" fn(c_int)>>();
    // SAFETY: the symbol is a live, correctly typed function-pointer object.
    unsafe { *hook = Some(initfirst_reopen); }
    let root = loader.open(&path, 0);
    unsafe { *hook = None; }
    assert_eq!(INITFIRST_REOPENED.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(events(loader, sink), "RLM");
    loader.close(root);
    assert_eq!(events(loader, sink), "RLMrml");
    loader.close(sink);
}

#[test]
fn native_initfirst_cycle_initializes_and_finalizes_each_object_once() {
    let Some(loader) = child_case("native_initfirst_cycle_initializes_and_finalizes_each_object_once") else { return; };
    let f = Fixture::new();
    let sink = loader.open(&f.lifecycle_sink(), 0);
    // Link a SONAME-only placeholder, retained on disk. At runtime DT_NEEDED
    // resolves root.so, completing a cycle without deleting a fixture file.
    f.compile("placeholder_root", "extern \"C\" { int placeholder; }", &["-Wl,-soname,root.so"]);
    f.lifecycle_dso("leaf", 'L', &["placeholder_root"], false, false);
    f.lifecycle_dso("middle", 'M', &["leaf"], false, false);
    let path = f.lifecycle_dso("root", 'R', &["middle"], true, false);
    let root = loader.open(&path, 0);
    let before = events(loader, sink);
    assert!(before.starts_with('R'), "the cycle's INITFIRST root must run first");
    let mut tags = before.chars().collect::<Vec<_>>();
    tags.sort_unstable();
    assert_eq!(tags, ['L', 'M', 'R']);
    loader.close(root);
    let after = events(loader, sink);
    let mut finis = after[before.len()..].chars().collect::<Vec<_>>();
    finis.sort_unstable();
    assert_eq!(finis, ['l', 'm', 'r']);
    assert!(!loader.resident(&path));
    loader.close(sink);
}
