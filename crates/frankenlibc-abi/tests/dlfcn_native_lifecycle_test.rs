#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::{CString, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use frankenlibc_abi::dlfcn_abi::{dlclose, dlopen, dlsym, native_dso_handle_for_tests};
#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

static SERIAL: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy)]
enum Loader { Native, Host }
impl Loader {
    fn open(self, path: &Path, flags: c_int) -> *mut c_void {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let result = unsafe {
            match self {
                Self::Native => dlopen(path.as_ptr(), flags),
                Self::Host => {
                    let open: unsafe extern "C" fn(*const libc::c_char, c_int) -> *mut c_void =
                        dlsym_oracle::host_fn(c"dlopen", dlopen as *const ());
                    open(path.as_ptr(), flags)
                }
            }
        };
        if matches!(self, Self::Native) && !result.is_null() {
            assert!(native_dso_handle_for_tests(result), "host fallback is not native execution");
        }
        result
    }
    fn close(self, handle: *mut c_void) {
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
    fn symbol(self, handle: *mut c_void, name: &str) -> *mut c_void {
        let name = CString::new(name).unwrap();
        let result = unsafe {
            match self {
                Self::Native => dlsym(handle, name.as_ptr()),
                Self::Host => {
                    let lookup: unsafe extern "C" fn(*mut c_void, *const libc::c_char) -> *mut c_void =
                        dlsym_oracle::host_fn(c"dlsym", dlsym as *const ());
                    lookup(handle, name.as_ptr())
                }
            }
        };
        assert!(!result.is_null(), "missing symbol {name:?}");
        result
    }
    fn value(self, handle: *mut c_void, name: &str) -> c_int {
        let function: unsafe extern "C" fn() -> c_int = unsafe { std::mem::transmute(self.symbol(handle, name)) };
        unsafe { function() }
    }
}

struct Fixture { dir: PathBuf, prefix: String }
impl Fixture {
    fn new() -> Self {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let prefix = format!("fl_lifecycle_{}_{stamp}", std::process::id());
        let dir = std::env::temp_dir().join(&prefix);
        std::fs::create_dir_all(&dir).unwrap();
        Self { dir, prefix }
    }
    fn compile(&self, name: &str, source: &str, dependencies: &[&Path], flags: &[&str]) -> PathBuf {
        let source_path = self.dir.join(format!("{name}.c"));
        let library = self.dir.join(format!("{name}.so"));
        let source = source.replace("event_push", &format!("{}_push", self.prefix))
            .replace("event_count", &format!("{}_count", self.prefix))
            .replace("event_get", &format!("{}_get", self.prefix));
        std::fs::write(&source_path, source).unwrap();
        let output = Command::new("cc").args(["-shared", "-fPIC", "-nostdlib", "-Wl,--build-id=none"])
            .arg(&source_path).args(flags).arg("-Wl,--no-as-needed").args(dependencies)
            .arg("-o").arg(&library).output().unwrap();
        assert!(output.status.success(), "cc failed: {}", String::from_utf8_lossy(&output.stderr));
        library
    }
    fn sink(&self, loader: Loader) -> *mut c_void {
        let path = self.compile("sink", "static int values[128], count; void event_push(int x) { if(count<128) values[count++]=x; } int event_count(void) { return count; } int event_get(int i) { return values[i]; }", &[], &[]);
        let handle = loader.open(&path, libc::RTLD_NOW | libc::RTLD_GLOBAL);
        assert!(!handle.is_null());
        handle
    }
    fn events(&self, loader: Loader, sink: *mut c_void) -> Vec<c_int> {
        let count = loader.value(sink, &format!("{}_count", self.prefix));
        assert!((0..=128).contains(&count));
        let get: unsafe extern "C" fn(c_int) -> c_int = unsafe { std::mem::transmute(loader.symbol(sink, &format!("{}_get", self.prefix))) };
        (0..count).map(|i| unsafe { get(i) }).collect()
    }
}

// Reentrant callbacks are tested in bounded subprocesses, so a regression in
// lock ordering fails the test rather than wedging the entire test campaign.
fn child_case(name: &str) -> bool {
    if std::env::var("FL_LIFECYCLE_CHILD").as_deref() == Ok(name) { return true; }
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env("FL_LIFECYCLE_CHILD", name).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "child {name} failed: {status}");
            return false;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("native loader callback deadlocked in {name}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn native_lifecycle_soname_reopen_preserves_identity_and_global_promotion() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for loader in [Loader::Host, Loader::Native] {
        let fixture = Fixture::new();
        let sink = fixture.sink(loader);
        let soname = format!("lib{}_resident.so", fixture.prefix);
        let soname_flag = format!("-Wl,-soname,{soname}");
        let library = fixture.compile(
            "resident",
            r#"
                extern void event_push(int);
                static int starts;
                __attribute__((constructor)) static void init(void) {
                    ++starts; event_push(17);
                }
                __attribute__((destructor)) static void fini(void) {
                    event_push(-17);
                }
                int resident_started(void) { return starts; }
            "#,
            &[],
            &[&soname_flag],
        );
        let consumer = fixture.compile(
            "consumer",
            "extern int resident_started(void); int result(void) { return resident_started(); }",
            &[],
            &[],
        );
        let first = loader.open(&library, libc::RTLD_NOW | libc::RTLD_LOCAL);
        assert!(!first.is_null(), "initial pathname open failed");
        assert_eq!(loader.value(first, "resident_started"), 1);
        assert_eq!(fixture.events(loader, sink), [17]);
        assert!(
            loader.open(&consumer, libc::RTLD_NOW).is_null(),
            "LOCAL provider must not satisfy an unrelated consumer"
        );

        // The SONAME denotes the retained image, not the current filesystem.
        std::fs::rename(&library, fixture.dir.join("resident-renamed.so")).unwrap();
        let second = loader.open(Path::new(&soname), libc::RTLD_NOW);
        assert_eq!(second, first, "SONAME reopen must retain native identity");
        let third = loader.open(
            Path::new(&soname),
            libc::RTLD_NOW | libc::RTLD_NOLOAD | libc::RTLD_GLOBAL,
        );
        assert_eq!(third, first, "NOLOAD promotion must reuse the resident image");
        assert_eq!(loader.value(third, "resident_started"), 1);
        assert_eq!(fixture.events(loader, sink), [17], "constructor ran twice");

        let dependent = loader.open(&consumer, libc::RTLD_NOW);
        assert!(!dependent.is_null(), "GLOBAL promotion was not observed");
        assert_eq!(loader.value(dependent, "result"), 1);
        loader.close(first);
        loader.close(second);
        loader.close(third);
        assert_eq!(
            fixture.events(loader, sink),
            [17],
            "relocation consumer must retain the provider after explicit closes"
        );
        loader.close(dependent);
        assert_eq!(fixture.events(loader, sink), [17, -17]);
        assert!(
            loader
                .open(Path::new(&soname), libc::RTLD_NOW | libc::RTLD_NOLOAD)
                .is_null(),
            "NOLOAD must not reopen an unloaded SONAME"
        );
        loader.close(sink);
    }
}

#[test]
fn native_lifecycle_runtime_metadata_ignores_section_headers() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for loader in [Loader::Host, Loader::Native] {
        let fixture = Fixture::new();
        let sink = fixture.sink(loader);
        for variant in ["ordinary", "emit-relocs", "null-section", "no-sections", "bad-section-offset"] {
            let flags: &[&str] = if variant == "emit-relocs" {
                &["-Wl,--emit-relocs"]
            } else {
                &[]
            };
            let library = fixture.compile(
                variant,
                r#"
                    extern void event_push(int);
                    static int value = 40;
                    static int *pointer = &value;
                    __attribute__((constructor)) static void init(void) {
                        *pointer += 2; event_push(23);
                    }
                    __attribute__((destructor)) static void fini(void) {
                        event_push(-23);
                    }
                    int result(void) { return *pointer; }
                "#,
                &[],
                flags,
            );
            let mut bytes = std::fs::read(&library).unwrap();
            assert_eq!(&bytes[..6], b"\x7fELF\x02\x01");
            let section_count = u16::from_le_bytes(bytes[60..62].try_into().unwrap());
            assert!(section_count > 1, "fixture must originally carry sections");
            match variant {
                // Leave a present but uninformative table. An implementation
                // branching on sections.is_empty() cannot recover the symbols.
                "null-section" => {
                    bytes[60..62].copy_from_slice(&1u16.to_le_bytes());
                    bytes[62..64].copy_from_slice(&0u16.to_le_bytes());
                }
                "no-sections" => {
                    bytes[40..48].fill(0);
                    bytes[58..64].fill(0);
                }
                "bad-section-offset" => {
                    bytes[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
                }
                _ => {}
            }
            std::fs::write(&library, &bytes).unwrap();
            let before = fixture.events(loader, sink).len();
            let handle = loader.open(&library, libc::RTLD_NOW);
            assert!(!handle.is_null(), "runtime image rejected: {variant}");
            assert_eq!(loader.value(handle, "result"), 42, "variant={variant}");
            assert_eq!(&fixture.events(loader, sink)[before..], &[23]);
            loader.close(handle);
            assert_eq!(&fixture.events(loader, sink)[before..], &[23, -23]);
        }
        loader.close(sink);
    }
}

#[test]
fn native_lifecycle_malformed_dynamic_metadata_cannot_use_sections() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new();
    let sink = fixture.sink(Loader::Native);
    let source = fixture.compile(
        "runtime-source",
        r#"
            extern void event_push(int);
            static int value = 40;
            static int *pointer = &value;
            __attribute__((constructor)) static void init(void) {
                *pointer += 2; event_push(29);
            }
            int result(void) { return *pointer; }
        "#,
        &[],
        &[],
    );
    let original = std::fs::read(&source).unwrap();
    let parser = frankenlibc_core::elf::ElfLoader::new(0);
    let object = parser.parse(&original).unwrap();
    assert!(!object.section_headers.is_empty());
    assert!(!object.rela_dyn.is_empty());
    let dynamic = object
        .program_headers
        .iter()
        .find(|header| header.p_type == frankenlibc_core::elf::ProgramType::Dynamic)
        .unwrap();
    let start = usize::try_from(dynamic.p_offset).unwrap();
    let end = start.checked_add(usize::try_from(dynamic.p_filesz).unwrap()).unwrap();
    for (case, tag, value) in [
        ("bad-rela-entry-size", 9i64, 8u64),
        ("unmapped-symbol-table", 6, u64::MAX),
        ("unmapped-rela-table", 7, u64::MAX),
    ] {
        let mut bytes = original.clone();
        let mut changed = false;
        for entry in bytes[start..end].chunks_exact_mut(16) {
            let current = i64::from_le_bytes(entry[..8].try_into().unwrap());
            if current == 0 {
                break;
            }
            if current == tag {
                entry[8..16].copy_from_slice(&value.to_le_bytes());
                changed = true;
            }
        }
        assert!(changed, "fixture did not contain required dynamic tag: {case}");
        assert!(
            parser.parse(&bytes).is_err(),
            "valid sections must not rescue invalid PT_DYNAMIC: {case}"
        );
        let library = fixture.dir.join(format!("{case}.so"));
        std::fs::write(&library, bytes).unwrap();
        assert!(
            Loader::Native.open(&library, libc::RTLD_NOW).is_null(),
            "invalid runtime metadata was published: {case}"
        );
        assert!(fixture.events(Loader::Native, sink).is_empty());
    }
    Loader::Native.close(sink);
}

#[test]
fn native_lifecycle_priority_reopen_reload_matches_host() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for loader in [Loader::Host, Loader::Native] {
        let fixture = Fixture::new(); let sink = fixture.sink(loader);
        let library = fixture.compile("ordered", r#"
            extern void event_push(int); static int value;
            void legacy_init(void) { value=1; event_push(10); }
            __attribute__((constructor(200))) static void init2(void) { value=value*10+2; event_push(20); }
            __attribute__((constructor(300))) static void init3(void) { value=value*10+3; event_push(30); }
            __attribute__((destructor(200))) static void fini2(void) { event_push(-20); }
            __attribute__((destructor(300))) static void fini3(void) { event_push(-30); }
            void legacy_fini(void) { event_push(-10); }
            int result(void) { return value; }
        "#, &[], &["-Wl,-init,legacy_init", "-Wl,-fini,legacy_fini"]);
        for iteration in 1..=2 {
            let first = loader.open(&library, libc::RTLD_NOW); assert!(!first.is_null());
            assert_eq!(loader.value(first, "result"), 123);
            let second = loader.open(&library, libc::RTLD_NOW); assert_eq!(first, second);
            loader.close(first);
            assert_eq!(fixture.events(loader, sink).len(), (iteration - 1) * 6 + 3);
            loader.close(second);
            assert_eq!(fixture.events(loader, sink), [10,20,30,-30,-20,-10].repeat(iteration));
        }
        loader.close(sink);
    }
}

#[test]
fn native_lifecycle_shared_dependency_order_matches_host() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for loader in [Loader::Host, Loader::Native] {
        let f = Fixture::new(); let sink = f.sink(loader);
        let leaf = f.compile("leaf", "extern void event_push(int); __attribute__((constructor)) void init(void){event_push(1);} __attribute__((destructor)) void fini(void){event_push(-1);} int leaf(void){return 7;}", &[], &["-Wl,-Bsymbolic"]);
        let mid = f.compile("mid", "extern void event_push(int); extern int leaf(void); __attribute__((constructor)) void init(void){event_push(leaf()-5);} __attribute__((destructor)) void fini(void){event_push(-2);} int mid(void){return leaf();}", &[&leaf], &["-Wl,-Bsymbolic"]);
        let root = f.compile("root", "extern void event_push(int); __attribute__((constructor)) void init(void){event_push(3);} __attribute__((destructor)) void fini(void){event_push(-3);}", &[&mid], &["-Wl,-Bsymbolic"]);
        let other = f.compile("other", "extern void event_push(int); __attribute__((constructor)) void init(void){event_push(4);} __attribute__((destructor)) void fini(void){event_push(-4);}", &[&leaf], &["-Wl,-Bsymbolic"]);
        let first=loader.open(&root,libc::RTLD_NOW); assert!(!first.is_null());
        let second=loader.open(&other,libc::RTLD_NOW); assert!(!second.is_null());
        assert_eq!(f.events(loader,sink), [1,2,3,4]);
        loader.close(first); assert_eq!(f.events(loader,sink), [1,2,3,4,-3,-2]);
        loader.close(second); assert_eq!(f.events(loader,sink), [1,2,3,4,-3,-2,-4,-1]);
        loader.close(sink);
    }
}

#[test]
fn native_lifecycle_callbacks_can_reenter_loader() {
    if !child_case("native_lifecycle_callbacks_can_reenter_loader") { return; }
    for loader in [Loader::Host, Loader::Native] {
        let f=Fixture::new(); let sink=f.sink(loader);
        let child=f.compile("child","extern void event_push(int); __attribute__((constructor)) static void init(void){event_push(1);} __attribute__((destructor)) static void fini(void){event_push(-1);} int answer(void){return 7;}",&[],&[]);
        let source=format!(r#"
            extern void event_push(int); extern void *dlopen(const char*,int); extern void *dlsym(void*,const char*); extern int dlclose(void*);
            static void *child; static int value;
            __attribute__((constructor)) static void init(void) {{ event_push(10); child=dlopen({:?},2); if(child){{ int(*answer)(void)=dlsym(child,"answer"); if(answer)value=answer(); }} event_push(20); }}
            __attribute__((destructor)) static void fini(void) {{ event_push(-20); if(child)dlclose(child); event_push(-10); }}
            int result(void){{return value;}}
        "#, child.to_str().unwrap());
        let root=f.compile("root",&source,&[],&[]);
        let h=loader.open(&root,libc::RTLD_NOW); assert!(!h.is_null()); assert_eq!(loader.value(h,"result"),7);
        assert_eq!(f.events(loader,sink),[10,1,20]); loader.close(h);
        // Live glibc defers the child finalizer until the enclosing finalizer
        // has returned; the nested dlclose updates counts without recursing.
        assert_eq!(f.events(loader,sink),[10,1,20,-20,-10,-1]); loader.close(sink);
    }
}

#[test]
fn native_lifecycle_concurrent_first_opens_initialize_once() {
    if !child_case("native_lifecycle_concurrent_first_opens_initialize_once") { return; }
    let f=Fixture::new(); let sink=f.sink(Loader::Native);
    let path=f.compile("slow","extern void event_push(int); static int value; __attribute__((constructor)) static void init(void){for(volatile unsigned i=0;i<1000000;i++){} value=123; event_push(1);} __attribute__((destructor)) static void fini(void){event_push(-1);} int result(void){return value;}",&[],&[]);
    let barrier=Arc::new(Barrier::new(8));
    let threads=(0..8).map(|_| {let path=path.clone();let barrier=barrier.clone();std::thread::spawn(move||{
        barrier.wait(); let h=Loader::Native.open(&path,libc::RTLD_NOW); assert!(!h.is_null());
        assert_eq!(Loader::Native.value(h,"result"),123); h as usize
    })}).collect::<Vec<_>>();
    let handles=threads.into_iter().map(|thread|thread.join().unwrap()).collect::<Vec<_>>();
    assert!(handles.iter().all(|handle|*handle==handles[0])); assert_eq!(f.events(Loader::Native,sink),[1]);
    for h in handles {Loader::Native.close(h as *mut c_void);}
    assert_eq!(f.events(Loader::Native,sink),[1,-1]); Loader::Native.close(sink);
}

#[test]
fn native_lifecycle_invalid_callbacks_roll_back_before_any_initializer() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let f=Fixture::new();let sink=f.sink(Loader::Native);
    let dependency=f.compile("dependency","extern void event_push(int); __attribute__((constructor)) static void init(void){event_push(1);}",&[],&[]);
    for (name,value) in [("outside","(void*)0x123"),("data","(void*)&data")] {
        let source=format!("static int data; __attribute__((used,section(\".init_array\"))) static void (*bad)(void)={value};");
        let path=f.compile(name,&source,&[&dependency],&[]);
        assert!(Loader::Native.open(&path,libc::RTLD_NOW).is_null());
        assert!(f.events(Loader::Native,sink).is_empty());
        assert!(Loader::Native.open(&dependency,libc::RTLD_NOW|libc::RTLD_NOLOAD).is_null());
    }
    Loader::Native.close(sink);
}

#[test]
fn native_lifecycle_nodelete_defers_finalization() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for loader in [Loader::Host, Loader::Native] {
        let f=Fixture::new();let sink=f.sink(loader);
        let path=f.compile("pinned","extern void event_push(int); __attribute__((constructor)) static void init(void){event_push(1);} __attribute__((destructor)) static void fini(void){event_push(-1);}",&[],&[]);
        let h=loader.open(&path,libc::RTLD_NOW|libc::RTLD_NODELETE); assert!(!h.is_null());loader.close(h);
        assert_eq!(f.events(loader,sink),[1]);let again=loader.open(&path,libc::RTLD_NOW);assert_eq!(again,h);loader.close(again);
        assert_eq!(f.events(loader,sink),[1]);loader.close(sink);
    }
}

#[test]
fn native_lifecycle_constructor_receives_argument_vectors() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for loader in [Loader::Host, Loader::Native] {
        let f=Fixture::new();
        let path=f.compile("arguments","static int ok; __attribute__((constructor)) static void init(int argc,char **argv,char **envp){ok=argc>0 && argv && argv[0] && argv[argc]==0 && envp;} int result(void){return ok;}",&[],&[]);
        let h=loader.open(&path,libc::RTLD_NOW);assert!(!h.is_null());assert_eq!(loader.value(h,"result"),1);loader.close(h);
    }
}

#[test]
fn native_lifecycle_cycle_keeps_every_mapping_until_finalizers_finish() {
    if !child_case("native_lifecycle_cycle_keeps_every_mapping_until_finalizers_finish") { return; }
    let f=Fixture::new();let sink=f.sink(Loader::Native);
    let seed=f.compile("a","int a_value(void){return 80;}",&[],&[]);
    let b=f.compile("b","extern void event_push(int); extern int a_value(void); int b_value(void){return 70;} __attribute__((constructor)) static void init(void){event_push(20);} __attribute__((destructor)) static void fini(void){event_push(-20);event_push(a_value());}",&[&seed],&[]);
    let a=f.compile("a","extern void event_push(int); extern int b_value(void); int a_value(void){return 80;} __attribute__((constructor)) static void init(void){event_push(10);} __attribute__((destructor)) static void fini(void){event_push(-10);event_push(b_value());}",&[&b],&[]);
    let h=Loader::Native.open(&a,libc::RTLD_NOW);assert!(!h.is_null());
    assert_eq!(f.events(Loader::Native,sink),[20,10]);Loader::Native.close(h);
    assert_eq!(f.events(Loader::Native,sink),[20,10,-10,70,-20,80]);
    assert!(Loader::Native.open(&a,libc::RTLD_NOW|libc::RTLD_NOLOAD).is_null());
    assert!(Loader::Native.open(&b,libc::RTLD_NOW|libc::RTLD_NOLOAD).is_null());
    Loader::Native.close(sink);
}

#[test]
fn native_lifecycle_self_reopen_does_not_repeat_initialization() {
    if !child_case("native_lifecycle_self_reopen_does_not_repeat_initialization") { return; }
    let f=Fixture::new();let sink=f.sink(Loader::Native);
    let path=f.dir.join("self.so");
    let source=format!(r#"
        extern void event_push(int); extern void *dlopen(const char*,int); extern int dlclose(void*);
        __attribute__((constructor)) static void init(void){{event_push(1);void *h=dlopen({:?},2);event_push(h?2:99);if(h)dlclose(h);event_push(3);}}
        __attribute__((destructor)) static void fini(void){{event_push(-1);void *h=dlopen({:?},2);event_push(h?99:-2);if(h)dlclose(h);}}
    "#,path.to_str().unwrap(),path.to_str().unwrap());
    let path=f.compile("self",&source,&[],&[]);
    let h=Loader::Native.open(&path,libc::RTLD_NOW);assert!(!h.is_null());
    assert_eq!(f.events(Loader::Native,sink),[1,2,3]);Loader::Native.close(h);
    assert_eq!(f.events(Loader::Native,sink),[1,2,3,-1,-2]);
    assert!(!native_dso_handle_for_tests(h));Loader::Native.close(sink);
}


fn replace_dynamic_value(path: &Path, wanted: i64, replacement: u64) {
    let mut bytes = std::fs::read(path).unwrap();
    let phoff = u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize;
    let stride = u16::from_le_bytes(bytes[54..56].try_into().unwrap()) as usize;
    let count = u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as usize;
    for index in 0..count {
        let header = phoff + index * stride;
        if u32::from_le_bytes(bytes[header..header+4].try_into().unwrap()) != 2 { continue; }
        let offset = u64::from_le_bytes(bytes[header+8..header+16].try_into().unwrap()) as usize;
        let size = u64::from_le_bytes(bytes[header+32..header+40].try_into().unwrap()) as usize;
        for entry in (offset..offset+size).step_by(16) {
            let tag = i64::from_le_bytes(bytes[entry..entry+8].try_into().unwrap());
            if tag == 0 { break; }
            if tag == wanted {
                bytes[entry+8..entry+16].copy_from_slice(&replacement.to_le_bytes());
                std::fs::write(path, bytes).unwrap();
                return;
            }
        }
    }
    panic!("fixture did not contain dynamic tag {wanted}");
}

#[test]
fn native_lifecycle_rejects_malformed_array_metadata_without_side_effects() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let f=Fixture::new();let sink=f.sink(Loader::Native);
    let dependency=f.compile("dependency","extern void event_push(int); __attribute__((constructor)) static void init(void){event_push(1);}",&[],&[]);
    let source="extern void event_push(int); __attribute__((constructor)) static void init(void){event_push(2);} __attribute__((destructor)) static void fini(void){event_push(-2);}";
    for (index,(tag,value)) in [(27,9),(28,9),(25,u64::MAX-7),(26,u64::MAX-7),(27,8*65537)].into_iter().enumerate() {
        let path=f.compile(&format!("malformed{index}"),source,&[&dependency],&[]);
        replace_dynamic_value(&path,tag,value);
        assert!(Loader::Native.open(&path,libc::RTLD_NOW).is_null());
        assert!(f.events(Loader::Native,sink).is_empty());
        assert!(Loader::Native.open(&dependency,libc::RTLD_NOW|libc::RTLD_NOLOAD).is_null());
    }
    Loader::Native.close(sink);
}
