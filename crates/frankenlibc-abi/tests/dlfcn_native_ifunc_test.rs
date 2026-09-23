#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::{CString, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use frankenlibc_abi::dlfcn_abi::{dlclose, dlerror, dlopen, dlsym, dlvsym, native_dso_handle_for_tests};
use frankenlibc_core::elf::{ElfLoader, RelocationType};
#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

#[derive(Clone, Copy)]
enum Loader { Host, Native }
impl Loader {
    fn open(self, path: &Path, flags: c_int) -> *mut c_void {
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        let handle = unsafe {
            match self {
                Self::Native => dlopen(name.as_ptr(), flags),
                Self::Host => {
                    let open: unsafe extern "C" fn(*const libc::c_char, c_int) -> *mut c_void =
                        dlsym_oracle::host_fn(c"dlopen", dlopen as *const ());
                    open(name.as_ptr(), flags)
                }
            }
        };
        if matches!(self, Self::Native) && !handle.is_null() {
            assert!(native_dso_handle_for_tests(handle), "host fallback is not native IFUNC execution");
        }
        handle
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
    fn value(self, handle: *mut c_void, name: &str, value: c_int) -> c_int {
        // SAFETY: all called fixture functions have this exact signature.
        let function: unsafe extern "C" fn(c_int) -> c_int = unsafe { std::mem::transmute(self.symbol(handle, name)) };
        unsafe { function(value) }
    }
}

struct Fixture { dir: PathBuf }
impl Fixture {
    fn new() -> Self {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("fl_ifunc_{}_{stamp}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Self { dir }
    }
    fn compile(&self, name: &str, source: &str, dependencies: &[&Path], flags: &[&str]) -> PathBuf {
        let input = self.dir.join(format!("{name}.c"));
        let output = self.dir.join(format!("{name}.so"));
        std::fs::write(&input, source).unwrap();
        let result = Command::new("cc").args(["-shared", "-fPIC", "-nostdlib", "-Wl,--build-id=none"])
            .arg(&input).args(flags).arg("-Wl,--no-as-needed").args(dependencies)
            .arg("-o").arg(&output).output().unwrap();
        assert!(result.status.success(), "cc failed: {}", String::from_utf8_lossy(&result.stderr));
        output
    }
}

// A bad machine-code relocation must fail only its bounded child, not hide all
// later cases in this binary. This also turns loader-lock reentry into a failure.
fn child_case(name: &str) -> bool {
    if std::env::var("FL_IFUNC_CHILD").as_deref() == Ok(name) { return true; }
    let mut child = Command::new(std::env::current_exe().unwrap()).args(["--exact", name, "--nocapture"])
        .env("FL_IFUNC_CHILD", name).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "IFUNC child {name} failed: {status}");
            return false;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap(); let _ = child.wait();
            panic!("IFUNC child {name} deadlocked");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

const BASIC: &str = r#"
    static int count, constructed, value=21;
    static int *pointer=&value;
    static int implementation(int x) { return *pointer+x; }
    static void *choose(void) { ++count; return implementation; }
    int dispatch(int) __attribute__((ifunc("choose")));
    int (*slot)(int)=dispatch;
    __attribute__((constructor)) static void init(void) { constructed=1; }
    int call(int x) { return dispatch(x)+slot(x); }
    int calls(int unused) { return count; }
    int initialized(int unused) { return constructed; }
"#;

#[test]
fn native_ifunc_data_got_plt_and_lookup_match_host() {
    if !child_case("native_ifunc_data_got_plt_and_lookup_match_host") { return; }
    for flags in [vec![], vec!["-fno-plt"], vec!["-Wl,-z,now"]] {
        let mut observations = Vec::new();
        for loader in [Loader::Host, Loader::Native] {
            let f=Fixture::new(); let path=f.compile("basic",BASIC,&[],&flags);
            let bytes=std::fs::read(&path).unwrap(); let elf=ElfLoader::new(0).parse(&bytes).unwrap();
            assert!(elf.dynsym.iter().any(|symbol| symbol.is_ifunc()));
            assert!(elf.rela_dyn.iter().any(|reloc| reloc.reloc_type()==RelocationType::R64));
            let h=loader.open(&path,libc::RTLD_NOW); assert!(!h.is_null(), "IFUNC fixture must load natively");
            let initial=loader.value(h,"calls",0); assert!(initial>0);
            assert_eq!(loader.value(h,"call",4),50); assert_eq!(loader.value(h,"initialized",0),1);
            assert_eq!(loader.value(h,"calls",0),initial, "eager call must not resolve again");
            assert_eq!(loader.value(h,"dispatch",2),23);
            assert_eq!(loader.value(h,"dispatch",3),24);
            observations.push((initial,loader.value(h,"calls",0)));
            assert_eq!(observations.last().unwrap().1,initial+2, "dlsym resolves every request");
            let again=loader.open(&path,libc::RTLD_NOW); assert_eq!(again,h);
            assert_eq!(loader.value(h,"calls",0),initial+2);
            loader.close(again); loader.close(h);
        }
        assert_eq!(observations[0],observations[1]);
    }
}

#[test]
fn native_ifunc_irelative_sees_relocated_data_before_constructors() {
    if !child_case("native_ifunc_irelative_sees_relocated_data_before_constructors") { return; }
    for loader in [Loader::Host,Loader::Native] {
        let f=Fixture::new(); let path=f.compile("hidden",r#"
            static int value=31, initialized, calls;
            static int *pointer=&value;
            static int good(int x){return *pointer+x;}
            static int bad(int x){return -1;}
            static void *choose(void){++calls; return !initialized && *pointer==31 ? good : bad;}
            static int dispatch(int) __attribute__((ifunc("choose")));
            __attribute__((constructor)) static void init(void){initialized=1;}
            int call(int x){return dispatch(x);} int count(int x){return calls;}
        "#,&[],&[]);
        let bytes=std::fs::read(&path).unwrap(); let elf=ElfLoader::new(0).parse(&bytes).unwrap();
        assert!(elf.rela_plt.iter().chain(&elf.rela_dyn).any(|reloc| reloc.reloc_type()==RelocationType::IRelative));
        let h=loader.open(&path,libc::RTLD_NOW); assert!(!h.is_null());
        assert_eq!(loader.value(h,"call",1),32); assert_eq!(loader.value(h,"count",0),1); loader.close(h);
    }
}

#[test]
fn native_ifunc_versioned_imports_and_dependency_resolvers_match_host() {
    if !child_case("native_ifunc_versioned_imports_and_dependency_resolvers_match_host") { return; }
    for loader in [Loader::Host,Loader::Native] {
        let f=Fixture::new(); let version=f.dir.join("version.map");
        std::fs::write(&version,"IFUNC_1 { global: leaf_dispatch; local: *; };").unwrap();
        let flag=format!("-Wl,--version-script={}",version.display());
        let leaf=f.compile("leaf",r#"
            static int value=40; static int *p=&value;
            static int impl(int x){return *p+x;}
            static void *choose(void){return impl;}
            int leaf_dispatch(int) __attribute__((ifunc("choose")));
        "#,&[],&[&flag]);
        let root=f.compile("root",r#"
            extern int leaf_dispatch(int);
            static int good(int x){return leaf_dispatch(x)+1;}
            static int bad(int x){return -1;}
            static void *choose(void){return leaf_dispatch(0)==40 ? good : bad;}
            static int dispatch(int) __attribute__((ifunc("choose")));
            int call(int x){return dispatch(x);}
        "#,&[&leaf],&[]);
        let h=loader.open(&root,libc::RTLD_NOW); assert!(!h.is_null());
        assert_eq!(loader.value(h,"call",1),42);
        let lookup: unsafe extern "C" fn(*mut c_void,*const libc::c_char,*const libc::c_char)->*mut c_void = unsafe {
            match loader { Loader::Native=>dlvsym, Loader::Host=>dlsym_oracle::host_fn(c"dlvsym",dlvsym as *const ()) }
        };
        let address=unsafe{lookup(h,c"leaf_dispatch".as_ptr(),c"IFUNC_1".as_ptr())}; assert!(!address.is_null());
        let call: unsafe extern "C" fn(c_int)->c_int=unsafe{std::mem::transmute(address)};
        assert_eq!(unsafe{call(2)},42);
        assert!(unsafe{lookup(h,c"leaf_dispatch".as_ptr(),c"WRONG".as_ptr())}.is_null());
        loader.close(h);
    }
}

#[test]
fn native_ifunc_global_provider_survives_consumer_lifetime() {
    if !child_case("native_ifunc_global_provider_survives_consumer_lifetime") { return; }
    for loader in [Loader::Host,Loader::Native] {
        let f=Fixture::new(); let provider=f.compile("provider",r#"
            static int impl(int x){return 39+x;} static void *choose(void){return impl;}
            int provided(int) __attribute__((ifunc("choose")));
        "#,&[],&[]);
        let consumer=f.compile("consumer","extern int provided(int); int call(int x){return provided(x);}",&[],&[]);
        let p=loader.open(&provider,libc::RTLD_NOW|libc::RTLD_GLOBAL); assert!(!p.is_null());
        let h=loader.open(&consumer,libc::RTLD_NOW); assert!(!h.is_null());
        loader.close(p); assert_eq!(loader.value(h,"call",3),42);
        if matches!(loader,Loader::Native){assert!(native_dso_handle_for_tests(p));}
        loader.close(h);
        if matches!(loader,Loader::Native){assert!(!native_dso_handle_for_tests(p));}
    }
}

#[test]
fn native_ifunc_selected_code_without_needed_edge_is_retained() {
    if !child_case("native_ifunc_selected_code_without_needed_edge_is_retained") { return; }
    // A conservative native lifetime extension: even a resolver returning a
    // numeric address must not create a pointer to a subsequently unmapped DSO.
    for relocation in [false,true] {
        let f=Fixture::new(); let p=f.compile("implementation","int implementation(int x){return 40+x;}",&[],&[]);
        let p=Loader::Native.open(&p,libc::RTLD_NOW); assert!(!p.is_null());
        let address=Loader::Native.symbol(p,"implementation") as usize;
        let source=format!("static void *choose(void){{return (void*){address}UL;}} int dispatch(int) __attribute__((ifunc(\"choose\"))); {}",
            if relocation {"int call(int x){return dispatch(x);}"} else {""});
        let path=f.compile("selection",&source,&[],&[]);
        let h=Loader::Native.open(&path,libc::RTLD_NOW); assert!(!h.is_null());
        let selected=Loader::Native.symbol(h,if relocation{"call"}else{"dispatch"});
        Loader::Native.close(p); assert!(native_dso_handle_for_tests(p));
        let call: unsafe extern "C" fn(c_int)->c_int=unsafe{std::mem::transmute(selected)};
        assert_eq!(unsafe{call(2)},42); Loader::Native.close(h); assert!(!native_dso_handle_for_tests(p));
    }
}

#[test]
fn native_ifunc_ordinary_failure_runs_no_resolvers_or_constructors() {
    if !child_case("native_ifunc_ordinary_failure_runs_no_resolvers_or_constructors") { return; }
    let f=Fixture::new(); let sink=f.compile("sink","static int n; void record(void){++n;} int count(int x){return n;}",&[],&[]);
    let sink=Loader::Native.open(&sink,libc::RTLD_NOW|libc::RTLD_GLOBAL); assert!(!sink.is_null());
    let path=f.compile("broken",r#"
        extern void record(void); extern int absent; int *missing=&absent;
        static int impl(int x){return x;} static void *choose(void){record();return impl;}
        int dispatch(int) __attribute__((ifunc("choose")));
        int (*slot)(int)=dispatch;
        __attribute__((constructor)) static void init(void){record();}
    "#,&[],&[]);
    assert!(Loader::Native.open(&path,libc::RTLD_NOW).is_null());
    assert!(!unsafe{dlerror()}.is_null()); assert_eq!(Loader::Native.value(sink,"count",0),0);
    Loader::Native.close(sink); assert!(!native_dso_handle_for_tests(sink));
}

#[test]
fn native_ifunc_own_tls_writes_survive_initialization_and_reload() {
    if !child_case("native_ifunc_own_tls_writes_survive_initialization_and_reload") { return; }
    // Own-TLS-in-resolver support was only guaranteed by glibc 2.44. Do not
    // execute this through an older host oracle which may crash inside dlopen.
    let f=Fixture::new(); let path=f.compile("tls",r#"
        __thread int tls_value=11; static int seen;
        static int impl(int x){return tls_value+x;}
        static void *choose(void){++tls_value;return impl;}
        static int dispatch(int) __attribute__((ifunc("choose")));
        __attribute__((constructor)) static void init(void){seen=tls_value;}
        int call(int x){return dispatch(x);} int initial(int x){return seen;}
    "#,&[],&["-mtls-dialect=gnu"]);
    for _ in 0..2 {
        let h=Loader::Native.open(&path,libc::RTLD_NOW); assert!(!h.is_null());
        assert_eq!(Loader::Native.value(h,"initial",0),12);
        assert_eq!(Loader::Native.value(h,"call",0),12);
        let address=Loader::Native.symbol(h,"tls_value").cast::<c_int>(); assert_eq!(unsafe{*address},12);
        let raw=h as usize;
        std::thread::spawn(move||assert_eq!(Loader::Native.value(raw as *mut c_void,"call",0),11)).join().unwrap();
        Loader::Native.close(h);
    }
}

#[test]
fn native_ifunc_null_result_relocates_without_calling_zero() {
    if !child_case("native_ifunc_null_result_relocates_without_calling_zero") { return; }
    for loader in [Loader::Host,Loader::Native] {
        let f=Fixture::new(); let path=f.compile("null",r#"
            static void *choose(void){return 0;} int dispatch(int) __attribute__((ifunc("choose")));
            int (*slot)(int)=dispatch; int is_null(int x){return slot==0;}
        "#,&[],&[]);
        let h=loader.open(&path,libc::RTLD_NOW); assert!(!h.is_null());
        assert_eq!(loader.value(h,"is_null",0),1); loader.close(h);
    }
}

fn u16_at(bytes:&[u8],offset:usize)->usize{u16::from_le_bytes(bytes[offset..offset+2].try_into().unwrap()) as usize}
fn u64_at(bytes:&[u8],offset:usize)->u64{u64::from_le_bytes(bytes[offset..offset+8].try_into().unwrap())}

#[test]
fn native_ifunc_invalid_resolver_and_write_ranges_fail_closed() {
    if !child_case("native_ifunc_invalid_resolver_and_write_ranges_fail_closed") { return; }
    let f=Fixture::new(); let valid=f.compile("valid",r#"
        int data; static int impl(int x){return x;} static void *choose(void){return impl;}
        static int dispatch(int) __attribute__((ifunc("choose")));
        int call(int x){return dispatch(x);}
    "#,&[],&[]);
    let original=std::fs::read(&valid).unwrap(); let elf=ElfLoader::new(0).parse(&original).unwrap();
    let data=elf.lookup_symbol("data").unwrap().st_value;
    let text=elf.program_headers.iter().find(|p|p.is_load() && p.p_flags.is_executable()).unwrap().p_vaddr;
    let shoff=u64_at(&original,40) as usize; let stride=u16_at(&original,58); let count=u16_at(&original,60);
    let mut entry=None;
    for i in 0..count {
        let sh=shoff+i*stride;
        if u32::from_le_bytes(original[sh+4..sh+8].try_into().unwrap())!=4 {continue;}
        let offset=u64_at(&original,sh+24) as usize; let size=u64_at(&original,sh+32) as usize;
        for position in (offset..offset+size).step_by(24) {
            if u64_at(&original,position+8) as u32==37 {entry=Some(position);}
        }
    }
    let entry=entry.expect("fixture must emit IRELATIVE");
    for (name,field,value) in [("data-resolver",16,data),("bad-resolver",16,u64::MAX),
        ("outside-write",0,u64::MAX),("text-write",0,text),("symbol-index",8,(1u64<<32)|37)] {
        let mut bytes=original.clone(); bytes[entry+field..entry+field+8].copy_from_slice(&value.to_le_bytes());
        let path=f.dir.join(format!("{name}.so"));std::fs::write(&path,bytes).unwrap();
        assert!(Loader::Native.open(&path,libc::RTLD_NOW).is_null(),"accepted {name}");
        assert!(!unsafe{dlerror()}.is_null());
    }
    let h=Loader::Native.open(&valid,libc::RTLD_NOW);assert!(!h.is_null());assert_eq!(Loader::Native.value(h,"call",42),42);Loader::Native.close(h);
}

#[test]
fn native_ifunc_recursive_loader_calls_fail_without_deadlock() {
    if !child_case("native_ifunc_recursive_loader_calls_fail_without_deadlock") { return; }
    let f=Fixture::new();let target=f.dir.join("recursive.so");
    let source=format!(r#"
        extern void *dlopen(const char*,int); static int rejected;
        static int impl(int x){{return x;}}
        static void *choose(void){{rejected=dlopen({:?},2)==0;return impl;}}
        int dispatch(int) __attribute__((ifunc("choose")));
        int call(int x){{return dispatch(x);}} int denied(int x){{return rejected;}}
    "#,target.to_str().unwrap());
    let path=f.compile("recursive",&source,&[],&[]);
    let h=Loader::Native.open(&path,libc::RTLD_NOW);assert!(!h.is_null());
    assert_eq!(Loader::Native.value(h,"denied",0),1);assert_eq!(Loader::Native.value(h,"dispatch",42),42);
    Loader::Native.close(h);
}

#[test]
fn native_ifunc_relro_is_sealed_after_late_binding() {
    if !child_case("native_ifunc_relro_is_sealed_after_late_binding") { return; }
    let f=Fixture::new();let path=f.compile("relro",r#"
        int implementation(int x){return 40+x;} static void *choose(void){return implementation;}
        int dispatch(int) __attribute__((ifunc("choose")));
        int (*const readonly_slot)(int)=dispatch; int call(int x){return readonly_slot(x);}
    "#,&[],&["-Wl,-z,relro,-z,now"]);
    let h=Loader::Native.open(&path,libc::RTLD_NOW);assert!(!h.is_null());
    assert_eq!(Loader::Native.value(h,"call",2),42);
    let code=Loader::Native.symbol(h,"dispatch") as usize;
    let slot=Loader::Native.symbol(h,"readonly_slot") as usize;
    let maps=std::fs::read_to_string("/proc/self/maps").unwrap();
    for (address,expected) in [(code,"r-x"),(slot,"r--")] {
        let permissions=maps.lines().find_map(|line| {
            let mut fields=line.split_whitespace();let (start,end)=fields.next()?.split_once('-')?;
            let start=usize::from_str_radix(start,16).ok()?;let end=usize::from_str_radix(end,16).ok()?;
            let flags=fields.next()?; (start<=address && address<end).then_some(flags)
        }).unwrap();
        assert!(permissions.starts_with(expected),"address {address:x}: {permissions}");
    }
    Loader::Native.close(h);
}
