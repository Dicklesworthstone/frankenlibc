#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::{CString, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use frankenlibc_abi::dlfcn_abi::{dlclose, dlopen, dlsym, native_dso_handle_for_tests};
#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

#[derive(Clone, Copy)]
enum Loader { Host, Native }
impl Loader {
    fn open(self, path: &Path, flags: c_int) -> *mut c_void {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
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
        assert!(!handle.is_null(), "binding fixture must load");
        if matches!(self, Self::Native) { assert!(native_dso_handle_for_tests(handle), "host fallback is not native binding"); }
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
        let pointer = unsafe {
            match self {
                Self::Native => dlsym(handle, name.as_ptr()),
                Self::Host => {
                    let symbol: unsafe extern "C" fn(*mut c_void,*const libc::c_char)->*mut c_void =
                        dlsym_oracle::host_fn(c"dlsym", dlsym as *const ());
                    symbol(handle, name.as_ptr())
                }
            }
        };
        assert!(!pointer.is_null(), "missing {name:?}");
        pointer
    }
    fn value(self, handle: *mut c_void, name: &str, x: c_int) -> c_int {
        // SAFETY: fixture call sites declare this exact C function signature.
        let call: unsafe extern "C" fn(c_int)->c_int = unsafe { std::mem::transmute(self.symbol(handle,name)) };
        unsafe { call(x) }
    }
    fn data(self, handle: *mut c_void, name: &str) -> c_int {
        // SAFETY: fixture variables are live, aligned C integers.
        unsafe { *self.symbol(handle,name).cast::<c_int>() }
    }
}

struct Fixture { dir: PathBuf }
impl Fixture {
    fn new() -> Self {
        let stamp=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir=std::env::temp_dir().join(format!("fl_binding_{}_{stamp}",std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();Self{dir}
    }
    fn compile(&self,name:&str,source:&str,dependencies:&[&Path])->PathBuf {
        let input=self.dir.join(format!("{name}.c"));let output=self.dir.join(format!("{name}.so"));
        std::fs::write(&input,source).unwrap();
        let result=Command::new("cc").args(["-shared","-fPIC","-nostdlib","-Wl,--build-id=none"])
            .arg(&input).arg("-Wl,--no-as-needed").args(dependencies).arg("-o").arg(&output).output().unwrap();
        assert!(result.status.success(),"cc failed: {}",String::from_utf8_lossy(&result.stderr));output
    }
}

fn child_case(name:&str)->bool {
    if std::env::var("FL_BINDING_CHILD").as_deref()==Ok(name){return true;}
    let mut child=Command::new(std::env::current_exe().unwrap()).args(["--exact",name,"--nocapture"])
        .env("FL_BINDING_CHILD",name).env_remove("LD_DYNAMIC_WEAK").spawn().unwrap();
    let deadline=Instant::now()+Duration::from_secs(25);
    loop {
        if let Some(status)=child.try_wait().unwrap(){assert!(status.success(),"binding child failed: {status}");return false;}
        if Instant::now()>=deadline {child.kill().unwrap();let _=child.wait();panic!("binding child deadlocked: {name}");}
        std::thread::sleep(Duration::from_millis(20));
    }
}

const GLOBAL: &str="int binding_data=40; int binding_op(int x){return binding_data+x;}";
const LOCAL: &str="int binding_data=7; int binding_op(int x){return binding_data+x;} int answer(int x){return binding_op(x)+binding_data;}";

#[test]
fn native_binding_preempts_own_data_and_function_definitions() {
    if !child_case("native_binding_preempts_own_data_and_function_definitions"){return;}
    for loader in [Loader::Host,Loader::Native] {
        let f=Fixture::new();let global=f.compile("global",GLOBAL,&[]);let local=f.compile("local",LOCAL,&[]);
        let p=loader.open(&global,libc::RTLD_NOW|libc::RTLD_GLOBAL);
        let h=loader.open(&local,libc::RTLD_NOW);
        assert_eq!(loader.value(h,"answer",1),81,"default-visible definitions must be preempted");
        assert_eq!(loader.data(h,"binding_data"),7,"dlsym(handle) must not use relocation scope");
        // An open with new flags must not silently rebind resident relocations.
        let again=loader.open(&local,libc::RTLD_NOW|libc::RTLD_DEEPBIND);assert_eq!(again,h);
        assert_eq!(loader.value(h,"answer",1),81);loader.close(again);
        loader.close(p);assert_eq!(loader.value(h,"answer",1),81);
        if matches!(loader,Loader::Native){assert!(native_dso_handle_for_tests(p));}
        loader.close(h);
        if matches!(loader,Loader::Native){assert!(!native_dso_handle_for_tests(p));}
        let h=loader.open(&local,libc::RTLD_NOW);assert_eq!(loader.value(h,"answer",1),15);loader.close(h);
    }
}

#[test]
fn native_binding_deepbind_uses_root_and_dependency_scope() {
    if !child_case("native_binding_deepbind_uses_root_and_dependency_scope"){return;}
    for loader in [Loader::Host,Loader::Native] {
        for deep in [false,true] {
            let f=Fixture::new();let global=f.compile("global",GLOBAL,&[]);
            let dep=f.compile("dependency","int binding_data=8; int binding_op(int x){return binding_data+x;}",&[]);
            let root=f.compile("root","extern int binding_data; extern int binding_op(int); int answer(int x){return binding_op(x)+binding_data;}",&[&dep]);
            let p=loader.open(&global,libc::RTLD_NOW|libc::RTLD_GLOBAL);
            let h=loader.open(&root,libc::RTLD_NOW|if deep{libc::RTLD_DEEPBIND}else{0});
            assert_eq!(loader.value(h,"answer",1),if deep{17}else{81});
            assert_eq!(loader.data(h,"binding_data"),8);
            loader.close(h);loader.close(p);
        }
    }
}

fn u16_at(bytes:&[u8],offset:usize)->usize{u16::from_le_bytes(bytes[offset..offset+2].try_into().unwrap()) as usize}
fn u64_at(bytes:&[u8],offset:usize)->u64{u64::from_le_bytes(bytes[offset..offset+8].try_into().unwrap())}

fn add_symbolic_tag(path:&Path,tag:i64) {
    let mut bytes=std::fs::read(path).unwrap();let start=u64_at(&bytes,32) as usize;
    let stride=u16_at(&bytes,54);let count=u16_at(&bytes,56);let mut changed=false;
    for i in 0..count {
        let header=start+i*stride;
        if u32::from_le_bytes(bytes[header..header+4].try_into().unwrap())!=2{continue;}
        let offset=u64_at(&bytes,header+8) as usize;let size=u64_at(&bytes,header+32) as usize;
        for entry in (offset..offset+size).step_by(16) {
            if u64_at(&bytes,entry)==0 {
                assert!(entry+32<=offset+size);assert_eq!(u64_at(&bytes,entry+16),0);
                bytes[entry..entry+8].copy_from_slice(&tag.to_le_bytes());
                bytes[entry+8..entry+16].copy_from_slice(&(if tag==30{2u64}else{0u64}).to_le_bytes());
                changed=true;break;
            }
        }
    }
    assert!(changed);std::fs::write(path,bytes).unwrap();
}

#[test]
fn native_binding_honors_dynamic_symbolic_metadata() {
    if !child_case("native_binding_honors_dynamic_symbolic_metadata"){return;}
    for loader in [Loader::Host,Loader::Native] {
        for tag in [16,30] {
            let f=Fixture::new();let global=f.compile("global",GLOBAL,&[]);let local=f.compile("local",LOCAL,&[]);
            // Patching only runtime metadata preserves all preemptible dynamic
            // relocations. A -Bsymbolic-only fixture can be vacuous because the
            // static linker may have resolved those references already.
            add_symbolic_tag(&local,tag);
            let p=loader.open(&global,libc::RTLD_NOW|libc::RTLD_GLOBAL);
            let h=loader.open(&local,libc::RTLD_NOW);assert_eq!(loader.value(h,"answer",1),15);
            loader.close(h);loader.close(p);
        }
    }
}

#[test]
fn native_binding_protected_definitions_remain_local() {
    if !child_case("native_binding_protected_definitions_remain_local"){return;}
    for loader in [Loader::Host,Loader::Native] {
        let f=Fixture::new();let global=f.compile("global",GLOBAL,&[]);
        let local=f.compile("local",r#"
            __attribute__((visibility("protected"))) int binding_data=7;
            __attribute__((visibility("protected"))) int binding_op(int x){return binding_data+x;}
            int *data_slot=&binding_data; int(*function_slot)(int)=binding_op;
            int answer(int x){return function_slot(x)+*data_slot;}
        "#,&[]);
        let p=loader.open(&global,libc::RTLD_NOW|libc::RTLD_GLOBAL);let h=loader.open(&local,libc::RTLD_NOW);
        assert_eq!(loader.value(h,"answer",1),15);assert_eq!(loader.data(h,"binding_data"),7);
        loader.close(h);loader.close(p);
    }
}

#[test]
fn native_binding_regular_function_can_preempt_ifunc() {
    if !child_case("native_binding_regular_function_can_preempt_ifunc"){return;}
    for loader in [Loader::Host,Loader::Native] {
        for deep in [false,true] {
            let f=Fixture::new();let global=f.compile("global","int binding_dispatch(int x){return 90+x;}",&[]);
            let local=f.compile("local",r#"
                static int calls; static int implementation(int x){return 20+x;}
                static void *choose(void){++calls;return implementation;}
                int binding_dispatch(int) __attribute__((ifunc("choose")));
                int answer(int x){return binding_dispatch(x);} int count(int x){return calls;}
            "#,&[]);
            let p=loader.open(&global,libc::RTLD_NOW|libc::RTLD_GLOBAL);
            let h=loader.open(&local,libc::RTLD_NOW|if deep{libc::RTLD_DEEPBIND}else{0});
            assert_eq!(loader.value(h,"answer",1),if deep{21}else{91});
            assert_eq!(loader.value(h,"count",0),if deep{1}else{0});
            assert_eq!(loader.value(h,"binding_dispatch",1),21,"explicit lookup selects the owning IFUNC");
            assert_eq!(loader.value(h,"count",0),if deep{2}else{1});
            loader.close(h);loader.close(p);
        }
    }
}

#[test]
fn native_binding_ifunc_can_preempt_regular_function() {
    if !child_case("native_binding_ifunc_can_preempt_regular_function"){return;}
    for loader in [Loader::Host,Loader::Native] {
        for deep in [false,true] {
            let f=Fixture::new();let global=f.compile("global",r#"
                static int implementation(int x){return 90+x;} static void *choose(void){return implementation;}
                int binding_dispatch(int) __attribute__((ifunc("choose")));
            "#,&[]);
            let local=f.compile("local","int binding_dispatch(int x){return 20+x;} int answer(int x){return binding_dispatch(x);}",&[]);
            let p=loader.open(&global,libc::RTLD_NOW|libc::RTLD_GLOBAL);
            let h=loader.open(&local,libc::RTLD_NOW|if deep{libc::RTLD_DEEPBIND}else{0});
            assert_eq!(loader.value(h,"answer",1),if deep{21}else{91});
            assert_eq!(loader.value(h,"binding_dispatch",1),21);
            loader.close(h);loader.close(p);
        }
    }
}

#[test]
fn native_binding_tls_uses_the_same_deepbind_scope() {
    if !child_case("native_binding_tls_uses_the_same_deepbind_scope"){return;}
    for loader in [Loader::Host,Loader::Native] {
        for deep in [false,true] {
            let f=Fixture::new();let global=f.compile("global","__thread int binding_tls=90;",&[]);
            let local=f.compile("local","__thread int binding_tls=20; int answer(int x){return binding_tls+x;}",&[]);
            let p=loader.open(&global,libc::RTLD_NOW|libc::RTLD_GLOBAL);
            let h=loader.open(&local,libc::RTLD_NOW|if deep{libc::RTLD_DEEPBIND}else{0});
            assert_eq!(loader.value(h,"answer",1),if deep{21}else{91});
            assert_eq!(loader.data(h,"binding_tls"),20);
            let raw=h as usize;
            std::thread::spawn(move||{
                assert_eq!(loader.value(raw as *mut c_void,"answer",1),if deep{21}else{91});
                assert_eq!(loader.data(raw as *mut c_void,"binding_tls"),20);
            }).join().unwrap();
            loader.close(h);loader.close(p);
        }
    }
}

#[test]
fn native_binding_weak_references_and_first_provider_match_host() {
    if !child_case("native_binding_weak_references_and_first_provider_match_host"){return;}
    for loader in [Loader::Host,Loader::Native] {
        let f=Fixture::new();let weak=f.compile("weak","__attribute__((weak)) int binding_choice(int x){return 10+x;}",&[]);
        let strong=f.compile("strong","int binding_choice(int x){return 20+x;}",&[]);
        let root=f.compile("root",r#"
            extern int absent_optional(int) __attribute__((weak));
            extern int absent_data __attribute__((weak));
            extern int binding_choice(int);
            int answer(int x){if(absent_optional || &absent_data)return -1;return binding_choice(x);}
        "#,&[]);
        let w=loader.open(&weak,libc::RTLD_NOW|libc::RTLD_GLOBAL);let s=loader.open(&strong,libc::RTLD_NOW|libc::RTLD_GLOBAL);
        let h=loader.open(&root,libc::RTLD_NOW);assert_eq!(loader.value(h,"answer",1),11);
        loader.close(h);loader.close(s);loader.close(w);
    }
}
