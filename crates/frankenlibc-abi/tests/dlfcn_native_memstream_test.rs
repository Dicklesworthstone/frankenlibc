#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use frankenlibc_abi::{dlfcn_abi as dl, stdio_abi as stdio};
use frankenlibc_core::elf::ElfLoader;
#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

type Open = unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void;
type Sym = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
type Close = unsafe extern "C" fn(*mut c_void) -> c_int;
type Error = unsafe extern "C" fn() -> *const c_char;
type Frontend = unsafe extern "C" fn(usize, c_int, *const c_char) -> *mut c_void;

const SOURCE: &str = r#"#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include <unistd.h>
#define REQUIRE(x,n) do { if (!(x)) return (n); } while (0)
#ifdef WEAK_MALLOC
extern void *malloc(size_t) __attribute__((weak));
#endif
int version_anchor(void) { return 1; }
int fmem_version_anchor(void) { return 1; }
void *memory_malloc_address(void) { return (void *)(uintptr_t)&malloc; }
#define FUNCTIONS(X) X(fmemopen) X(open_memstream) X(getline) X(getdelim) \
 X(printf) X(vprintf) X(fprintf) X(vfprintf) X(snprintf) X(vsnprintf) \
 X(sprintf) X(vsprintf) X(asprintf) X(vasprintf) X(__getdelim)
#define STR(x) #x,
static const char *const names[] = {FUNCTIONS(STR)};
#define PTR(x) (void *)(uintptr_t)&x,
static void *const functions[] = {FUNCTIONS(PTR)};
size_t memory_frontend_count(void) { return sizeof functions/sizeof functions[0]; }
void *memory_frontend(size_t i, int dynamic, const char *version) {
    if (i >= memory_frontend_count()) return 0;
    if (!dynamic) return functions[i];
    void *p = version ? dlvsym(RTLD_DEFAULT,names[i],version) : dlsym(RTLD_DEFAULT,names[i]);
    __asm__ __volatile__("" : "+r"(p)); return p;
}
static int format_vsn(char *p,size_t n,const char *fmt,...) {
    va_list ap; va_start(ap,fmt); int r=vsnprintf(p,n,fmt,ap);va_end(ap);return r;
}
static int format_vs(char *p,const char *fmt,...) {
    va_list ap;va_start(ap,fmt);int r=vsprintf(p,fmt,ap);va_end(ap);return r;
}
static int format_va(char **p,const char *fmt,...) {
    va_list ap;va_start(ap,fmt);int r=vasprintf(p,fmt,ap);va_end(ap);return r;
}
static int format_vf(FILE *s,const char *fmt,...) {
    va_list ap;va_start(ap,fmt);int r=vfprintf(s,fmt,ap);va_end(ap);return r;
}
static int format_vp(const char *fmt,...) {
    va_list ap;va_start(ap,fmt);int r=vprintf(fmt,ap);va_end(ap);return r;
}
int memory_format_protocol(void) {
    const char *expected="v:-7:9:feed:1.25";
    const char *fmt="%s:%d:%zu:%llx:%.2f";
    char a[80],b[80]; size_t n=strlen(expected);
    REQUIRE(sprintf(a,fmt,"v",-7,(size_t)9,0xfeedULL,1.25)==(int)n,1);
    REQUIRE(strcmp(a,expected)==0,2);
    REQUIRE(format_vs(b,fmt,"v",-7,(size_t)9,0xfeedULL,1.25)==(int)n && strcmp(a,b)==0,3);
    REQUIRE(snprintf(0,0,fmt,"v",-7,(size_t)9,0xfeedULL,1.25)==(int)n,4);
    memset(a,0xa5,sizeof a);
    REQUIRE(snprintf(a,5,"%s",expected)==(int)n && a[4]==0 && (unsigned char)a[5]==0xa5,5);
    REQUIRE(format_vsn(b,sizeof b,fmt,"v",-7,(size_t)9,0xfeedULL,1.25)==(int)n && strcmp(b,expected)==0,6);
    REQUIRE(format_vsn(b,sizeof b,"%2$d/%1$d",4,8)==3 && strcmp(b,"8/4")==0,7);
    char *owned=0;
    REQUIRE(asprintf(&owned,"%s/%d","item",42)==7 && strcmp(owned,"item/42")==0,8);free(owned);
    REQUIRE(format_va(&owned,"%.2f:%lld",2.5,-123456789LL)==15 && strcmp(owned,"2.50:-123456789")==0,9);
    free(owned);
    char *output=0;size_t size=0;FILE *s=open_memstream(&output,&size);REQUIRE(s,10);
    REQUIRE(fprintf(s,fmt,"v",-7,(size_t)9,0xfeedULL,1.25)==(int)n,11);
    REQUIRE(format_vf(s,"/%d",17)==3 && fclose(s)==0,12);
    REQUIRE(size==n+3 && memcmp(output,expected,n)==0 && strcmp(output+n,"/17")==0,13);
    free(output);return 0;
}
int memory_fixed_stream(void) {
    FILE *empty=fmemopen(0,0,"r"); REQUIRE(empty,1);
    REQUIRE(fgetc(empty)==EOF && feof(empty) && fclose(empty)==0,2);
    unsigned char bytes[20];memset(bytes,0xa5,sizeof bytes);
    FILE *s=fmemopen(bytes,12,"w+");REQUIRE(s,3);
    REQUIRE(fwrite("abcd",1,4,s)==4 && fflush(s)==0,4);
    REQUIRE(memcmp(bytes,"abcd\0",5)==0,5);
    for(size_t i=12;i<sizeof bytes;++i) REQUIRE(bytes[i]==0xa5,6);
    rewind(s);char out[5]={0};REQUIRE(fread(out,1,4,s)==4 && strcmp(out,"abcd")==0,7);
    REQUIRE(fclose(s)==0,8);
    for(size_t i=12;i<sizeof bytes;++i) REQUIRE(bytes[i]==0xa5,9);
    return 0;
}
int memory_growing_stream(void) {
    char *buf=0;size_t len=0;FILE *s=open_memstream(&buf,&len);REQUIRE(s,1);
    REQUIRE(fwrite("hello",1,5,s)==5 && fflush(s)==0,2);
    REQUIRE(len==5 && memcmp(buf,"hello\0",6)==0,3);
    REQUIRE(fseek(s,8,SEEK_SET)==0 && fputc('Z',s)=='Z' && fflush(s)==0,4);
    REQUIRE(len==9 && memcmp(buf,"hello\0\0\0Z\0",10)==0,5);
    REQUIRE(fclose(s)==0 && len==9,6);
    char *grown=realloc(buf,64);REQUIRE(grown,7);
    REQUIRE(memcmp(grown,"hello\0\0\0Z\0",10)==0,8);free(grown);return 0;
}
int memory_line_protocol(void) {
    char input[]="a\0b:second\ntail";
    FILE *s=fmemopen(input,sizeof input-1,"r");REQUIRE(s,1);
    char *line=0;size_t capacity=0;
    REQUIRE(getdelim(&line,&capacity,':',s)==4 && memcmp(line,"a\0b:",4)==0 && line[4]==0,2);
    REQUIRE(getline(&line,&capacity,s)==7 && memcmp(line,"second\n\0",8)==0,3);
    REQUIRE(getline(&line,&capacity,s)==4 && strcmp(line,"tail")==0,4);
    REQUIRE(getline(&line,&capacity,s)==-1 && feof(s) && fclose(s)==0,5);free(line);
    char *large=malloc(8192);REQUIRE(large,6);memset(large,'q',8192);large[8191]='\n';
    s=fmemopen(large,8192,"r");REQUIRE(s,7);line=malloc(8);REQUIRE(line,8);capacity=8;
    REQUIRE(getline(&line,&capacity,s)==8192 && capacity>=8193 && line[8192]==0,9);
    REQUIRE(memcmp(line,large,8192)==0 && fclose(s)==0,10);
    free(line);free(large);return 0;
}
int memory_stdout_protocol(void) {
    REQUIRE(fflush(0)==0,1);int fds[2];REQUIRE(pipe(fds)==0,2);
    int saved=dup(1);REQUIRE(saved>=0,3);REQUIRE(dup2(fds[1],1)==1 && close(fds[1])==0,4);
    int a=printf("stdout:%d\n",27);int b=format_vp("%s:%.2f\n","value",1.25);int c=fflush(0);
    int restored=dup2(saved,1);int closed=close(saved);
    REQUIRE(restored==1 && closed==0,5);
    REQUIRE(a==10 && b==11 && c==0,6);
    char out[64]={0};ssize_t n=read(fds[0],out,sizeof out);close(fds[0]);
    REQUIRE(n==21 && memcmp(out,"stdout:27\nvalue:1.25\n",21)==0,7);return 0;
}

void *memory_standard_address(size_t i,int dynamic) {
    if(i>=3) return 0;
    if(!dynamic) {
        switch(i) {case 0:return &stdin;case 1:return &stdout;default:return &stderr;}
    }
    const char *names[3]={"stdin","stdout","stderr"};
    void *p=dlsym(RTLD_DEFAULT,names[i]);__asm__ __volatile__("" : "+r"(p));return p;
}
"#;

const VERSIONS: &str = "GLIBC_2.22 { global: fmem_version_anchor; }; GLIBC_2.34 { global: version_anchor; };\n";

fn frontends() -> Vec<(&'static str, *const ())> {
    vec![
        ("fmemopen", stdio::fmemopen as *const ()),
        ("open_memstream", stdio::open_memstream as *const ()),
        ("getline", stdio::getline as *const ()),
        ("getdelim", stdio::getdelim as *const ()),
        ("printf", stdio::printf as *const ()),
        ("vprintf", stdio::vprintf as *const ()),
        ("fprintf", stdio::fprintf as *const ()),
        ("vfprintf", stdio::vfprintf as *const ()),
        ("snprintf", stdio::snprintf as *const ()),
        ("vsnprintf", stdio::vsnprintf as *const ()),
        ("sprintf", stdio::sprintf as *const ()),
        ("vsprintf", stdio::vsprintf as *const ()),
        ("asprintf", stdio::asprintf as *const ()),
        ("vasprintf", stdio::vasprintf as *const ()),
        ("__getdelim", stdio::getdelim as *const ()),
    ]
}

#[derive(Clone, Copy)]
struct Api { open: Open, sym: Sym, close: Close, error: Error, native: bool }
impl Api {
    fn new(native: bool) -> Self {
        if native { Self { open: dl::dlopen, sym: dl::dlsym, close: dl::dlclose, error: dl::dlerror, native } }
        else { unsafe { Self {
            open: dlsym_oracle::host_fn(c"dlopen", dl::dlopen as *const ()),
            sym: dlsym_oracle::host_fn(c"dlsym", dl::dlsym as *const ()),
            close: dlsym_oracle::host_fn(c"dlclose", dl::dlclose as *const ()),
            error: dlsym_oracle::host_fn(c"dlerror", dl::dlerror as *const ()), native,
        } } }
    }
    fn open(self, path: &Path, flags: c_int) -> *mut c_void {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let handle = unsafe { (self.open)(path.as_ptr(), flags | libc::RTLD_NOW) };
        assert!(!handle.is_null(), "dlopen {path:?}");
        if self.native { assert!(dl::native_dso_handle_for_tests(handle), "host fallback: {path:?}"); }
        handle
    }
    fn symbol(self, handle: *mut c_void, name: &CStr) -> *mut c_void {
        let address = unsafe { (self.sym)(handle, name.as_ptr()) };
        assert!(!address.is_null(), "dlsym {name:?}"); address
    }
    fn frontend(self, handle: *mut c_void) -> Frontend {
        unsafe { std::mem::transmute(self.symbol(handle, c"memory_frontend")) }
    }
    fn close(self, handle: *mut c_void) { assert_eq!(unsafe { (self.close)(handle) }, 0); }
    fn loaded(self, path: &Path) -> bool {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let h = unsafe { (self.open)(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD) };
        if h.is_null() { false } else { self.close(h); true }
    }
}

fn word(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at.checked_add(2).unwrap()].try_into().unwrap())
}
fn dword(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at.checked_add(4).unwrap()].try_into().unwrap())
}
fn offset(bytes: &[u8], at: usize) -> usize {
    usize::try_from(u64::from_le_bytes(bytes[at..at.checked_add(8).unwrap()].try_into().unwrap())).unwrap()
}

/// Encode a real versioned undefined reference without adding a host DT_NEEDED.
/// Bare unversioned host relocations select legacy fmemopen, whereas dlsym
/// selects its modern default. The fixture explicitly requests GLIBC_2.22;
/// this is not a claim that the native frontend implements the pre-2.22 ABI.
/// GNU versym indices refer to linker-generated VERDEF names. The host loader
/// independently checks these serialized indices in the paired execution lane.
fn version_import(path: &Path, symbol: &str, anchor: &str) {
    let mut bytes = std::fs::read(path).unwrap();
    let object = ElfLoader::new(0).parse(&bytes).unwrap();
    let index = object.dynsym.iter().position(|entry| object.symbol_name(entry) == Some(symbol)).unwrap();
    let anchor = object.dynsym.iter().position(|entry| object.symbol_name(entry) == Some(anchor)).unwrap();
    assert!(object.dynsym[index].is_undefined());
    assert!(object.dynsym[anchor].is_defined());
    let sections = offset(&bytes, 40);
    let stride = usize::from(word(&bytes, 58));
    let count = usize::from(word(&bytes, 60));
    assert!(stride >= 64 && count != 0);
    let section = (0..count).map(|i| sections.checked_add(i.checked_mul(stride).unwrap()).unwrap())
        .find(|&at| dword(&bytes, at + 4) == 0x6fff_ffff).expect("GNU versym section");
    let start = offset(&bytes, section + 24);
    let size = offset(&bytes, section + 32);
    assert!(index.checked_mul(2).unwrap() + 2 <= size);
    assert!(anchor.checked_mul(2).unwrap() + 2 <= size);
    let version = word(&bytes, start + anchor * 2) & 0x7fff;
    assert!(version > 1);
    let target = start.checked_add(index.checked_mul(2).unwrap()).unwrap();
    bytes[target..target + 2].copy_from_slice(&version.to_le_bytes());
    std::fs::write(path, &bytes).unwrap();
    let reloaded = std::fs::read(path).unwrap();
    assert_eq!(word(&reloaded, target), version);
    assert!(ElfLoader::new(0).parse(&reloaded).unwrap().needed_libraries.is_empty());
}

struct Fixture { dir: PathBuf, library: PathBuf }
impl Fixture {
    fn new(extra: &[&str], impossible_malloc: bool) -> Self {
        let dir = std::env::temp_dir().join(format!("frankenlibc-memstream-{}-{}",
            std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir(&dir).unwrap();
        let source = dir.join("memory.c"); let library = dir.join("libmemory.so");
        std::fs::write(&source, SOURCE).unwrap();
        std::fs::write(dir.join("versions.map"), VERSIONS).unwrap();
        let output = Command::new("gcc")
            .args(["-shared", "-fPIC", "-nostdlib", "-O2", "-fno-builtin", "-fno-optimize-sibling-calls",
                "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0", "-Wall", "-Wextra", "-Werror", "-Wl,--hash-style=both"])
            .arg(format!("-Wl,--version-script={}", dir.join("versions.map").display()))
            .args(extra).arg(&source).arg("-o").arg(&library)
            .output().expect("gcc is required");
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        version_import(&library, "fmemopen", "fmem_version_anchor");
        if impossible_malloc { version_import(&library, "malloc", "version_anchor"); }
        let object = ElfLoader::new(0).parse(&std::fs::read(&library).unwrap()).unwrap();
        assert!(object.needed_libraries.is_empty(), "no runtime DT_NEEDED allowed");
        for name in ["fmemopen", "open_memstream", "vasprintf", "vsnprintf", "stdout", "__getdelim"] {
            assert!(object.undefined_symbols().any(|(_, entry)| object.symbol_name(entry) == Some(name)),
                "compiler elided import {name}");
        }
        let malloc = object.dynsym.iter().find(|entry| object.symbol_name(entry) == Some("malloc")).unwrap();
        assert_eq!(malloc.is_weak(), extra.contains(&"-DWEAK_MALLOC"));
        Self { dir, library }
    }
    fn custom_provider(&self) -> PathBuf {
        let source = self.dir.join("provider.c");
        let library = self.dir.join("libprovider.so");
        std::fs::write(&source, "#include <stddef.h>\nvoid *fmemopen(void *p,size_t n,const char *m) {(void)p;(void)n;(void)m;return 0;}\n").unwrap();
        let map = self.dir.join("custom.map");
        std::fs::write(&map, "CUSTOM_MEMORY_1 { global: fmemopen; local: *; };\n").unwrap();
        let output = Command::new("gcc").args(["-shared", "-fPIC", "-nostdlib", "-O2", "-Wl,--hash-style=both"])
            .arg(format!("-Wl,--version-script={}", map.display()))
            .arg(&source).arg("-o").arg(&library).output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        assert!(ElfLoader::new(0).parse(&std::fs::read(&library).unwrap()).unwrap().needed_libraries.is_empty());
        library
    }
}

fn isolated(name: &str, native_only: bool, scenario: fn(Api)) {
    if let Ok(mode) = std::env::var("FRANKENLIBC_MEMSTREAM_CHILD") {
        assert!(mode == "host" || mode == "native"); scenario(Api::new(mode == "native")); return;
    }
    for mode in if native_only { &["native"][..] } else { &["host", "native"][..] } {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"]).env("FRANKENLIBC_MEMSTREAM_CHILD", mode)
            .spawn().unwrap();
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "{name}: {mode}: {status}"); break;
            }
            if start.elapsed() > Duration::from_secs(45) {
                child.kill().unwrap(); child.wait().unwrap(); panic!("{name}: {mode}: timeout");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[test]
fn memstream_direct_dynamic_and_versioned_frontends_agree() {
    isolated("memstream_direct_dynamic_and_versioned_frontends_agree", false, |api| {
        for options in [&[][..], &["-fno-plt"][..]] {
            let f = Fixture::new(options, false); let h = api.open(&f.library, 0);
            let count: unsafe extern "C" fn() -> usize = unsafe { std::mem::transmute(api.symbol(h, c"memory_frontend_count")) };
            assert_eq!(unsafe { count() }, frontends().len());
            let query = api.frontend(h);
            for (index, (name, expected)) in frontends().into_iter().enumerate() {
                let version = if name == "fmemopen" { c"GLIBC_2.22" } else { c"GLIBC_2.2.5" };
                let direct = unsafe { query(index, 0, std::ptr::null()) };
                assert!(!direct.is_null());
                assert_eq!(direct, unsafe { query(index, 1, std::ptr::null()) }, "{name}: dynamic");
                assert_eq!(direct, unsafe { query(index, 1, version.as_ptr()) }, "{name}: versioned");
                if api.native { assert_eq!(direct.cast_const().cast::<()>(), expected, "{name}: wrong frontend"); }
                assert!(unsafe { query(index, 1, c"GLIBC_PRIVATE".as_ptr()) }.is_null());
            }
            let data: unsafe extern "C" fn(usize, c_int) -> *mut c_void =
                unsafe { std::mem::transmute(api.symbol(h, c"memory_standard_address")) };
            let expected = [(&raw mut stdio::stdin).cast::<c_void>(),
                (&raw mut stdio::stdout).cast::<c_void>(), (&raw mut stdio::stderr).cast::<c_void>()];
            for (index, expected) in expected.into_iter().enumerate() {
                let direct = unsafe { data(index, 0) };
                assert!(!direct.is_null()); assert_eq!(direct, unsafe { data(index, 1) });
                if api.native { assert_eq!(direct, expected, "FILE* variable address, not its value"); }
            }
            api.close(h);
        }
    });
}

fn protocol(api: Api, name: &CStr) {
    let f = Fixture::new(&[], false); let h = api.open(&f.library, 0);
    let call: unsafe extern "C" fn() -> c_int = unsafe { std::mem::transmute(api.symbol(h, name)) };
    assert_eq!(unsafe { call() }, 0, "{name:?}"); api.close(h);
}
#[test]
fn memstream_printf_and_va_list_protocols() {
    isolated("memstream_printf_and_va_list_protocols", false, |api| protocol(api, c"memory_format_protocol"));
}
#[test]
fn memstream_modern_fixed_stream_zero_size_and_bounds() {
    isolated("memstream_modern_fixed_stream_zero_size_and_bounds", false, |api| protocol(api, c"memory_fixed_stream"));
}
#[test]
fn memstream_growth_holes_and_allocator_ownership() {
    isolated("memstream_growth_holes_and_allocator_ownership", false, |api| protocol(api, c"memory_growing_stream"));
}
#[test]
fn memstream_delimiters_embedded_nuls_and_line_reallocation() {
    isolated("memstream_delimiters_embedded_nuls_and_line_reallocation", false, |api| protocol(api, c"memory_line_protocol"));
}
#[test]
fn memstream_standard_output_uses_the_stream_frontend() {
    isolated("memstream_standard_output_uses_the_stream_frontend", false, |api| protocol(api, c"memory_stdout_protocol"));
}
#[test]
fn memstream_strong_runtime_version_mismatch_rejects_load() {
    isolated("memstream_strong_runtime_version_mismatch_rejects_load", false, |api| {
        let f = Fixture::new(&[], true);
        let name = CString::new(f.library.as_os_str().as_bytes()).unwrap();
        unsafe { (api.error)() };
        assert!(unsafe { (api.open)(name.as_ptr(), libc::RTLD_NOW) }.is_null());
        assert!(!unsafe { (api.error)() }.is_null()); assert!(!api.loaded(&f.library));
        protocol(api, c"memory_format_protocol");
    });
}
#[test]
fn memstream_weak_runtime_version_mismatch_resolves_to_zero() {
    isolated("memstream_weak_runtime_version_mismatch_resolves_to_zero", false, |api| {
        let f = Fixture::new(&["-DWEAK_MALLOC"], true); let h = api.open(&f.library, 0);
        let call: unsafe extern "C" fn() -> *mut c_void =
            unsafe { std::mem::transmute(api.symbol(h, c"memory_malloc_address")) };
        assert!(unsafe { call() }.is_null()); api.close(h);
    });
}
#[test]
fn memstream_native_legacy_version_does_not_escape_to_host() {
    isolated("memstream_native_legacy_version_does_not_escape_to_host", true, |api| {
        // glibc really implements both ABIs; the native runtime currently
        // implements only the modern contract. A host legacy FILE is unsafe
        // as an implicit replacement for that unsupported native version.
        let f = Fixture::new(&[], false); let h = api.open(&f.library, 0);
        let query = api.frontend(h);
        unsafe { (api.error)() };
        assert!(unsafe { query(0, 1, c"GLIBC_2.2.5".as_ptr()) }.is_null());
        assert!(!unsafe { (api.error)() }.is_null());
        assert_eq!(unsafe { query(0, 1, c"GLIBC_2.22".as_ptr()) }, stdio::fmemopen as *const () as *mut c_void);
        assert!(unsafe { (api.error)() }.is_null()); api.close(h);
    });
}
#[test]
fn memstream_native_custom_version_precedes_runtime_refusal() {
    isolated("memstream_native_custom_version_precedes_runtime_refusal", true, |api| {
        let f = Fixture::new(&[], false); let provider = f.custom_provider();
        let p = api.open(&provider, libc::RTLD_GLOBAL); let expected = api.symbol(p, c"fmemopen");
        let h = api.open(&f.library, 0); let query = api.frontend(h);
        assert_eq!(unsafe { query(0, 0, std::ptr::null()) }, stdio::fmemopen as *const () as *mut c_void);
        assert_eq!(unsafe { query(0, 1, c"CUSTOM_MEMORY_1".as_ptr()) }, expected);
        api.close(p); assert!(api.loaded(&provider));
        api.close(h); assert!(!api.loaded(&provider));
    });
}
