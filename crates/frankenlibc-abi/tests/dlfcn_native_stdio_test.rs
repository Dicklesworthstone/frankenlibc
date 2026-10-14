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
type Frontend = unsafe extern "C" fn(usize, c_int, *const c_char) -> *mut c_void;
type OnePath = unsafe extern "C" fn(*const c_char) -> c_int;

const SOURCE: &str = r#"#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#define EXPECT(x, n) do { if (!(x)) return (n); } while (0)
#define FRONTENDS(X) \
 X(fopen) X(fdopen) X(freopen) X(fclose) X(fread) X(fwrite) \
 X(fgetc) X(fputc) X(fgets) X(fputs) X(ungetc) X(fseek) X(ftell) X(rewind) \
 X(feof) X(ferror) X(clearerr) X(fflush) X(setbuf) X(setvbuf) X(fileno) \
 X(flockfile) X(ftrylockfile) X(funlockfile)
#define NAME(n) #n,
static const char *const names[] = { FRONTENDS(NAME) };
#define ADDRESS(n) (void *)(uintptr_t)&n,
static void *const addresses[] = { FRONTENDS(ADDRESS) };
size_t stream_frontend_count(void) { return sizeof addresses / sizeof addresses[0]; }
void *stream_frontend(size_t index, int dynamic, const char *version) {
    if (index >= stream_frontend_count()) return 0;
    if (!dynamic) return addresses[index];
    void *result = version ? dlvsym(RTLD_DEFAULT, names[index], version)
                           : dlsym(RTLD_DEFAULT, names[index]);
    __asm__ __volatile__("" : "+r"(result));
    return result;
}
int stream_roundtrip(const char *path) {
    FILE *s = fopen(path, "w+"); EXPECT(s, 1);
    char buffer[128]; EXPECT(setvbuf(s, buffer, _IOFBF, sizeof buffer) == 0, 2);
    EXPECT(fwrite("ab\0cd\n", 2, 3, s) == 3, 3);
    EXPECT(ftell(s) == 6, 4); EXPECT(fflush(s) == 0, 5);
    char data[16] = {0};
    int fd = open(path, O_RDONLY); EXPECT(fd >= 0, 6);
    EXPECT(read(fd, data, sizeof data) == 6, 7); EXPECT(close(fd) == 0, 8);
    EXPECT(data[0]=='a' && data[2]==0 && data[5]=='\n', 9);
    EXPECT(fseek(s, 0, SEEK_SET)==0, 10);
    EXPECT(fread(data, 4, 2, s)==1, 11); EXPECT(feof(s)!=0 && ferror(s)==0, 12);
    clearerr(s); EXPECT(feof(s)==0 && ferror(s)==0, 13);
    rewind(s); EXPECT(ftell(s)==0, 14);
    EXPECT(fgetc(s)=='a', 15); EXPECT(ungetc('Z',s)=='Z' && fgetc(s)=='Z', 16);
    EXPECT(fseek(s,0,SEEK_END)==0 && fputc('!',s)=='!', 17);
    EXPECT(fclose(s)==0, 18);
    return 0;
}
int stream_reopen(const char *first, const char *second) {
    FILE *s=fopen(first,"w+"); EXPECT(s,1);
    setbuf(s,0); EXPECT(fputs("old",s)>=0,2);
    EXPECT(freopen(second,"w+",s)==s,3);
    EXPECT(fputs("new\n",s)>=0 && fflush(s)==0,4);
    rewind(s); char data[8]={0}; EXPECT(fgets(data,sizeof data,s)==data,5);
    EXPECT(data[0]=='n' && data[3]=='\n' && data[4]==0,6);
    EXPECT(fclose(s)==0,7);
    s=fopen(second,"a+"); EXPECT(s,8);
    EXPECT(fseek(s,0,SEEK_SET)==0 && fputc('+',s)=='+',9);
    EXPECT(fclose(s)==0,10);
    return 0;
}
int stream_fd_ownership(const char *path) {
    int fd=open(path,O_CREAT|O_TRUNC|O_RDWR,0600); EXPECT(fd>=0,1);
    FILE *s=fdopen(fd,"w+"); EXPECT(s,2); EXPECT(fileno(s)==fd,3);
    EXPECT(fputs("descriptor",s)>=0 && fflush(s)==0,4);
    EXPECT(fclose(s)==0,5);
    errno=0; char c; EXPECT(read(fd,&c,1)==-1 && errno==EBADF,6);
    fd=open(path,O_RDONLY); EXPECT(fd>=0,7);
    errno=0; EXPECT(fdopen(fd,"w")==0 && errno==EINVAL,8);
    EXPECT(read(fd,&c,1)==1 && c=='d',9); EXPECT(close(fd)==0,10);
    return 0;
}
int stream_errors(const char *path) {
    FILE *s=fopen(path,"w+"); EXPECT(s,1);
    EXPECT(fputs("one\ntwo\n",s)>=0 && fclose(s)==0,2);
    s=fopen(path,"r"); EXPECT(s,3);
    char data[16]; EXPECT(fgets(data,sizeof data,s)==data && data[0]=='o',4);
    EXPECT(fgets(data,sizeof data,s)==data && data[0]=='t',5);
    EXPECT(fgetc(s)==EOF && feof(s)!=0,6);
    clearerr(s); EXPECT(!feof(s) && !ferror(s),7);
    errno=0; EXPECT(fputc('x',s)==EOF && ferror(s)!=0 && errno==EBADF,8);
    clearerr(s); EXPECT(!ferror(s),9);
    rewind(s); EXPECT(fgetc(s)=='o' && !feof(s),10);
    EXPECT(fclose(s)==0,11);
    return 0;
}
void *stream_open_shared(const char *path) { return fopen(path,"w+"); }
int stream_write_locked(void *ptr, int byte, size_t lines) {
    FILE *s=ptr; char data[8];
    for (size_t i=0;i<sizeof data-1;++i) data[i]=(char)byte;
    data[7]='\n';
    for(size_t i=0;i<lines;++i) {
        flockfile(s);
        int lock=ftrylockfile(s);
        if(lock!=0) { funlockfile(s); return 1; }
        size_t n=fwrite(data,1,sizeof data,s);
        funlockfile(s); funlockfile(s);
        if(n!=sizeof data) return 2;
    }
    return 0;
}
int stream_close_shared(void *ptr) { return fclose(ptr); }
#ifdef LIFECYCLE_PATH
static int init_result;
__attribute__((constructor)) static void initialize(void) {
    FILE *s=fopen(LIFECYCLE_PATH,"w");
    if(!s) {init_result=1;return;}
    int a=fputs("init\n",s); int b=fclose(s); init_result=a<0||b!=0;
}
int stream_init_result(void) { return init_result; }
__attribute__((destructor)) static void finalize(void) {
    FILE *s=fopen(LIFECYCLE_PATH,"a");
    if(s) { fputs("fini\n",s); fclose(s); }
}
#endif
#ifdef BAD_IMPORT
extern void missing_native_stream_import(void);
void stream_bad_import(void) { missing_native_stream_import(); }
#endif
#ifdef LOCAL_OVERRIDE
int fputs(const char *text, FILE *stream) { (void)text; (void)stream; return 917; }
#endif
"#;

fn frontends() -> Vec<(&'static str, *const ())> {
    vec![
        ("fopen", stdio::fopen as *const ()),
        ("fdopen", stdio::fdopen as *const ()),
        ("freopen", stdio::freopen as *const ()),
        ("fclose", stdio::fclose as *const ()),
        ("fread", stdio::fread as *const ()),
        ("fwrite", stdio::fwrite as *const ()),
        ("fgetc", stdio::fgetc as *const ()),
        ("fputc", stdio::fputc as *const ()),
        ("fgets", stdio::fgets as *const ()),
        ("fputs", stdio::fputs as *const ()),
        ("ungetc", stdio::ungetc as *const ()),
        ("fseek", stdio::fseek as *const ()),
        ("ftell", stdio::ftell as *const ()),
        ("rewind", stdio::rewind as *const ()),
        ("feof", stdio::feof as *const ()),
        ("ferror", stdio::ferror as *const ()),
        ("clearerr", stdio::clearerr as *const ()),
        ("fflush", stdio::fflush as *const ()),
        ("setbuf", stdio::setbuf as *const ()),
        ("setvbuf", stdio::setvbuf as *const ()),
        ("fileno", stdio::fileno as *const ()),
        ("flockfile", stdio::flockfile as *const ()),
        ("ftrylockfile", stdio::ftrylockfile as *const ()),
        ("funlockfile", stdio::funlockfile as *const ()),
    ]
}

#[derive(Clone, Copy)]
struct Api { open: Open, sym: Sym, close: Close, native: bool }
impl Api {
    fn new(native: bool) -> Self {
        if native { Self { open: dl::dlopen, sym: dl::dlsym, close: dl::dlclose, native } }
        else { unsafe { Self {
            open: dlsym_oracle::host_fn(c"dlopen", dl::dlopen as *const ()),
            sym: dlsym_oracle::host_fn(c"dlsym", dl::dlsym as *const ()),
            close: dlsym_oracle::host_fn(c"dlclose", dl::dlclose as *const ()), native,
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
        let value = unsafe { (self.sym)(handle, name.as_ptr()) };
        assert!(!value.is_null(), "dlsym {name:?}"); value
    }
    fn close(self, handle: *mut c_void) { assert_eq!(unsafe { (self.close)(handle) }, 0); }
    fn loaded(self, path: &Path) -> bool {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let handle = unsafe { (self.open)(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD) };
        if handle.is_null() { false } else { self.close(handle); true }
    }
}

struct Fixture { dir: PathBuf, library: PathBuf }
impl Fixture {
    fn new(extra: &[&str]) -> Self {
        let dir = std::env::temp_dir().join(format!("frankenlibc-stream-{}-{}",
            std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir(&dir).unwrap();
        let library = dir.join("libstream.so");
        let source = dir.join("stream.c"); std::fs::write(&source, SOURCE).unwrap();
        let mut command = Command::new("gcc");
        command.args(["-shared", "-fPIC", "-nostdlib", "-O2", "-fno-builtin",
            "-fno-optimize-sibling-calls", "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0",
            "-Wall", "-Wextra", "-Werror", "-Wl,--hash-style=both"])
            .arg(format!("-DLIFECYCLE_PATH=\"{}\"", dir.join("lifecycle.txt").display()))
            .args(extra).arg(&source).arg("-o").arg(&library);
        let output = command.output().expect("gcc is required");
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let object = ElfLoader::new(0).parse(&std::fs::read(&library).unwrap()).unwrap();
        assert!(object.needed_libraries.is_empty(), "host dependencies are forbidden");
        // Verify the generated DSO really imports the selected stream API.
        for name in ["fopen", "fclose", "fread", "fwrite", "fdopen", "flockfile", "fflush"] {
            assert!(object.undefined_symbols().any(|(_, symbol)| object.symbol_name(symbol) == Some(name)),
                "compiler elided import {name}");
        }
        Self { dir, library }
    }
    fn path(&self, name: &str) -> CString {
        CString::new(self.dir.join(name).as_os_str().as_bytes()).unwrap()
    }
}

fn isolated(name: &str, native_only: bool, scenario: fn(Api)) {
    if let Ok(mode) = std::env::var("FRANKENLIBC_STREAM_CHILD") {
        assert!(mode == "host" || mode == "native"); scenario(Api::new(mode == "native")); return;
    }
    for mode in if native_only { &["native"][..] } else { &["host", "native"][..] } {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"]).env("FRANKENLIBC_STREAM_CHILD", mode)
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
fn stream_imports_and_dynamic_lookup_share_all_frontends() {
    isolated("stream_imports_and_dynamic_lookup_share_all_frontends", false, |api| {
        for options in [&[][..], &["-fno-plt"][..]] {
            let f = Fixture::new(options); let h = api.open(&f.library, 0);
            let count: unsafe extern "C" fn() -> usize = unsafe { std::mem::transmute(api.symbol(h, c"stream_frontend_count")) };
            let query: Frontend = unsafe { std::mem::transmute(api.symbol(h, c"stream_frontend")) };
            assert_eq!(unsafe { count() }, frontends().len());
            for (index, (name, expected)) in frontends().into_iter().enumerate() {
                let direct = unsafe { query(index, 0, std::ptr::null()) };
                let dynamic = unsafe { query(index, 1, std::ptr::null()) };
                let versioned = unsafe { query(index, 1, c"GLIBC_2.2.5".as_ptr()) };
                assert_eq!(direct, dynamic, "{name}: direct/dynamic mismatch");
                assert_eq!(direct, versioned, "{name}: versioned mismatch");
                if api.native { assert_eq!(direct.cast_const().cast::<()>(), expected, "{name}: wrong Rust frontend"); }
                assert!(unsafe { query(index, 1, c"GLIBC_PRIVATE".as_ptr()) }.is_null());
            }
            api.close(h);
        }
    });
}

fn one_path(api: Api, symbol: &CStr, expected: Option<&[u8]>) {
    let f = Fixture::new(&[]); let h = api.open(&f.library, 0);
    let call: OnePath = unsafe { std::mem::transmute(api.symbol(h, symbol)) };
    assert_eq!(unsafe { call(f.path("output").as_ptr()) }, 0, "{symbol:?}");
    if let Some(expected) = expected { assert_eq!(std::fs::read(f.dir.join("output")).unwrap(), expected); }
    api.close(h);
}
#[test]
fn stream_binary_roundtrip_and_flush_visibility() {
    isolated("stream_binary_roundtrip_and_flush_visibility", false,
        |api| one_path(api, c"stream_roundtrip", Some(b"ab\0cd\n!")));
}
#[test]
fn stream_descriptor_transfer_and_failed_fdopen_ownership() {
    isolated("stream_descriptor_transfer_and_failed_fdopen_ownership", false,
        |api| one_path(api, c"stream_fd_ownership", Some(b"descriptor")));
}
#[test]
fn stream_eof_error_and_rewind_state() {
    isolated("stream_eof_error_and_rewind_state", false,
        |api| one_path(api, c"stream_errors", Some(b"one\ntwo\n")));
}
#[test]
fn stream_freopen_and_append_preserve_file_protocol() {
    isolated("stream_freopen_and_append_preserve_file_protocol", false, |api| {
        let f = Fixture::new(&[]); let h = api.open(&f.library, 0);
        let call: unsafe extern "C" fn(*const c_char, *const c_char) -> c_int =
            unsafe { std::mem::transmute(api.symbol(h, c"stream_reopen")) };
        assert_eq!(unsafe { call(f.path("first").as_ptr(), f.path("second").as_ptr()) }, 0);
        assert_eq!(std::fs::read(f.dir.join("first")).unwrap(), b"old");
        assert_eq!(std::fs::read(f.dir.join("second")).unwrap(), b"new\n+");
        api.close(h);
    });
}
#[test]
fn stream_recursive_locks_serialize_concurrent_records() {
    isolated("stream_recursive_locks_serialize_concurrent_records", false, |api| {
        let f = Fixture::new(&[]); let h = api.open(&f.library, 0);
        let open: unsafe extern "C" fn(*const c_char) -> *mut c_void =
            unsafe { std::mem::transmute(api.symbol(h, c"stream_open_shared")) };
        let write: unsafe extern "C" fn(*mut c_void, c_int, usize) -> c_int =
            unsafe { std::mem::transmute(api.symbol(h, c"stream_write_locked")) };
        let close: unsafe extern "C" fn(*mut c_void) -> c_int =
            unsafe { std::mem::transmute(api.symbol(h, c"stream_close_shared")) };
        let stream = unsafe { open(f.path("records").as_ptr()) } as usize;
        assert_ne!(stream, 0);
        let workers = [b'A', b'B', b'C', b'D'].map(|byte| std::thread::spawn(move || {
            assert_eq!(unsafe { write(stream as *mut c_void, byte as c_int, 200) }, 0);
        }));
        for worker in workers { worker.join().unwrap(); }
        assert_eq!(unsafe { close(stream as *mut c_void) }, 0);
        let bytes = std::fs::read(f.dir.join("records")).unwrap();
        assert_eq!(bytes.len(), 4 * 200 * 8);
        let mut counts = [0usize; 4];
        for line in bytes.chunks_exact(8) {
            assert_eq!(line[7], b'\n'); assert!((b'A'..=b'D').contains(&line[0]));
            assert!(line[..7].iter().all(|byte| *byte == line[0]));
            counts[(line[0] - b'A') as usize] += 1;
        }
        assert_eq!(counts, [200; 4]); api.close(h);
    });
}
#[test]
fn stream_constructors_and_finalizers_use_runtime_streams() {
    isolated("stream_constructors_and_finalizers_use_runtime_streams", false, |api| {
        let f = Fixture::new(&[]); let h = api.open(&f.library, 0);
        let init: unsafe extern "C" fn() -> c_int = unsafe { std::mem::transmute(api.symbol(h, c"stream_init_result")) };
        assert_eq!(unsafe { init() }, 0);
        assert_eq!(std::fs::read(f.dir.join("lifecycle.txt")).unwrap(), b"init\n");
        api.close(h);
        assert_eq!(std::fs::read(f.dir.join("lifecycle.txt")).unwrap(), b"init\nfini\n");
        assert!(!api.loaded(&f.library));
    });
}
#[test]
fn stream_missing_strong_import_rolls_back_before_constructor_io() {
    isolated("stream_missing_strong_import_rolls_back_before_constructor_io", false, |api| {
        let f = Fixture::new(&["-DBAD_IMPORT"]);
        let name = CString::new(f.library.as_os_str().as_bytes()).unwrap();
        assert!(unsafe { (api.open)(name.as_ptr(), libc::RTLD_NOW) }.is_null());
        assert!(!f.dir.join("lifecycle.txt").exists()); assert!(!api.loaded(&f.library));
        // Refusal did not poison the native/host stream registry for the next load.
        one_path(api, c"stream_roundtrip", Some(b"ab\0cd\n!"));
    });
}
#[test]
fn stream_native_overrides_precede_runtime_and_retain_provider() {
    isolated("stream_native_overrides_precede_runtime_and_retain_provider", true, |api| {
        let provider = Fixture::new(&["-DLOCAL_OVERRIDE"]);
        let p = api.open(&provider.library, libc::RTLD_GLOBAL);
        let expected = api.symbol(p, c"fputs");
        let consumer = Fixture::new(&[]); let c = api.open(&consumer.library, 0);
        let query: Frontend = unsafe { std::mem::transmute(api.symbol(c, c"stream_frontend")) };
        let index = frontends().iter().position(|(name, _)| *name == "fputs").unwrap();
        assert_eq!(unsafe { query(index, 0, std::ptr::null()) }, expected);
        assert_eq!(unsafe { query(index, 1, std::ptr::null()) }, expected);
        api.close(p); assert!(api.loaded(&provider.library));
        let own = Fixture::new(&["-DLOCAL_OVERRIDE"]);
        let d = api.open(&own.library, libc::RTLD_DEEPBIND);
        let own_expected = api.symbol(d, c"fputs"); assert_ne!(own_expected, expected);
        let own_query: Frontend = unsafe { std::mem::transmute(api.symbol(d, c"stream_frontend")) };
        assert_eq!(unsafe { own_query(index, 0, std::ptr::null()) }, own_expected);
        assert_eq!(unsafe { own_query(index, 1, std::ptr::null()) }, own_expected);
        api.close(d); api.close(c); assert!(!api.loaded(&provider.library));
    });
}
