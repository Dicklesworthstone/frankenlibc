#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc fgetspent oracle

//! /etc/shadow line parsing, against the host's own parser.
//!
//! Driven through `fmemopen`, so host `fgetspent` parses synthetic lines with
//! nothing written to disk — which matters more here than for passwd/group,
//! because /etc/shadow is root-only and a test that needed a real file could
//! not run unprivileged at all.
//!
//! Two rules fl had wrong, both found this way:
//!   * leading blanks belong to nobody — the parser computed a trimmed copy for
//!     its blank/comment test and then split the UNtrimmed line, so "  u:..."
//!     produced the name "  u";
//!   * a TENTH field rejects the entry. /etc/shadow has exactly nine, and glibc
//!     refuses anything longer; fl stopped reading after the flag field and
//!     silently accepted the rest.

use std::ffi::{c_char, c_int, c_long, c_ulong, c_void};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

#[repr(C)]
struct CSpwd {
    sp_namp: *const c_char,
    sp_pwdp: *const c_char,
    sp_lstchg: c_long,
    sp_min: c_long,
    sp_max: c_long,
    sp_warn: c_long,
    sp_inact: c_long,
    sp_expire: c_long,
    sp_flag: c_ulong,
}

unsafe extern "C" {
    fn fmemopen(buf: *mut c_void, size: usize, mode: *const c_char) -> *mut c_void;
    fn fclose(stream: *mut c_void) -> c_int;
    fn fgetspent(stream: *mut c_void) -> *const CSpwd;
}

type ShadowTuple = (Vec<u8>, Vec<u8>, i64, i64, i64, i64, i64, i64, u64);

fn host_shadow(line: &str) -> Option<ShadowTuple> {
    let mut data = format!("{line}\n").into_bytes();
    let mode = c"r";
    let stream = unsafe { fmemopen(data.as_mut_ptr().cast(), data.len(), mode.as_ptr()) };
    assert!(!stream.is_null(), "fmemopen failed");
    let p = unsafe { fgetspent(stream) };
    let out = if p.is_null() {
        None
    } else {
        let e = unsafe { &*p };
        let name = unsafe { std::ffi::CStr::from_ptr(e.sp_namp) }
            .to_bytes()
            .to_vec();
        let pwd = unsafe { std::ffi::CStr::from_ptr(e.sp_pwdp) }
            .to_bytes()
            .to_vec();
        Some((
            name,
            pwd,
            e.sp_lstchg as i64,
            e.sp_min as i64,
            e.sp_max as i64,
            e.sp_warn as i64,
            e.sp_inact as i64,
            e.sp_expire as i64,
            e.sp_flag as u64,
        ))
    };
    unsafe { fclose(stream) };
    out
}

/// Each case defeats a different plausible reading of the format.
const CASES: &[&str] = &[
    "root:!:19000:0:99999:7:::", // the shape a real /etc/shadow uses
    "u:x:1:2:3:4:5:6:7",
    "u:x:::::::",      // every numeric empty -> -1, flag -> ~0
    "u:x::::::: ",     // a lone space is NOT an empty flag
    "u:x:1:2:3:4:5:6", // no flag field at all -> ~0
    "u:x:1:2:3:4:5",   // too few fields
    "u:x:1",
    "u:x",
    "  u:x:1:2:3:4:5:6:7", // leading blanks belong to nobody
    "\tu:x:1:2:3:4:5:6:7",
    ":x:1:2:3:4:5:6:7", // empty name is valid
    "u::1:2:3:4:5:6:7",
    "u:x:-1:2:3:4:5:6:7", // negative is REJECTED, not read as -1
    "u:x:+1:2:3:4:5:6:7", // but a '+' sign is accepted
    "u:x: 5:2:3:4:5:6:7", // leading blanks inside a numeric field
    "u:x:007:2:3:4:5:6:7",
    "u:x:abc:2:3:4:5:6:7",
    "u:x:0x10:2:3:4:5:6:7", // base 10, so "0" then junk -> reject
    "u:x:99999999999999999999:2:3:4:5:6:7",
    "u:x:1:2:3:4:5:6:7:extra", // a tenth field rejects the entry
    "# comment",
    "",
    "   # c",
    "  ",
];

#[test]
fn shadow_lines_match_glibc() {
    let mut accepted = 0usize;
    let mut divergences = Vec::new();
    for &line in CASES {
        let host = host_shadow(line);
        if host.is_some() {
            accepted += 1;
        }
        let ours = frankenlibc_core::pwd::shadow::parse_shadow_line(line.as_bytes()).map(|e| {
            (
                e.name, e.passwd, e.lstchg, e.min, e.max, e.warn, e.inact, e.expire, e.flag,
            )
        });
        if ours != host {
            divergences.push(format!("{line:?}: fl={ours:?} glibc={host:?}"));
        }
    }
    // Most of these cases are meant to be REJECTED, so "both said None" is the
    // common answer and could hide a parser that rejects everything. Require
    // that glibc accepted a real share of them.
    assert!(
        accepted >= 8,
        "glibc accepted only {accepted} of {} cases -- near-vacuous",
        CASES.len()
    );
    assert!(
        divergences.is_empty(),
        "shadow line divergences ({} of {}):\n  {}",
        divergences.len(),
        CASES.len(),
        divergences.join("\n  ")
    );
}

type ShadowRead = unsafe extern "C-unwind" fn(*mut c_void) -> *mut libc::spwd;
type ShadowReadR = unsafe extern "C-unwind" fn(
    *mut libc::FILE,
    *mut libc::spwd,
    *mut c_char,
    usize,
    *mut *mut libc::spwd,
) -> c_int;

struct ShadowStreamApi {
    open: unsafe extern "C" fn(*mut c_void, usize, *const c_char) -> *mut c_void,
    fdopen: unsafe extern "C" fn(c_int, *const c_char) -> *mut c_void,
    close: unsafe extern "C-unwind" fn(*mut c_void) -> c_int,
    position: unsafe extern "C-unwind" fn(*mut c_void) -> i64,
    eof: unsafe extern "C-unwind" fn(*mut c_void) -> c_int,
    error: unsafe extern "C-unwind" fn(*mut c_void) -> c_int,
    errno: unsafe extern "C" fn() -> *mut c_int,
    read: ShadowRead,
    read_r: ShadowReadR,
}

impl ShadowStreamApi {
    fn native() -> Self {
        use frankenlibc_abi::{errno_abi, stdio_abi, unistd_abi};
        Self {
            open: stdio_abi::fmemopen,
            fdopen: stdio_abi::fdopen,
            close: stdio_abi::fclose,
            position: stdio_abi::ftello,
            eof: stdio_abi::feof,
            error: stdio_abi::ferror,
            errno: errno_abi::__errno_location,
            read: unistd_abi::fgetspent,
            read_r: unistd_abi::fgetspent_r,
        }
    }

    fn host() -> Self {
        let native = Self::native();
        // SAFETY: every signature matches the GNU declaration. Resolve the
        // entire FILE lifecycle from GNU so the reference cannot self-compare
        // or accidentally send a native FILE through a host reader.
        unsafe {
            Self {
                open: dlsym_oracle::host_fn(c"fmemopen", native.open as *const ()),
                fdopen: dlsym_oracle::host_fn(c"fdopen", native.fdopen as *const ()),
                close: dlsym_oracle::host_fn(c"fclose", native.close as *const ()),
                position: dlsym_oracle::host_fn(c"ftello", native.position as *const ()),
                eof: dlsym_oracle::host_fn(c"feof", native.eof as *const ()),
                error: dlsym_oracle::host_fn(c"ferror", native.error as *const ()),
                errno: dlsym_oracle::host_fn(c"__errno_location", native.errno as *const ()),
                read: dlsym_oracle::host_fn(c"fgetspent", native.read as *const ()),
                read_r: dlsym_oracle::host_fn(c"fgetspent_r", native.read_r as *const ()),
            }
        }
    }
}

struct ShadowStream<'a> {
    api: &'a ShadowStreamApi,
    stream: *mut c_void,
    _memory: Vec<u8>,
}

impl<'a> ShadowStream<'a> {
    fn memory(api: &'a ShadowStreamApi, input: &[u8]) -> Self {
        let mut memory = input.to_vec();
        memory.push(0); // Keep the empty stream's backing address nonnull too.
        // SAFETY: this allocation stays live until the provider closes FILE.
        let stream = unsafe { (api.open)(memory.as_mut_ptr().cast(), input.len(), c"r".as_ptr()) };
        assert!(!stream.is_null());
        Self {
            api,
            stream,
            _memory: memory,
        }
    }

    fn pipe(api: &'a ShadowStreamApi, input: &[u8]) -> Self {
        assert!(input.len() < 512);
        let mut descriptors = [-1; 2];
        // SAFETY: the short fixture fits an empty pipe; no writer remains to
        // make a failed reader hang waiting for another record.
        unsafe {
            assert_eq!(libc::pipe(descriptors.as_mut_ptr()), 0);
            assert_eq!(
                libc::write(descriptors[1], input.as_ptr().cast(), input.len()),
                input.len() as isize
            );
            assert_eq!(libc::close(descriptors[1]), 0);
        }
        // SAFETY: fdopen assumes ownership of the valid read descriptor.
        let stream = unsafe { (api.fdopen)(descriptors[0], c"r".as_ptr()) };
        assert!(!stream.is_null());
        Self {
            api,
            stream,
            _memory: Vec::new(),
        }
    }

    fn observation(
        &self,
        rc: c_int,
        error: c_int,
        record: Option<ShadowTuple>,
    ) -> ShadowObservation {
        ShadowObservation {
            rc,
            error,
            record,
            // Capture errno before querying a nonseekable FILE position.
            position: unsafe { (self.api.position)(self.stream) },
            eof: unsafe { (self.api.eof)(self.stream) } != 0,
            failed: unsafe { (self.api.error)(self.stream) } != 0,
        }
    }

    fn read(&self) -> ShadowObservation {
        // SAFETY: errno and FILE belong to this provider and remain live.
        unsafe { *(self.api.errno)() = 42 };
        let result = unsafe { (self.api.read)(self.stream) };
        let error = unsafe { *(self.api.errno)() };
        self.observation(if result.is_null() { error } else { 0 }, error, unsafe {
            shadow_tuple(result)
        })
    }

    fn read_r(&self, capacity: usize) -> ShadowObservation {
        let mut entry = std::mem::MaybeUninit::<libc::spwd>::zeroed();
        let mut result = std::ptr::dangling_mut::<libc::spwd>();
        let mut storage = vec![0xa5_u8; capacity + 17];
        // Deliberately unaligned character storage, with guards on both ends.
        let buffer = unsafe { storage.as_mut_ptr().add(7).cast::<c_char>() };
        // SAFETY: all outputs are live; the advertised byte extent excludes
        // the guards. A successful result must point at our supplied struct.
        let rc = unsafe {
            *(self.api.errno)() = 42;
            (self.api.read_r)(
                self.stream.cast(),
                entry.as_mut_ptr(),
                buffer,
                capacity,
                &mut result,
            )
        };
        let error = unsafe { *(self.api.errno)() };
        assert!(storage[..7].iter().all(|&byte| byte == 0xa5));
        assert!(storage[capacity + 7..].iter().all(|&byte| byte == 0xa5));
        if rc == 0 {
            assert_eq!(result, entry.as_mut_ptr());
            // SAFETY: success has initialized the record and its two strings.
            let initialized = unsafe { entry.assume_init_ref() };
            for field in [initialized.sp_namp, initialized.sp_pwdp] {
                let begin = buffer as usize;
                let end = begin + capacity;
                assert!((begin..end).contains(&(field as usize)));
                let length = unsafe { std::ffi::CStr::from_ptr(field) }.to_bytes().len();
                assert!(length < end - field as usize);
            }
        } else {
            assert!(result.is_null(), "error must clear the result pointer");
        }
        self.observation(rc, error, unsafe { shadow_tuple(result) })
    }
}

impl Drop for ShadowStream<'_> {
    fn drop(&mut self) {
        // SAFETY: FILE is closed before its optional memory backing drops.
        unsafe { (self.api.close)(self.stream) };
    }
}

#[derive(PartialEq, Eq)]
struct ShadowObservation {
    rc: c_int,
    error: c_int,
    record: Option<ShadowTuple>,
    position: i64,
    eof: bool,
    failed: bool,
}

impl std::fmt::Debug for ShadowObservation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Keep a long-record failure below the isolated child's pipe capacity.
        // Equality still compares every byte; only diagnostic output is bounded.
        let record = self.record.as_ref().map(|record| {
            (
                (&record.0[..record.0.len().min(32)], record.0.len()),
                (&record.1[..record.1.len().min(32)], record.1.len()),
                [record.2, record.3, record.4, record.5, record.6, record.7],
                record.8,
            )
        });
        formatter
            .debug_struct("ShadowObservation")
            .field("rc", &self.rc)
            .field("errno", &self.error)
            .field("record", &record)
            .field("position", &self.position)
            .field("eof", &self.eof)
            .field("failed", &self.failed)
            .finish()
    }
}

unsafe fn shadow_tuple(entry: *const libc::spwd) -> Option<ShadowTuple> {
    if entry.is_null() {
        return None;
    }
    // SAFETY: callers snapshot a successful result before its storage changes.
    let entry = unsafe { &*entry };
    assert!(!entry.sp_namp.is_null() && !entry.sp_pwdp.is_null());
    Some((
        unsafe { std::ffi::CStr::from_ptr(entry.sp_namp) }
            .to_bytes()
            .to_vec(),
        unsafe { std::ffi::CStr::from_ptr(entry.sp_pwdp) }
            .to_bytes()
            .to_vec(),
        entry.sp_lstchg,
        entry.sp_min,
        entry.sp_max,
        entry.sp_warn,
        entry.sp_inact,
        entry.sp_expire,
        entry.sp_flag,
    ))
}

fn shadow_stream_child(name: &str) -> bool {
    const CHILD: &str = "FRANKENLIBC_SHADOW_STREAM_CHILD";
    if std::env::var(CHILD).as_deref() == Ok(name) {
        return false;
    }
    for mode in ["strict", "hardened"] {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture", "--test-threads=1"])
            .env(CHILD, name)
            .env("FRANKENLIBC_MODE", mode)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut timed_out = false;
        while child.try_wait().unwrap().is_none() {
            if std::time::Instant::now() >= deadline {
                timed_out = true;
                let _ = child.kill();
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !timed_out && output.status.success() && stdout.contains("1 passed;"),
            "{name} {mode}: timeout={timed_out} status={}\n{stdout}\n{stderr}",
            output.status
        );
    }
    true
}

#[test]
fn shadow_stream_records_and_retries_match_glibc() {
    if shadow_stream_child("shadow_stream_records_and_retries_match_glibc") {
        return;
    }
    let host = ShadowStreamApi::host();
    let native = ShadowStreamApi::native();
    let mut cases = vec![
        Vec::new(),
        b"\n# comment\nmalformed\n".to_vec(),
        b"alpha:!:1:2:3:4:5:6:7\n".to_vec(),
        b"alpha:!:1:2:3:4:5:6:7".to_vec(),
        b"\t# comment\nbroken\n  alpha:!:1:2:3:4:5:6:7\nbeta:*:::::::\n".to_vec(),
        b"name\xff:hash\xfe:1:2:3:4:5:6:7\nlast:!:::::::\n".to_vec(),
        format!(
            "{}:{}:1:2:3:4:5:6:7\nlast:!:::::::\n",
            "n".repeat(5000),
            "p".repeat(7000)
        )
        .into_bytes(),
    ];
    cases.push(format!("#{}\nalpha:!:1:2:3:4:5:6:7\n", "c".repeat(4096)).into_bytes());
    // GNU keeps the grown nonreentrant line buffer across FILEs, even if
    // growth only skipped a comment before EOF. The following fitting read
    // must preserve its incoming errno instead of repeating ERANGE growth.
    cases.push(format!("#{}\n", "c".repeat(20000)).into_bytes());
    cases.push(format!("#{}\nalpha:!:1:2:3:4:5:6:7\n", "c".repeat(20000)).into_bytes());
    let mut comparisons = 0;
    let mut accepted = 0;
    for (index, input) in cases.iter().enumerate() {
        let reference = ShadowStream::memory(&host, input);
        let candidate = ShadowStream::memory(&native, input);
        for read in 0..3 {
            let expected = reference.read();
            let actual = candidate.read();
            accepted += usize::from(expected.record.is_some());
            assert_eq!(actual, expected, "nonreentrant case={index} read={read}");
            comparisons += 1;
        }
        let mut capacities = vec![
            0,
            1,
            2,
            3,
            16,
            1024,
            input.len(),
            input.len() + 1,
            input.len() + 2,
        ];
        capacities.sort_unstable();
        capacities.dedup();
        for capacity in capacities {
            let reference = ShadowStream::memory(&host, input);
            let candidate = ShadowStream::memory(&native, input);
            for requested in [capacity, input.len() + 64, input.len() + 64] {
                let expected = reference.read_r(requested);
                let actual = candidate.read_r(requested);
                accepted += usize::from(expected.record.is_some());
                assert_eq!(
                    actual, expected,
                    "reentrant case={index} capacity={requested}"
                );
                comparisons += 1;
            }
        }
    }
    let pipe_input = b"alpha:!:1:2:3:4:5:6:7\nbeta:!:8:9:10:11:12:13:14\n";
    for capacity in [0, 2, 8, 128] {
        let reference = ShadowStream::pipe(&host, pipe_input);
        let candidate = ShadowStream::pipe(&native, pipe_input);
        for requested in [capacity, 128, 128] {
            assert_eq!(
                candidate.read_r(requested),
                reference.read_r(requested),
                "pipe capacity={requested}"
            );
            comparisons += 1;
        }
    }
    // GNU's nonreentrant reader refuses a pipe before consuming any data.
    // A following reentrant call must therefore still see the first record.
    let reference = ShadowStream::pipe(&host, pipe_input);
    let candidate = ShadowStream::pipe(&native, pipe_input);
    assert_eq!(candidate.read(), reference.read());
    assert_eq!(candidate.read_r(128), reference.read_r(128));
    assert!(comparisons >= 150 && accepted >= 30);
    eprintln!("shadow stream comparisons={comparisons} accepted_records={accepted}");
}

#[test]
fn shadow_stream_native_owner_preserves_creator_result() {
    if shadow_stream_child("shadow_stream_native_owner_preserves_creator_result") {
        return;
    }
    use frankenlibc_abi::{pthread_abi, unistd_abi};
    let api = ShadowStreamApi::native();
    let creator = ShadowStream::memory(&api, b"creator:!:1:2:3:4:5:6:7\n");
    let worker = ShadowStream::memory(&api, b"worker:!!:8:9:10:11:12:13:14\n");
    // SAFETY: creator FILE remains live through both result observations.
    let retained = unsafe { unistd_abi::fgetspent(creator.stream) };
    assert!(!retained.is_null());
    let before = unsafe { shadow_tuple(retained) };
    let context = [worker.stream as usize, retained as usize];
    unsafe extern "C" fn read_native(argument: *mut c_void) -> *mut c_void {
        if frankenlibc_core::pthread::thread::current_thread_handle().is_none() {
            return 1usize as *mut c_void;
        }
        // SAFETY: the creator's stack context and the independent FILE remain
        // live until join. Inspect fields before native TLS teardown runs.
        unsafe {
            let context = &*argument.cast::<[usize; 2]>();
            let entry = unistd_abi::fgetspent(context[0] as *mut c_void);
            if entry.is_null() || entry as usize == context[1] {
                return 2usize as *mut c_void;
            }
            if std::ffi::CStr::from_ptr((*entry).sp_namp).to_bytes() != b"worker"
                || std::ffi::CStr::from_ptr((*entry).sp_pwdp).to_bytes() != b"!!"
                || (*entry).sp_lstchg != 8
            {
                return 3usize as *mut c_void;
            }
        }
        std::ptr::null_mut()
    }
    let previous = pthread_abi::pthread_threading_swap_force_native_for_tests();
    let mut thread = 0;
    let mut answer = std::ptr::dangling_mut::<c_void>();
    // SAFETY: both the argument and worker FILE outlive the joined thread.
    let created = unsafe {
        pthread_abi::pthread_create(
            &mut thread,
            std::ptr::null(),
            Some(read_native),
            context.as_ptr().cast_mut().cast(),
        )
    };
    assert_eq!(created, 0);
    let joined = unsafe { pthread_abi::pthread_join(thread, &mut answer) };
    pthread_abi::pthread_threading_restore_for_tests(previous);
    assert_eq!(joined, 0);
    assert!(answer.is_null(), "native worker result={answer:p}");
    assert_eq!(unsafe { shadow_tuple(retained) }, before);
}
