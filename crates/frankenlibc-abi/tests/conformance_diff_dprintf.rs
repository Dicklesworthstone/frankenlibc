#![cfg(target_os = "linux")]
#![feature(c_variadic)]

//! Differential conformance harness for `dprintf(3)`.
//!
//! dprintf writes formatted output to a file descriptor (no FILE*).
//! fl exports its own implementation in stdio_abi.rs; this is the first
//! head-to-head diff against host glibc.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{c_char, c_int, c_void};
use std::sync::OnceLock;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

use frankenlibc_abi::{errno_abi, glibc_internal_abi, stdio_abi};

type Print = unsafe extern "C-unwind" fn(c_int, *const c_char, ...) -> c_int;
type Vprint = unsafe extern "C-unwind" fn(c_int, *const c_char, *mut c_void) -> c_int;
type Errno = unsafe extern "C" fn() -> *mut c_int;

fn host_dprintf() -> Print {
    static HOST: OnceLock<Print> = OnceLock::new();
    *HOST.get_or_init(|| {
        // SAFETY: the independently resolved GNU symbol has this variadic ABI.
        unsafe { dlsym_oracle::host_fn(c"dprintf", stdio_abi::dprintf as *const ()) }
    })
}

fn host_errno() -> Errno {
    static HOST: OnceLock<Errno> = OnceLock::new();
    *HOST.get_or_init(|| {
        // SAFETY: __errno_location returns the calling thread's errno slot.
        unsafe {
            dlsym_oracle::host_fn(
                c"__errno_location",
                errno_abi::__errno_location as *const (),
            )
        }
    })
}

unsafe extern "C-unwind" fn native_vdprintf(
    fd: c_int,
    format: *const c_char,
    mut args: ...
) -> c_int {
    // SAFETY: the forwarding frame owns the promoted arguments and live va_list.
    unsafe { stdio_abi::vdprintf(fd, format, std::ptr::addr_of_mut!(args).cast()) }
}

unsafe extern "C-unwind" fn host_vdprintf(
    fd: c_int,
    format: *const c_char,
    mut args: ...
) -> c_int {
    static HOST: OnceLock<Vprint> = OnceLock::new();
    let print = *HOST.get_or_init(|| {
        // SAFETY: the independently resolved symbol consumes this C va_list ABI.
        unsafe { dlsym_oracle::host_fn(c"vdprintf", stdio_abi::vdprintf as *const ()) }
    });
    // SAFETY: the forwarding frame retains its va_list through this call.
    unsafe { print(fd, format, std::ptr::addr_of_mut!(args).cast()) }
}

fn engines() -> [(&'static str, Print, Print); 2] {
    [
        ("dprintf", host_dprintf(), stdio_abi::dprintf as Print),
        ("vdprintf", host_vdprintf as Print, native_vdprintf as Print),
    ]
}

fn capture_memfd<T>(call: impl FnOnce(c_int) -> T) -> (T, Vec<u8>) {
    // SAFETY: a constant valid name creates an anonymous, seekable descriptor.
    let fd = unsafe { libc::memfd_create(c"dprintf-output".as_ptr(), 0) };
    assert!(fd >= 0);
    let result = call(fd);
    // SAFETY: the caller retains ownership of this descriptor after formatting.
    let length = unsafe { libc::lseek(fd, 0, libc::SEEK_END) };
    assert!(length >= 0);
    let mut output = vec![0; length as usize];
    // SAFETY: seek and read stay within the live descriptor and owned output.
    unsafe {
        assert_eq!(libc::lseek(fd, 0, libc::SEEK_SET), 0);
        assert_eq!(
            libc::read(fd, output.as_mut_ptr().cast(), output.len()),
            length as isize
        );
        assert_eq!(libc::close(fd), 0);
    }
    (result, output)
}

/// Run a single dprintf to a memory-backed pipe and return the captured bytes.
///
/// fd-based output requires a real fd; we use a pipe and read the write side
/// after dprintf returns.
unsafe fn capture_dprintf<F>(call: F) -> (c_int, Vec<u8>)
where
    F: FnOnce(c_int) -> c_int,
{
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return (-1, Vec::new());
    }
    let n = call(fds[1]);
    unsafe { libc::close(fds[1]) };
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let r = unsafe { libc::read(fds[0], buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if r <= 0 {
            break;
        }
        out.extend_from_slice(&buf[..r as usize]);
    }
    unsafe { libc::close(fds[0]) };
    (n, out)
}

#[derive(Debug)]
struct Divergence {
    case: String,
    field: &'static str,
    frankenlibc: String,
    glibc: String,
}

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        out.push_str(&format!(
            "  case: {} | field: {} | fl: {} | glibc: {}\n",
            d.case, d.field, d.frankenlibc, d.glibc,
        ));
    }
    out
}

#[test]
fn diff_dprintf_basic_specifiers() {
    let mut divs = Vec::new();

    macro_rules! pair {
        ($case:literal, $fl_call:expr, $lc_call:expr) => {{
            let (fl_n, fl_out) = unsafe { capture_dprintf($fl_call) };
            let (lc_n, lc_out) = unsafe { capture_dprintf($lc_call) };
            if fl_n != lc_n {
                divs.push(Divergence {
                    case: $case.to_string(),
                    field: "return",
                    frankenlibc: format!("{fl_n}"),
                    glibc: format!("{lc_n}"),
                });
            }
            if fl_out != lc_out {
                divs.push(Divergence {
                    case: $case.to_string(),
                    field: "output",
                    frankenlibc: format!("{:?}", String::from_utf8_lossy(&fl_out)),
                    glibc: format!("{:?}", String::from_utf8_lossy(&lc_out)),
                });
            }
        }};
    }

    pair!(
        "literal",
        |fd| frankenlibc_abi::stdio_abi::dprintf(fd, c"hello world".as_ptr()),
        |fd| host_dprintf()(fd, c"hello world".as_ptr())
    );

    pair!(
        "%d",
        |fd| frankenlibc_abi::stdio_abi::dprintf(fd, c"%d".as_ptr(), 42),
        |fd| host_dprintf()(fd, c"%d".as_ptr(), 42)
    );

    pair!(
        "%s",
        |fd| frankenlibc_abi::stdio_abi::dprintf(fd, c"%s".as_ptr(), c"hello".as_ptr()),
        |fd| host_dprintf()(fd, c"%s".as_ptr(), c"hello".as_ptr())
    );

    pair!(
        "mixed",
        |fd| {
            frankenlibc_abi::stdio_abi::dprintf(
                fd,
                c"%s=%d %s=%d\n".as_ptr(),
                c"x".as_ptr(),
                10,
                c"y".as_ptr(),
                20,
            )
        },
        |fd| host_dprintf()(
            fd,
            c"%s=%d %s=%d\n".as_ptr(),
            c"x".as_ptr(),
            10,
            c"y".as_ptr(),
            20
        )
    );

    pair!(
        "%08x",
        |fd| { frankenlibc_abi::stdio_abi::dprintf(fd, c"%08x".as_ptr(), 0xdeadbeefu32) },
        |fd| host_dprintf()(fd, c"%08x".as_ptr(), 0xdeadbeefu32)
    );

    pair!(
        "long output %200d",
        |fd| frankenlibc_abi::stdio_abi::dprintf(fd, c"%200d".as_ptr(), 1),
        |fd| host_dprintf()(fd, c"%200d".as_ptr(), 1)
    );

    pair!(
        "empty format",
        |fd| frankenlibc_abi::stdio_abi::dprintf(fd, c"".as_ptr()),
        |fd| host_dprintf()(fd, c"".as_ptr())
    );

    pair!(
        "%% literal",
        |fd| frankenlibc_abi::stdio_abi::dprintf(fd, c"50%% complete".as_ptr()),
        |fd| host_dprintf()(fd, c"50%% complete".as_ptr())
    );

    assert!(
        divs.is_empty(),
        "dprintf divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_dprintf_invalid_fd_returns_minus_one() {
    let fl_n = unsafe { frankenlibc_abi::stdio_abi::dprintf(-1, c"oops".as_ptr()) };
    let lc_n = unsafe { host_dprintf()(-1, c"oops".as_ptr()) };
    assert_eq!(fl_n, lc_n, "dprintf invalid-fd return: fl={fl_n} lc={lc_n}");
    assert_eq!(fl_n, -1, "dprintf(-1) should return -1");
}

#[test]
fn dprintf_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc dprintf\",\"reference\":\"glibc\",\"functions\":1,\"divergences\":0}}",
    );
}

#[test]
fn descriptor_write_failure_stops_later_count_stores() {
    for (entry, host, native) in engines() {
        for length in [0, 1, 2047, 2048, 2049, 4095, 4096, 8193, 16_384] {
            let input = std::ffi::CString::new(vec![b'x'; length]).unwrap();
            let mut expected = None;
            for (print, errno) in [
                (host, host_errno()),
                (native, errno_abi::__errno_location as Errno),
            ] {
                // SAFETY: open the existing failing device; no file is created.
                let fd = unsafe { libc::open(c"/dev/full".as_ptr(), libc::O_WRONLY) };
                assert!(fd >= 0);
                let mut before = -771;
                let mut after = -772;
                // SAFETY: the string and both correctly typed count slots stay live.
                let observed = unsafe {
                    *errno() = 23;
                    let rc = print(
                        fd,
                        c"%n%s%n".as_ptr(),
                        &mut before,
                        input.as_ptr(),
                        &mut after,
                    );
                    (rc, *errno(), before, after)
                };
                // The formatter must retain caller ownership even on write failure.
                assert_ne!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
                assert_eq!(unsafe { libc::close(fd) }, 0);
                if let Some(expected) = expected {
                    assert_eq!(observed, expected, "{entry} length={length}");
                } else {
                    assert_eq!(observed.2, 0);
                    if length == 0 {
                        assert_eq!(observed, (0, 23, 0, 0));
                    } else {
                        assert_eq!((observed.0, observed.1), (-1, libc::ENOSPC));
                    }
                    expected = Some(observed);
                }
            }
        }
    }
}

#[test]
fn descriptor_encoding_failure_keeps_only_committed_prefix() {
    for (entry, host, native) in engines() {
        for length in [0, 1, 2047, 2048, 2049, 4095, 4096, 8193, 16_384] {
            let input = std::ffi::CString::new(vec![b'x'; length]).unwrap();
            let mut expected = None;
            for (print, errno) in [
                (host, host_errno()),
                (native, errno_abi::__errno_location as Errno),
            ] {
                // memfd avoids pipe-capacity deadlocks and creates no pathname.
                let fd = unsafe { libc::memfd_create(c"dprintf-prefix".as_ptr(), 0) };
                assert!(fd >= 0);
                let mut before = -771;
                let mut after = -772;
                // A surrogate is unrepresentable in both C and UTF-8 locales.
                // SAFETY: all promoted arguments match their conversions.
                let (rc, error) = unsafe {
                    *errno() = 23;
                    let rc = print(
                        fd,
                        c"%s%n%lc%n".as_ptr(),
                        input.as_ptr(),
                        &mut before,
                        0xd800u32,
                        &mut after,
                    );
                    (rc, *errno())
                };
                let emitted = unsafe { libc::lseek(fd, 0, libc::SEEK_END) };
                assert!(emitted >= 0);
                let mut output = vec![0; emitted as usize];
                assert_eq!(unsafe { libc::lseek(fd, 0, libc::SEEK_SET) }, 0);
                assert_eq!(
                    unsafe { libc::read(fd, output.as_mut_ptr().cast(), output.len()) },
                    emitted as isize
                );
                assert_eq!(unsafe { libc::close(fd) }, 0);
                assert!(output.iter().all(|&byte| byte == b'x'));
                let observed = (rc, error, before, after, output.len());
                if let Some(expected) = expected {
                    assert_eq!(observed, expected, "{entry} length={length}");
                } else {
                    assert_eq!(
                        (rc, error, before, after),
                        (-1, libc::EILSEQ, length as c_int, -772)
                    );
                    expected = Some(observed);
                }
            }
        }
    }
}

#[test]
fn descriptor_wide_string_failure_and_precision_preserve_gnu_chunks() {
    for (entry, host, native) in engines() {
        for format in [
            c"%ls%n",
            c"%1ls%n",
            c"%-1ls%n",
            c"%.4096ls%n",
            c"%1.4096ls%n",
            c"%-1.4096ls%n",
        ] {
            for length in [0, 255, 256, 2048, 2049, 4095, 4096, 8193] {
                let mut input = vec![b'x' as u32; length];
                input.extend_from_slice(&[0xd800, 0]);
                let mut expected = None;
                for (print, errno) in [
                    (host, host_errno()),
                    (native, errno_abi::__errno_location as Errno),
                ] {
                    let observed = capture_memfd(|fd| {
                        let mut count = -772;
                        // SAFETY: the terminated wide string and count slot
                        // match the conversions; surrogate failure is defined.
                        unsafe {
                            *errno() = 23;
                            let rc = print(fd, format.as_ptr(), input.as_ptr(), &mut count);
                            (rc, *errno(), count)
                        }
                    });
                    if let Some(expected) = expected.as_ref() {
                        assert_eq!(&observed, expected, "{entry} {format:?} length={length}");
                    } else {
                        if observed.0.0 < 0 {
                            assert_eq!(observed.0, (-1, libc::EILSEQ, -772));
                        } else {
                            assert_eq!(observed.0, (4096, 23, 4096));
                            assert_eq!(observed.1, vec![b'x'; 4096]);
                        }
                        expected = Some(observed);
                    }
                }
            }
        }
    }
}

#[test]
fn descriptor_empty_output_preserves_errno_without_validating_fd() {
    for (entry, host, native) in engines() {
        // SAFETY: this descriptor is intentionally unsuitable for output.
        let read_only = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        assert!(read_only >= 0);
        for fd in [-1, read_only] {
            for (print, errno) in [
                (host, host_errno()),
                (native, errno_abi::__errno_location as Errno),
            ] {
                let mut count = -772;
                // SAFETY: the correctly typed conversions produce no bytes.
                let observed = unsafe {
                    *errno() = 23;
                    let rc = print(fd, c"%n%.0s".as_ptr(), &mut count, c"unused".as_ptr());
                    (rc, *errno(), count)
                };
                assert_eq!(observed, (0, 23, 0), "{entry} fd={fd}");
            }
        }
        // SAFETY: neither formatter owns or closes this descriptor.
        assert_eq!(unsafe { libc::close(read_only) }, 0);
    }
}

#[test]
fn descriptor_success_streams_positional_width_precision_and_float_fields() {
    let input = std::ffi::CString::new(vec![b'x'; 8193]).unwrap();
    let wide = [b'A' as u32, b'B' as u32, 0];
    for (entry, host, native) in engines() {
        for width in [0, 17, 4097] {
            for precision in [0, 3, 3001] {
                let mut expected = None;
                for (print, errno) in [
                    (host, host_errno()),
                    (native, errno_abi::__errno_location as Errno),
                ] {
                    let observed = capture_memfd(|fd| {
                        let mut count = -772;
                        // SAFETY: positional indices and promoted argument types
                        // match the dynamic-width, float, wide-string and count fields.
                        unsafe {
                            *errno() = 23;
                            let rc = print(
                                fd,
                                c"[%3$*1$.*2$s]|%4$#.6g|%5$#.3a|%6$ls%7$n".as_ptr(),
                                width,
                                precision,
                                input.as_ptr(),
                                1.234567f64,
                                1.25f64,
                                wide.as_ptr(),
                                &mut count,
                            );
                            (rc, *errno(), count)
                        }
                    });
                    assert_eq!(observed.0.0 as usize, observed.1.len());
                    assert_eq!(observed.0.2, observed.0.0);
                    if let Some(expected) = expected.as_ref() {
                        assert_eq!(
                            &observed, expected,
                            "{entry} width={width} precision={precision}"
                        );
                    } else {
                        expected = Some(observed);
                    }
                }
            }
        }
    }
}

#[test]
fn descriptor_nonblocking_failure_preserves_prefix_without_replay() {
    for (entry, host, native) in engines() {
        let mut expected = None;
        for (print, errno) in [
            (host, host_errno()),
            (native, errno_abi::__errno_location as Errno),
        ] {
            let mut fds = [-1; 2];
            // SAFETY: pipe2 initializes two caller-owned descriptor slots.
            assert_eq!(
                unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK) },
                0
            );
            // SAFETY: this Linux command reads the live pipe's capacity.
            let capacity = unsafe { libc::fcntl(fds[1], libc::F_GETPIPE_SZ) };
            assert!(capacity > 0);
            let input = std::ffi::CString::new(
                (0..capacity as usize + 8193)
                    .map(|index| b'a' + (index % 23) as u8)
                    .collect::<Vec<_>>(),
            )
            .unwrap();
            let mut count = -772;
            // SAFETY: the string and count pointer match the format.
            let result = unsafe {
                *errno() = 23;
                let rc = print(fds[1], c"%s%n".as_ptr(), input.as_ptr(), &mut count);
                (rc, *errno(), count)
            };
            assert_eq!(result, (-1, libc::EAGAIN, -772));
            let mut output = vec![0; capacity as usize];
            // SAFETY: closing our write side produces EOF after the committed
            // prefix; the live read side writes only within the owned vector.
            let length = unsafe {
                assert_eq!(libc::close(fds[1]), 0);
                let length = libc::read(fds[0], output.as_mut_ptr().cast(), output.len());
                assert_eq!(libc::close(fds[0]), 0);
                length
            };
            assert!(length > 0);
            output.truncate(length as usize);
            assert_eq!(output, input.as_bytes()[..length as usize]);
            let observed = (result, output);
            if let Some(expected) = expected.as_ref() {
                assert_eq!(&observed, expected, "{entry}");
            } else {
                expected = Some(observed);
            }
        }
    }
}

type Register = unsafe extern "C" fn(c_int, *mut c_void, *mut c_void) -> c_int;
type Fwrite = unsafe extern "C-unwind" fn(*const c_void, usize, usize, *mut c_void) -> usize;
type Fprint = unsafe extern "C-unwind" fn(*mut c_void, *const c_char, ...) -> c_int;

unsafe extern "C" fn no_handler_arguments(
    _info: *const c_void,
    _count: usize,
    _types: *mut c_int,
    _sizes: *mut c_int,
) -> c_int {
    0
}

unsafe extern "C-unwind" fn native_ignoring_handler(
    stream: *mut c_void,
    _info: *const c_void,
    _args: *const *const c_void,
) -> c_int {
    // SAFETY: GNU callbacks receive a live FILE. Both writes are deliberately
    // ignored to verify that a positive callback result cannot clear failure.
    unsafe {
        stdio_abi::fwrite(c"[".as_ptr().cast(), 1, 1, stream);
        stdio_abi::fprintf(stream, c"%8192s".as_ptr(), c"".as_ptr());
    }
    8193
}

unsafe extern "C-unwind" fn host_ignoring_handler(
    stream: *mut c_void,
    _info: *const c_void,
    _args: *const *const c_void,
) -> c_int {
    static WRITE: OnceLock<Fwrite> = OnceLock::new();
    static PRINT: OnceLock<Fprint> = OnceLock::new();
    let write = *WRITE.get_or_init(|| {
        // SAFETY: this independently resolved function has the fwrite ABI.
        unsafe { dlsym_oracle::host_fn(c"fwrite", stdio_abi::fwrite as *const ()) }
    });
    let print = *PRINT.get_or_init(|| {
        // SAFETY: this independently resolved function has the fprintf ABI.
        unsafe { dlsym_oracle::host_fn(c"fprintf", stdio_abi::fprintf as *const ()) }
    });
    // SAFETY: the GNU stream is consumed only by GNU FILE operations.
    unsafe {
        write(c"[".as_ptr().cast(), 1, 1, stream);
        print(stream, c"%8192s".as_ptr(), c"".as_ptr());
    }
    8193
}

struct HandlerRegistration(Register);

impl Drop for HandlerRegistration {
    fn drop(&mut self) {
        // SAFETY: unregister the test-only conversion even if an assertion fails.
        unsafe { (self.0)(b'Q' as c_int, std::ptr::null_mut(), std::ptr::null_mut()) };
    }
}

#[test]
fn descriptor_registered_handler_failure_stops_later_count_stores() {
    // SAFETY: register_printf_specifier has the same GNU callback registration ABI.
    let host_register: Register = unsafe {
        dlsym_oracle::host_fn(
            c"register_printf_specifier",
            glibc_internal_abi::register_printf_specifier as *const (),
        )
    };
    let registrations = [
        (
            host_register,
            host_ignoring_handler as *const () as *mut c_void,
        ),
        (
            glibc_internal_abi::register_printf_specifier as Register,
            native_ignoring_handler as *const () as *mut c_void,
        ),
    ];
    let mut guards = Vec::new();
    for (register, handler) in registrations {
        // SAFETY: both static callbacks implement the registered ABI and remain live.
        assert_eq!(
            unsafe {
                register(
                    b'Q' as c_int,
                    handler,
                    no_handler_arguments as *const () as *mut c_void,
                )
            },
            0
        );
        guards.push(HandlerRegistration(register));
    }
    for (entry, host, native) in engines() {
        for length in [0, 1, 2048, 2049] {
            let input = std::ffi::CString::new(vec![b'a'; length]).unwrap();
            for (print, errno) in [
                (host, host_errno()),
                (native, errno_abi::__errno_location as Errno),
            ] {
                // SAFETY: the existing device rejects every nonempty write.
                let fd = unsafe { libc::open(c"/dev/full".as_ptr(), libc::O_WRONLY) };
                assert!(fd >= 0);
                let mut count = -772;
                // SAFETY: the count and string arguments match the format;
                // the registered Q handler consumes no arguments.
                let observed = unsafe {
                    *errno() = 23;
                    let rc = print(fd, c"%s%Q%n".as_ptr(), input.as_ptr(), &mut count);
                    (rc, *errno(), count)
                };
                // SAFETY: descriptor ownership remains with this test on failure.
                assert_eq!(unsafe { libc::close(fd) }, 0);
                assert_eq!(
                    observed,
                    (-1, libc::ENOSPC, -772),
                    "{entry} prefix={length}"
                );
            }
        }
        let mut expected = None;
        for (print, errno) in [
            (host, host_errno()),
            (native, errno_abi::__errno_location as Errno),
        ] {
            let observed = capture_memfd(|fd| {
                let mut count = -772;
                // SAFETY: the successful handler writes one byte then recursively
                // formats 8192 spaces; the final count slot remains live.
                unsafe {
                    *errno() = 23;
                    let rc = print(fd, c"%Q%n".as_ptr(), &mut count);
                    (rc, *errno(), count)
                }
            });
            assert_eq!(observed.0, (8193, 23, 8193));
            assert_eq!(observed.1.len(), 8193);
            assert_eq!(observed.1[0], b'[');
            assert!(observed.1[1..].iter().all(|&byte| byte == b' '));
            if let Some(expected) = expected.as_ref() {
                assert_eq!(&observed, expected, "{entry}");
            } else {
                expected = Some(observed);
            }
        }
    }
}
