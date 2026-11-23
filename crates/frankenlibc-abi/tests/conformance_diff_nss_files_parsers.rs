//! Exercise native GNU files parsers against an independently resolved libc.
//! Both modes run in fresh processes, with fields and errors checked rather
//! than merely checking symbol presence or a self-consistent round trip.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::unistd_abi as native;
use std::ffi::{CStr, c_char, c_int, c_void};

type Parse =
    unsafe extern "C" fn(*mut c_char, *mut c_void, *mut c_void, usize, *mut c_int) -> c_int;
type Errno = unsafe extern "C" fn() -> *mut c_int;

unsafe extern "C" {
    fn dlopen(name: *const c_char, flags: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Ether,
    Network,
    Protocol,
    Rpc,
    Service,
}

#[repr(C)]
struct Etherent {
    name: *mut c_char,
    address: [u8; 6],
}
#[repr(C)]
struct Numbered {
    name: *mut c_char,
    aliases: *mut *mut c_char,
    number: c_int,
}
#[repr(C)]
struct Netent {
    name: *mut c_char,
    aliases: *mut *mut c_char,
    family: c_int,
    number: u32,
}
#[repr(C)]
struct Servent {
    name: *mut c_char,
    aliases: *mut *mut c_char,
    port: c_int,
    protocol: *mut c_char,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Record {
    name: Vec<u8>,
    aliases: Vec<Vec<u8>>,
    number: u32,
    family: c_int,
    protocol: Vec<u8>,
    address: [u8; 6],
}

#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    status: c_int,
    error: c_int,
    ordinary_errno: c_int,
    record: Option<Record>,
}

fn isolated(test: &str) -> bool {
    if std::env::var("FRANKENLIBC_NSS_PARSER_CHILD").as_deref() == Ok(test) {
        return false;
    }
    for mode in ["strict", "hardened"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture", "--test-threads=1"])
            .env("FRANKENLIBC_NSS_PARSER_CHILD", test)
            .env("FRANKENLIBC_MODE", mode)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{test} in {mode}:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "child filter must execute one test"
        );
    }
    true
}

fn parsers() -> [(Kind, &'static CStr, Parse); 5] {
    [
        (
            Kind::Ether,
            c"_nss_files_parse_etherent",
            native::_nss_files_parse_etherent,
        ),
        (
            Kind::Network,
            c"_nss_files_parse_netent",
            native::_nss_files_parse_netent,
        ),
        (
            Kind::Protocol,
            c"_nss_files_parse_protoent",
            native::_nss_files_parse_protoent,
        ),
        (
            Kind::Rpc,
            c"_nss_files_parse_rpcent",
            native::_nss_files_parse_rpcent,
        ),
        (
            Kind::Service,
            c"_nss_files_parse_servent",
            native::_nss_files_parse_servent,
        ),
    ]
}

unsafe fn symbol(handle: *mut c_void, name: &CStr) -> *mut c_void {
    // SAFETY: handle was opened below and name is terminated.
    let pointer = unsafe { dlsym(handle, name.as_ptr()) };
    assert!(!pointer.is_null(), "missing GNU oracle {name:?}");
    pointer
}

fn checked_text(pointer: *const c_char, start: usize, end: usize) -> Vec<u8> {
    let address = pointer as usize;
    assert!(
        (start..end).contains(&address),
        "string must remain in the caller's line"
    );
    // SAFETY: validate the pointer against the original line extent first.
    let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), end - address) };
    let length = bytes
        .iter()
        .position(|&byte| byte == 0)
        .expect("bounded NUL");
    bytes[..length].to_vec()
}

fn run(
    kind: Kind,
    parser: Parse,
    errno: Errno,
    input: &[u8],
    capacity: usize,
    offset: usize,
    candidate: bool,
) -> Outcome {
    let mut storage = vec![0xa5a5_a5a5_a5a5_a5a5u64; 4096];
    let base = storage.as_mut_ptr().cast::<u8>();
    assert!(offset + input.len() + 1 < storage.len() * 8);
    // SAFETY: this initialized, aligned allocation holds the line and table.
    let line = unsafe {
        std::ptr::copy_nonoverlapping(input.as_ptr(), base.add(offset), input.len());
        base.add(offset + input.len()).write(0);
        base.add(offset).cast::<c_char>()
    };
    let mut output = [0usize; 8];
    let mut error = 711;
    // SAFETY: both errno providers return the current thread's writable cell.
    unsafe { *errno() = 712 };
    // SAFETY: output is aligned and large enough for each of the five layouts.
    // The advertised parser workspace may be small, while the input stays live.
    let status = unsafe {
        parser(
            line,
            output.as_mut_ptr().cast(),
            base.cast(),
            capacity,
            &mut error,
        )
    };
    let ordinary_errno = unsafe { *errno() };
    let mut record = None;
    if status == 1 {
        let mut value = Record::default();
        let mut aliases = std::ptr::null_mut();
        let start = line as usize;
        let end = start + input.len() + 1;
        // SAFETY: a successful parser published the matching repr(C) object.
        unsafe {
            match kind {
                Kind::Ether => {
                    let result = &*output.as_ptr().cast::<Etherent>();
                    value.name = checked_text(result.name, start, end);
                    value.address = result.address;
                }
                Kind::Network => {
                    let result = &*output.as_ptr().cast::<Netent>();
                    value.name = checked_text(result.name, start, end);
                    value.number = result.number;
                    value.family = result.family;
                    aliases = result.aliases;
                }
                Kind::Protocol | Kind::Rpc => {
                    let result = &*output.as_ptr().cast::<Numbered>();
                    value.name = checked_text(result.name, start, end);
                    value.number = result.number as u32;
                    aliases = result.aliases;
                }
                Kind::Service => {
                    let result = &*output.as_ptr().cast::<Servent>();
                    value.name = checked_text(result.name, start, end);
                    value.number = result.port as u32;
                    value.protocol = checked_text(result.protocol, start, end);
                    aliases = result.aliases;
                }
            }
            if kind != Kind::Ether {
                let word = std::mem::size_of::<*mut c_char>();
                let mut cursor = aliases;
                loop {
                    assert_eq!((cursor as usize) % std::mem::align_of::<*mut c_char>(), 0);
                    assert!(cursor as usize >= base as usize);
                    assert!(
                        (cursor as usize).checked_add(word).unwrap() <= base as usize + capacity,
                        "alias table must remain within the advertised workspace"
                    );
                    let pointer = cursor.read();
                    if pointer.is_null() {
                        break;
                    }
                    value.aliases.push(checked_text(pointer, start, end));
                    cursor = cursor.add(1);
                }
            }
        }
        record = Some(value);
    } else if status == -1 && candidate {
        // An insufficient-workspace retry must not lose delimiters or comments.
        let unchanged = unsafe { std::slice::from_raw_parts(line.cast::<u8>(), input.len()) };
        assert_eq!(
            unchanged, input,
            "ERANGE must leave the input available for retry"
        );
    }
    Outcome {
        status,
        error,
        ordinary_errno,
        record,
    }
}

fn cases(kind: Kind) -> Vec<Vec<u8>> {
    let mut cases: Vec<Vec<u8>> = [b"".as_slice(), b" ", b"# comment", b"\nignored"]
        .into_iter()
        .map(Vec::from)
        .collect();
    let lines: &[&[u8]] = match kind {
        Kind::Ether => &[
            b"00:11:22:33:44:55 host alias",
            b"0:1:2:a:f:FF host",
            b" 0:1:2:3:4:5 host#comment",
            b"0:1:2:3:4:5",
            b"0:1:2:3:4:555 host",
            b"000:001:002:003:004:005 host",
            b"+0: 0x1:2:3:4:0005 host",
            b"-0:1:2:3:4:5 host",
            b"0:1:2:3:4:05x host",
            b"0 :1:2:3:4:5 host",
            b"0:1:2:3:4:5:6 host",
            b"0:1:2:3:4:5\x0bhost",
            b"0:1:2:3:4:fffffffffffffffff host",
        ],
        Kind::Network => &[
            b"loop 127 loopback",
            b"local 127.1 alias",
            b"local 0x7f.01 alias",
            b"all 255.255.255.255",
            b"bad 256 alias",
            b"bad 09 alias",
            b"bad -1 alias",
            b"bad 127.1junk alias",
            b"missing",
            b" 6",
            b"name\x0b127\x0cfirst\tsecond#tail",
        ],
        Kind::Protocol | Kind::Rpc => &[
            b"tcp 6 TCP alias",
            b" tcp 6 TCP",
            b" 6",
            b"tcp 6junk",
            b"tcp -1",
            b"tcp -0",
            b"tcp -18446744073709551615",
            b"tcp 0x6",
            b"tcp +6",
            b"tcp 2147483648",
            b"tcp 4294967295",
            b"tcp 4294967296",
            b"tcp 18446744073709551616junk",
            b"tcp\x0b6\x0cTCP\talt",
            b"tcp 6#comment alias",
            b"tcp 6 TCP\nnext 9",
            b"tcp",
            b"tcp ",
        ],
        Kind::Service => &[
            b"http 80/tcp www alias",
            b"http 0x50/tcp",
            b"echo 010/udp",
            b"bad 080/tcp",
            b"bad -1/tcp",
            b"http +0x50/tcp",
            b"wrap 65536/tcp",
            b"bad 4294967296/tcp",
            b"bad 18446744073709551616/tcp",
            b"name 80/tcp/extra",
            b"name 80/ alias",
            b"name 80",
            b"name 80 ",
            b"name 80\t",
            b"name 80 /tcp",
            b"name 80 #comment",
            b"name -0/tcp",
            b"name -18446744073709551615/tcp",
            b"name /tcp",
            b"name\x0b80/tcp\x0cwww\talias#tail",
            b"name 80/tcp www\nignored",
        ],
    };
    cases.extend(lines.iter().map(|line| line.to_vec()));
    if kind != Kind::Ether {
        let mut long = if kind == Kind::Service {
            b"entry 80/tcp".to_vec()
        } else {
            b"entry 6".to_vec()
        };
        for index in 0..96 {
            long.extend_from_slice(format!(" alias{index}").as_bytes());
        }
        cases.push(long);
    }
    cases
}

#[test]
fn native_files_parsers_match_gnu_fields_and_conversion_errors() {
    if isolated("native_files_parsers_match_gnu_fields_and_conversion_errors") {
        return;
    }
    let library = unsafe { dlopen(c"libc.so.6".as_ptr(), 2) };
    assert!(!library.is_null());
    let host_errno: Errno = unsafe { std::mem::transmute(symbol(library, c"__errno_location")) };
    for (kind, name, candidate) in parsers() {
        let host_pointer = unsafe { symbol(library, name) };
        assert_ne!(
            candidate as usize, host_pointer as usize,
            "oracle must be independent"
        );
        let host: Parse = unsafe { std::mem::transmute(host_pointer) };
        for line in cases(kind) {
            for offset in 0..8 {
                let expected = run(kind, host, host_errno, &line, 32768, offset, false);
                let actual = run(
                    kind,
                    candidate,
                    frankenlibc_abi::errno_abi::__errno_location,
                    &line,
                    32768,
                    offset,
                    true,
                );
                assert_eq!(actual, expected, "{kind:?}, offset={offset}, line={line:?}");
            }
        }
    }
}

#[test]
fn native_files_parsers_match_gnu_capacity_and_preserve_retry_input() {
    if isolated("native_files_parsers_match_gnu_capacity_and_preserve_retry_input") {
        return;
    }
    let library = unsafe { dlopen(c"libc.so.6".as_ptr(), 2) };
    assert!(!library.is_null());
    let host_errno: Errno = unsafe { std::mem::transmute(symbol(library, c"__errno_location")) };
    for (kind, name, candidate) in parsers() {
        let host_pointer = unsafe { symbol(library, name) };
        assert_ne!(candidate as usize, host_pointer as usize);
        let host: Parse = unsafe { std::mem::transmute(host_pointer) };
        let input: &[u8] = match kind {
            Kind::Ether => b"0:1:2:3:4:5 host",
            Kind::Service => b"entry 80/tcp first second",
            _ => b"entry 6 first second",
        };
        for offset in 0..8 {
            for capacity in 0..80 {
                let expected = run(kind, host, host_errno, input, capacity, offset, false);
                let actual = run(
                    kind,
                    candidate,
                    frankenlibc_abi::errno_abi::__errno_location,
                    input,
                    capacity,
                    offset,
                    true,
                );
                assert_eq!(
                    actual, expected,
                    "{kind:?}, offset={offset}, capacity={capacity}"
                );
            }
        }
    }
}
