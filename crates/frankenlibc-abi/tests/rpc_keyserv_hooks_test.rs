#![cfg(target_os = "linux")]

//! Local keyserver hook ABI regressions. These are integration tests because
//! the ABI library deliberately excludes exported modules under cfg(test).
//! Each call crosses the public wrapper, including its C-unwind boundary.

use frankenlibc_abi::rpc_abi::{
    __key_decryptsession_pk_LOCAL, __key_encryptsession_pk_LOCAL, __key_gendes_LOCAL,
    key_decryptsession_pk, key_encryptsession_pk, key_gendes as generate,
};
use std::ffi::{c_char, c_int, c_uint, c_void};
use std::ptr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicPtr, Ordering};

// Independent layouts of the public key_prot.x C records seen by local hooks.
#[repr(C)]
struct NetObject {
    length: c_uint,
    bytes: *mut c_char,
}

#[repr(C)]
struct PublicCryptArgument {
    name: *mut c_char,
    public: NetObject,
    key: [u8; 8],
}

#[repr(C)]
struct CryptResult {
    status: c_int,
    key: [u8; 8],
}

unsafe fn session_pk(
    name: *const c_char,
    public: *mut c_void,
    key: *mut c_void,
    encrypt: bool,
) -> c_int {
    if encrypt {
        unsafe { key_encryptsession_pk(name, public, key) }
    } else {
        unsafe { key_decryptsession_pk(name, public, key) }
    }
}

static HOOKS: Mutex<()> = Mutex::new(());
static SUCCESS: CryptResult = CryptResult {
    status: 0,
    key: *b"changed!",
};
static FAILURE: c_int = 2;
static GENERATED: [u8; 8] = *b"new-key!";

struct Installed(&'static AtomicPtr<c_void>, *mut c_void);
impl Installed {
    fn new(slot: &'static AtomicPtr<c_void>, callback: *mut c_void) -> Self {
        Self(slot, slot.swap(callback, Ordering::AcqRel))
    }
}
impl Drop for Installed {
    fn drop(&mut self) {
        self.0.store(self.1, Ordering::Release);
    }
}

unsafe extern "C-unwind" fn success(uid: u32, argument: *mut c_void) -> *const c_void {
    assert_eq!(uid, unsafe { libc::geteuid() });
    // SAFETY: the implementation supplies its private live argument record.
    let argument = unsafe { &*argument.cast::<PublicCryptArgument>() };
    assert_eq!(
        unsafe { std::ffi::CStr::from_ptr(argument.name) }.to_bytes(),
        b"rpc-test"
    );
    assert_eq!(argument.public.length, 7);
    assert_eq!(
        unsafe { std::slice::from_raw_parts(argument.public.bytes.cast::<u8>(), 7) },
        b"pub\0key"
    );
    assert_eq!(&argument.key, b"old-key!");
    (&SUCCESS as *const CryptResult).cast()
}

unsafe extern "C-unwind" fn failure(_: u32, _: *mut c_void) -> *const c_void {
    (&FAILURE as *const c_int).cast()
}

unsafe extern "C-unwind" fn missing(_: u32, _: *mut c_void) -> *const c_void {
    ptr::null()
}

unsafe extern "C-unwind" fn generate_local(uid: u32, argument: *mut c_void) -> *const c_void {
    assert_eq!(uid, unsafe { libc::geteuid() });
    assert!(argument.is_null());
    GENERATED.as_ptr().cast()
}

unsafe fn exercise(encrypt: bool) -> (c_int, [u8; 10]) {
    let mut public = *b"pub\0key";
    let mut object = NetObject {
        length: 7,
        bytes: public.as_mut_ptr().cast(),
    };
    let mut output = *b"[old-key!]";
    // SAFETY: all supplied objects are live and have their documented extents.
    let status = unsafe {
        session_pk(
            c"rpc-test".as_ptr(),
            (&mut object as *mut NetObject).cast(),
            output.as_mut_ptr().add(1).cast(),
            encrypt,
        )
    };
    assert_eq!(&public, b"pub\0key");
    (status, output)
}

#[test]
fn local_public_key_hooks_receive_uid_and_binary_public_key() {
    let _lock = HOOKS.lock().unwrap();
    for (slot, encrypt) in [
        (&__key_encryptsession_pk_LOCAL, true),
        (&__key_decryptsession_pk_LOCAL, false),
    ] {
        let _installed = Installed::new(slot, success as *mut c_void);
        assert_eq!(unsafe { exercise(encrypt) }, (0, *b"[changed!]"));
    }
}

#[test]
fn local_failure_union_and_null_result_preserve_the_session_key() {
    let _lock = HOOKS.lock().unwrap();
    for callback in [failure as *mut c_void, missing as *mut c_void] {
        let _installed = Installed::new(&__key_encryptsession_pk_LOCAL, callback);
        assert_eq!(unsafe { exercise(true) }, (-1, *b"[old-key!]"));
    }
}

#[test]
fn local_generator_writes_exactly_one_des_block() {
    let _lock = HOOKS.lock().unwrap();
    let _installed = Installed::new(&__key_gendes_LOCAL, generate_local as *mut c_void);
    let mut output = [0xa5u8; 10];
    assert_eq!(unsafe { generate(output.as_mut_ptr().add(1).cast()) }, 0);
    assert_eq!(&output[1..9], &GENERATED);
    assert_eq!(output[0], 0xa5);
    assert_eq!(output[9], 0xa5);
}

unsafe extern "C-unwind" fn reentrant(uid: u32, argument: *mut c_void) -> *const c_void {
    let mut nested = [0u8; 8];
    assert_eq!(unsafe { generate(nested.as_mut_ptr().cast()) }, 0);
    assert_eq!(nested, GENERATED);
    unsafe { success(uid, argument) }
}

unsafe extern "C-unwind" fn unwind(_: u32, _: *mut c_void) -> *const c_void {
    panic!("test local keyserver callback unwind");
}

#[test]
fn local_hooks_allow_reentry_and_unwinding_without_publishing() {
    let _lock = HOOKS.lock().unwrap();
    let _generator = Installed::new(&__key_gendes_LOCAL, generate_local as *mut c_void);
    {
        let _installed =
            Installed::new(&__key_encryptsession_pk_LOCAL, reentrant as *mut c_void);
        assert_eq!(unsafe { exercise(true) }, (0, *b"[changed!]"));
    }
    {
        let _installed = Installed::new(&__key_encryptsession_pk_LOCAL, unwind as *mut c_void);
        let mut public = *b"pub\0key";
        let mut object = NetObject {
            length: 7,
            bytes: public.as_mut_ptr().cast(),
        };
        let mut output = *b"old-key!";
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            session_pk(
                c"rpc-test".as_ptr(),
                (&mut object as *mut NetObject).cast(),
                output.as_mut_ptr().cast(),
                true,
            )
        }));
        assert!(caught.is_err());
        assert_eq!(&output, b"old-key!");
    }
    let _installed = Installed::new(&__key_encryptsession_pk_LOCAL, success as *mut c_void);
    assert_eq!(unsafe { exercise(true) }, (0, *b"[changed!]"));
}

#[test]
fn invalid_argument_extents_are_rejected_before_local_hooks() {
    let _lock = HOOKS.lock().unwrap();
    // Calling this hook would panic, so rejection must happen first.
    let _installed = Installed::new(&__key_encryptsession_pk_LOCAL, unwind as *mut c_void);
    let mut public = NetObject {
        length: 1025,
        bytes: ptr::null_mut(),
    };
    let mut key = *b"old-key!";
    assert_eq!(
        unsafe {
            session_pk(
                c"rpc-test".as_ptr(),
                (&mut public as *mut NetObject).cast(),
                key.as_mut_ptr().cast(),
                true,
            )
        },
        -1
    );
    public.length = 1;
    assert_eq!(
        unsafe {
            session_pk(
                c"rpc-test".as_ptr(),
                (&mut public as *mut NetObject).cast(),
                key.as_mut_ptr().cast(),
                true,
            )
        },
        -1
    );
    public.length = 0;
    assert_eq!(
        unsafe {
            session_pk(
                ptr::null(),
                (&mut public as *mut NetObject).cast(),
                key.as_mut_ptr().cast(),
                true,
            )
        },
        -1
    );
    assert_eq!(&key, b"old-key!");
}
