//! Native client for the classic Secure RPC key server (program 100029).
//!
//! The daemon owns private-key storage and cryptographic operations. These
//! entrypoints marshal its documented version 1/2 protocol with independently
//! owned clients. Credentialed operations use the local Unix socket and a fresh
//! effective-UID credential; key generation uses GNU's loopback UDP transport
//! and portmapper discovery with AUTH_NONE. No host RPC implementation or
//! process-wide cached descriptor is used. Private argument/result storage keeps
//! failed calls from publishing a partially decoded session key.

use super::super::{
    __key_decryptsession_pk_LOCAL, __key_encryptsession_pk_LOCAL, __key_gendes_LOCAL, XDR_TRUE,
    xdr_cryptkeyarg, xdr_cryptkeyarg2, xdr_cryptkeyres, xdr_des_block, xdr_key_netstarg,
    xdr_key_netstres, xdr_keybuf, xdr_keystatus,
};
use super::{
    Auth, Client, Network, RPC_SYSTEMERROR, RpcError, Timeval, XdrProc, authunix_create, call,
    destroy, import, kernel, make_client, publish,
};
use frankenlibc_core::syscall as raw;
use std::ffi::{c_char, c_int, c_uint, c_void};
use std::ptr;
use std::sync::atomic::{Ordering, compiler_fence};

const PROGRAM: u64 = 100029;
const KEY_BYTES: usize = 48;
const MAX_NAME: usize = 255;
const MAX_PUBLIC_KEY: usize = 1024;
const KEY_SUCCESS: c_int = 0;
const KEY_SYSTEMERR: c_int = 3;

#[repr(C)]
#[derive(Clone, Copy)]
struct NetObject {
    length: c_uint,
    bytes: *mut c_char,
}

#[repr(C)]
struct CryptArgument {
    name: *mut c_char,
    key: [u8; 8],
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

#[repr(C)]
#[derive(Clone, Copy)]
struct NetworkArgument {
    private: [u8; KEY_BYTES],
    public: [u8; KEY_BYTES],
    name: *mut c_char,
}

#[repr(C)]
struct NetworkResult {
    status: c_int,
    network: NetworkArgument,
}

struct OwnedNetworkArgument(NetworkArgument);
impl Drop for OwnedNetworkArgument {
    fn drop(&mut self) {
        erase(&mut self.0.private);
    }
}

/// Erase our own secret copies, including when a local hook unwinds. Volatile
/// writes prevent dead-store elimination after the last semantic use.
fn erase(bytes: &mut [u8]) {
    for byte in bytes {
        // SAFETY: every pointer comes from this exclusive live byte slice.
        unsafe { ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

struct Secret([u8; KEY_BYTES]);
impl Drop for Secret {
    fn drop(&mut self) {
        erase(&mut self.0);
    }
}
impl Drop for CryptArgument {
    fn drop(&mut self) {
        erase(&mut self.key);
    }
}
impl Drop for PublicCryptArgument {
    fn drop(&mut self) {
        erase(&mut self.key);
    }
}
impl Drop for CryptResult {
    fn drop(&mut self) {
        erase(&mut self.key);
    }
}
impl Drop for NetworkResult {
    fn drop(&mut self) {
        // The result decoder is the only writer of this pointer. Its bounded
        // XDR string allocation belongs to us even after a truncated reply.
        if !self.network.name.is_null() {
            // SAFETY: native xdr_string allocated this private result with the
            // ABI allocator; no caller pointer is ever installed in this slot.
            unsafe { crate::malloc_abi::free(self.network.name.cast()) };
        }
        erase(&mut self.network.private);
    }
}

fn local_error(errno: c_int) -> RpcError {
    RpcError::system(RPC_SYSTEMERROR, errno)
}

fn finish(result: Result<c_int, RpcError>) -> c_int {
    result.unwrap_or_else(|error| {
        let errno = c_int::from_ne_bytes(error.detail[..4].try_into().unwrap_or([0; 4]));
        if errno != 0 {
            // SAFETY: only the calling thread's errno slot is changed.
            unsafe { super::super::set_abi_errno(errno) };
        }
        -1
    })
}

unsafe fn name(pointer: *const c_char) -> Result<[u8; MAX_NAME + 1], RpcError> {
    if pointer.is_null() {
        return Err(local_error(libc::EINVAL));
    }
    let mut bytes = [0u8; MAX_NAME + 1];
    for (index, byte) in bytes.iter_mut().enumerate() {
        // SAFETY: import checks the next byte before reading it; a terminator
        // at the final readable byte never causes a speculative overread.
        *byte = unsafe { import(pointer.cast::<u8>().wrapping_add(index)) }?;
        if *byte == 0 {
            return Ok(bytes);
        }
    }
    Err(local_error(libc::EINVAL))
}

fn effective_uid() -> Result<u32, RpcError> {
    // SAFETY: geteuid has no pointer arguments or externally visible mutation.
    kernel(unsafe { raw::syscall0(libc::SYS_geteuid as usize) })
        .map(|uid| uid as u32)
        .map_err(local_error)
}

struct OwnedClient {
    client: *mut Client,
    auth: *mut Auth,
}
impl Drop for OwnedClient {
    fn drop(&mut self) {
        // SAFETY: both objects were privately created for this call. The call
        // gate is released before this guard, including during unwinding.
        unsafe {
            destroy(self.client);
            if !self.auth.is_null() {
                ((*(*self.auth).operations).destroy)(self.auth);
            }
        }
    }
}

unsafe fn client(version: u64) -> Result<OwnedClient, RpcError> {
    // SAFETY: sockaddr_un contains integer/byte fields with a valid zero value.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as _;
    for (out, byte) in address.sun_path.iter_mut().zip(b"/var/run/keyservsock\0") {
        *out = *byte as c_char;
    }
    let mut descriptor = -1;
    // SAFETY: constructor inputs are fully initialized owned stack objects;
    // descriptor -1 requests a new socket, owned by the resulting CLIENT.
    let pointer = unsafe {
        make_client(
            (&mut address as *mut libc::sockaddr_un).cast(),
            PROGRAM,
            version,
            Timeval {
                tv_sec: 1,
                tv_usec: 0,
            },
            &mut descriptor,
            0,
            0,
            Network::Unix,
        )
    }
    .map_err(|error| error.error)?;
    let mut owned = OwnedClient {
        client: pointer.cast(),
        auth: ptr::null_mut(),
    };
    let uid = effective_uid()?;
    // GNU keyserv credentials contain an empty machine name, the effective
    // uid, gid zero and no supplementary groups. The Unix transport separately
    // supplies kernel credentials; AUTH_SYS itself is not cryptographic proof.
    // SAFETY: the empty string is static; zero groups never reads its pointer.
    let auth =
        unsafe { authunix_create(c"".as_ptr().cast_mut(), uid as c_int, 0, 0, ptr::null_mut()) };
    if auth.is_null() {
        return Err(local_error(libc::ENOMEM));
    }
    owned.auth = auth.cast();
    // SAFETY: our new CLIENT is private and owns no user-installed authenticator.
    unsafe { (*owned.client).auth = owned.auth };
    Ok(owned)
}

unsafe fn generator_client() -> Result<OwnedClient, RpcError> {
    let mut address = libc::sockaddr_in {
        sin_family: libc::AF_INET as _,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        },
        sin_zero: [0; 8],
    };
    let mut descriptor = -1;
    // GNU's key_gendes uses loopback UDP, not the Unix key_call transport.
    // Port zero asks the shared native constructor to consult portmapper v2.
    // SAFETY: all inputs are initialized owned objects and the constructor
    // returns a new CLIENT/socket with its process-lifetime AUTH_NONE handle.
    let pointer = unsafe {
        make_client(
            (&mut address as *mut libc::sockaddr_in).cast(),
            PROGRAM,
            1,
            Timeval {
                tv_sec: 5,
                tv_usec: 0,
            },
            &mut descriptor,
            1024,
            1024,
            Network::Datagram,
        )
    }
    .map_err(|error| error.error)?;
    Ok(OwnedClient {
        client: pointer.cast(),
        auth: ptr::null_mut(),
    })
}

unsafe fn invoke(
    procedure: u64,
    arguments: XdrProc,
    argument: *mut c_void,
    results: XdrProc,
    result: *mut c_void,
) -> Result<(), RpcError> {
    // Version 2 adds procedures 6..10. The first five retain their original
    // version 1 identity, allowing an older daemon to handle basic operations.
    let owned = unsafe { client(if procedure <= 5 { 1 } else { 2 }) }?;
    // SAFETY: only private, initialized argument/result records and native XDR
    // callbacks are supplied. The owned client outlives the bounded invocation.
    let status = unsafe {
        call(
            owned.client,
            procedure,
            Some(arguments),
            argument,
            Some(results),
            result,
            Timeval {
                tv_sec: 30,
                tv_usec: 0,
            },
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(RpcError::status(status))
    }
}

unsafe extern "C" fn no_arguments(_: *mut c_void, _: *mut c_void) -> c_int {
    XDR_TRUE
}

unsafe fn publish_key(result: &CryptResult, output: *mut c_void) -> Result<c_int, RpcError> {
    if result.status != KEY_SUCCESS {
        return Ok(-1);
    }
    // SAFETY: publication checks tracked bounds and actual writable mappings;
    // the caller receives bytes only after a complete successful result.
    unsafe { publish(&result.key, output.cast()) }?;
    Ok(0)
}

unsafe fn key_storage(output: *mut c_void) -> Result<[u8; 8], RpcError> {
    // Check the complete output extent before invoking a daemon or local hook.
    // Republishing its unchanged bytes also checks writable kernel mappings;
    // caller storage is never exposed as a Rust reference or slice.
    let original = unsafe { import::<[u8; 8]>(output.cast()) }?;
    unsafe { publish(&original, output.cast()) }?;
    Ok(original)
}

pub(crate) unsafe fn session(remote: *const c_char, output: *mut c_void, encrypt: bool) -> c_int {
    finish((|| {
        let mut remote = unsafe { name(remote) }?;
        // SAFETY: session keys have exactly eight caller-owned bytes.
        let key = unsafe { key_storage(output) }?;
        let mut argument = CryptArgument {
            name: remote.as_mut_ptr().cast(),
            key,
        };
        let mut result = CryptResult {
            status: KEY_SYSTEMERR,
            key: [0; 8],
        };
        // SAFETY: both records match the public key_prot.h ABI and remain live.
        unsafe {
            invoke(
                if encrypt { 2 } else { 3 },
                xdr_cryptkeyarg,
                (&mut argument as *mut CryptArgument).cast(),
                xdr_cryptkeyres,
                (&mut result as *mut CryptResult).cast(),
            )?;
            publish_key(&result, output)
        }
    })())
}

pub(crate) unsafe fn session_pk(
    remote: *const c_char,
    public: *mut c_void,
    output: *mut c_void,
    encrypt: bool,
) -> c_int {
    finish((|| {
        let mut remote = unsafe { name(remote) }?;
        // SAFETY: only integer/pointer fields are imported; no caller reference
        // or Rust slice is formed from this public netobj.
        let public = unsafe { import::<NetObject>(public.cast()) }?;
        if public.length as usize > MAX_PUBLIC_KEY {
            return Err(local_error(libc::EINVAL));
        }
        let mut bytes = [0u8; MAX_PUBLIC_KEY];
        if public.length != 0 {
            // SAFETY: the destination covers the bounded length. The common
            // copier checks caller extent and readability, including embedded NULs.
            unsafe {
                super::user_copy::copy_user_bytes(
                    public.bytes.cast(),
                    bytes.as_mut_ptr(),
                    public.length as usize,
                )
            }
            .map_err(local_error)?;
        }
        let key = unsafe { key_storage(output) }?;
        let mut argument = PublicCryptArgument {
            name: remote.as_mut_ptr().cast(),
            public: NetObject {
                length: public.length,
                bytes: bytes.as_mut_ptr().cast(),
            },
            key,
        };
        let mut result = CryptResult {
            status: KEY_SYSTEMERR,
            key: [0; 8],
        };
        let slot = if encrypt {
            &__key_encryptsession_pk_LOCAL
        } else {
            &__key_decryptsession_pk_LOCAL
        };
        let hook = slot.load(Ordering::Acquire);
        if hook.is_null() {
            // SAFETY: argument/result match the version 2 protocol layouts.
            unsafe {
                invoke(
                    if encrypt { 6 } else { 7 },
                    xdr_cryptkeyarg2,
                    (&mut argument as *mut PublicCryptArgument).cast(),
                    xdr_cryptkeyres,
                    (&mut result as *mut CryptResult).cast(),
                )?;
            }
        } else {
            // GNU local hooks return a borrowed cryptkeyres*, not an int. They
            // run outside locks and may reenter or unwind across the C boundary.
            type Hook = unsafe extern "C-unwind" fn(u32, *mut c_void) -> *const c_void;
            // SAFETY: the installer supplies a live callback with this ABI.
            let callback: Hook = unsafe { std::mem::transmute(hook) };
            let uid = effective_uid()?;
            let returned =
                unsafe { callback(uid, (&mut argument as *mut PublicCryptArgument).cast()) };
            // SAFETY: copy the discriminant first; a failed union arm need not
            // provide any key bytes. Invalid/null callback results fail closed.
            result.status = unsafe { import::<c_int>(returned.cast()) }?;
            if result.status == KEY_SUCCESS {
                result.key =
                    unsafe { import::<[u8; 8]>(returned.cast::<u8>().wrapping_add(4).cast()) }?;
            }
        }
        unsafe { publish_key(&result, output) }
    })())
}

pub(crate) unsafe fn generate(output: *mut c_void) -> c_int {
    finish((|| {
        let mut result = CryptResult {
            status: KEY_SUCCESS,
            key: unsafe { key_storage(output) }?,
        };
        let hook = __key_gendes_LOCAL.load(Ordering::Acquire);
        if hook.is_null() {
            // KEY_GEN returns a bare des_block, without a status discriminant.
            let owned = unsafe { generator_client() }?;
            let status = unsafe {
                call(
                    owned.client,
                    4,
                    Some(no_arguments),
                    ptr::null_mut(),
                    Some(xdr_des_block),
                    result.key.as_mut_ptr().cast(),
                    Timeval {
                        tv_sec: 60,
                        tv_usec: 0,
                    },
                )
            };
            if status != 0 {
                return Err(RpcError::status(status));
            }
        } else {
            // Native extension: GNU's separate key_gendes UDP entry bypasses
            // this historical local-generator hook. Installed hooks here use
            // the same borrowed-result convention as the public-key hooks.
            type Hook = unsafe extern "C-unwind" fn(u32, *mut c_void) -> *const c_void;
            // SAFETY: the installer supplies the keyserv local-generator ABI;
            // the void argument is null and the returned block remains borrowed.
            let callback: Hook = unsafe { std::mem::transmute(hook) };
            let returned = unsafe { callback(effective_uid()?, ptr::null_mut()) };
            result.key = unsafe { import::<[u8; 8]>(returned.cast()) }?;
        }
        unsafe { publish_key(&result, output) }
    })())
}

pub(crate) unsafe fn conversation(public: *const c_char, output: *mut c_void) -> c_int {
    finish((|| {
        // A keybuf is exactly 48 opaque bytes, not a NUL-terminated string.
        let mut public = unsafe { import::<[u8; KEY_BYTES]>(public.cast()) }?;
        let mut result = CryptResult {
            status: KEY_SYSTEMERR,
            key: unsafe { key_storage(output) }?,
        };
        unsafe {
            invoke(
                10,
                xdr_keybuf,
                public.as_mut_ptr().cast(),
                xdr_cryptkeyres,
                (&mut result as *mut CryptResult).cast(),
            )?;
            publish_key(&result, output)
        }
    })())
}

pub(crate) unsafe fn set_secret(secret: *const c_char) -> c_int {
    finish((|| {
        let mut secret = Secret(unsafe { import::<[u8; KEY_BYTES]>(secret.cast()) }?);
        let mut status = KEY_SYSTEMERR;
        unsafe {
            invoke(
                1,
                xdr_keybuf,
                secret.0.as_mut_ptr().cast(),
                xdr_keystatus,
                (&mut status as *mut c_int).cast(),
            )?;
        }
        Ok(if status == KEY_SUCCESS { 0 } else { -1 })
    })())
}

pub(crate) unsafe fn set_network(argument: *mut c_void) -> c_int {
    finish((|| {
        let mut argument =
            OwnedNetworkArgument(unsafe { import::<NetworkArgument>(argument.cast()) }?);
        let mut remote = unsafe { name(argument.0.name) }?;
        argument.0.name = remote.as_mut_ptr().cast();
        let mut status = KEY_SYSTEMERR;
        unsafe {
            invoke(
                8,
                xdr_key_netstarg,
                (&mut argument.0 as *mut NetworkArgument).cast(),
                xdr_keystatus,
                (&mut status as *mut c_int).cast(),
            )?;
        }
        // Unlike key_setsecret, GNU key_setnet reports one on success.
        Ok(if status == KEY_SUCCESS { 1 } else { -1 })
    })())
}

pub(crate) unsafe fn secret_is_set() -> c_int {
    let mut result = NetworkResult {
        status: KEY_SYSTEMERR,
        network: NetworkArgument {
            private: [0; KEY_BYTES],
            public: [0; KEY_BYTES],
            name: ptr::null_mut(),
        },
    };
    // SAFETY: only our decoder can allocate the bounded returned netname, and
    // NetworkResult drops it on all paths while erasing the private key copy.
    let status = unsafe {
        invoke(
            9,
            no_arguments,
            ptr::null_mut(),
            xdr_key_netstres,
            (&mut result as *mut NetworkResult).cast(),
        )
    };
    c_int::from(status.is_ok() && result.status == KEY_SUCCESS && result.network.private[0] != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicPtr;

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
        assert_eq!(uid, effective_uid().ok().expect("geteuid must succeed"));
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
        assert_eq!(uid, effective_uid().ok().expect("geteuid must succeed"));
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
}
