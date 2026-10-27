//! Owned client-side AUTH_DES and its RFC 868 clock synchronization.
//!
//! RFC 1057 section 9.3 defines the fullname/nickname state machine and DES
//! blocks. The existing keyserver client encrypts the conversation key; this
//! module owns every input needed for later refreshes. No host authenticator is
//! used. DES is provided for legacy interoperability, not modern security.
//! An AUTH must remain live during its operations. The gate rejects callback
//! reentry; it does not make concurrent caller destruction of C handles valid.

use super::{Auth, AuthOps, OpaqueAuth, RpcError, Socket, Xdr, boxed, import, kernel, publish};
use frankenlibc_core::crypt::des::rpc_des_crypt;
use frankenlibc_core::syscall as raw;
use std::cell::UnsafeCell;
use std::ffi::{c_char, c_int, c_uint, c_void};
use std::mem::size_of;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering, compiler_fence};

const MAX_NAME: usize = 255;
const MAX_PUBLIC: usize = 1024;
const EPOCH: u32 = 2_208_988_800;

#[repr(C)]
#[derive(Clone, Copy)]
struct NetObject {
    length: c_uint,
    bytes: *mut c_char,
}

/// GNU deliberately uses 32-bit fields here on LP64, too.
#[repr(C)]
#[derive(Clone, Copy)]
struct RpcTimeval {
    seconds: u32,
    micros: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Verifier {
    _flavor: c_int,
    bytes: *mut u8,
    length: c_uint,
}

fn error(errno: c_int) -> RpcError {
    RpcError::system(super::RPC_SYSTEMERROR, errno)
}

fn report(error: RpcError) {
    let errno = c_int::from_ne_bytes(error.detail[..4].try_into().unwrap_or([0; 4]));
    // SAFETY: changes only the calling thread's errno.
    unsafe { super::super::set_abi_errno(if errno == 0 { libc::EIO } else { errno }) };
}

fn erase(bytes: &mut [u8]) {
    for byte in bytes {
        // SAFETY: the exclusively borrowed secret storage is live and writable.
        unsafe { ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

struct Secret([u8; 8]);
impl Drop for Secret {
    fn drop(&mut self) {
        erase(&mut self.0);
    }
}

struct Data {
    server: [u8; MAX_NAME + 1],
    public: Vec<u8>,
    name: [u8; MAX_NAME + 1],
    name_length: usize,
    window: u32,
    sync: Option<libc::sockaddr_in>,
    offset_micros: i64,
    encrypted_key: [u8; 8],
    nickname: [u8; 4],
    shortened: bool,
    timestamp: [u8; 8],
    has_timestamp: bool,
}

impl Drop for Data {
    fn drop(&mut self) {
        erase(&mut self.encrypted_key);
    }
}

struct State {
    busy: AtomicBool,
    data: UnsafeCell<Data>,
}

struct Gate<'a>(&'a State);
impl<'a> Gate<'a> {
    fn enter(state: &'a State) -> Option<Self> {
        state
            .busy
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()?;
        Some(Self(state))
    }
}
impl Drop for Gate<'_> {
    fn drop(&mut self) {
        self.0.busy.store(false, Ordering::Release);
    }
}

unsafe fn name(pointer: *const c_char) -> Result<[u8; MAX_NAME + 1], RpcError> {
    if pointer.is_null() {
        return Err(error(libc::EINVAL));
    }
    let mut result = [0; MAX_NAME + 1];
    for (index, byte) in result.iter_mut().enumerate() {
        // SAFETY: the shared importer checks precisely the next byte, including
        // tracked extents and faults, without reading beyond a terminating NUL.
        *byte = unsafe { import(pointer.cast::<u8>().wrapping_add(index)) }?;
        if *byte == 0 {
            return Ok(result);
        }
    }
    Err(error(libc::EINVAL))
}

fn clock() -> Result<i64, RpcError> {
    let mut time: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: clock_gettime writes only our complete initialized timespec.
    kernel(unsafe {
        raw::syscall2(
            libc::SYS_clock_gettime as usize,
            libc::CLOCK_REALTIME as usize,
            (&mut time as *mut libc::timespec) as usize,
        )
    })
    .map_err(error)?;
    time.tv_sec
        .checked_mul(1_000_000)
        .and_then(|seconds| seconds.checked_add(time.tv_nsec / 1_000))
        .ok_or_else(|| error(libc::EOVERFLOW))
}

fn timestamp(offset: i64) -> Result<[u8; 8], RpcError> {
    let micros = clock()?
        .checked_add(offset)
        .ok_or_else(|| error(libc::EOVERFLOW))?;
    let mut result = [0; 8];
    result[..4].copy_from_slice(&(micros.div_euclid(1_000_000) as u32).to_be_bytes());
    result[4..].copy_from_slice(&(micros.rem_euclid(1_000_000) as u32).to_be_bytes());
    Ok(result)
}

unsafe fn renew(data: &mut Data, key: &[u8; 8]) -> Result<(), RpcError> {
    let mut encrypted = Secret(*key);
    let mut public = NetObject {
        length: data.public.len() as u32,
        bytes: data.public.as_mut_ptr().cast(),
    };
    // SAFETY: every input is owned and bounded, and the keyserver publishes only
    // a complete result. A local keyserver hook may unwind through this frame.
    if unsafe {
        super::super::key_encryptsession_pk(
            data.server.as_ptr().cast(),
            (&mut public as *mut NetObject).cast(),
            encrypted.0.as_mut_ptr().cast(),
        )
    } < 0
    {
        return Err(error(libc::EIO));
    }
    if let Some(address) = data.sync {
        // A time server is optional. An unavailable clock leaves authentication
        // using the local clock, as with GNU's legacy constructor/refresh.
        if let Ok(remote) = query_time(
            address,
            Some(RpcTimeval {
                seconds: 5,
                micros: 0,
            }),
        ) {
            if let Ok(local) = clock() {
                data.offset_micros = i64::from(remote.seconds) * 1_000_000 - local;
            }
        }
    }
    data.encrypted_key = encrypted.0;
    data.shortened = false;
    data.has_timestamp = false;
    Ok(())
}

unsafe fn make(
    server: [u8; MAX_NAME + 1],
    public: Vec<u8>,
    window: u32,
    sync: *mut c_void,
    supplied_key: *mut c_void,
) -> Result<*mut c_void, RpcError> {
    let sync = if sync.is_null() {
        None
    } else {
        Some(unsafe { import::<libc::sockaddr_in>(sync.cast()) }?)
    };
    let mut key = Secret(if supplied_key.is_null() {
        [0; 8]
    } else {
        unsafe { import(supplied_key.cast::<[u8; 8]>()) }?
    });
    let mut netname = [0u8; MAX_NAME + 1];
    // SAFETY: getnetname writes at most MAXNETNAMELEN + 1 into owned storage.
    if unsafe { super::super::getnetname(netname.as_mut_ptr().cast()) } == 0 {
        return Err(error(libc::ENOENT));
    }
    let name_length = netname
        .iter()
        .position(|&byte| byte == 0)
        .ok_or_else(|| error(libc::EINVAL))?;
    if supplied_key.is_null() && unsafe { super::super::key_gendes(key.0.as_mut_ptr().cast()) } < 0
    {
        return Err(error(libc::EIO));
    }
    let mut data = Data {
        server,
        public,
        name: netname,
        name_length,
        window,
        sync,
        offset_micros: 0,
        encrypted_key: [0; 8],
        nickname: [0; 4],
        shortened: false,
        timestamp: [0; 8],
        has_timestamp: false,
    };
    unsafe { renew(&mut data, &key.0) }?;
    let state = boxed(State {
        busy: AtomicBool::new(false),
        data: UnsafeCell::new(data),
    })?;
    let mut auth = boxed(Auth {
        credential: OpaqueAuth {
            oa_flavor: 3,
            oa_base: ptr::null_mut(),
            oa_length: 0,
        },
        verifier: OpaqueAuth {
            oa_flavor: 3,
            oa_base: ptr::null_mut(),
            oa_length: 0,
        },
        key: [0; 8],
        operations: &OPERATIONS,
        private: (&*state as *const State).cast_mut().cast(),
    })?;
    // Neither allocation is published until all fallible work is complete.
    auth.key = key.0;
    let _ = Box::into_raw(state);
    Ok(Box::into_raw(auth).cast())
}

fn finish(result: Result<*mut c_void, RpcError>) -> *mut c_void {
    match result {
        Ok(pointer) => pointer,
        Err(error) => {
            report(error);
            ptr::null_mut()
        }
    }
}

pub(crate) unsafe fn create_pk(
    server: *mut c_char,
    public: *mut c_void,
    window: u32,
    sync: *mut c_void,
    key: *mut c_void,
) -> *mut c_void {
    finish((|| {
        let server = unsafe { name(server) }?;
        let object = unsafe { import::<NetObject>(public.cast()) }?;
        if object.length as usize > MAX_PUBLIC {
            return Err(error(libc::EINVAL));
        }
        let mut public = super::buffer(object.length as usize)?;
        if !public.is_empty() {
            // SAFETY: bounded length was checked before allocation and copying.
            unsafe {
                super::user_copy::copy_user_bytes(
                    object.bytes.cast(),
                    public.as_mut_ptr(),
                    public.len(),
                )
            }
            .map_err(error)?;
        }
        unsafe { make(server, public, window, sync, key) }
    })())
}

pub(crate) unsafe fn create(
    server: *mut c_char,
    window: u32,
    sync: *mut c_void,
    key: *mut c_void,
) -> *mut c_void {
    finish((|| {
        let server = unsafe { name(server) }?;
        let mut public = [0u8; 49];
        // SAFETY: name is terminated; getpublickey's complete fixed output fits.
        if unsafe { super::super::getpublickey(server.as_ptr().cast(), public.as_mut_ptr().cast()) }
            == 0
        {
            return Err(error(libc::ENOENT));
        }
        let mut owned = super::buffer(public.len())?;
        owned.copy_from_slice(&public);
        unsafe { make(server, owned, window, sync, key) }
    })())
}

unsafe extern "C" fn next(_: *mut Auth) {}

unsafe extern "C" fn marshal(auth: *mut Auth, xdr: *mut Xdr) -> c_int {
    if xdr.is_null() || unsafe { (*xdr).x_op != super::super::XDR_ENCODE || (*xdr).x_ops.is_null() }
    {
        return 0;
    }
    // SAFETY: AUTH and its private allocation stay live through every operation.
    let state = unsafe { &*(*auth).private.cast::<State>() };
    let Some(_gate) = Gate::enter(state) else {
        return 0;
    };
    let data = unsafe { &mut *state.data.get() };
    let Ok(stamp) = timestamp(data.offset_micros) else {
        return 0;
    };
    let mut blocks = [0; 16];
    blocks[..8].copy_from_slice(&stamp);
    let key = Secret(unsafe { (*auth).key });
    let length = if data.shortened {
        8
    } else {
        blocks[8..12].copy_from_slice(&data.window.to_be_bytes());
        blocks[12..].copy_from_slice(&data.window.wrapping_sub(1).to_be_bytes());
        16
    };
    let mut iv = [0; 8];
    if rpc_des_crypt(
        &key.0,
        &mut blocks[..length],
        false,
        if data.shortened { None } else { Some(&mut iv) },
    )
    .is_err()
    {
        return 0;
    }
    let mut credential = [0u8; 276];
    let credential_length = if data.shortened {
        credential[..4].copy_from_slice(&1u32.to_be_bytes());
        credential[4..8].copy_from_slice(&data.nickname);
        8
    } else {
        let padded = (data.name_length + 3) & !3;
        credential[4..8].copy_from_slice(&(data.name_length as u32).to_be_bytes());
        credential[8..8 + data.name_length].copy_from_slice(&data.name[..data.name_length]);
        credential[8 + padded..16 + padded].copy_from_slice(&data.encrypted_key);
        credential[16 + padded..20 + padded].copy_from_slice(&blocks[8..12]);
        20 + padded
    };
    let mut verifier = [0u8; 12];
    verifier[..8].copy_from_slice(&blocks[..8]);
    if !data.shortened {
        verifier[8..].copy_from_slice(&blocks[12..]);
    }
    let mut flavor = 3;
    let mut size = credential_length as u32;
    let mut verifier_size = 12;
    // SAFETY: XDR encodes bounded owned slices. The gate prevents nested
    // callbacks from replacing/destroying the borrowed authenticator state.
    if unsafe { super::super::xdr_u_int(xdr.cast(), &mut flavor) } == 0
        || unsafe { super::super::xdr_u_int(xdr.cast(), &mut size) } == 0
        || unsafe { super::super::xdr_opaque(xdr.cast(), credential.as_mut_ptr().cast(), size) }
            == 0
        || unsafe { super::super::xdr_u_int(xdr.cast(), &mut flavor) } == 0
        || unsafe { super::super::xdr_u_int(xdr.cast(), &mut verifier_size) } == 0
        || unsafe { super::super::xdr_opaque(xdr.cast(), verifier.as_mut_ptr().cast(), 12) } == 0
    {
        return 0;
    }
    data.timestamp = stamp;
    data.has_timestamp = true;
    1
}

unsafe extern "C" fn validate(auth: *mut Auth, verifier: *mut OpaqueAuth) -> c_int {
    let state = unsafe { &*(*auth).private.cast::<State>() };
    let Some(_gate) = Gate::enter(state) else {
        return 0;
    };
    let data = unsafe { &mut *state.data.get() };
    if !data.has_timestamp {
        return 0;
    }
    let Ok(verifier) = (unsafe { import::<Verifier>(verifier.cast()) }) else {
        return 0;
    };
    // GNU checks the actual 12-byte proof, independently of oa_flavor.
    if verifier.length != 12 {
        return 0;
    }
    let Ok(mut bytes) = (unsafe { import::<[u8; 12]>(verifier.bytes.cast()) }) else {
        return 0;
    };
    let key = Secret(unsafe { (*auth).key });
    if rpc_des_crypt(&key.0, &mut bytes[..8], true, None).is_err() {
        return 0;
    }
    let expected_seconds =
        u32::from_be_bytes(data.timestamp[..4].try_into().unwrap()).wrapping_sub(1);
    let mut expected = data.timestamp;
    expected[..4].copy_from_slice(&expected_seconds.to_be_bytes());
    // Accumulate the comparison so a rejected proof never updates the nickname.
    let mismatch = bytes[..8]
        .iter()
        .zip(expected)
        .fold(0, |difference, (&left, right)| difference | (left ^ right));
    if mismatch != 0 {
        return 0;
    }
    data.nickname.copy_from_slice(&bytes[8..]);
    data.shortened = true;
    1
}

unsafe extern "C-unwind" fn refresh(auth: *mut Auth) -> c_int {
    let state = unsafe { &*(*auth).private.cast::<State>() };
    let Some(_gate) = Gate::enter(state) else {
        return 0;
    };
    let data = unsafe { &mut *state.data.get() };
    let key = Secret(unsafe { (*auth).key });
    match unsafe { renew(data, &key.0) } {
        Ok(()) => 1,
        Err(error) => {
            report(error);
            0
        }
    }
}

unsafe extern "C" fn destroy(auth: *mut Auth) {
    let state = unsafe { (*auth).private.cast::<State>() };
    if unsafe {
        (*state)
            .busy
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
    }
    .is_err()
    {
        unsafe { super::super::set_abi_errno(libc::EBUSY) };
        return;
    }
    // SAFETY: these exact allocations were published by make. The successful
    // gate excludes callback reentry; the caller owns external synchronization.
    unsafe {
        erase(&mut (*auth).key);
        drop(Box::from_raw(state));
        drop(Box::from_raw(auth));
    }
}

static OPERATIONS: AuthOps = AuthOps {
    next,
    marshal,
    validate,
    refresh,
    destroy,
};

fn query_time(
    mut address: libc::sockaddr_in,
    timeout: Option<RpcTimeval>,
) -> Result<RpcTimeval, RpcError> {
    address.sin_family = libc::AF_INET as _;
    address.sin_port = 37u16.to_be();
    let kind = if timeout.is_some() {
        libc::SOCK_DGRAM
    } else {
        libc::SOCK_STREAM
    };
    // SAFETY: create an independently owned socket; no public pointer is used.
    let socket = Socket {
        fd: kernel(unsafe {
            raw::syscall3(
                libc::SYS_socket as usize,
                libc::AF_INET as usize,
                (kind | libc::SOCK_CLOEXEC) as usize,
                0,
            )
        })
        .map_err(error)? as c_int,
        owned: true,
    };
    // SAFETY: the complete owned sockaddr lives across connect.
    kernel(unsafe {
        raw::syscall3(
            libc::SYS_connect as usize,
            socket.fd as usize,
            (&address as *const libc::sockaddr_in) as usize,
            size_of::<libc::sockaddr_in>(),
        )
    })
    .map_err(error)?;
    let mut bytes = [0u8; 4];
    if let Some(timeout) = timeout {
        if timeout.micros >= 1_000_000 {
            return Err(error(libc::EINVAL));
        }
        // The GNU TIME client sends a four-byte query; its contents have no
        // protocol meaning. Initialize them instead of exposing stack bytes.
        kernel(unsafe {
            raw::syscall6(
                libc::SYS_sendto as usize,
                socket.fd as usize,
                bytes.as_ptr() as usize,
                bytes.len(),
                libc::MSG_NOSIGNAL as usize,
                0,
                0,
            )
        })
        .map_err(error)?;
        let duration =
            u64::from(timeout.seconds) * super::SECOND + u64::from(timeout.micros) * 1000;
        let deadline = super::monotonic()?
            .checked_add(duration)
            .ok_or_else(|| error(libc::EINVAL))?;
        loop {
            let remaining = deadline.saturating_sub(super::monotonic()?);
            let wait = libc::timespec {
                tv_sec: (remaining / super::SECOND) as _,
                tv_nsec: (remaining % super::SECOND) as _,
            };
            let mut descriptor = libc::pollfd {
                fd: socket.fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: ppoll sees one initialized pollfd and a live timespec.
            let ready = kernel(unsafe {
                raw::syscall5(
                    libc::SYS_ppoll as usize,
                    (&mut descriptor as *mut libc::pollfd) as usize,
                    1,
                    (&wait as *const libc::timespec) as usize,
                    0,
                    0,
                )
            });
            match ready {
                Err(libc::EINTR) => continue,
                Err(errno) => return Err(error(errno)),
                Ok(0) => return Err(error(libc::ETIMEDOUT)),
                Ok(_) => {}
            }
            let received = kernel(unsafe {
                raw::syscall6(
                    libc::SYS_recvfrom as usize,
                    socket.fd as usize,
                    bytes.as_mut_ptr() as usize,
                    bytes.len(),
                    libc::MSG_DONTWAIT as usize,
                    0,
                    0,
                )
            });
            match received {
                Ok(4) => break,
                Ok(_) => return Err(error(libc::EIO)),
                Err(libc::EAGAIN) if super::monotonic()? < deadline => continue,
                Err(errno) => return Err(error(errno)),
            }
        }
    } else {
        // TIME has exactly one four-byte response and no TCP request body.
        let received = kernel(unsafe {
            raw::syscall3(
                libc::SYS_read as usize,
                socket.fd as usize,
                bytes.as_mut_ptr() as usize,
                bytes.len(),
            )
        })
        .map_err(error)?;
        if received != 4 {
            return Err(error(libc::EIO));
        }
    }
    Ok(RpcTimeval {
        seconds: u32::from_be_bytes(bytes).wrapping_sub(EPOCH),
        micros: 0,
    })
}

pub(crate) unsafe fn rtime(
    address: *mut c_void,
    output: *mut c_void,
    timeout: *mut c_void,
) -> c_int {
    let result = (|| {
        if output.is_null() {
            return Err(error(libc::EINVAL));
        }
        let mut owned = unsafe { import::<libc::sockaddr_in>(address.cast()) }?;
        let timeout = if timeout.is_null() {
            None
        } else {
            Some(unsafe { import::<RpcTimeval>(timeout.cast()) }?)
        };
        if timeout.is_some_and(|value| value.micros >= 1_000_000) {
            return Err(error(libc::EINVAL));
        }
        owned.sin_family = libc::AF_INET as _;
        owned.sin_port = 37u16.to_be();
        unsafe { publish(&owned, address.cast()) }?;
        let time = query_time(owned, timeout)?;
        unsafe { publish(&time, output.cast()) }?;
        Ok(())
    })();
    match result {
        Ok(()) => 0,
        Err(error) => {
            report(error);
            -1
        }
    }
}
