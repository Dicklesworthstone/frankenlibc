//! Owned AUTH_SYS (historically AUTH_UNIX) credentials for the native RPC client.
//!
//! RFC 5531 Appendix A bounds the hostname at 255 bytes and groups at 16.
//! Credentials assert a client identity; they are NOT cryptographic authentication.
//! The CLIENT does not own a user-installed AUTH: callers destroy it separately.
//! AUTH_SHORT replies replace the credential, and refresh restores the original.
//! A handle must stay live across every operation: the gate contains callback
//! reentry, not externally unsynchronized concurrent destruction.

use super::{Auth, AuthOps, OpaqueAuth, RpcError, Xdr, boxed, import, kernel};
use frankenlibc_core::syscall as raw;
use std::cell::UnsafeCell;
use std::ffi::{c_char, c_int, c_void};
use std::mem::size_of;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_NAME: usize = 255;
const MAX_GROUPS: usize = 16;
const MAX_CREDENTIAL: usize = 20 + 256 + 4 * MAX_GROUPS;
const MAX_AUTH: usize = 400;
const MAX_KERNEL_GROUPS: usize = 65536;

struct Data {
    original: [u8; MAX_CREDENTIAL],
    original_len: usize,
    short: [u8; MAX_AUTH],
    short_len: usize,
    short_flavor: c_int,
    shortened: bool,
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

fn invalid() -> RpcError {
    RpcError::system(12, libc::EINVAL)
}

/// Encode into fixed storage only after validating every extent. The trailing
/// part of output is left unchanged, including on a rejected input.
fn encode(
    output: &mut [u8],
    stamp: u32,
    name: &[u8],
    uid: u32,
    gid: u32,
    groups: &[u32],
) -> Option<usize> {
    if name.len() > MAX_NAME || groups.len() > MAX_GROUPS {
        return None;
    }
    let padded = (name.len() + 3) & !3;
    let length = 20 + padded + 4 * groups.len();
    let output = output.get_mut(..length)?;
    output[..4].copy_from_slice(&stamp.to_be_bytes());
    output[4..8].copy_from_slice(&(name.len() as u32).to_be_bytes());
    output[8..8 + name.len()].copy_from_slice(name);
    output[8 + name.len()..8 + padded].fill(0);
    for (slot, value) in output[8 + padded..].chunks_exact_mut(4).zip(
        [uid, gid, groups.len() as u32]
            .into_iter()
            .chain(groups.iter().copied()),
    ) {
        slot.copy_from_slice(&value.to_be_bytes());
    }
    Some(length)
}

fn stamp() -> Result<u32, RpcError> {
    let mut value: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: the raw syscall writes exactly our initialized timespec.
    kernel(unsafe {
        raw::syscall2(
            libc::SYS_clock_gettime as usize,
            libc::CLOCK_REALTIME as usize,
            (&mut value as *mut libc::timespec) as usize,
        )
    })
    .map_err(|error| RpcError::system(12, error))?;
    Ok(value.tv_sec as u32)
}

unsafe fn name_bytes(pointer: *const c_char) -> Result<Vec<u8>, RpcError> {
    if pointer.is_null() {
        return Err(invalid());
    }
    let mut result = Vec::new();
    result
        .try_reserve_exact(MAX_NAME)
        .map_err(|_| RpcError::system(12, libc::ENOMEM))?;
    for index in 0..=MAX_NAME {
        // Probe only the next byte, so a NUL at a guard-page boundary never
        // causes an overread. Do not scan an unbounded caller hostname first.
        let byte = unsafe { import(pointer.cast::<u8>().wrapping_add(index)) }?;
        if byte == 0 {
            return Ok(result);
        }
        if index == MAX_NAME {
            return Err(invalid());
        }
        result.push(byte);
    }
    Err(invalid())
}

fn make(name: &[u8], uid: u32, gid: u32, groups: &[u32]) -> Result<*mut c_void, RpcError> {
    let mut original = [0; MAX_CREDENTIAL];
    let length = encode(&mut original, stamp()?, name, uid, gid, groups).ok_or_else(invalid)?;
    let state = boxed(State {
        busy: AtomicBool::new(false),
        data: UnsafeCell::new(Data {
            original,
            original_len: length,
            short: [0; MAX_AUTH],
            short_len: 0,
            short_flavor: 2,
            shortened: false,
        }),
    })?;
    // SAFETY: this Box is unpublished and stable. Both buffers are embedded in
    // its allocation and remain live until the matching authenticator destroy.
    let data = unsafe { &mut *state.data.get() };
    let auth = boxed(Auth {
        credential: OpaqueAuth {
            oa_flavor: 1,
            oa_base: data.original.as_mut_ptr().cast(),
            oa_length: data.original_len as u32,
        },
        verifier: OpaqueAuth {
            oa_flavor: 0,
            oa_base: ptr::null_mut(),
            oa_length: 0,
        },
        key: [0; 8],
        operations: &OPERATIONS,
        private: (&*state as *const State).cast_mut().cast(),
    })?;
    // No ownership escapes on a preceding allocation failure.
    let _ = Box::into_raw(state);
    Ok(Box::into_raw(auth).cast())
}

fn finish(result: Result<*mut c_void, RpcError>) -> *mut c_void {
    match result {
        Ok(auth) => auth,
        Err(error) => {
            let errno = c_int::from_ne_bytes(error.detail[..4].try_into().unwrap_or([0; 4]));
            unsafe { super::super::set_abi_errno(if errno == 0 { libc::EINVAL } else { errno }) };
            ptr::null_mut()
        }
    }
}

pub(crate) unsafe fn create(
    name: *mut c_char,
    uid: c_int,
    gid: c_int,
    count: c_int,
    groups: *mut c_int,
) -> *mut c_void {
    finish((|| {
        if !(0..=MAX_GROUPS as c_int).contains(&count) {
            return Err(invalid());
        }
        let name = unsafe { name_bytes(name) }?;
        let mut values = [0u32; MAX_GROUPS];
        if count != 0 {
            // SAFETY: count was bounded before computing bytes. The shared
            // fault-checked copier reads caller storage into the owned array.
            unsafe {
                super::user_copy::copy_user_bytes(
                    groups.cast(),
                    values.as_mut_ptr().cast(),
                    count as usize * size_of::<u32>(),
                )
            }
            .map_err(|error| RpcError::system(12, error))?;
        }
        make(&name, uid as u32, gid as u32, &values[..count as usize])
    })())
}

fn process_groups() -> Result<Vec<u32>, RpcError> {
    for _ in 0..3 {
        let count = kernel(unsafe { raw::syscall2(libc::SYS_getgroups as usize, 0, 0) })
            .map_err(|error| RpcError::system(12, error))?;
        if count > MAX_KERNEL_GROUPS {
            return Err(RpcError::system(12, libc::EOVERFLOW));
        }
        if count == 0 {
            return Ok(Vec::new());
        }
        let mut groups = Vec::<u32>::new();
        groups
            .try_reserve_exact(count)
            .map_err(|_| RpcError::system(12, libc::ENOMEM))?;
        groups.resize(count, 0);
        // SAFETY: Linux gid_t is u32; capacity covers every kernel output word.
        match kernel(unsafe {
            raw::syscall2(
                libc::SYS_getgroups as usize,
                count,
                groups.as_mut_ptr() as usize,
            )
        }) {
            Ok(actual) if actual <= count => {
                groups.truncate(actual.min(MAX_GROUPS));
                return Ok(groups);
            }
            // A concurrent credential change can increase the group count.
            Err(libc::EINVAL) => continue,
            Err(error) => return Err(RpcError::system(12, error)),
            Ok(_) => return Err(RpcError::system(12, libc::EOVERFLOW)),
        }
    }
    Err(RpcError::system(12, libc::EAGAIN))
}

pub(crate) unsafe fn create_default() -> *mut c_void {
    finish((|| {
        let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
        // SAFETY: uname writes the complete correctly sized owned structure.
        kernel(unsafe {
            raw::syscall1(
                libc::SYS_uname as usize,
                (&mut uts as *mut libc::utsname) as usize,
            )
        })
        .map_err(|error| RpcError::system(12, error))?;
        let length = uts
            .nodename
            .iter()
            .position(|&byte| byte == 0)
            .ok_or_else(invalid)?;
        let mut name = [0u8; MAX_NAME];
        if length > name.len() {
            return Err(invalid());
        }
        for (out, &byte) in name[..length].iter_mut().zip(&uts.nodename[..length]) {
            *out = byte as u8;
        }
        let uid = kernel(unsafe { raw::syscall0(libc::SYS_geteuid as usize) })
            .map_err(|error| RpcError::system(12, error))? as u32;
        let gid = kernel(unsafe { raw::syscall0(libc::SYS_getegid as usize) })
            .map_err(|error| RpcError::system(12, error))? as u32;
        make(&name[..length], uid, gid, &process_groups()?)
    })())
}

unsafe fn select(auth: *mut Auth, data: &mut Data, shortened: bool) {
    data.shortened = shortened;
    let (flavor, base, length) = if shortened {
        (data.short_flavor, data.short.as_mut_ptr(), data.short_len)
    } else {
        (1, data.original.as_mut_ptr(), data.original_len)
    };
    // SAFETY: auth is the live owned handle; its fields point into the separate
    // private allocation. No mutable reference to caller-owned AUTH is formed.
    unsafe {
        (*auth).credential = OpaqueAuth {
            oa_flavor: flavor,
            oa_base: base.cast(),
            oa_length: length as u32,
        }
    };
}

unsafe extern "C" fn next(_: *mut Auth) {}

unsafe extern "C" fn marshal(auth: *mut Auth, xdr: *mut Xdr) -> c_int {
    // A decoder would write through the borrowed credential slice below.
    // AUTH_MARSHALL is an encoder; reject the wrong direction before callbacks.
    if xdr.is_null() || unsafe { (*xdr).x_op != super::super::XDR_ENCODE || (*xdr).x_ops.is_null() }
    {
        return 0;
    }
    let state = unsafe { &*(*auth).private.cast::<State>() };
    let Some(_gate) = Gate::enter(state) else {
        return 0;
    };
    let data = unsafe { &*state.data.get() };
    let (flavor, body) = if data.shortened {
        (data.short_flavor as u32, &data.short[..data.short_len])
    } else {
        (1, &data.original[..data.original_len])
    };
    let mut flavor = flavor;
    let mut length = body.len() as u32;
    let mut zero = 0;
    // SAFETY: XDR callbacks borrow our bounded stable buffers for the call.
    // The gate prevents a reentrant callback from freeing or replacing them.
    if unsafe { super::super::xdr_u_int(xdr.cast(), &mut flavor) } == 0
        || unsafe { super::super::xdr_u_int(xdr.cast(), &mut length) } == 0
        || unsafe { super::super::xdr_opaque(xdr.cast(), body.as_ptr().cast_mut().cast(), length) }
            == 0
        || unsafe { super::super::xdr_u_int(xdr.cast(), &mut zero) } == 0
        || unsafe { super::super::xdr_u_int(xdr.cast(), &mut zero) } == 0
    {
        return 0;
    }
    1
}

// Only plain C scalar/pointer fields: every bit pattern is valid to import.
#[repr(C)]
#[derive(Clone, Copy)]
struct Verifier {
    flavor: c_int,
    base: *mut c_char,
    length: u32,
}

unsafe fn shorthand(
    verifier: Verifier,
    output: &mut [u8; MAX_AUTH],
) -> Result<Option<(c_int, usize)>, RpcError> {
    if verifier.length < 8 {
        return Ok(None);
    }
    let prefix = unsafe { import::<[u8; 8]>(verifier.base.cast()) }?;
    let flavor = u32::from_be_bytes(prefix[..4].try_into().map_err(|_| invalid())?);
    let length = u32::from_be_bytes(prefix[4..].try_into().map_err(|_| invalid())?) as usize;
    if length > MAX_AUTH || 8 + ((length + 3) & !3) > verifier.length as usize {
        return Ok(None);
    }
    // The verifier contains an XDR opaque_auth, not just its credential bytes.
    // Read the padding as well, so a declared padded extent cannot hide a fault.
    let mut padded = [0u8; MAX_AUTH];
    let count = (length + 3) & !3;
    if count != 0 {
        unsafe {
            super::user_copy::copy_user_bytes(
                verifier.base.cast::<u8>().wrapping_add(8),
                padded.as_mut_ptr(),
                count,
            )
        }
        .map_err(|error| RpcError::system(12, error))?;
    }
    output[..length].copy_from_slice(&padded[..length]);
    Ok(Some((flavor as c_int, length)))
}

unsafe extern "C" fn validate(auth: *mut Auth, verifier: *mut OpaqueAuth) -> c_int {
    let state = unsafe { &*(*auth).private.cast::<State>() };
    let Some(_gate) = Gate::enter(state) else {
        return 0;
    };
    let Ok(verifier) = (unsafe { import::<Verifier>(verifier.cast()) }) else {
        return 0;
    };
    // AUTH_SYS does not authenticate ordinary reply verifiers. Preserve the
    // existing host contract; only AUTH_SHORT changes stored credentials.
    if verifier.flavor != 2 {
        return 1;
    }
    let data = unsafe { &mut *state.data.get() };
    match unsafe { shorthand(verifier, &mut data.short) } {
        Ok(Some((flavor, length))) => {
            data.short_flavor = flavor;
            data.short_len = length;
            unsafe { select(auth, data, true) };
            1
        }
        Ok(None) => {
            // A malformed nickname is ignored in favor of original credentials,
            // not a reason to discard an otherwise accepted RPC reply.
            unsafe { select(auth, data, false) };
            1
        }
        Err(_) => {
            unsafe { select(auth, data, false) };
            0
        }
    }
}

unsafe extern "C" fn refresh(auth: *mut Auth) -> c_int {
    let state = unsafe { &*(*auth).private.cast::<State>() };
    let Some(_gate) = Gate::enter(state) else {
        return 0;
    };
    let data = unsafe { &mut *state.data.get() };
    if !data.shortened {
        return 0;
    }
    let Ok(stamp) = stamp() else {
        return 0;
    };
    data.original[..4].copy_from_slice(&stamp.to_be_bytes());
    unsafe { select(auth, data, false) };
    1
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
    // SAFETY: these are the two exact allocations created by make. The gate
    // rejects destruction from a callback still borrowing the private buffers.
    unsafe {
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

#[cfg(test)]
#[path = "rpc_auth_unix_tests.rs"]
mod tests;
