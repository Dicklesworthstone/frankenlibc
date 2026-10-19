//! Shared CLIENT invocation and bounded AUTH_REJECTEDCRED recovery.
//!
//! RFC 5531 Appendix A permits returning from an expired AUTH_SHORT nickname
//! to the original AUTH_SYS identity. No other remote status or local failure
//! is a retry authorization. All attempts share one absolute call deadline.

use super::{
    Client, Data, Deadline, OpaqueAuth, RemoteError, Reply, RpcError, Timeval, Xdr, XdrProc,
    exchange_until, nanos, transaction_id, wire,
};
use std::ffi::{c_int, c_uint, c_void};

pub(super) unsafe fn invoke(
    client: *mut Client,
    data: &mut Data,
    procedure: u64,
    arguments: Option<XdrProc>,
    argument: *mut c_void,
    results: Option<XdrProc>,
    result: *mut c_void,
    timeout: Timeval,
) -> Result<(), RpcError> {
    let timeout = nanos(data.timeout.unwrap_or(timeout), false)?;
    let retry = nanos(data.retry, true)?;
    let deadline = Deadline::new(timeout)?;
    let arguments = arguments.ok_or_else(|| RpcError::status(1))?;
    let results = results.ok_or_else(|| RpcError::status(2))?;
    let auth = unsafe { (*client).auth };
    if auth.is_null() || unsafe { (*auth).operations.is_null() } {
        return Err(RpcError::remote(RemoteError::Authentication(7)));
    }
    let mut refreshes = 0;
    let mut attempted_ids = [0u32; 3];
    loop {
        if !deadline.nonblocking {
            deadline.check()?;
        }
        let xid = if refreshes == 0 {
            data.next_xid.take().unwrap_or_else(transaction_id)
        } else {
            // Reserve from the shared serial even on refresh, so the next
            // ordinary call cannot reuse this attempt's ID. Caller-forced IDs
            // must also be excluded from this call's later attempts.
            let mut candidate = transaction_id();
            while attempted_ids[..refreshes].contains(&candidate) {
                candidate = transaction_id();
            }
            candidate
        };
        attempted_ids[refreshes] = xid;
        data.xid = xid;
        wire::encode_call_prefix(
            &mut data.send,
            xid,
            data.program,
            data.version,
            procedure as u32,
        )
        .map_err(|_| RpcError::status(1))?;
        let mut xdr: Xdr = unsafe { std::mem::zeroed() };
        // SAFETY: the XDR stream's capacity is the exact owned allocation remainder.
        unsafe {
            super::super::xdrmem_create(
                (&mut xdr as *mut Xdr).cast(),
                data.send.as_mut_ptr().add(wire::CALL_PREFIX_BYTES).cast(),
                (data.send.len() - wire::CALL_PREFIX_BYTES) as c_uint,
                super::super::XDR_ENCODE,
            )
        };
        // The public initializer has a void ABI and can decline a policy decision.
        // Never dispatch a callback through the zeroed handle on that path.
        if xdr.x_ops.is_null() {
            return Err(RpcError::status(1));
        }
        // Data is exclusively gated. Reentrant calls/control/free/destroy fail without
        // accessing it; no Rust mutable reference to the AUTH or CLIENT is formed.
        if unsafe { ((*(*auth).operations).marshal)(auth, &mut xdr) } == 0
            || unsafe { arguments((&mut xdr as *mut Xdr).cast(), argument) } == 0
        {
            return Err(RpcError::status(1));
        }
        let used = wire::CALL_PREFIX_BYTES
            .checked_add(unsafe { super::super::mem_pos(&xdr) } as usize)
            .filter(|&length| length <= data.send.len())
            .ok_or_else(|| RpcError::status(1))?;
        let length = if let Some(stream) = &mut data.stream {
            stream.exchange(
                &data.socket,
                &data.send[..used],
                &mut data.receive,
                xid,
                deadline,
            )?
        } else {
            exchange_until(
                &data.socket,
                &data.peer,
                &data.send[..used],
                &mut data.receive,
                xid,
                retry,
                deadline,
            )?
        };
        match wire::decode_reply(&data.receive[..length], xid).map_err(|_| RpcError::status(2))? {
            Reply::Failure(RemoteError::Authentication(2)) if refreshes < 2 => {
                // Only an explicit server rejection authorizes re-encoding/retry.
                // Transport failures and an invalid verifier on an ACCEPTED reply
                // must never replay a procedure that may already have executed.
                deadline.check()?;
                if unsafe { ((*(*auth).operations).refresh)(auth) } == 0 {
                    return Err(RpcError::remote(RemoteError::Authentication(2)));
                }
                refreshes += 1;
                // A caller callback cannot be preempted, but its elapsed time must
                // not buy another transport budget or another send after expiry.
                deadline.check()?;
                continue;
            }
            Reply::Failure(error) => return Err(RpcError::remote(error)),
            Reply::Success {
                verifier_flavor,
                verifier,
                results: range,
            } => {
                let mut verifier_bytes = [0u8; wire::MAX_AUTH_BYTES];
                verifier_bytes[..verifier.len()].copy_from_slice(&data.receive[verifier.clone()]);
                let mut verifier = OpaqueAuth {
                    oa_flavor: verifier_flavor as c_int,
                    oa_base: verifier_bytes.as_mut_ptr().cast(),
                    oa_length: verifier.len() as c_uint,
                };
                if unsafe { ((*(*auth).operations).validate)(auth, &mut verifier) } == 0 {
                    return Err(RpcError::remote(RemoteError::Authentication(6)));
                }
                // SAFETY: range came from the bounded envelope parser; callbacks see
                // only procedure results, not stale bytes or the verifier/header.
                // Clear the previous ENCODE stream first: a denied initializer must
                // not leave a valid-looking handle into the request buffer behind.
                xdr = unsafe { std::mem::zeroed() };
                unsafe {
                    super::super::xdrmem_create(
                        (&mut xdr as *mut Xdr).cast(),
                        data.receive.as_mut_ptr().add(range.start).cast(),
                        range.len() as c_uint,
                        super::super::XDR_DECODE,
                    )
                };
                if xdr.x_ops.is_null() {
                    return Err(RpcError::status(2));
                }
                if unsafe { results((&mut xdr as *mut Xdr).cast(), result) } == 0 {
                    return Err(RpcError::status(2));
                }
                return Ok(());
            }
        }
    }
}
