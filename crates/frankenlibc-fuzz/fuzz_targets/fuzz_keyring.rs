#![no_main]
//! Structure-aware fuzz target for the Linux kernel keyring family:
//!
//!   add_key(type, description, payload, plen, keyring_id)
//!   request_key(type, description, callout_info, dest_keyring)
//!   keyctl(cmd, arg2, arg3, arg4, arg5)
//!
//! The keyring API takes attacker-controlled key types ("user",
//! "logon", "keyring", etc.), descriptions, and payloads. There have
//! been multiple kernel CVEs in this surface (CVE-2016-0728 add_key
//! refcount overflow, CVE-2022-1011 keyctl race). Our user-space
//! wrappers must validate pointers, propagate errno, and never panic.
//!
//! Strategy:
//! - Restrict key TYPES to a small allowlist of known-safe ones
//!   ("user", "logon", "asymmetric", "keyring", plus a fuzz string).
//! - Bound payload length to PAYLOAD_CAP so we don't queue huge
//!   payloads in the kernel keyring across iterations.
//! - Always target known-failing keyring IDs (KEY_SPEC_THREAD_KEYRING
//!   is real but we use it sparingly; bogus serial -1 always fails).
//! - keyctl: drive ~30 KEYCTL_* commands with fuzz-shaped args.
//!
//! Invariants:
//! - Never panic for any (type, desc, payload, cmd, args) tuple
//! - rc is -1 or non-negative (key serial / count / size)
//! - Guard bytes around the payload buffer survive every call
//!
//! Bead: bd-ris3r

use std::ffi::CString;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use frankenlibc_abi::unistd_abi::{add_key, keyctl, request_key};

const PAYLOAD_CAP: usize = 256;
const STR_CAP: usize = 64;
const GUARD_BYTES: usize = 32;
const GUARD_VAL: u8 = 0xCB;

/// Allowlisted key types — kernel-recognized only. A fuzz-string slot
/// is folded in via `use_fuzz_type` to exercise unknown-type EINVAL.
const KEY_TYPES: &[&[u8]] = &[
    b"user\0",
    b"logon\0",
    b"keyring\0",
    b"big_key\0",
    b"asymmetric\0",
];

/// Special keyring IDs (KEY_SPEC_*) — negative serial constants.
const KEYRING_IDS: &[i32] = &[
    -2, // KEY_SPEC_PROCESS_KEYRING
    -3, // KEY_SPEC_SESSION_KEYRING
    -4, // KEY_SPEC_USER_KEYRING
    -5, // KEY_SPEC_USER_SESSION_KEYRING
    -7, // KEY_SPEC_REQKEY_AUTH_KEY
    -8, // KEY_SPEC_REQUESTOR_KEYRING
    -1, // KEY_SPEC_THREAD_KEYRING (intentionally last; using this with
        // add_key actually creates a per-thread key, which we want to keep
        // bounded — the harness add_key payloads are <=256 bytes).
    0,  // bogus
    i32::MAX,
];

/// KEYCTL_* command numbers — kernel-stable.
const KEYCTL_CMDS: &[libc::c_int] = &[
    0,  // KEYCTL_GET_KEYRING_ID
    1,  // KEYCTL_JOIN_SESSION_KEYRING
    2,  // KEYCTL_UPDATE
    3,  // KEYCTL_REVOKE
    4,  // KEYCTL_CHOWN
    5,  // KEYCTL_SETPERM
    6,  // KEYCTL_DESCRIBE
    7,  // KEYCTL_CLEAR
    8,  // KEYCTL_LINK
    9,  // KEYCTL_UNLINK
    10, // KEYCTL_SEARCH
    11, // KEYCTL_READ
    12, // KEYCTL_INSTANTIATE
    13, // KEYCTL_NEGATE
    14, // KEYCTL_SET_REQKEY_KEYRING
    15, // KEYCTL_SET_TIMEOUT
    16, // KEYCTL_ASSUME_AUTHORITY
    17, // KEYCTL_GET_SECURITY
    18, // KEYCTL_SESSION_TO_PARENT
    19, // KEYCTL_REJECT
    20, // KEYCTL_INSTANTIATE_IOV
    21, // KEYCTL_INVALIDATE
    22, // KEYCTL_GET_PERSISTENT
    23, // KEYCTL_DH_COMPUTE
    24, // KEYCTL_PKEY_QUERY
    25, // KEYCTL_PKEY_ENCRYPT
    26, // KEYCTL_PKEY_DECRYPT
    27, // KEYCTL_PKEY_SIGN
    28, // KEYCTL_PKEY_VERIFY
    29, // KEYCTL_RESTRICT_KEYRING
    30, // KEYCTL_MOVE
    31, // KEYCTL_CAPABILITIES
    32, // KEYCTL_WATCH_KEY
    -1, // intentionally invalid
];

#[derive(Debug, Arbitrary)]
struct KeyringInput {
    op: u8,
    type_sel: u8,
    use_fuzz_type: bool,
    fuzz_type: Vec<u8>,
    desc_bytes: Vec<u8>,
    payload_bytes: Vec<u8>,
    callout_bytes: Vec<u8>,
    keyring_sel: u8,
    keyctl_cmd_sel: u8,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
}

fn pick_type(input: &KeyringInput) -> CString {
    if input.use_fuzz_type {
        let n = input.fuzz_type.len().min(STR_CAP);
        let cleaned: Vec<u8> = input.fuzz_type[..n]
            .iter()
            .copied()
            .filter(|&b| b != 0)
            .collect();
        CString::new(cleaned).unwrap_or_default()
    } else {
        let bytes = KEY_TYPES[(input.type_sel as usize) % KEY_TYPES.len()];
        let trimmed: &[u8] = if let Some(&0) = bytes.last() {
            &bytes[..bytes.len() - 1]
        } else {
            bytes
        };
        CString::new(trimmed).unwrap_or_default()
    }
}

fn pick_keyring(sel: u8) -> i32 {
    KEYRING_IDS[(sel as usize) % KEYRING_IDS.len()]
}

fn pick_keyctl_cmd(sel: u8) -> libc::c_int {
    KEYCTL_CMDS[(sel as usize) % KEYCTL_CMDS.len()]
}

fn populate_guard_payload(seed: &[u8], cap: usize) -> Vec<u8> {
    let mut buf = vec![GUARD_VAL; 2 * GUARD_BYTES + cap];
    let n = seed.len().min(cap);
    buf[GUARD_BYTES..GUARD_BYTES + n].copy_from_slice(&seed[..n]);
    buf
}

fn assert_guards(buf: &[u8], cap: usize, label: &str) {
    for (i, &b) in buf[..GUARD_BYTES].iter().enumerate() {
        assert_eq!(
            b, GUARD_VAL,
            "{label}: leading guard clobbered at offset {i}"
        );
    }
    let trail_start = GUARD_BYTES + cap;
    for (i, &b) in buf[trail_start..].iter().enumerate() {
        assert_eq!(b, GUARD_VAL, "{label}: trailing guard clobbered at +{i}");
    }
}

fuzz_target!(|input: KeyringInput| {
    if input.payload_bytes.len() > PAYLOAD_CAP * 2
        || input.desc_bytes.len() > STR_CAP * 2
        || input.callout_bytes.len() > STR_CAP * 2
        || input.fuzz_type.len() > STR_CAP * 2
    {
        return;
    }

    let typ = pick_type(&input);
    let desc_n = input.desc_bytes.len().min(STR_CAP);
    let desc_clean: Vec<u8> = input.desc_bytes[..desc_n]
        .iter()
        .copied()
        .filter(|&b| b != 0)
        .collect();
    let desc = CString::new(desc_clean).unwrap_or_default();

    match input.op % 3 {
        0 => {
            // add_key with bounded payload + guarded buffer.
            let payload_n = input.payload_bytes.len().min(PAYLOAD_CAP);
            let mut buf = populate_guard_payload(&input.payload_bytes, PAYLOAD_CAP);
            let payload_ptr =
                unsafe { buf.as_ptr().add(GUARD_BYTES) as *const std::ffi::c_void };
            let rc = unsafe {
                add_key(
                    typ.as_ptr(),
                    desc.as_ptr(),
                    payload_ptr,
                    payload_n,
                    pick_keyring(input.keyring_sel),
                )
            };
            assert!(rc >= -1, "add_key rc={rc}");
            assert_guards(&buf, PAYLOAD_CAP, "add_key");
        }
        1 => {
            // request_key with bounded callout_info.
            let callout_n = input.callout_bytes.len().min(STR_CAP);
            let callout_clean: Vec<u8> = input.callout_bytes[..callout_n]
                .iter()
                .copied()
                .filter(|&b| b != 0)
                .collect();
            let callout = CString::new(callout_clean).unwrap_or_default();
            let callout_ptr = if callout.as_bytes().is_empty() {
                std::ptr::null()
            } else {
                callout.as_ptr()
            };
            let rc = unsafe {
                request_key(
                    typ.as_ptr(),
                    desc.as_ptr(),
                    callout_ptr,
                    pick_keyring(input.keyring_sel),
                )
            };
            assert!(rc >= -1, "request_key rc={rc}");
        }
        _ => {
            // keyctl with fuzz cmd + 4 ulong args. Most cmds will
            // fail with EINVAL on bogus args; the harness just wants
            // no panic + sane rc shape.
            //
            // Bound every arg to <= ARG_CAP so commands that interpret
            // an arg as a buffer size (KEYCTL_READ length, KEYCTL_DH_COMPUTE
            // out_len, KEYCTL_INSTANTIATE plen, KEYCTL_PKEY_* sizes)
            // don't ask the kernel/libc to allocate gigabytes and trip
            // the libfuzzer OOM ceiling.
            const ARG_CAP: u64 = 16 * 1024;
            let cmd = pick_keyctl_cmd(input.keyctl_cmd_sel);
            let rc = unsafe {
                keyctl(
                    cmd,
                    (input.arg2 % ARG_CAP) as libc::c_ulong,
                    (input.arg3 % ARG_CAP) as libc::c_ulong,
                    (input.arg4 % ARG_CAP) as libc::c_ulong,
                    (input.arg5 % ARG_CAP) as libc::c_ulong,
                )
            };
            assert!(rc >= -1, "keyctl(cmd={cmd}) rc={rc}");
        }
    }
});
