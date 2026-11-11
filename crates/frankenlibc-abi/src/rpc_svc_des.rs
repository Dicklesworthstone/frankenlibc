//! Native server-side AUTH_DES conversations and UNIX credential mapping.
//!
//! RFC 1057/2695 wire proofs live in safe core. This layer owns the bounded
//! nickname cache and C storage. NSS and keyserver callbacks run without the
//! cache lock; generation checks prevent their results from reaching a reused
//! session. Replay checks and timestamp publication are one locked operation.

use super::{NetObj, OpaqueAuth, known_remaining, rpc_lookup_netid_user};
use frankenlibc_core::rpc::NetidUser;
use frankenlibc_core::rpc::auth_des::{self, AuthError, Credential, NameKind, Timestamp};
use frankenlibc_core::rpc::wire::service::SystemCredentialPolicy;
use frankenlibc_core::syscall as raw;
use std::ffi::{c_char, c_int, c_void};
use std::mem::{MaybeUninit, size_of};
use std::ptr;
use std::sync::atomic::{Ordering, compiler_fence};
use std::sync::{Mutex, MutexGuard};

const SESSIONS: usize = 64;

#[repr(C)]
#[derive(Clone, Copy)]
struct Fullname {
    name: *mut c_char,
    key: [u8; 8],
    window: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct DesCredential {
    kind: c_int,
    fullname: Fullname,
    nickname: u32,
}

#[repr(C)]
struct Cooked {
    credential: DesCredential,
    name: [u8; 256],
    proof: [u8; 12],
}

const _: () = {
    assert!(size_of::<DesCredential>() == 40);
    assert!(std::mem::offset_of!(DesCredential, fullname) == 8);
    assert!(std::mem::offset_of!(DesCredential, nickname) == 32);
    assert!(size_of::<Cooked>() <= 400);
    assert!(std::mem::align_of::<Cooked>() <= 8);
};

struct Secret([u8; 8]);

impl Drop for Secret {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            // SAFETY: these exclusively owned key bytes remain live through Drop.
            unsafe { ptr::write_volatile(byte, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Name {
    bytes: [u8; 256],
    length: usize,
}

impl Name {
    fn new(bytes: &[u8]) -> Result<Self, AuthError> {
        if bytes.is_empty() || bytes.len() > auth_des::MAX_NAME || bytes.contains(&0) {
            return Err(AuthError::BadCredential);
        }
        let mut name = Self {
            bytes: [0; 256],
            length: bytes.len(),
        };
        name.bytes[..bytes.len()].copy_from_slice(bytes);
        Ok(name)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

/// A successful mapping is cached until a fullname refresh or eviction. GNU
/// retries an initially unknown identity, but remembers a failed refresh of an
/// existing local-credential record; preserve that distinction without keeping
/// stale uid/group values after a refresh.
enum LocalIdentity {
    Vacant,
    Invalid,
    Missing,
    Mapped(NetidUser),
}

impl LocalIdentity {
    fn invalidated(&self) -> Self {
        match self {
            Self::Vacant => Self::Vacant,
            _ => Self::Invalid,
        }
    }
}

struct Session {
    generation: u64,
    name: Name,
    key: Secret,
    window: u32,
    last: Timestamp,
    identity: LocalIdentity,
}

struct Snapshot {
    slot: usize,
    generation: u64,
    name: Name,
    key: Secret,
    window: u32,
}

struct Accepted {
    session: Snapshot,
    proof: [u8; 12],
}

struct Cache {
    sessions: [Option<Session>; SESSIONS],
    recent: [usize; SESSIONS],
    next_generation: u64,
}

impl Cache {
    const fn new() -> Self {
        let mut recent = [0; SESSIONS];
        let mut index = 0;
        while index < SESSIONS {
            recent[index] = index;
            index += 1;
        }
        Self {
            sessions: [const { None }; SESSIONS],
            recent,
            next_generation: 1,
        }
    }

    fn touch(&mut self, slot: usize) {
        let position = self.recent.iter().position(|&value| value == slot).unwrap();
        self.recent.copy_within(..position, 1);
        self.recent[0] = slot;
    }

    fn snapshot(&self, slot: usize) -> Result<Snapshot, AuthError> {
        let entry = self
            .sessions
            .get(slot)
            .ok_or(AuthError::BadCredential)?
            .as_ref()
            .ok_or(AuthError::RejectedVerifier)?;
        Ok(Snapshot {
            slot,
            generation: entry.generation,
            name: entry.name,
            key: Secret(entry.key.0),
            window: entry.window,
        })
    }

    fn matches(&self, snapshot: &Snapshot) -> bool {
        self.sessions
            .get(snapshot.slot)
            .and_then(Option::as_ref)
            .is_some_and(|entry| {
                entry.generation == snapshot.generation
                    && entry.name == snapshot.name
                    && entry.key.0 == snapshot.key.0
            })
    }

    fn accept_fullname(
        &mut self,
        name: Name,
        key: &Secret,
        stamp: Timestamp,
        window: u32,
        now: (i64, u32),
    ) -> Result<Accepted, AuthError> {
        let existing = self.sessions.iter().position(|entry| {
            entry
                .as_ref()
                .is_some_and(|entry| entry.name == name && entry.key.0 == key.0)
        });
        let previous =
            existing.and_then(|slot| self.sessions[slot].as_ref().map(|entry| entry.last));
        auth_des::check_timestamp(stamp, previous, window, now.0, now.1, NameKind::Fullname)?;
        let slot = existing.unwrap_or(self.recent[SESSIONS - 1]);
        let proof = auth_des::server_verifier(stamp, slot as u32, &key.0)?;
        // Never recycle a generation after integer exhaustion. This cannot be
        // reached in practice, but prevents an ABA admission rule at wraparound.
        let generation = self.next_generation;
        if generation == 0 {
            return Err(AuthError::Failed);
        }
        self.next_generation = generation.checked_add(1).unwrap_or(0);
        let identity = self.sessions[slot]
            .as_ref()
            .map_or(LocalIdentity::Vacant, |entry| entry.identity.invalidated());
        self.sessions[slot] = Some(Session {
            generation,
            name,
            key: Secret(key.0),
            window,
            last: stamp,
            identity,
        });
        self.touch(slot);
        Ok(Accepted {
            session: self.snapshot(slot)?,
            proof,
        })
    }

    fn accept_nickname(
        &mut self,
        snapshot: &Snapshot,
        stamp: Timestamp,
        now: (i64, u32),
    ) -> Result<Accepted, AuthError> {
        if !self.matches(snapshot) {
            return Err(AuthError::RejectedVerifier);
        }
        let entry = self.sessions[snapshot.slot].as_mut().unwrap();
        auth_des::check_timestamp(
            stamp,
            Some(entry.last),
            entry.window,
            now.0,
            now.1,
            NameKind::Nickname,
        )?;
        let proof = auth_des::server_verifier(stamp, snapshot.slot as u32, &entry.key.0)?;
        entry.last = stamp;
        self.touch(snapshot.slot);
        Ok(Accepted {
            session: self.snapshot(snapshot.slot)?,
            proof,
        })
    }
}

static CACHE: std::sync::OnceLock<Mutex<Box<Cache>>> = std::sync::OnceLock::new();

fn cache() -> MutexGuard<'static, Box<Cache>> {
    CACHE
        .get_or_init(|| Mutex::new(Box::new(Cache::new())))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn now() -> Result<(i64, u32), AuthError> {
    let mut time = raw::Timespec::default();
    // SAFETY: the complete writable record has the kernel timespec layout.
    unsafe { raw::sys_clock_gettime(libc::CLOCK_REALTIME, ptr::from_mut(&mut time).cast()) }
        .map_err(|_| AuthError::Failed)?;
    Ok((time.tv_sec, (time.tv_nsec / 1_000) as u32))
}

unsafe fn import<T: Copy>(source: *const T) -> Result<T, AuthError> {
    let mut value = MaybeUninit::<T>::uninit();
    // SAFETY: all imported records contain only C integers/addresses. The
    // bounded copier initializes their complete storage or reports a fault.
    unsafe {
        crate::io_abi::iov_snapshot::copy_user_bytes(
            source.cast(),
            value.as_mut_ptr().cast(),
            size_of::<T>(),
        )
    }
    .map_err(|_| AuthError::BadCredential)?;
    Ok(unsafe { value.assume_init() })
}

unsafe fn import_name(source: *const c_char) -> Result<Name, AuthError> {
    let mut bytes = [0; 256];
    for index in 0..bytes.len() {
        // SAFETY: read one checked byte, never past the terminating NUL.
        bytes[index] = unsafe { import(source.cast::<u8>().wrapping_add(index)) }?;
        if bytes[index] == 0 {
            return Name::new(&bytes[..index]);
        }
    }
    Err(AuthError::BadCredential)
}

/// Authenticate into caller-owned cooked storage. Direct callers retain that
/// storage through their reply. Native dispatch copies the proof into its
/// transport's fixed verifier field before dropping the dispatch stack frame.
pub(super) unsafe fn authenticate(
    credential: OpaqueAuth,
    verifier: OpaqueAuth,
    cooked: *mut c_void,
    outgoing: &mut OpaqueAuth,
) -> c_int {
    let result = (|| -> Result<(), AuthError> {
        if cooked.is_null()
            || known_remaining(cooked as usize).is_some_and(|size| size < size_of::<Cooked>())
        {
            return Err(AuthError::Failed);
        }
        let length = credential.oa_length as usize;
        let verifier_length = verifier.oa_length as usize;
        if length > auth_des::MAX_AUTH || verifier_length > auth_des::MAX_AUTH {
            return Err(AuthError::BadCredential);
        }
        let mut bytes = [0u8; auth_des::MAX_AUTH];
        let mut proof = [0u8; auth_des::MAX_AUTH];
        // SAFETY: the two destinations cover the admitted sizes. Faults or
        // truncated tracked allocations reject before a key lookup/cache change.
        unsafe {
            crate::io_abi::iov_snapshot::copy_user_bytes(
                credential.oa_base.cast(),
                bytes.as_mut_ptr(),
                length,
            )
            .map_err(|_| AuthError::BadCredential)?;
            crate::io_abi::iov_snapshot::copy_user_bytes(
                verifier.oa_base.cast(),
                proof.as_mut_ptr(),
                verifier_length,
            )
            .map_err(|_| AuthError::BadCredential)?;
        }
        let policy = if frankenlibc_membrane::config::safety_level().heals_enabled() {
            SystemCredentialPolicy::ExactIdentity
        } else {
            SystemCredentialPolicy::Glibc
        };
        let request =
            auth_des::decode_request(&bytes[..length], &proof[..verifier_length], policy)?;
        let accepted = match request.credential {
            Credential::Fullname {
                name,
                encrypted_key,
                encrypted_window,
            } => {
                let name = Name::new(name)?;
                let mut public = [0u8; 49];
                // No cache guard exists while NSS or a local keyserver hook
                // executes. Both may reenter; the keyserver hook additionally
                // supports foreign unwind. Existing NSS C boundaries remain.
                if unsafe {
                    super::getpublickey(name.bytes.as_ptr().cast(), public.as_mut_ptr().cast())
                } == 0
                {
                    return Err(AuthError::BadCredential);
                }
                let mut public = NetObj {
                    len: public.len() as u32,
                    bytes: public.as_mut_ptr().cast(),
                };
                let mut key = Secret(encrypted_key);
                if unsafe {
                    super::key_decryptsession_pk(
                        name.bytes.as_ptr().cast(),
                        ptr::from_mut(&mut public).cast(),
                        key.0.as_mut_ptr().cast(),
                    )
                } < 0
                {
                    return Err(AuthError::BadCredential);
                }
                let (stamp, window) =
                    auth_des::decrypt_fullname(encrypted_window, request.verifier, &key.0)?;
                let now = now()?;
                cache().accept_fullname(name, &key, stamp, window, now)?
            }
            Credential::Nickname(slot) => {
                let snapshot = cache().snapshot(slot as usize)?;
                let stamp = auth_des::decrypt_nickname(request.verifier, &snapshot.key.0)?;
                let now = now()?;
                cache().accept_nickname(&snapshot, stamp, now)?
            }
        };
        let destination = cooked.cast::<Cooked>();
        // SAFETY: the caller provides aligned writable cooked storage. The
        // pointers target that same area; no cache-owned pointer escapes.
        unsafe {
            destination.write(std::mem::zeroed());
            let destination = &mut *destination;
            destination.name = accepted.session.name.bytes;
            destination.proof = accepted.proof;
            destination.credential.kind = 0;
            destination.credential.fullname.name = destination.name.as_mut_ptr().cast();
            destination.credential.fullname.key = accepted.session.key.0;
            destination.credential.fullname.window = accepted.session.window;
            destination.credential.nickname = accepted.session.slot as u32;
            outgoing.oa_base = destination.proof.as_mut_ptr().cast();
            outgoing.oa_flavor = 3;
            outgoing.oa_length = destination.proof.len() as u32;
        }
        Ok(())
    })();
    result.map_or_else(|error| error as c_int, |()| 0)
}

struct Outputs {
    uid: *mut u32,
    gid: *mut u32,
    count: *mut i16,
    groups: *mut u32,
    group_capacity: Option<usize>,
}

impl Outputs {
    unsafe fn publish(&self, user: &NetidUser) -> c_int {
        // The legacy ABI reports a signed short count. Publish exactly that
        // prefix, including when NSS supplies Linux's larger NGROUPS limit.
        let count = user.groups.len().min(i16::MAX as usize);
        let bytes = count * size_of::<u32>();
        if count != 0
            && (self.groups.is_null() || self.group_capacity.is_some_and(|size| size < bytes))
        {
            return 0;
        }
        // SAFETY: scalar extents were admitted before lookup; the complete
        // group extent is checked above, before any caller output is changed.
        unsafe {
            if count != 0 {
                ptr::copy_nonoverlapping(user.groups.as_ptr(), self.groups, count);
            }
            *self.uid = user.uid;
            *self.gid = user.gid;
            *self.count = count as i16;
        }
        1
    }
}

/// Map only a live authenticated cache identity. A reused nickname must not
/// expose another caller's uid/groups, even if an NSS callback replaced it.
pub(super) unsafe fn getucred(
    credential: *mut c_void,
    uid: *mut u32,
    gid: *mut u32,
    count: *mut i16,
    groups: *mut u32,
) -> c_int {
    if uid.is_null()
        || gid.is_null()
        || count.is_null()
        || known_remaining(uid as usize).is_some_and(|size| size < size_of::<u32>())
        || known_remaining(gid as usize).is_some_and(|size| size < size_of::<u32>())
        || known_remaining(count as usize).is_some_and(|size| size < size_of::<i16>())
    {
        return 0;
    }
    let Ok(credential) = (unsafe { import(credential.cast::<DesCredential>()) }) else {
        return 0;
    };
    if credential.kind != 0 {
        return 0;
    }
    let Ok(name) = (unsafe { import_name(credential.fullname.name) }) else {
        return 0;
    };
    let outputs = Outputs {
        uid,
        gid,
        count,
        groups,
        group_capacity: known_remaining(groups as usize),
    };
    let snapshot = {
        let cache = cache();
        let Ok(snapshot) = cache.snapshot(credential.nickname as usize) else {
            return 0;
        };
        if snapshot.name != name || snapshot.key.0 != credential.fullname.key {
            return 0;
        }
        match &cache.sessions[snapshot.slot].as_ref().unwrap().identity {
            LocalIdentity::Mapped(user) => return unsafe { outputs.publish(user) },
            LocalIdentity::Missing => return 0,
            LocalIdentity::Vacant | LocalIdentity::Invalid => {}
        }
        snapshot
    };
    // Callback results remain private until the exact session generation is
    // checked again. A failed or stale lookup never changes caller outputs.
    let user = rpc_lookup_netid_user(snapshot.name.as_bytes());
    let mut cache = cache();
    if !cache.matches(&snapshot) {
        return 0;
    }
    let entry = cache.sessions[snapshot.slot].as_mut().unwrap();
    // A concurrent lookup may already have published a mapping for this exact
    // generation; use that authoritative result instead of replacing it.
    match &entry.identity {
        LocalIdentity::Mapped(user) => return unsafe { outputs.publish(user) },
        LocalIdentity::Missing => return 0,
        LocalIdentity::Vacant | LocalIdentity::Invalid => {}
    }
    match user {
        Some(user) => {
            entry.identity = LocalIdentity::Mapped(user);
            if let LocalIdentity::Mapped(user) = &entry.identity {
                unsafe { outputs.publish(user) }
            } else {
                unreachable!()
            }
        }
        None => {
            if matches!(entry.identity, LocalIdentity::Invalid) {
                entry.identity = LocalIdentity::Missing;
            }
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accept(cache: &mut Cache, name: &[u8], seconds: u32) -> Accepted {
        cache
            .accept_fullname(
                Name::new(name).unwrap(),
                &Secret(*b"12345678"),
                Timestamp {
                    seconds,
                    micros: 100,
                },
                300,
                (1000, 0),
            )
            .unwrap()
    }

    #[test]
    fn fullname_refresh_reuses_identity_but_invalidates_old_generations() {
        let mut cache = Cache::new();
        let first = accept(&mut cache, b"unix.1001@example", 1000);
        let second = accept(&mut cache, b"unix.1001@example", 1001);
        assert_eq!(first.session.slot, second.session.slot);
        assert!(!cache.matches(&first.session));
        assert!(cache.matches(&second.session));
        assert!(matches!(
            cache.accept_nickname(
                &first.session,
                Timestamp {
                    seconds: 1002,
                    micros: 0
                },
                (1000, 0)
            ),
            Err(AuthError::RejectedVerifier),
        ));
    }

    #[test]
    fn failed_replay_commit_preserves_the_current_session() {
        let mut cache = Cache::new();
        let accepted = accept(&mut cache, b"unix.1001@example", 1002);
        assert!(matches!(
            cache.accept_fullname(
                Name::new(b"unix.1001@example").unwrap(),
                &Secret(*b"12345678"),
                Timestamp {
                    seconds: 1001,
                    micros: 100
                },
                300,
                (1000, 0)
            ),
            Err(AuthError::RejectedCredential),
        ));
        assert!(cache.matches(&accepted.session));
        assert!(
            cache
                .accept_nickname(
                    &accepted.session,
                    Timestamp {
                        seconds: 1003,
                        micros: 0
                    },
                    (1000, 0)
                )
                .is_ok()
        );
        assert!(matches!(
            cache.accept_nickname(
                &accepted.session,
                Timestamp {
                    seconds: 1002,
                    micros: 500
                },
                (1000, 0)
            ),
            Err(AuthError::RejectedVerifier),
        ));
    }

    #[test]
    fn fixed_capacity_eviction_never_admits_a_stale_nickname_snapshot() {
        let mut cache = Cache::new();
        let first = accept(&mut cache, b"unix.first@example", 1000);
        for number in 0..SESSIONS {
            let name = format!("unix.{number}@example");
            accept(&mut cache, name.as_bytes(), 1000);
        }
        assert_eq!(cache.sessions.iter().flatten().count(), SESSIONS);
        assert!(!cache.matches(&first.session));
        assert!(matches!(
            cache.accept_nickname(
                &first.session,
                Timestamp {
                    seconds: 1001,
                    micros: 0
                },
                (1000, 0)
            ),
            Err(AuthError::RejectedVerifier),
        ));
    }

    #[test]
    fn fullname_refresh_discards_a_cached_unix_identity() {
        let mut cache = Cache::new();
        let first = accept(&mut cache, b"unix.1001@example", 1000);
        cache.sessions[first.session.slot]
            .as_mut()
            .unwrap()
            .identity = LocalIdentity::Mapped(NetidUser {
            uid: 1001,
            gid: 42,
            groups: vec![17, 88],
        });
        let second = accept(&mut cache, b"unix.1001@example", 1001);
        assert!(matches!(
            cache.sessions[second.session.slot]
                .as_ref()
                .unwrap()
                .identity,
            LocalIdentity::Invalid,
        ));
        assert!(matches!(
            cache.snapshot(SESSIONS),
            Err(AuthError::BadCredential)
        ));
    }

    #[test]
    fn large_mapping_publishes_only_the_representable_group_prefix() {
        let user = NetidUser {
            uid: 1001,
            gid: 42,
            groups: (0..40_000).collect(),
        };
        let mut groups = vec![u32::MAX; i16::MAX as usize + 2];
        let (mut uid, mut gid, mut count) = (0, 0, -1i16);
        let outputs = Outputs {
            uid: &mut uid,
            gid: &mut gid,
            count: &mut count,
            groups: groups.as_mut_ptr(),
            group_capacity: Some(i16::MAX as usize * size_of::<u32>()),
        };
        assert_eq!(unsafe { outputs.publish(&user) }, 1);
        assert_eq!((uid, gid, count), (1001, 42, i16::MAX));
        assert_eq!(groups[i16::MAX as usize - 1], i16::MAX as u32 - 1);
        assert_eq!(&groups[i16::MAX as usize..], &[u32::MAX; 2]);
    }
}
