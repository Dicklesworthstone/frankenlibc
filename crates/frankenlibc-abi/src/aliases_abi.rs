//! Native files aliases and configured NSS alias lookup/enumeration.
//!
//! The files cursor is shared by public and direct provider calls. Caller
//! buffers never own cursor progress: a complete entry stays pending until it
//! can be published, including after ERANGE. Foreign callbacks run outside
//! registry locks and mutable TLS borrows.

use std::ffi::{c_char, c_int, c_void};
use std::io::BufRead;
use std::os::unix::ffi::OsStrExt;
use std::sync::{Condvar, Mutex};

use frankenlibc_core::aliases::AliasEntry;

use crate::errno_abi::set_abi_errno;
use crate::unistd_abi::{
    NetdbIteration, current_abi_errno, read_c_string_bytes, tracked_object_fits,
    tracked_output_capacity,
};

const SUCCESS: c_int = 1;
const NOTFOUND: c_int = 0;
const UNAVAIL: c_int = -1;
const TRYAGAIN: c_int = -2;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct AliasEnt {
    name: *mut c_char,
    members_len: usize,
    members: *mut *mut c_char,
    local: c_int,
}

impl AliasEnt {
    const fn empty() -> Self {
        Self {
            name: std::ptr::null_mut(),
            members_len: 0,
            members: std::ptr::null_mut(),
            local: 0,
        }
    }
}

fn aliases_path() -> std::path::PathBuf {
    crate::stdlib_abi::secure_var_os("FRANKENLIBC_ALIASES_PATH")
        .filter(|path| !path.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/etc/aliases"))
}

fn read_include(path: &[u8], error: &mut Option<c_int>) -> Option<Vec<u8>> {
    match std::fs::read(std::ffi::OsStr::from_bytes(path)) {
        Ok(bytes) => Some(bytes),
        Err(failure) => {
            *error = Some(failure.raw_os_error().unwrap_or(libc::EIO));
            None
        }
    }
}

/// Admit the whole record before writing any byte. Align the absolute caller
/// address, since a perfectly valid char buffer can begin at an odd address.
unsafe fn pack(
    entry: &AliasEntry,
    output: *mut AliasEnt,
    buffer: *mut c_char,
    capacity: usize,
) -> Result<(), c_int> {
    let mut strings = entry.name.len().checked_add(1).ok_or(libc::ERANGE)?;
    for member in &entry.members {
        strings = strings
            .checked_add(member.len().checked_add(1).ok_or(libc::ERANGE)?)
            .ok_or(libc::ERANGE)?;
    }
    let align = core::mem::align_of::<*mut c_char>();
    let address = (buffer as usize).checked_add(strings).ok_or(libc::ERANGE)?;
    let table = strings
        .checked_add(address.wrapping_neg() & (align - 1))
        .ok_or(libc::ERANGE)?;
    let pointers = entry
        .members
        .len()
        .checked_mul(core::mem::size_of::<*mut c_char>())
        .ok_or(libc::ERANGE)?;
    let total = table.checked_add(pointers).ok_or(libc::ERANGE)?;
    if total > capacity || total > isize::MAX as usize {
        return Err(libc::ERANGE);
    }
    // SAFETY: callers validate the complete header and actual writable buffer;
    // all checked offsets above fit that buffer, including the pointer table.
    unsafe {
        let bytes = buffer.cast::<u8>();
        std::ptr::copy_nonoverlapping(entry.name.as_ptr(), bytes, entry.name.len());
        *bytes.add(entry.name.len()) = 0;
        let members = bytes.add(table).cast::<*mut c_char>();
        let mut offset = entry.name.len() + 1;
        for (index, member) in entry.members.iter().enumerate() {
            members.add(index).write(bytes.add(offset).cast());
            std::ptr::copy_nonoverlapping(member.as_ptr(), bytes.add(offset), member.len());
            *bytes.add(offset + member.len()) = 0;
            offset += member.len() + 1;
        }
        output.write(AliasEnt {
            name: buffer,
            members_len: entry.members.len(),
            members,
            local: 1,
        });
    }
    Ok(())
}

struct FilesCursor {
    source: Option<std::path::PathBuf>,
    reader: Option<std::io::BufReader<std::fs::File>>,
    line: Vec<u8>,
    pending: Option<AliasEntry>,
    line_ready: bool,
    include_error: Option<c_int>,
}

impl FilesCursor {
    const fn new() -> Self {
        Self {
            source: None,
            reader: None,
            line: Vec::new(),
            pending: None,
            line_ready: false,
            include_error: None,
        }
    }

    fn close(&mut self) {
        self.source = None;
        self.reader = None;
        self.line.clear();
        self.pending = None;
        self.line_ready = false;
        self.include_error = None;
    }

    fn open(&mut self) -> Result<(), c_int> {
        let path = aliases_path();
        if self.source.as_ref() != Some(&path) {
            self.close();
        }
        if self.reader.is_none() {
            let file = std::fs::File::open(&path)
                .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))?;
            self.reader = Some(std::io::BufReader::new(file));
            self.source = Some(path);
        }
        Ok(())
    }

    fn read_record(&mut self) -> Result<bool, c_int> {
        self.line.clear();
        let reader = self.reader.as_mut().ok_or(libc::EIO)?;
        let count = reader
            .read_until(b'\n', &mut self.line)
            .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))?;
        if count == 0 {
            return Ok(false);
        }
        // Malformed lines do not acquire following indented records. Keep
        // lookahead in the reader rather than consuming the next entry.
        if frankenlibc_core::aliases::parse_aliases_line(&self.line).is_some() {
            loop {
                let continuation = reader
                    .fill_buf()
                    .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))?
                    .first()
                    .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | 0x0b | 0x0c));
                if !continuation {
                    break;
                }
                reader
                    .read_until(b'\n', &mut self.line)
                    .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))?;
            }
        }
        self.line_ready = true;
        Ok(true)
    }

    unsafe fn next(
        &mut self,
        output: *mut AliasEnt,
        buffer: *mut c_char,
        capacity: usize,
    ) -> Result<bool, c_int> {
        if !self.line_ready {
            self.include_error = None;
        }
        // The files parser needs at least one pointer-sized workspace even at
        // EOF. Admission precedes parsing, including nonmatching/comment lines.
        admit_line(&[], capacity)?;
        while self.pending.is_none() {
            if !self.line_ready && !self.read_record()? {
                return Ok(false);
            }
            admit_line(&self.line, capacity)?;
            let error = &mut self.include_error;
            self.pending = frankenlibc_core::aliases::next_alias(&self.line, &mut 0, |path| {
                read_include(path, error)
            });
            if self.pending.is_none() {
                self.line_ready = false;
            }
        }
        // SAFETY: the caller supplies a complete header and bounded buffer.
        unsafe { pack(self.pending.as_ref().unwrap(), output, buffer, capacity) }?;
        self.pending = None;
        self.line_ready = false;
        Ok(true)
    }
}

fn admit_line(record: &[u8], capacity: usize) -> Result<(), c_int> {
    let align = core::mem::size_of::<*mut c_char>();
    let mut needed = align;
    for line in record.split_inclusive(|&byte| byte == b'\n') {
        let raw = line.len().checked_add(1).ok_or(libc::ERANGE)?;
        let rounded = raw.checked_add(align - 1).ok_or(libc::ERANGE)? & !(align - 1);
        needed = needed.max(rounded);
    }
    if capacity < needed {
        Err(libc::ERANGE)
    } else {
        Ok(())
    }
}

static FILES: Mutex<FilesCursor> = Mutex::new(FilesCursor::new());

pub(crate) fn files_setent() -> c_int {
    let saved_errno = current_abi_errno();
    let mut cursor = FILES.lock().unwrap_or_else(|error| error.into_inner());
    cursor.close();
    let error = cursor.open().err().unwrap_or(0);
    // SAFETY: successful open/rewind preserves the caller's errno.
    unsafe { set_abi_errno(if error == 0 { saved_errno } else { error }) };
    error
}

pub(crate) fn files_endent() {
    let saved_errno = current_abi_errno();
    FILES
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .close();
    // SAFETY: internal close must not replace the public caller's error.
    unsafe { set_abi_errno(saved_errno) };
}

unsafe fn files_status(
    outcome: Result<bool, c_int>,
    errnop: *mut c_int,
    saved_errno: c_int,
    include_error: Option<c_int>,
) -> c_int {
    match outcome {
        Ok(found) => {
            // SAFETY: errno is the calling thread's own error cell. Missing
            // includes are ignored as records but keep GNU's I/O side effect.
            unsafe { set_abi_errno(include_error.unwrap_or(saved_errno)) };
            if found { SUCCESS } else { NOTFOUND }
        }
        Err(error) => {
            // SAFETY: the optional error cell was checked at the boundary.
            unsafe {
                // GNU's files parser reports buffer exhaustion through
                // errnop. A separate errno cell is left alone; public calls
                // deliberately pass their canonical errno as errnop.
                set_abi_errno(if error == libc::ERANGE {
                    include_error.unwrap_or(saved_errno)
                } else {
                    error
                });
                if !errnop.is_null() {
                    errnop.write(error);
                }
            }
            if matches!(error, libc::ERANGE | libc::EAGAIN) {
                TRYAGAIN
            } else {
                UNAVAIL
            }
        }
    }
}

fn files_open_failure(error: c_int) -> c_int {
    // SAFETY: file open errors affect errno, but leave a separate NSS errnop
    // untouched. No writable provider output has been used yet.
    unsafe { set_abi_errno(error) };
    if error == libc::EAGAIN {
        TRYAGAIN
    } else {
        UNAVAIL
    }
}

fn valid_outputs(output: *mut c_void, buffer: *mut c_char, errnop: *mut c_int) -> bool {
    tracked_object_fits::<AliasEnt>(output.cast())
        && (errnop.is_null() || tracked_object_fits(errnop))
        && !buffer.is_null()
}

pub(crate) unsafe fn files_next_r(
    output: *mut c_void,
    buffer: *mut c_char,
    length: usize,
    errnop: *mut c_int,
) -> c_int {
    if !errnop.is_null() && !tracked_object_fits(errnop) {
        // SAFETY: invalid external storage must not be written.
        unsafe { set_abi_errno(libc::EINVAL) };
        return UNAVAIL;
    }
    let saved_errno = current_abi_errno();
    if !valid_outputs(output, buffer, errnop) {
        // SAFETY: errnop is either NULL or a checked complete integer.
        return unsafe { files_status(Err(libc::EINVAL), errnop, saved_errno, None) };
    }
    let mut cursor = FILES.lock().unwrap_or_else(|error| error.into_inner());
    if let Err(error) = cursor.open() {
        // GNU enumeration keeps both incoming error cells on an open failure,
        // unlike setent and keyed lookup. Retry the open on the next call so a
        // database created after an earlier failure becomes visible at once.
        // SAFETY: no provider output has been written; errno is thread-local.
        unsafe { set_abi_errno(saved_errno) };
        return if error == libc::EAGAIN {
            TRYAGAIN
        } else {
            UNAVAIL
        };
    }
    let capacity = tracked_output_capacity(buffer, length);
    // SAFETY: complete typed header and actual caller buffer are valid.
    let outcome = unsafe { cursor.next(output.cast(), buffer, capacity) };
    let include_error = cursor.include_error;
    // SAFETY: optional error output was validated before any file I/O.
    unsafe { files_status(outcome, errnop, saved_errno, include_error) }
}

pub(crate) unsafe fn files_by_name_r(
    name: *const c_char,
    output: *mut c_void,
    buffer: *mut c_char,
    length: usize,
    errnop: *mut c_int,
) -> c_int {
    if !errnop.is_null() && !tracked_object_fits(errnop) {
        // SAFETY: invalid external storage must not be written.
        unsafe { set_abi_errno(libc::EINVAL) };
        return UNAVAIL;
    }
    let saved_errno = current_abi_errno();
    let mut include_error = None;
    let mut open_error = None;
    let outcome = (|| {
        if !valid_outputs(output, buffer, errnop) {
            return Err(libc::EINVAL);
        }
        // SAFETY: the bounded reader rejects a NULL or tracked unterminated key.
        let name = unsafe { read_c_string_bytes(name) }.ok_or(libc::EINVAL)?;
        let mut cursor = FilesCursor::new();
        if let Err(error) = cursor.open() {
            open_error = Some(error);
            return Err(error);
        }
        let capacity = tracked_output_capacity(buffer, length);
        admit_line(&[], capacity)?;
        while cursor.read_record()? {
            admit_line(&cursor.line, capacity)?;
            let entry = frankenlibc_core::aliases::lookup_alias_by_name_with_includes(
                &cursor.line,
                &name,
                |path| read_include(path, &mut include_error),
            );
            if let Some(entry) = entry {
                // SAFETY: typed output and exact caller capacity were checked.
                unsafe { pack(&entry, output.cast(), buffer, capacity) }?;
                return Ok(true);
            }
        }
        Ok(false)
    })();
    if let Some(error) = open_error {
        return files_open_failure(error);
    }
    // SAFETY: the optional complete error object was checked at entry.
    unsafe { files_status(outcome, errnop, saved_errno, include_error) }
}

struct ThreadOutput {
    entry: AliasEnt,
    buffer: Vec<u8>,
    lookup: AliasEnt,
    lookup_buffer: Vec<u8>,
    lookup_busy: bool,
}

impl ThreadOutput {
    const fn new() -> Self {
        Self {
            entry: AliasEnt::empty(),
            buffer: Vec::new(),
            lookup: AliasEnt::empty(),
            lookup_buffer: Vec::new(),
            lookup_busy: false,
        }
    }
}

// SAFETY: the cache keys slots by kernel thread. Pointers refer only to each
// slot's own buffers and are rebuilt after every successful provider call.
unsafe impl Send for ThreadOutput {}

static OWNED_OUTPUT: crate::owned_tls_cache::OwnedTlsCache<ThreadOutput> =
    crate::owned_tls_cache::OwnedTlsCache::new(ThreadOutput::new);

#[cfg(not(feature = "owned-tls-cache"))]
std::thread_local! {
    static OUTPUT: crate::util::TlsHeapCell<std::cell::UnsafeCell<ThreadOutput>> =
        const { crate::util::TlsHeapCell::new() };
}

fn with_output<R>(callback: impl FnOnce(&mut ThreadOutput) -> R) -> R {
    #[cfg(feature = "owned-tls-cache")]
    {
        OWNED_OUTPUT.with(callback)
    }
    #[cfg(not(feature = "owned-tls-cache"))]
    {
        if crate::owned_tls_cache::uses_owned_tls() {
            return OWNED_OUTPUT.with(callback);
        }
        OUTPUT.with(|slot| {
            slot.with_init(
                || std::cell::UnsafeCell::new(ThreadOutput::new()),
                |cell| {
                    // SAFETY: this short thread-local borrow never spans a
                    // foreign callback, nor does a mutable reference escape.
                    callback(unsafe { &mut *cell.get() })
                },
            )
        })
    }
}

struct EnumerationState {
    owner: c_int,
    iteration: NetdbIteration,
}

static ENUMERATION: Mutex<EnumerationState> = Mutex::new(EnumerationState {
    owner: 0,
    iteration: NetdbIteration::new(crate::nss_module::NetdbDatabase::Aliases),
});
static AVAILABLE: Condvar = Condvar::new();

struct EnumerationLease {
    iteration: NetdbIteration,
    buffer: Vec<u8>,
}

impl EnumerationLease {
    fn acquire() -> Option<Self> {
        let saved_errno = current_abi_errno();
        let owner = frankenlibc_core::syscall::sys_gettid() as c_int;
        let mut state = ENUMERATION
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if state.owner == owner {
            // SAFETY: acquiring internal state must not replace caller errno.
            unsafe { set_abi_errno(saved_errno) };
            return None;
        }
        while state.owner != 0 {
            state = AVAILABLE
                .wait(state)
                .unwrap_or_else(|error| error.into_inner());
        }
        state.owner = owner;
        let iteration = std::mem::replace(
            &mut state.iteration,
            NetdbIteration::new(crate::nss_module::NetdbDatabase::Aliases),
        );
        drop(state);
        let buffer = with_output(|state| std::mem::take(&mut state.buffer));
        // SAFETY: TLS initialization must not change the provider's errno.
        unsafe { set_abi_errno(saved_errno) };
        Some(Self { iteration, buffer })
    }
}

impl Drop for EnumerationLease {
    fn drop(&mut self) {
        let saved_errno = current_abi_errno();
        let iteration = std::mem::replace(
            &mut self.iteration,
            NetdbIteration::new(crate::nss_module::NetdbDatabase::Aliases),
        );
        let buffer = std::mem::take(&mut self.buffer);
        with_output(|state| state.buffer = buffer);
        let mut state = ENUMERATION
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.iteration = iteration;
        state.owner = 0;
        drop(state);
        AVAILABLE.notify_one();
        // SAFETY: publishing cursor state preserves the completed error.
        unsafe { set_abi_errno(saved_errno) };
    }
}

struct LookupLease {
    buffer: Vec<u8>,
}

impl LookupLease {
    fn acquire() -> Option<Self> {
        let saved_errno = current_abi_errno();
        let lease = with_output(|state| {
            if state.lookup_busy {
                return None;
            }
            state.lookup_busy = true;
            Some(Self {
                buffer: std::mem::take(&mut state.lookup_buffer),
            })
        });
        // SAFETY: private storage initialization preserves caller errno.
        unsafe { set_abi_errno(saved_errno) };
        lease
    }
}

impl Drop for LookupLease {
    fn drop(&mut self) {
        let saved_errno = current_abi_errno();
        let buffer = std::mem::take(&mut self.buffer);
        with_output(|state| {
            state.lookup_buffer = buffer;
            state.lookup_busy = false;
        });
        // SAFETY: releasing private storage preserves lookup errno.
        unsafe { set_abi_errno(saved_errno) };
    }
}

pub(crate) fn setent() {
    if let Some(mut lease) = EnumerationLease::acquire() {
        lease.iteration.rewind(0);
    } else {
        // SAFETY: recursion cannot borrow an active traversal.
        unsafe { set_abi_errno(libc::EDEADLK) };
    }
}

pub(crate) fn endent() {
    if let Some(mut lease) = EnumerationLease::acquire() {
        lease.iteration.end();
    } else {
        // SAFETY: recursion cannot borrow an active traversal.
        unsafe { set_abi_errno(libc::EDEADLK) };
    }
}

unsafe fn prepare(
    output: *mut c_void,
    buffer: *mut c_char,
    result: *mut *mut c_void,
) -> Result<(), c_int> {
    if !tracked_object_fits(result) {
        return Err(libc::EINVAL);
    }
    // SAFETY: the complete result pointer slot was checked before clearing it.
    unsafe { result.write(std::ptr::null_mut()) };
    if !valid_outputs(output, buffer, std::ptr::null_mut()) {
        return Err(libc::EINVAL);
    }
    Ok(())
}

pub(crate) unsafe fn next_r(
    output: *mut c_void,
    buffer: *mut c_char,
    length: usize,
    result: *mut *mut c_void,
) -> c_int {
    // SAFETY: prepare validates all complete output objects before mutation.
    if let Err(error) = unsafe { prepare(output, buffer, result) } {
        unsafe { set_abi_errno(error) };
        return error;
    }
    let Some(mut lease) = EnumerationLease::acquire() else {
        // SAFETY: the caller's errno cell remains live during recursive calls.
        unsafe { set_abi_errno(libc::EDEADLK) };
        return libc::EDEADLK;
    };
    // SAFETY: no mutex or TLS reference spans callbacks; the caller buffer's
    // effective writable length, not an inflated size, reaches each provider.
    let status = unsafe {
        lease
            .iteration
            .next_r(output, buffer, tracked_output_capacity(buffer, length))
    };
    match status {
        SUCCESS => {
            // SAFETY: a successful provider initialized the complete record.
            unsafe { result.write(output) };
            0
        }
        TRYAGAIN => current_abi_errno(),
        _ => libc::ENOENT,
    }
}

pub(crate) unsafe fn by_name_r(
    name: *const c_char,
    output: *mut c_void,
    buffer: *mut c_char,
    length: usize,
    result: *mut *mut c_void,
) -> c_int {
    use frankenlibc_core::nss::{Action, Database, Status};
    let saved_errno = current_abi_errno();
    // SAFETY: clear and validate outputs before selecting any provider.
    if let Err(error) = unsafe { prepare(output, buffer, result) } {
        unsafe { set_abi_errno(error) };
        return error;
    }
    // Own a stable bounded name before a callback writes into caller storage.
    let Some(mut name) = (unsafe { read_c_string_bytes(name) }) else {
        unsafe { set_abi_errno(libc::EINVAL) };
        return libc::EINVAL;
    };
    name.push(0);
    let capacity = tracked_output_capacity(buffer, length);
    let sources = crate::nss_module::services(Database::Aliases);
    // SAFETY: internal policy I/O is separate from the provider's errno.
    unsafe { set_abi_errno(saved_errno) };
    let mut status = Status::Unavailable;
    for source in sources.iter() {
        // SAFETY: the key is terminated and all complete output objects stay
        // valid throughout this callback. No configuration lock is retained.
        let answer = unsafe {
            if source.name() == b"files" {
                Some(files_by_name_r(
                    name.as_ptr().cast(),
                    output,
                    buffer,
                    capacity,
                    crate::errno_abi::__errno_location(),
                ))
            } else {
                crate::nss_module::alias_by_name_r(
                    source.name(),
                    name.as_ptr().cast(),
                    output.cast(),
                    buffer,
                    capacity,
                )
            }
        };
        let Some(answer) = answer else {
            if source.action(Status::Unavailable) != Action::Continue {
                break;
            }
            continue;
        };
        status = Status::from_raw(answer);
        let action = if answer == 2 {
            source.return_action()
        } else {
            source.action(status)
        };
        if status == Status::Success && action == Action::Merge {
            // SAFETY: aliases have no composite record merge operation.
            unsafe { set_abi_errno(libc::EINVAL) };
            return libc::EINVAL;
        }
        if (status == Status::TryAgain && current_abi_errno() == libc::ERANGE)
            || action != Action::Continue
        {
            break;
        }
    }
    match status {
        Status::Success => {
            // SAFETY: only the final successful provider publishes a record.
            unsafe {
                result.write(output);
                set_abi_errno(0);
            }
            0
        }
        Status::NotFound => {
            // SAFETY: GNU keyed lookup clears errno on a definitive miss.
            unsafe { set_abi_errno(0) };
            0
        }
        Status::Unavailable if current_abi_errno() == libc::ERANGE => {
            // SAFETY: an unavailable provider cannot request buffer growth.
            unsafe { set_abi_errno(libc::EINVAL) };
            libc::EINVAL
        }
        Status::Unavailable | Status::TryAgain => current_abi_errno(),
    }
}

fn grow(buffer: &mut Vec<u8>, capacity: usize) -> Result<(), c_int> {
    if capacity > buffer.len() {
        buffer
            .try_reserve_exact(capacity - buffer.len())
            .map_err(|_| libc::ENOMEM)?;
        buffer.resize(capacity, 0);
    }
    Ok(())
}

pub(crate) unsafe fn next() -> *mut c_void {
    let Some(mut lease) = EnumerationLease::acquire() else {
        // SAFETY: recursive enumeration cannot reuse the active output buffer.
        unsafe { set_abi_errno(libc::EDEADLK) };
        return std::ptr::null_mut();
    };
    let mut capacity = lease.buffer.len().max(1024);
    let mut entry = AliasEnt::empty();
    loop {
        if let Err(error) = grow(&mut lease.buffer, capacity) {
            unsafe { set_abi_errno(error) };
            return std::ptr::null_mut();
        }
        // SAFETY: typed local output and leased buffer survive each callback.
        let status = unsafe {
            lease.iteration.next_r(
                (&raw mut entry).cast(),
                lease.buffer.as_mut_ptr().cast(),
                capacity,
            )
        };
        if status == SUCCESS {
            drop(lease);
            return with_output(|state| {
                state.entry = entry;
                (&raw mut state.entry).cast()
            });
        }
        if status != TRYAGAIN || current_abi_errno() != libc::ERANGE {
            return std::ptr::null_mut();
        }
        let Some(next) = capacity
            .checked_mul(2)
            .filter(|&size| size <= isize::MAX as usize)
        else {
            unsafe { set_abi_errno(libc::ENOMEM) };
            return std::ptr::null_mut();
        };
        capacity = next;
    }
}

pub(crate) unsafe fn by_name(name: *const c_char) -> *mut c_void {
    // Copy the key before borrowing or growing storage which might contain it.
    let Some(mut name) = (unsafe { read_c_string_bytes(name) }) else {
        unsafe { set_abi_errno(libc::EINVAL) };
        return std::ptr::null_mut();
    };
    name.push(0);
    let Some(mut lease) = LookupLease::acquire() else {
        unsafe { set_abi_errno(libc::EDEADLK) };
        return std::ptr::null_mut();
    };
    let mut capacity = lease.buffer.len().max(1024);
    let mut entry = AliasEnt::empty();
    loop {
        if let Err(error) = grow(&mut lease.buffer, capacity) {
            unsafe { set_abi_errno(error) };
            return std::ptr::null_mut();
        }
        let mut result = std::ptr::null_mut();
        // SAFETY: complete local header, leased buffer, and owned key are live.
        let rc = unsafe {
            by_name_r(
                name.as_ptr().cast(),
                (&raw mut entry).cast(),
                lease.buffer.as_mut_ptr().cast(),
                capacity,
                &mut result,
            )
        };
        if rc != libc::ERANGE {
            if result.is_null() {
                return std::ptr::null_mut();
            }
            drop(lease);
            return with_output(|state| {
                state.lookup = entry;
                (&raw mut state.lookup).cast()
            });
        }
        let Some(next) = capacity
            .checked_mul(2)
            .filter(|&size| size <= isize::MAX as usize)
        else {
            unsafe { set_abi_errno(libc::ENOMEM) };
            return std::ptr::null_mut();
        };
        capacity = next;
    }
}
