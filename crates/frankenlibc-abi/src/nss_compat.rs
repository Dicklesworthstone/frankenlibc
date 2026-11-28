//! Owned passwd/group/shadow compatibility provider.
//!
//! Local files supply ordered records and `+`/`-` directives. The first
//! configured *_compat service supplies remote records; it is not a second
//! ordinary NSS source chain. Foreign callbacks run outside every cursor,
//! configuration and module-table lock. The exported veneers and configured
//! `compat` service use the same hidden callbacks below.

use std::collections::VecDeque;
use std::ffi::{CStr, c_char, c_int, c_long, c_void};
use std::path::PathBuf;
use std::sync::{Condvar, Mutex};

use frankenlibc_core::nss::Database;
use frankenlibc_core::nss::compat::{
    self, GroupOverrides, PasswdOverrides, Record, Selection, Selector, ShadowOverrides,
};

use crate::nss_module;

const SUCCESS: c_int = 1;
const NOTFOUND: c_int = 0;
const UNAVAIL: c_int = -1;
const TRYAGAIN: c_int = -2;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Db {
    Passwd,
    Group,
    Shadow,
}

impl Db {
    fn index(self) -> usize {
        match self {
            Self::Passwd => 0,
            Self::Group => 1,
            Self::Shadow => 2,
        }
    }

    fn database(self) -> Database {
        match self {
            Self::Passwd => Database::PasswdCompat,
            Self::Group => Database::GroupCompat,
            Self::Shadow => Database::ShadowCompat,
        }
    }

    fn path(self) -> PathBuf {
        let (variable, default) = match self {
            Self::Passwd => ("FRANKENLIBC_PASSWD_PATH", "/etc/passwd"),
            Self::Group => ("FRANKENLIBC_GROUP_PATH", "/etc/group"),
            Self::Shadow => ("FRANKENLIBC_SHADOW_PATH", "/etc/shadow"),
        };
        crate::stdlib_abi::secure_var_os(variable)
            .filter(|path| !path.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(default))
    }

    fn functions(
        self,
    ) -> (
        &'static str,
        &'static str,
        &'static str,
        &'static str,
        &'static str,
    ) {
        match self {
            Self::Passwd => (
                "setpwent",
                "getpwent_r",
                "endpwent",
                "getpwnam_r",
                "getpwuid_r",
            ),
            Self::Group => (
                "setgrent",
                "getgrent_r",
                "endgrent",
                "getgrnam_r",
                "getgrgid_r",
            ),
            Self::Shadow => ("setspent", "getspent_r", "endspent", "getspnam_r", ""),
        }
    }

    fn parse(self, line: &[u8]) -> Option<Rule> {
        macro_rules! convert {
            ($record:expr, $entry:ident, $overrides:ident) => {
                match $record? {
                    Record::Local(entry) => Some(Rule::Local(Entry::$entry(entry))),
                    Record::Include {
                        selector,
                        overrides,
                    } => Some(Rule::Include {
                        selector,
                        overrides: Overrides::$overrides(overrides),
                    }),
                    Record::Exclude(selector) => Some(Rule::Exclude(selector)),
                }
            };
        }
        match self {
            Self::Passwd => convert!(compat::parse_passwd_record(line), Passwd, Passwd),
            Self::Group => convert!(compat::parse_group_record(line), Group, Group),
            Self::Shadow => convert!(compat::parse_shadow_record(line), Shadow, Shadow),
        }
    }

    fn parse_files(self, line: &[u8]) -> Option<Entry> {
        match self {
            Self::Passwd => frankenlibc_core::pwd::parse_passwd_line(line).map(Entry::Passwd),
            Self::Group => frankenlibc_core::grp::parse_group_line(line).map(Entry::Group),
            Self::Shadow => {
                frankenlibc_core::pwd::shadow::parse_shadow_line(line).map(Entry::Shadow)
            }
        }
    }
}

enum Entry {
    Passwd(frankenlibc_core::pwd::Passwd),
    Group(frankenlibc_core::grp::Group),
    Shadow(frankenlibc_core::pwd::shadow::ShadowEntry),
}

impl Entry {
    fn name(&self) -> &[u8] {
        match self {
            Self::Passwd(entry) => &entry.pw_name,
            Self::Group(entry) => &entry.gr_name,
            Self::Shadow(entry) => &entry.name,
        }
    }

    fn matches(&self, key: Key<'_>) -> bool {
        match key {
            Key::Name(name) => self.name() == name,
            Key::Id(id) => match self {
                Self::Passwd(entry) => entry.pw_uid == id,
                Self::Group(entry) => entry.gr_gid == id,
                Self::Shadow(_) => false,
            },
        }
    }

    unsafe fn pack(&self, output: *mut c_void, call: Call) -> c_int {
        // SAFETY: the provider validated the matching complete C result and
        // caller buffer. Existing writers retain alignment and capacity rules.
        unsafe {
            match self {
                Self::Passwd(entry) => {
                    let mut result = std::ptr::null_mut();
                    crate::pwd_abi::fill_passwd_r(
                        entry,
                        output.cast(),
                        call.buffer,
                        call.capacity,
                        &mut result,
                    )
                }
                Self::Group(entry) => {
                    let mut result = std::ptr::null_mut();
                    crate::grp_abi::fill_group_r(
                        entry,
                        output.cast(),
                        call.buffer,
                        call.capacity,
                        &mut result,
                    )
                }
                Self::Shadow(entry) => crate::pwd_abi::fill_shadow_parsed_caller(
                    entry,
                    output.cast(),
                    call.buffer,
                    call.capacity,
                ),
            }
        }
    }
}

enum Overrides {
    Passwd(PasswdOverrides),
    Group(GroupOverrides),
    Shadow(ShadowOverrides),
}

impl Overrides {
    fn reserved(&self) -> Option<usize> {
        let fields: &[Option<Vec<u8>>] = match self {
            Self::Passwd(value) => {
                return [&value.passwd, &value.gecos, &value.dir, &value.shell]
                    .into_iter()
                    .try_fold(0usize, |size, field| {
                        size.checked_add(
                            field
                                .as_ref()
                                .map_or(0, |bytes| bytes.len().saturating_add(1)),
                        )
                    });
            }
            Self::Group(_) => &[],
            Self::Shadow(value) => std::slice::from_ref(&value.passwd),
        };
        fields.iter().try_fold(0usize, |size, field| {
            size.checked_add(
                field
                    .as_ref()
                    .map_or(0, |bytes| bytes.len().saturating_add(1)),
            )
        })
    }

    fn apply(&self, entry: &mut Entry) {
        match (self, entry) {
            (Self::Passwd(overrides), Entry::Passwd(entry)) => overrides.apply(entry),
            (Self::Group(overrides), Entry::Group(entry)) => overrides.apply(entry),
            (Self::Shadow(overrides), Entry::Shadow(entry)) => overrides.apply(entry),
            _ => unreachable!("compat database is fixed for the traversal"),
        }
    }
}

enum Rule {
    Local(Entry),
    Include {
        selector: Selector,
        overrides: Overrides,
    },
    Exclude(Selector),
}

#[derive(Clone, Copy)]
enum Key<'a> {
    Name(&'a [u8]),
    Id(u32),
}

#[derive(Clone, Copy)]
struct Call {
    buffer: *mut c_char,
    capacity: usize,
    error: *mut c_int,
}

impl Call {
    fn fail(self, status: c_int, error: c_int) -> Reply {
        // SAFETY: every public entry validates this writable scalar first.
        unsafe { *self.error = error };
        Reply::status(status)
    }

    fn reserve(self, overrides: &Overrides) -> Result<Self, Reply> {
        let Some(capacity) = overrides
            .reserved()
            .and_then(|size| self.capacity.checked_sub(size))
        else {
            return Err(self.fail(TRYAGAIN, libc::ERANGE));
        };
        Ok(Self { capacity, ..self })
    }
}

struct Reply {
    status: c_int,
    entry: Option<Entry>,
}

impl Reply {
    fn status(status: c_int) -> Self {
        Self {
            status,
            entry: None,
        }
    }
    fn found(entry: Entry) -> Self {
        Self {
            status: SUCCESS,
            entry: Some(entry),
        }
    }
}

struct FileImage {
    bytes: Vec<u8>,
    position: usize,
}

impl FileImage {
    fn open(database: Db) -> Result<Self, c_int> {
        std::fs::read(database.path())
            .map(|bytes| Self { bytes, position: 0 })
            .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))
    }

    fn line(&self, capacity: usize) -> Result<Option<&[u8]>, c_int> {
        if capacity < 3 {
            return Err(libc::ERANGE);
        }
        let tail = &self.bytes[self.position..];
        if tail.is_empty() {
            return Ok(None);
        }
        let length = tail
            .iter()
            .position(|&byte| byte == b'\n')
            .map_or(tail.len(), |index| index + 1);
        if length.saturating_add(2) > capacity {
            return Err(libc::ERANGE);
        }
        Ok(Some(&tail[..length]))
    }

    fn advance(&mut self, length: usize) {
        self.position += length;
    }
}

/// A backend identity is captured once per traversal. GNU compat selects
/// the first service; its later status-action clauses do not select a second.
struct Backend {
    database: Db,
    service: Option<Vec<u8>>,
    files: Option<FileImage>,
    started: bool,
    stayopen: c_int,
}

impl Backend {
    fn new(database: Db, stayopen: c_int) -> Self {
        Self {
            database,
            service: nss_module::services(database.database())
                .first()
                .map(|service| service.name().to_vec()),
            files: None,
            started: false,
            stayopen,
        }
    }

    fn by_key(&mut self, key: Key<'_>, call: Call) -> Reply {
        let Some(service) = self.service.as_deref() else {
            return Reply::status(UNAVAIL);
        };
        if service == b"compat" {
            return call.fail(UNAVAIL, libc::EDEADLK);
        }
        if service == b"files" {
            let mut file = match FileImage::open(self.database) {
                Ok(file) => file,
                Err(error) => return call.fail(UNAVAIL, error),
            };
            loop {
                let line = match file.line(call.capacity) {
                    Ok(Some(line)) => line,
                    Ok(None) => return Reply::status(NOTFOUND),
                    Err(error) => return call.fail(TRYAGAIN, error),
                };
                let length = line.len();
                let entry = self.database.parse_files(line);
                file.advance(length);
                if let Some(entry) = entry
                    && entry.matches(key)
                {
                    return Reply::found(entry);
                }
            }
        }
        let functions = self.database.functions();
        let operation = match key {
            Key::Name(_) => functions.3,
            Key::Id(_) => functions.4,
        };
        let Some(address) = nss_module::module_function(service, operation) else {
            return Reply::status(UNAVAIL);
        };
        // SAFETY: the database and key select the exact documented NSS ABI.
        let mut reply = unsafe { invoke(self.database, address, Some(key), call) };
        if self.database == Db::Passwd && matches!(key, Key::Id(_)) && reply.status != SUCCESS {
            // GNU's uid compat path reports every invoked backend miss or
            // failure as NOTFOUND, retaining errnop (even backend ERANGE).
            // A missing callback or our file/buffer preflight is distinct
            // and returns above with its original status.
            reply.status = NOTFOUND;
        }
        reply
    }

    fn next(&mut self, call: Call) -> Reply {
        let Some(service) = self.service.as_deref() else {
            return Reply::status(UNAVAIL);
        };
        if service == b"compat" {
            return call.fail(UNAVAIL, libc::EDEADLK);
        }
        let functions = self.database.functions();
        if !self.started {
            self.started = true;
            if service == b"files" {
                self.files = match FileImage::open(self.database) {
                    Ok(file) => Some(file),
                    Err(error) => return call.fail(UNAVAIL, error),
                };
            } else if let Some(address) = nss_module::module_function(service, functions.0) {
                // SAFETY: all three account set callbacks take one stayopen int.
                let set: unsafe extern "C" fn(c_int) -> c_int =
                    unsafe { std::mem::transmute(address) };
                let status = unsafe { set(self.stayopen) };
                if status != SUCCESS {
                    return Reply::status(status);
                }
            }
        }
        if service == b"files" {
            let Some(file) = &mut self.files else {
                return Reply::status(UNAVAIL);
            };
            loop {
                let line = match file.line(call.capacity) {
                    Ok(Some(line)) => line,
                    Ok(None) => return Reply::status(NOTFOUND),
                    Err(error) => return call.fail(TRYAGAIN, error),
                };
                let length = line.len();
                let entry = self.database.parse_files(line);
                file.advance(length);
                if let Some(entry) = entry {
                    return Reply::found(entry);
                }
            }
        }
        let Some(address) = nss_module::module_function(service, functions.1) else {
            return Reply::status(UNAVAIL);
        };
        // SAFETY: this database selects the matching getent output layout.
        unsafe { invoke(self.database, address, None, call) }
    }

    fn end(&mut self) {
        if self.started {
            self.started = false;
            if let Some(service) = self.service.as_deref()
                && service != b"files"
                && service != b"compat"
                && let Some(address) =
                    nss_module::module_function(service, self.database.functions().2)
            {
                // SAFETY: all account end callbacks take no arguments.
                let end: unsafe extern "C" fn() -> c_int = unsafe { std::mem::transmute(address) };
                unsafe { end() };
            }
        }
        self.files = None;
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        // Cleanup must not overwrite a callback's final error result.
        let saved = unsafe { *crate::errno_abi::__errno_location() };
        self.end();
        unsafe { crate::errno_abi::set_abi_errno(saved) };
    }
}

unsafe fn invoke(database: Db, address: usize, key: Option<Key<'_>>, call: Call) -> Reply {
    macro_rules! typed {
        ($layout:ty, $convert:ident, $entry:ident) => {{
            let mut output = std::mem::MaybeUninit::<$layout>::zeroed();
            let status = match key {
                Some(Key::Name(name)) => {
                    let mut terminated = name.to_vec();
                    terminated.push(0);
                    let function: unsafe extern "C" fn(
                        *const c_char,
                        *mut $layout,
                        *mut c_char,
                        usize,
                        *mut c_int,
                    ) -> c_int = unsafe { std::mem::transmute(address) };
                    unsafe {
                        function(
                            terminated.as_ptr().cast(),
                            output.as_mut_ptr(),
                            call.buffer,
                            call.capacity,
                            call.error,
                        )
                    }
                }
                Some(Key::Id(id)) => {
                    let function: unsafe extern "C" fn(
                        u32,
                        *mut $layout,
                        *mut c_char,
                        usize,
                        *mut c_int,
                    ) -> c_int = unsafe { std::mem::transmute(address) };
                    unsafe {
                        function(
                            id,
                            output.as_mut_ptr(),
                            call.buffer,
                            call.capacity,
                            call.error,
                        )
                    }
                }
                None => {
                    let function: unsafe extern "C" fn(
                        *mut $layout,
                        *mut c_char,
                        usize,
                        *mut c_int,
                    ) -> c_int = unsafe { std::mem::transmute(address) };
                    unsafe { function(output.as_mut_ptr(), call.buffer, call.capacity, call.error) }
                }
            };
            if status == SUCCESS {
                // SAFETY: successful NSS results remain live in the exact
                // caller buffer until this immediate owned copy completes.
                Reply::found(Entry::$entry(unsafe {
                    nss_module::$convert(&output.assume_init())
                }))
            } else {
                Reply::status(status)
            }
        }};
    }
    match database {
        Db::Passwd => typed!(libc::passwd, passwd_from_c, Passwd),
        Db::Group => typed!(libc::group, group_from_c, Group),
        Db::Shadow => typed!(libc::spwd, shadow_from_c, Shadow),
    }
}

fn domain() -> Option<Vec<u8>> {
    let mut uts = std::mem::MaybeUninit::<libc::utsname>::zeroed();
    // SAFETY: the kernel writes one complete utsname object.
    unsafe { frankenlibc_core::syscall::sys_uname(uts.as_mut_ptr().cast()) }.ok()?;
    let uts = unsafe { uts.assume_init() };
    let bytes = unsafe { CStr::from_ptr(uts.domainname.as_ptr()) }.to_bytes();
    (!bytes.is_empty() && bytes != b"(none)").then(|| bytes.to_vec())
}

fn netgroup_names(group: &[u8]) -> VecDeque<Vec<u8>> {
    let Ok(Some(mut session)) = nss_module::NetgroupSession::open(group, false) else {
        return VecDeque::new();
    };
    let domain = domain();
    let mut names = VecDeque::new();
    while let Ok(Some(triple)) = session.next() {
        if let Some(user) = triple.user
            && !user.is_empty()
            && triple
                .domain
                .as_ref()
                .is_none_or(|value| domain.as_ref() == Some(value))
        {
            names.push_back(user);
        }
    }
    names
}

fn netgroup_contains(group: &[u8], name: &[u8]) -> bool {
    let Ok(Some(mut session)) = nss_module::NetgroupSession::open(group, true) else {
        return false;
    };
    while let Ok(Some(triple)) = session.next() {
        // GNU keyed compat checks constrain only the user. NULL user is a
        // wildcard; hostname and domain do not restrict the keyed lookup.
        if triple
            .user
            .as_ref()
            .is_none_or(|user| user.as_slice() == name)
        {
            return true;
        }
    }
    false
}

enum Import {
    All,
    Names(VecDeque<Vec<u8>>),
}

struct Remote {
    import: Import,
    overrides: Overrides,
}

struct Pending {
    entry: Entry,
    remote: bool,
}

struct Cursor {
    database: Db,
    file: FileImage,
    backend: Backend,
    selection: Selection,
    remote: Option<Remote>,
    pending: Option<Pending>,
    finished: bool,
}

impl Cursor {
    fn open(database: Db, stayopen: c_int) -> Result<Self, c_int> {
        Ok(Self {
            database,
            file: FileImage::open(database)?,
            backend: Backend::new(database, stayopen),
            selection: Selection::default(),
            remote: None,
            pending: None,
            finished: false,
        })
    }

    fn next(&mut self, call: Call) -> Reply {
        if self.pending.is_some() {
            return Reply::status(SUCCESS);
        }
        loop {
            if let Some(remote) = &mut self.remote {
                let nested = match call.reserve(&remote.overrides) {
                    Ok(call) => call,
                    Err(reply) => return reply,
                };
                let (reply, all) = match &mut remote.import {
                    Import::All => (self.backend.next(nested), true),
                    Import::Names(names) => {
                        let Some(name) = names.front() else {
                            self.remote = None;
                            continue;
                        };
                        if !self.selection.permits_remote(name) {
                            names.pop_front();
                            continue;
                        }
                        let reply = self.backend.by_key(Key::Name(name), nested);
                        if reply.status != TRYAGAIN {
                            names.pop_front();
                        }
                        (reply, false)
                    }
                };
                if let Some(mut entry) = reply.entry {
                    if !self.selection.permits_remote(entry.name()) {
                        continue;
                    }
                    remote.overrides.apply(&mut entry);
                    self.pending = Some(Pending {
                        entry,
                        remote: true,
                    });
                    return Reply::status(SUCCESS);
                }
                if reply.status == TRYAGAIN {
                    return reply;
                }
                if all {
                    // A bare '+' switches permanently from local rows to the
                    // remote database; a local tail is deliberately hidden.
                    // Keep calling that backend after EOF or unavailability:
                    // it owns the repeated status and errnop, including a
                    // later recovery from a temporary failure.
                    return reply;
                }
                continue;
            }
            if self.finished {
                return Reply::status(NOTFOUND);
            }
            let line = match self.file.line(call.capacity) {
                Ok(Some(line)) => line,
                Ok(None) => {
                    self.finished = true;
                    return Reply::status(NOTFOUND);
                }
                Err(error) => return call.fail(TRYAGAIN, error),
            };
            let length = line.len();
            let rule = self.database.parse(line);
            self.file.advance(length);
            match rule {
                None => {}
                Some(Rule::Local(entry)) => {
                    self.pending = Some(Pending {
                        entry,
                        remote: false,
                    });
                    return Reply::status(SUCCESS);
                }
                Some(Rule::Exclude(Selector::Name(name))) => self.selection.exclude(&name),
                Some(Rule::Exclude(Selector::Netgroup(group))) => {
                    for name in netgroup_names(&group) {
                        self.selection.exclude(&name);
                    }
                }
                Some(Rule::Exclude(Selector::All)) => {}
                Some(Rule::Include {
                    selector,
                    overrides,
                }) => {
                    let import = match selector {
                        Selector::All => Import::All,
                        Selector::Name(name) => Import::Names(VecDeque::from([name])),
                        Selector::Netgroup(group) => Import::Names(netgroup_names(&group)),
                    };
                    self.remote = Some(Remote { import, overrides });
                }
            }
        }
    }

    fn committed(&mut self) {
        if let Some(pending) = self.pending.take()
            && pending.remote
        {
            self.selection.record_remote(pending.entry.name());
        }
    }
}

fn lookup(database: Db, key: Key<'_>, call: Call) -> Reply {
    let mut file = match FileImage::open(database) {
        Ok(file) => file,
        Err(error) => return call.fail(UNAVAIL, error),
    };
    let mut backend = Backend::new(database, 0);
    let mut excluded = Selection::default();
    let mut excluded_groups = Vec::new();
    loop {
        let line = match file.line(call.capacity) {
            Ok(Some(line)) => line,
            Ok(None) => return Reply::status(NOTFOUND),
            Err(error) => return call.fail(TRYAGAIN, error),
        };
        let length = line.len();
        let rule = database.parse(line);
        file.advance(length);
        match rule {
            None => {}
            Some(Rule::Local(entry)) if entry.matches(key) => return Reply::found(entry),
            Some(Rule::Local(_)) => {}
            Some(Rule::Exclude(Selector::Name(name))) => {
                if matches!(key, Key::Name(wanted) if wanted == name) {
                    return Reply::status(NOTFOUND);
                }
                // GNU's numeric lookups ignore named exclusions. Netgroup
                // exclusions below still apply to a remotely resolved uid.
                if matches!(key, Key::Name(_)) {
                    excluded.exclude(&name);
                }
            }
            Some(Rule::Exclude(Selector::Netgroup(group))) => {
                if let Key::Name(name) = key
                    && netgroup_contains(&group, name)
                {
                    return Reply::status(NOTFOUND);
                }
                excluded_groups.push(group);
            }
            Some(Rule::Exclude(Selector::All)) => {}
            Some(Rule::Include {
                selector,
                overrides,
            }) => {
                let selected_key = match &selector {
                    Selector::Name(name) => match key {
                        Key::Name(wanted) if wanted != name => continue,
                        Key::Id(_) if database == Db::Passwd => key,
                        _ => Key::Name(name),
                    },
                    Selector::Netgroup(group) => {
                        if let Key::Name(name) = key
                            && !netgroup_contains(group, name)
                        {
                            continue;
                        }
                        key
                    }
                    Selector::All => key,
                };
                let nested = match call.reserve(&overrides) {
                    Ok(call) => call,
                    Err(reply) => return reply,
                };
                let reply = backend.by_key(selected_key, nested);
                let Some(mut entry) = reply.entry else {
                    if matches!(key, Key::Id(_))
                        && !matches!(selector, Selector::All)
                        && reply.status == NOTFOUND
                    {
                        continue;
                    }
                    // A matching '+' directive owns a keyed answer, even a
                    // miss. A named directive cannot own a numeric answer
                    // until its remote name and id have both matched.
                    return reply;
                };
                if !entry.matches(key) {
                    continue;
                }
                if let Selector::Name(name) = &selector
                    && entry.name() != name
                {
                    continue;
                }
                if !excluded.permits_remote(entry.name())
                    || excluded_groups
                        .iter()
                        .any(|group| netgroup_contains(group, entry.name()))
                {
                    return Reply::status(NOTFOUND);
                }
                if let Selector::Netgroup(group) = &selector
                    && !netgroup_contains(group, entry.name())
                {
                    continue;
                }
                overrides.apply(&mut entry);
                return Reply::found(entry);
            }
        }
    }
}

// Provider callbacks may recursively query the same public database. This
// guard covers keyed and enumeration calls without retaining a mutex during
// callbacks and without relying on compiler TLS shared by native clones.
static ACTIVE: Mutex<Vec<(i32, Db)>> = Mutex::new(Vec::new());
struct Active {
    owner: i32,
    database: Db,
    nested: bool,
}
impl Active {
    fn enter(database: Db) -> Option<Self> {
        let owner = frankenlibc_core::syscall::sys_gettid();
        let mut active = ACTIVE.lock().unwrap_or_else(|error| error.into_inner());
        if active.contains(&(owner, database)) {
            return None;
        }
        let nested = active.iter().any(|&(tid, _)| tid == owner);
        active.push((owner, database));
        Some(Self {
            owner,
            database,
            nested,
        })
    }
}
impl Drop for Active {
    fn drop(&mut self) {
        let mut active = ACTIVE.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(index) = active
            .iter()
            .position(|&entry| entry == (self.owner, self.database))
        {
            active.swap_remove(index);
        }
    }
}

struct Slot {
    cursor: Option<Cursor>,
    busy: bool,
}
static CURSORS: Mutex<[Slot; 3]> = Mutex::new(
    [const {
        Slot {
            cursor: None,
            busy: false,
        }
    }; 3],
);
static CURSOR_READY: Condvar = Condvar::new();
struct Lease {
    database: Db,
    cursor: Option<Cursor>,
}
impl Lease {
    fn acquire(database: Db, may_wait: bool) -> Option<Self> {
        let mut cursors = CURSORS.lock().unwrap_or_else(|error| error.into_inner());
        while cursors[database.index()].busy {
            // Recursive callbacks may use an idle other database, but must
            // never wait while another thread could be waiting for this
            // callback's outer lease. ACTIVE was released before this lock.
            if !may_wait {
                return None;
            }
            cursors = CURSOR_READY
                .wait(cursors)
                .unwrap_or_else(|error| error.into_inner());
        }
        let slot = &mut cursors[database.index()];
        slot.busy = true;
        Some(Self {
            database,
            cursor: slot.cursor.take(),
        })
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        let mut cursors = CURSORS.lock().unwrap_or_else(|error| error.into_inner());
        let slot = &mut cursors[self.database.index()];
        slot.cursor = self.cursor.take();
        slot.busy = false;
        CURSOR_READY.notify_all();
    }
}

fn set(database: Db, stayopen: c_int) -> c_int {
    let Some(active) = Active::enter(database) else {
        unsafe { crate::errno_abi::set_abi_errno(libc::EDEADLK) };
        return UNAVAIL;
    };
    let Some(mut lease) = Lease::acquire(database, !active.nested) else {
        unsafe { crate::errno_abi::set_abi_errno(libc::EDEADLK) };
        return UNAVAIL;
    };
    // Drop the old backend outside the cursor lock before opening the new one.
    lease.cursor = None;
    match Cursor::open(database, stayopen) {
        Ok(cursor) => {
            lease.cursor = Some(cursor);
            SUCCESS
        }
        Err(error) => {
            unsafe { crate::errno_abi::set_abi_errno(error) };
            UNAVAIL
        }
    }
}

fn end(database: Db) -> c_int {
    let Some(active) = Active::enter(database) else {
        unsafe { crate::errno_abi::set_abi_errno(libc::EDEADLK) };
        return UNAVAIL;
    };
    let Some(mut lease) = Lease::acquire(database, !active.nested) else {
        unsafe { crate::errno_abi::set_abi_errno(libc::EDEADLK) };
        return UNAVAIL;
    };
    lease.cursor = None;
    SUCCESS
}

unsafe fn validated_call(
    output: *mut c_void,
    buffer: *mut c_char,
    capacity: usize,
    error: *mut c_int,
) -> Option<Call> {
    if output.is_null() || buffer.is_null() || error.is_null() {
        if !error.is_null() {
            unsafe { *error = libc::EINVAL };
        }
        return None;
    }
    let capacity = crate::malloc_abi::known_remaining(buffer as usize)
        .map_or(capacity, |remaining| capacity.min(remaining));
    Some(Call {
        buffer,
        capacity,
        error,
    })
}

unsafe fn get(database: Db, key: Option<Key<'_>>, output: *mut c_void, call: Call) -> c_int {
    let Some(active) = Active::enter(database) else {
        return call.fail(UNAVAIL, libc::EDEADLK).status;
    };
    if let Some(key) = key {
        let reply = lookup(database, key, call);
        if let Some(entry) = reply.entry {
            let error = unsafe { entry.pack(output, call) };
            return if error == 0 {
                SUCCESS
            } else {
                call.fail(TRYAGAIN, error).status
            };
        }
        return reply.status;
    }
    let Some(mut lease) = Lease::acquire(database, !active.nested) else {
        return call.fail(UNAVAIL, libc::EDEADLK).status;
    };
    if lease.cursor.is_none() {
        match Cursor::open(database, 0) {
            Ok(cursor) => lease.cursor = Some(cursor),
            Err(error) => return call.fail(UNAVAIL, error).status,
        }
    }
    let cursor = lease.cursor.as_mut().expect("cursor was opened");
    let reply = cursor.next(call);
    if let Some(pending) = &cursor.pending {
        let error = unsafe { pending.entry.pack(output, call) };
        if error != 0 {
            return call.fail(TRYAGAIN, error).status;
        }
        cursor.committed();
        SUCCESS
    } else {
        reply.status
    }
}

macro_rules! callbacks {
    ($set:ident, $end:ident, $next:ident, $name:ident, $database:ident, $layout:ty) => {
        unsafe extern "C" fn $set(stayopen: c_int) -> c_int {
            set(Db::$database, stayopen)
        }
        unsafe extern "C" fn $end() -> c_int {
            end(Db::$database)
        }
        unsafe extern "C" fn $next(
            output: *mut $layout,
            buffer: *mut c_char,
            capacity: usize,
            error: *mut c_int,
        ) -> c_int {
            let Some(call) = (unsafe { validated_call(output.cast(), buffer, capacity, error) })
            else {
                return UNAVAIL;
            };
            unsafe { get(Db::$database, None, output.cast(), call) }
        }
        unsafe extern "C" fn $name(
            name: *const c_char,
            output: *mut $layout,
            buffer: *mut c_char,
            capacity: usize,
            error: *mut c_int,
        ) -> c_int {
            let Some(call) = (unsafe { validated_call(output.cast(), buffer, capacity, error) })
            else {
                return UNAVAIL;
            };
            if name.is_null() {
                return call.fail(UNAVAIL, libc::EINVAL).status;
            }
            // SAFETY: the NSS by-name ABI supplies a terminated input string.
            let key = unsafe { CStr::from_ptr(name) }.to_bytes();
            unsafe { get(Db::$database, Some(Key::Name(key)), output.cast(), call) }
        }
    };
}
callbacks!(
    setpwent,
    endpwent,
    getpwent_r,
    getpwnam_r,
    Passwd,
    libc::passwd
);
callbacks!(
    setgrent,
    endgrent,
    getgrent_r,
    getgrnam_r,
    Group,
    libc::group
);
callbacks!(
    setspent,
    endspent,
    getspent_r,
    getspnam_r,
    Shadow,
    libc::spwd
);

unsafe extern "C" fn getpwuid_r(
    id: libc::uid_t,
    output: *mut libc::passwd,
    buffer: *mut c_char,
    capacity: usize,
    error: *mut c_int,
) -> c_int {
    let Some(call) = (unsafe { validated_call(output.cast(), buffer, capacity, error) }) else {
        return UNAVAIL;
    };
    unsafe { get(Db::Passwd, Some(Key::Id(id)), output.cast(), call) }
}
unsafe extern "C" fn getgrgid_r(
    id: libc::gid_t,
    output: *mut libc::group,
    buffer: *mut c_char,
    capacity: usize,
    error: *mut c_int,
) -> c_int {
    let Some(call) = (unsafe { validated_call(output.cast(), buffer, capacity, error) }) else {
        return UNAVAIL;
    };
    unsafe { get(Db::Group, Some(Key::Id(id)), output.cast(), call) }
}

/// Supplementary-group traversal owns its scratch and may grow it: unlike a
/// caller-buffer `_r` API, initgroups has no externally fixed scratch budget.
fn group_reply(
    backend: &mut Backend,
    key: Option<Key<'_>>,
    scratch: &mut Vec<u8>,
    error: *mut c_int,
) -> Reply {
    loop {
        let call = Call {
            buffer: scratch.as_mut_ptr().cast(),
            capacity: scratch.len(),
            error,
        };
        let reply = match key {
            Some(key) => backend.by_key(key, call),
            None => backend.next(call),
        };
        if reply.status == TRYAGAIN && unsafe { *error } == libc::ERANGE && scratch.len() < 1 << 24
        {
            scratch.resize(scratch.len() * 2, 0);
            continue;
        }
        return reply;
    }
}

unsafe extern "C" fn initgroups_dyn(
    user: *const c_char,
    base: libc::gid_t,
    start: *mut c_long,
    size: *mut c_long,
    groups: *mut *mut libc::gid_t,
    limit: c_long,
    error: *mut c_int,
) -> c_int {
    if error.is_null() {
        return UNAVAIL;
    }
    if user.is_null() {
        unsafe { *error = libc::EINVAL };
        return UNAVAIL;
    }
    // Validate and preserve the existing prefix through the same array writer
    // as the native files provider, before reading or calling a remote service.
    if let Err(value) =
        unsafe { crate::grp_abi::append_initgroups_dyn(&[], start, size, groups, limit) }
    {
        unsafe { *error = value };
        return UNAVAIL;
    }
    let Some(_active) = Active::enter(Db::Group) else {
        unsafe { *error = libc::EDEADLK };
        return UNAVAIL;
    };
    let user = unsafe { CStr::from_ptr(user) }.to_bytes();
    // This traversal owns its file position independently of getgrent. Prefer
    // the backend's dedicated dynamic callback: it can provide memberships
    // even when the service does not support group enumeration at all.
    let mut file = match FileImage::open(Db::Group) {
        Ok(file) => file,
        Err(value) => {
            unsafe { *error = value };
            return UNAVAIL;
        }
    };
    let mut backend = Backend::new(Db::Group, 0);
    let mut selection = Selection::default();
    let mut filtered = false;
    let mut scratch = vec![0u8; 1024];
    let append = |gid| {
        // SAFETY: the array was validated above; each successful append
        // immediately publishes any resize and the preserved prefix.
        unsafe { crate::grp_abi::append_initgroups_dyn(&[gid], start, size, groups, limit) }
    };
    loop {
        let line = match file.line(scratch.len()) {
            Ok(Some(line)) => line,
            Ok(None) => return SUCCESS,
            Err(libc::ERANGE) if scratch.len() < 1 << 24 => {
                scratch.resize(scratch.len() * 2, 0);
                continue;
            }
            Err(value) => {
                unsafe { *error = value };
                return TRYAGAIN;
            }
        };
        let length = line.len();
        let rule = Db::Group.parse(line);
        file.advance(length);
        let entry = match rule {
            Some(Rule::Local(Entry::Group(entry))) => Some(entry),
            Some(Rule::Exclude(Selector::Name(name))) => {
                filtered = true;
                selection.exclude(&name);
                None
            }
            Some(Rule::Include {
                selector: Selector::Name(name),
                ..
            }) => {
                filtered = true;
                if !selection.permits_remote(&name) {
                    continue;
                }
                let reply = group_reply(&mut backend, Some(Key::Name(&name)), &mut scratch, error);
                if let Some(Entry::Group(entry)) = reply.entry {
                    selection.record_remote(&entry.gr_name);
                    Some(entry)
                } else {
                    None
                }
            }
            Some(Rule::Include {
                selector: Selector::All,
                ..
            }) => {
                if backend.service.as_deref() == Some(b"compat") {
                    unsafe { *error = libc::EDEADLK };
                    return UNAVAIL;
                }
                let dynamic = backend
                    .service
                    .as_deref()
                    .filter(|service| *service != b"files")
                    .and_then(|service| nss_module::module_function(service, "initgroups_dyn"));
                if let Some(address) = dynamic {
                    // SAFETY: validation above established a readable prefix.
                    // A private copy prevents a foreign realloc from crossing
                    // the allocation domain of the caller's original array.
                    let current = if unsafe { *start } == 0 {
                        Vec::new()
                    } else {
                        unsafe { std::slice::from_raw_parts(*groups, *start as usize) }.to_vec()
                    };
                    let (status, gids) = nss_module::initgroups_dyn_with_error(
                        address,
                        user,
                        base,
                        &current,
                        if filtered { -1 } else { limit },
                        unsafe { &mut *error },
                    );
                    for gid in gids {
                        if gid == base {
                            continue;
                        }
                        if filtered {
                            let reply =
                                group_reply(&mut backend, Some(Key::Id(gid)), &mut scratch, error);
                            let Some(Entry::Group(entry)) = reply.entry else {
                                continue;
                            };
                            if !selection.permits_remote(&entry.gr_name) {
                                continue;
                            }
                        }
                        if let Err(value) = append(gid) {
                            unsafe { *error = value };
                            return TRYAGAIN;
                        }
                    }
                    if status == frankenlibc_core::nss::Status::Success {
                        return SUCCESS;
                    }
                    // A backend can lack a dynamic answer for this user yet
                    // still provide groups through getgrent. Its final error
                    // remains visible even though local groups make this
                    // complete compat operation successful.
                }
                loop {
                    let reply = group_reply(&mut backend, None, &mut scratch, error);
                    let Some(Entry::Group(entry)) = reply.entry else {
                        return SUCCESS;
                    };
                    if !selection.permits_remote(&entry.gr_name) {
                        continue;
                    }
                    selection.record_remote(&entry.gr_name);
                    if entry.gr_gid != base
                        && entry.gr_mem.iter().any(|member| member.as_slice() == user)
                        && let Err(value) = append(entry.gr_gid)
                    {
                        unsafe { *error = value };
                        return TRYAGAIN;
                    }
                }
            }
            _ => None,
        };
        if let Some(entry) = entry
            && entry.gr_gid != base
            && entry.gr_mem.iter().any(|member| member.as_slice() == user)
            && let Err(value) = append(entry.gr_gid)
        {
            unsafe { *error = value };
            return TRYAGAIN;
        }
    }
}

/// No exported function-item address enters this table: ELF preemption of a
/// public _nss_compat_* veneer cannot redirect the owned provider to GNU.
pub(crate) fn function(name: &'static str) -> Option<usize> {
    let function = match name {
        "setpwent" => setpwent as *const (),
        "endpwent" => endpwent as *const (),
        "getpwent_r" => getpwent_r as *const (),
        "getpwnam_r" => getpwnam_r as *const (),
        "getpwuid_r" => getpwuid_r as *const (),
        "setgrent" => setgrent as *const (),
        "endgrent" => endgrent as *const (),
        "getgrent_r" => getgrent_r as *const (),
        "getgrnam_r" => getgrnam_r as *const (),
        "getgrgid_r" => getgrgid_r as *const (),
        "setspent" => setspent as *const (),
        "endspent" => endspent as *const (),
        "getspent_r" => getspent_r as *const (),
        "getspnam_r" => getspnam_r as *const (),
        "initgroups_dyn" => initgroups_dyn as *const (),
        _ => return None,
    };
    Some(function as usize)
}
