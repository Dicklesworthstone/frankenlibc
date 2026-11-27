//! Reentrant services/protocols lookups must admit each preceding physical
//! record before a key can match. Cache the largest requirements through each
//! row so repeated calls can preserve that scan order without rereading it.
use std::collections::BTreeMap;
use std::ffi::{c_char, c_int, c_void};
use std::ops::Range;

use frankenlibc_core::nss::Answer;
use frankenlibc_core::resolv::{NssNetdbKind, NssNetdbValue, parse_nss_netdb_line};

use crate::nss_module::{ProtocolKey, ServiceKey};

#[derive(Clone, Copy)]
pub(super) enum Key<'a> {
    Service(ServiceKey<'a>, Option<&'a [u8]>),
    Protocol(ProtocolKey<'a>),
}

impl Key<'_> {
    fn kind(self) -> NssNetdbKind {
        match self {
            Self::Service(..) => NssNetdbKind::Service,
            Self::Protocol(_) => NssNetdbKind::Protocol,
        }
    }
}

#[derive(Clone, Copy, Default)]
struct Requirements {
    physical: usize,
    workspace: usize,
}

impl Requirements {
    fn fits(self, address: usize, capacity: usize) -> bool {
        if capacity < self.physical.max(3) {
            return false;
        }
        if self.workspace == 0 {
            return true;
        }
        // All pointer-table sizes are multiples of alignment. Taking the
        // prefix maximum before rounding therefore works at every alignment.
        let mask = align_of::<*mut c_char>() - 1;
        address
            .checked_add(self.workspace)
            .and_then(|end| end.checked_add(mask))
            .is_some_and(|end| ((end & !mask) - address) <= capacity)
    }
}

struct Record {
    line: Range<usize>,
    leading: usize,
    protocol: Option<Range<usize>>,
    prefix: Requirements,
}

#[derive(Default)]
pub(super) struct Index {
    generation: Option<u64>,
    records: Vec<Record>,
    names: BTreeMap<Vec<u8>, Vec<usize>>,
    numbers: BTreeMap<c_int, Vec<usize>>,
    total: Requirements,
}

fn space(byte: &u8) -> bool {
    matches!(*byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

impl Index {
    fn rebuild(&mut self, generation: u64, kind: NssNetdbKind, content: &[u8]) {
        if self.generation == Some(generation) {
            return;
        }
        self.records.clear();
        self.names.clear();
        self.numbers.clear();
        let mut prefix = Requirements::default();
        let mut offset = 0;
        for physical in content.split_inclusive(|&b| b == b'\n') {
            let start = offset;
            offset += physical.len();
            prefix.physical = prefix.physical.max(physical.len().saturating_add(2));
            let len = physical
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(physical.len());
            let leading = physical[..len].iter().take_while(|b| space(b)).count();
            let text = &physical[leading..len];
            let Some(parsed) = parse_nss_netdb_line(kind, text).record else {
                continue;
            };
            let (number, protocol) = match parsed.value {
                NssNetdbValue::Protocol(n) => (n, None),
                NssNetdbValue::Service { port, protocol } => {
                    let base = start + leading;
                    (
                        c_int::from(port.to_be()),
                        Some(base + protocol.start..base + protocol.end),
                    )
                }
                _ => unreachable!("only services and protocols are indexed"),
            };
            let table_bytes = parsed
                .alias_count
                .saturating_add(2)
                .saturating_mul(size_of::<*mut c_char>());
            prefix.workspace = prefix
                .workspace
                .max(len.saturating_add(1).saturating_add(table_bytes));
            let index = self.records.len();
            self.numbers.entry(number).or_default().push(index);
            let aliases = text[parsed.aliases].split(space).filter(|alias| !alias.is_empty());
            for name in std::iter::once(&text[parsed.name]).chain(aliases) {
                self.names.entry(name.to_vec()).or_default().push(index);
            }
            self.records.push(Record {
                line: start..start + len,
                leading,
                protocol,
                prefix,
            });
        }
        self.total = prefix;
        self.generation = Some(generation);
    }

    /// # Safety
    /// Callers validate the complete typed database output and exact writable
    /// buffer extent. The key and content remain live through lookup.
    pub(super) unsafe fn lookup(
        &mut self,
        content: &[u8],
        generation: u64,
        key: Key<'_>,
        out: *mut c_void,
        buf: *mut c_char,
        capacity: usize,
    ) -> Answer<()> {
        self.rebuild(generation, key.kind(), content);
        let candidates = match key {
            Key::Service(ServiceKey::Name(name), _) | Key::Protocol(ProtocolKey::Name(name)) => {
                self.names.get(name)
            }
            Key::Service(ServiceKey::Port(n), _) | Key::Protocol(ProtocolKey::Number(n)) => {
                self.numbers.get(&n)
            }
        };
        let record = candidates
            .into_iter()
            .flatten()
            .map(|&i| &self.records[i])
            .find(|record| match (key, &record.protocol) {
                (Key::Service(_, Some(wanted)), Some(range)) => wanted == &content[range.clone()],
                _ => true,
            });
        if !record.map_or(self.total, |r| r.prefix).fits(buf as usize, capacity) {
            return Answer::BufferTooSmall;
        }
        // GNU public files dispatch clears a prior provider's error on either
        // success or a completed miss. The private wrapper saves its own errno.
        unsafe { crate::errno_abi::set_abi_errno(0) };
        let Some(record) = record else {
            return Answer::NotFound;
        };
        let line = &content[record.line.clone()];
        // The physical length, NUL, and aligned table including its spare
        // slot fit. Pass the full line base as parser_data so leading spaces
        // count toward the allocation even though the parser skips them.
        unsafe {
            std::ptr::copy_nonoverlapping(line.as_ptr(), buf.cast::<u8>(), line.len());
            buf.add(line.len()).write(0);
            let parse = match key {
                Key::Service(..) => crate::unistd_abi::_nss_files_parse_servent,
                Key::Protocol(_) => crate::unistd_abi::_nss_files_parse_protoent,
            };
            let mut error = 0;
            match parse(buf.add(record.leading), out, buf.cast(), capacity, &mut error) {
                1 => {
                    crate::errno_abi::set_abi_errno(0);
                    Answer::Found(())
                }
                -1 => Answer::BufferTooSmall,
                _ => Answer::Unavailable(libc::EIO),
            }
        }
    }
}
