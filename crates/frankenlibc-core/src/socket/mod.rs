//! Socket operations.
//!
//! Implements `<sys/socket.h>` constants and pure-logic validators. Actual
//! syscall invocations (`socket`, `bind`, `listen`, etc.) live in the ABI
//! crate.

// ---------------------------------------------------------------------------
// Address families (AF_*)
// ---------------------------------------------------------------------------

/// Unspecified address family.
pub const AF_UNSPEC: i32 = 0;
/// Unix domain sockets.
pub const AF_UNIX: i32 = 1;
/// IPv4 Internet protocols.
pub const AF_INET: i32 = 2;
/// IPv6 Internet protocols.
pub const AF_INET6: i32 = 10;
/// Kernel user interface device.
pub const AF_NETLINK: i32 = 16;

// ---------------------------------------------------------------------------
// Socket types (SOCK_*)
// ---------------------------------------------------------------------------

/// Byte-stream socket.
pub const SOCK_STREAM: i32 = 1;
/// Datagram socket.
pub const SOCK_DGRAM: i32 = 2;
/// Raw network protocol access.
pub const SOCK_RAW: i32 = 3;
/// Sequenced, reliable, connection-based datagrams.
pub const SOCK_SEQPACKET: i32 = 5;

// ---------------------------------------------------------------------------
// Socket type flags (ORed into `socket()` type argument)
// ---------------------------------------------------------------------------

/// Set O_NONBLOCK on the new socket.
pub const SOCK_NONBLOCK: i32 = 0x800;
/// Set FD_CLOEXEC on the new socket.
pub const SOCK_CLOEXEC: i32 = 0x80000;

/// Mask covering all known socket-type flags.
const SOCK_TYPE_FLAG_MASK: i32 = SOCK_NONBLOCK | SOCK_CLOEXEC;

// ---------------------------------------------------------------------------
// Shutdown modes
// ---------------------------------------------------------------------------

/// Shut down the reading side.
pub const SHUT_RD: i32 = 0;
/// Shut down the writing side.
pub const SHUT_WR: i32 = 1;
/// Shut down both reading and writing.
pub const SHUT_RDWR: i32 = 2;

// ---------------------------------------------------------------------------
// Socket levels
// ---------------------------------------------------------------------------

/// Socket-level options (for `getsockopt`/`setsockopt`).
pub const SOL_SOCKET: i32 = 1;

// ---------------------------------------------------------------------------
// Socket options (SO_*)
// ---------------------------------------------------------------------------

/// Allow local address reuse.
pub const SO_REUSEADDR: i32 = 2;
/// Enable keep-alive probes.
pub const SO_KEEPALIVE: i32 = 9;
/// Receive buffer size.
pub const SO_RCVBUF: i32 = 8;
/// Send buffer size.
pub const SO_SNDBUF: i32 = 7;
/// Receive timeout.
pub const SO_RCVTIMEO: i32 = 20;
/// Send timeout.
pub const SO_SNDTIMEO: i32 = 21;
/// Pending error (get only).
pub const SO_ERROR: i32 = 4;
/// Socket type (get only).
pub const SO_TYPE: i32 = 3;
/// Linger on close if unsent data is present.
pub const SO_LINGER: i32 = 13;

// ---------------------------------------------------------------------------
// Message flags (MSG_*)
// ---------------------------------------------------------------------------

/// Peek at incoming data without consuming it.
pub const MSG_PEEK: i32 = 2;
/// Block until the full amount of data is available.
pub const MSG_WAITALL: i32 = 256;
/// Non-blocking operation.
pub const MSG_DONTWAIT: i32 = 64;
/// Do not generate SIGPIPE on stream-oriented sockets.
pub const MSG_NOSIGNAL: i32 = 0x4000;

/// Mask covering all known MSG_* flags.
const MSG_KNOWN_MASK: i32 = MSG_PEEK | MSG_WAITALL | MSG_DONTWAIT | MSG_NOSIGNAL;

// ---------------------------------------------------------------------------
// Miscellaneous
// ---------------------------------------------------------------------------

/// Maximum length of the pending-connection queue for `listen()`.
pub const SOMAXCONN: i32 = 4096;

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

/// Returns `true` if `af` is a recognized address family.
#[inline]
pub fn valid_address_family(af: i32) -> bool {
    matches!(af, AF_UNSPEC | AF_UNIX | AF_INET | AF_INET6 | AF_NETLINK)
}

/// Returns `true` if `stype` encodes a recognized base socket type, after
/// masking off the `SOCK_NONBLOCK` and `SOCK_CLOEXEC` modifier flags.
#[inline]
pub fn valid_socket_type(stype: i32) -> bool {
    let base = stype & !SOCK_TYPE_FLAG_MASK;
    matches!(base, SOCK_STREAM | SOCK_DGRAM | SOCK_RAW | SOCK_SEQPACKET)
}

/// Returns `true` if `how` is a valid shutdown mode.
#[inline]
pub fn valid_shutdown_how(how: i32) -> bool {
    matches!(how, SHUT_RD | SHUT_WR | SHUT_RDWR)
}

/// Clamps `backlog` into the range `[0, SOMAXCONN]`.
#[inline]
pub fn valid_backlog(backlog: i32) -> i32 {
    backlog.clamp(0, SOMAXCONN)
}

/// Returns `true` if `flags` contains only recognized MSG_* bits.
#[inline]
pub fn valid_msg_flags(flags: i32) -> bool {
    flags & !MSG_KNOWN_MASK == 0
}

/// Visit every GNU reserved TCP port once, descending and wrapping at 512.
///
/// Clamp the signed caller seed before converting it to a network port.
/// Socket creation, binding and errno handling belong to the ABI boundary.
#[inline]
pub fn reserved_port_candidates(seed: i32) -> impl Iterator<Item = u16> {
    let start = seed.clamp(512, 1023) as u16;
    (512..=start).rev().chain((start + 1..=1023).rev())
}

// ---------------------------------------------------------------------------
// Interface snapshots from Linux NETLINK_ROUTE
// ---------------------------------------------------------------------------

/// Borrowed link-layer fields from one complete RTM_NEWLINK record.
/// Names are kernel byte strings, not necessarily UTF-8. Statistics retain
/// the native-endian IFLA_STATS layout, including any future trailing fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterfaceLink<'a> {
    pub index: u32,
    pub flags: u32,
    pub hardware_type: u16,
    pub name: &'a [u8],
    pub address: Option<&'a [u8]>,
    pub broadcast: Option<&'a [u8]>,
    pub stats: Option<&'a [u8]>,
}

/// Borrowed Internet address fields from one complete RTM_NEWADDR record.
/// IFA_LOCAL is the local address when present; IFA_ADDRESS then supplies
/// the peer. IFA_BROADCAST and IFA_LABEL remain separate attributes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterfaceAddress<'a> {
    pub index: u32,
    pub family: u8,
    pub prefix_len: u8,
    pub local: &'a [u8],
    pub peer: Option<&'a [u8]>,
    pub broadcast: Option<&'a [u8]>,
    pub label: Option<&'a [u8]>,
}

fn netlink_record_span(length: usize, available: usize) -> Result<usize, i32> {
    if length > available {
        return Err(crate::errno::EIO);
    }
    if length == available {
        // A terminal record need not include alignment padding.
        return Ok(length);
    }
    let aligned = length.checked_add(3).ok_or(crate::errno::EIO)? & !3;
    if aligned > available {
        return Err(crate::errno::EIO);
    }
    Ok(aligned)
}

fn visit_netlink_messages<'a>(
    mut data: &'a [u8],
    wanted: u16,
    mut visit: impl FnMut(&'a [u8]) -> Result<(), i32>,
) -> Result<(), i32> {
    let mut done = false;
    while !data.is_empty() {
        let header = data.get(..16).ok_or(crate::errno::EIO)?;
        let length = u32::from_ne_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let kind = u16::from_ne_bytes([header[4], header[5]]);
        let flags = u16::from_ne_bytes([header[6], header[7]]);
        if length < 16 {
            return Err(crate::errno::EIO);
        }
        let span = netlink_record_span(length, data.len())?;
        let body = &data[16..length];
        if flags & 0x10 != 0 {
            return Err(crate::errno::EAGAIN); // NLM_F_DUMP_INTR
        }
        if kind == 4 {
            return Err(crate::errno::ENOBUFS); // NLMSG_OVERRUN
        }
        if matches!(kind, 2 | 3) {
            // NLMSG_DONE may have an empty payload on older kernels. A zero
            // NLMSG_ERROR is only an acknowledgement, not a completed dump.
            let error = if kind == 3 && body.is_empty() {
                0
            } else {
                let bytes = body.get(..4).ok_or(crate::errno::EIO)?;
                i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
            };
            if error != 0 {
                return Err(error
                    .checked_neg()
                    .filter(|value| *value > 0)
                    .unwrap_or(crate::errno::EIO));
            }
            done |= kind == 3;
        } else if kind == wanted {
            if done {
                return Err(crate::errno::EIO);
            }
            visit(body)?;
        }
        // Validate later records too: a DONE marker cannot hide a late error
        // or a truncated message appended to the collected datagrams.
        data = &data[span..];
    }
    if done { Ok(()) } else { Err(crate::errno::EIO) }
}

fn visit_netlink_attributes<'a>(
    mut data: &'a [u8],
    mut visit: impl FnMut(u16, &'a [u8]) -> Result<(), i32>,
) -> Result<(), i32> {
    while !data.is_empty() {
        let header = data.get(..4).ok_or(crate::errno::EIO)?;
        let length = usize::from(u16::from_ne_bytes([header[0], header[1]]));
        if length < 4 {
            return Err(crate::errno::EIO);
        }
        let span = netlink_record_span(length, data.len())?;
        // Strip the NLA_F_NESTED / NLA_F_NET_BYTEORDER attribute flags.
        let kind = u16::from_ne_bytes([header[2], header[3]]) & 0x3fff;
        visit(kind, &data[4..length])?;
        data = &data[span..];
    }
    Ok(())
}

fn interface_name(bytes: &[u8]) -> Result<&[u8], i32> {
    let length = bytes
        .iter()
        .position(|&byte| byte == 0)
        .ok_or(crate::errno::EIO)?;
    if !(1..16).contains(&length) {
        return Err(crate::errno::EIO);
    }
    Ok(&bytes[..length])
}

/// Visit validated links in a complete netlink dump without allocating.
/// Malformed records, failed/interrupted dumps, and visitor errors invalidate
/// the snapshot. Callers must discard any earlier visitor output on failure.
pub fn for_each_netlink_link<'a>(
    data: &'a [u8],
    mut visit: impl FnMut(InterfaceLink<'a>) -> Result<(), i32>,
) -> Result<(), i32> {
    visit_netlink_messages(data, 16, |body| {
        let header = body.get(..16).ok_or(crate::errno::EIO)?;
        let index = i32::from_ne_bytes([header[4], header[5], header[6], header[7]]);
        if index <= 0 {
            return Err(crate::errno::EIO);
        }
        let mut link = InterfaceLink {
            index: index as u32,
            flags: u32::from_ne_bytes([header[8], header[9], header[10], header[11]]),
            hardware_type: u16::from_ne_bytes([header[2], header[3]]),
            name: &[],
            address: None,
            broadcast: None,
            stats: None,
        };
        visit_netlink_attributes(&body[16..], |kind, value| {
            match kind {
                1 | 2 => {
                    // Linux MAX_ADDR_LEN includes 20-byte InfiniBand addresses.
                    if value.len() > 32 {
                        return Err(crate::errno::EIO);
                    }
                    if kind == 1 {
                        link.address = Some(value);
                    } else {
                        link.broadcast = Some(value);
                    }
                }
                3 => link.name = interface_name(value)?,
                7 => {
                    // rtnl_link_stats originally had 23 u32 counters; newer
                    // kernels append fields. IFLA_STATS64 has a different ABI.
                    if value.len() < 23 * 4 || !value.len().is_multiple_of(4) {
                        return Err(crate::errno::EIO);
                    }
                    link.stats = Some(value);
                }
                _ => {}
            }
            Ok(())
        })?;
        if link.name.is_empty() {
            return Err(crate::errno::EIO);
        }
        visit(link)
    })
}

/// Visit validated IPv4/IPv6 addresses in a complete netlink dump.
/// All address attributes have the family's exact width. Unknown families
/// are ignored; known families with missing or malformed data are errors.
pub fn for_each_netlink_address<'a>(
    data: &'a [u8],
    mut visit: impl FnMut(InterfaceAddress<'a>) -> Result<(), i32>,
) -> Result<(), i32> {
    visit_netlink_messages(data, 20, |body| {
        let header = body.get(..8).ok_or(crate::errno::EIO)?;
        let width = match i32::from(header[0]) {
            AF_INET => 4,
            AF_INET6 => 16,
            _ => return Ok(()),
        };
        let index = u32::from_ne_bytes([header[4], header[5], header[6], header[7]]);
        if index == 0 || index > i32::MAX as u32 || usize::from(header[1]) > width * 8 {
            return Err(crate::errno::EIO);
        }
        let (mut address, mut local, mut broadcast, mut label) = (None, None, None, None);
        visit_netlink_attributes(&body[8..], |kind, value| {
            match kind {
                1 | 2 | 4 => {
                    if value.len() != width {
                        return Err(crate::errno::EIO);
                    }
                    match kind {
                        1 => address = Some(value),
                        2 => local = Some(value),
                        _ => broadcast = Some(value),
                    }
                }
                3 => label = Some(interface_name(value)?),
                _ => {}
            }
            Ok(())
        })?;
        visit(InterfaceAddress {
            index,
            family: header[0],
            prefix_len: header[1],
            local: local.or(address).ok_or(crate::errno::EIO)?,
            peer: local.and(address),
            broadcast,
            label,
        })
    })
}

/// Scope IDs are interface indices for IPv6 link-local unicast/multicast.
/// Global, loopback and unspecified addresses have no interface scope.
#[must_use]
pub fn ipv6_interface_scope_id(address: &[u8; 16], index: u32) -> u32 {
    if (address[0] == 0xfe && address[1] & 0xc0 == 0x80)
        || (address[0] == 0xff && address[1] & 0x0f == 2)
    {
        index
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
        let length = 4 + value.len();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(length as u16).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(value);
        bytes.resize((length + 3) & !3, 0);
        bytes
    }

    fn message(kind: u16, flags: u16, body: &[u8]) -> Vec<u8> {
        let length = 16 + body.len();
        let mut bytes = vec![0; 16];
        bytes[..4].copy_from_slice(&(length as u32).to_ne_bytes());
        bytes[4..6].copy_from_slice(&kind.to_ne_bytes());
        bytes[6..8].copy_from_slice(&flags.to_ne_bytes());
        bytes.extend_from_slice(body);
        bytes.resize((length + 3) & !3, 0);
        bytes
    }

    fn complete(mut messages: Vec<u8>) -> Vec<u8> {
        messages.extend_from_slice(&message(3, 0, &[]));
        messages
    }

    fn link_body(index: u32, name: &[u8]) -> Vec<u8> {
        let mut body = vec![0; 16];
        body[2..4].copy_from_slice(&32u16.to_ne_bytes()); // ARPHRD_INFINIBAND
        body[4..8].copy_from_slice(&index.to_ne_bytes());
        body[8..12].copy_from_slice(&0x1043u32.to_ne_bytes());
        body.extend_from_slice(&attribute(3, name));
        body
    }

    fn address_body(family: u8, prefix: u8, index: u32) -> Vec<u8> {
        let mut body = vec![0; 8];
        body[0] = family;
        body[1] = prefix;
        body[4..8].copy_from_slice(&index.to_ne_bytes());
        body
    }

    #[test]
    fn netlink_links_preserve_byte_names_long_addresses_and_32_bit_statistics() {
        let mut body = link_body(17, b"ib\xff0\0");
        let hardware: Vec<u8> = (0..20).collect();
        let stats = vec![0x43; 23 * 4];
        body.extend_from_slice(&attribute(1, &hardware));
        body.extend_from_slice(&attribute(2, &[0xff; 20]));
        body.extend_from_slice(&attribute(7, &stats));
        body.extend_from_slice(&attribute(23, &[0x91; 24 * 8])); // IFLA_STATS64 is distinct.
        let dump = complete(message(16, 0, &body));
        let mut links = Vec::new();
        assert_eq!(
            for_each_netlink_link(&dump, |link| {
                links.push(link);
                Ok(())
            }),
            Ok(())
        );
        assert_eq!(links.len(), 1);
        let link = links[0];
        assert_eq!(
            (link.index, link.flags, link.hardware_type),
            (17, 0x1043, 32)
        );
        assert_eq!(link.name, b"ib\xff0");
        assert_eq!(link.address, Some(hardware.as_slice()));
        assert_eq!(link.broadcast, Some(&[0xff; 20][..]));
        assert_eq!(link.stats, Some(stats.as_slice()));
    }

    #[test]
    fn netlink_link_only_and_unaligned_dumps_are_valid() {
        let dump = complete(message(16, 0, &link_body(9, b"link0\0")));
        let mut unaligned = vec![0xa5];
        unaligned.extend_from_slice(&dump);
        let mut calls = 0;
        assert_eq!(
            for_each_netlink_link(&unaligned[1..], |link| {
                calls += 1;
                assert_eq!(link.name, b"link0");
                assert!(link.address.is_none());
                assert!(link.stats.is_none());
                Ok(())
            }),
            Ok(())
        );
        assert_eq!(calls, 1);
    }

    #[test]
    fn netlink_last_attribute_can_omit_alignment_padding() {
        let mut body = link_body(3, b"vlan0\0");
        body.extend_from_slice(&[5, 0, 1, 0, 0x7f]);
        let dump = complete(message(16, 0, &body));
        assert_eq!(
            for_each_netlink_link(&dump, |link| {
                assert_eq!(link.address, Some(&[0x7f][..]));
                Ok(())
            }),
            Ok(())
        );
    }

    #[test]
    fn netlink_links_reject_malformed_attribute_lengths_and_padding() {
        for malformed in [
            vec![1],
            vec![3, 0, 1, 0],
            vec![12, 0, 1, 0],
            vec![5, 0, 1, 0, 1, 0],
        ] {
            let mut body = link_body(3, b"eth0\0");
            body.extend_from_slice(&malformed);
            let dump = complete(message(16, 0, &body));
            assert_eq!(
                for_each_netlink_link(&dump, |_| Ok(())),
                Err(crate::errno::EIO),
                "{malformed:?}"
            );
        }
    }

    #[test]
    fn netlink_links_reject_invalid_names_hardware_and_stats_payloads() {
        for (kind, value) in [
            (1, vec![1; 33]),
            (2, vec![1; 33]),
            (3, b"unterminated".to_vec()),
            (3, vec![0]),
            (3, b"1234567890123456\0".to_vec()),
            (7, vec![0; 91]),
            (7, vec![0; 94]),
        ] {
            let mut body = link_body(3, b"eth0\0");
            body.extend_from_slice(&attribute(kind, &value));
            let dump = complete(message(16, 0, &body));
            assert_eq!(
                for_each_netlink_link(&dump, |_| Ok(())),
                Err(crate::errno::EIO)
            );
        }
        for index in [0, u32::MAX] {
            let dump = complete(message(16, 0, &link_body(index, b"eth0\0")));
            assert_eq!(
                for_each_netlink_link(&dump, |_| Ok(())),
                Err(crate::errno::EIO)
            );
        }
        assert_eq!(
            for_each_netlink_link(&complete(message(16, 0, &[0; 16])), |_| Ok(())),
            Err(crate::errno::EIO)
        );
    }

    #[test]
    fn netlink_ipv4_local_peer_and_label_are_independent_of_attribute_order() {
        for reverse in [false, true] {
            let mut body = address_body(AF_INET as u8, 27, 13);
            let mut attributes = [
                attribute(1, &[192, 0, 2, 2]),
                attribute(2, &[192, 0, 2, 1]),
                attribute(3, b"tun0:7\0"),
                attribute(4, &[192, 0, 2, 31]),
            ];
            if reverse {
                attributes.reverse();
            }
            for attr in attributes {
                body.extend_from_slice(&attr);
            }
            let dump = complete(message(20, 0, &body));
            assert_eq!(
                for_each_netlink_address(&dump, |address| {
                    assert_eq!(
                        (address.index, address.family, address.prefix_len),
                        (13, 2, 27)
                    );
                    assert_eq!(address.local, [192, 0, 2, 1]);
                    assert_eq!(address.peer, Some(&[192, 0, 2, 2][..]));
                    assert_eq!(address.broadcast, Some(&[192, 0, 2, 31][..]));
                    assert_eq!(address.label, Some(&b"tun0:7"[..]));
                    Ok(())
                }),
                Ok(())
            );
        }
    }

    #[test]
    fn netlink_ipv6_address_only_and_link_local_scope() {
        let mut local = [0; 16];
        local[..2].copy_from_slice(&[0xfe, 0x80]);
        local[15] = 1;
        let mut body = address_body(AF_INET6 as u8, 64, 22);
        body.extend_from_slice(&attribute(1, &local));
        let dump = complete(message(20, 0, &body));
        assert_eq!(
            for_each_netlink_address(&dump, |address| {
                assert_eq!(address.local, local);
                assert!(address.peer.is_none());
                assert!(address.broadcast.is_none());
                assert_eq!(ipv6_interface_scope_id(&local, address.index), 22);
                Ok(())
            }),
            Ok(())
        );
        for (prefix, scope) in [
            ([0xfe, 0xbf], 22),
            ([0xff, 0x02], 22),
            ([0xff, 0x12], 22),
            ([0xfe, 0xc0], 0),
            ([0x20, 0x01], 0),
            ([0, 0], 0),
        ] {
            local[..2].copy_from_slice(&prefix);
            assert_eq!(ipv6_interface_scope_id(&local, 22), scope);
        }
    }

    #[test]
    fn netlink_addresses_reject_missing_wrong_width_or_overlong_prefix() {
        for (family, prefix, width) in [(2, 33, 4), (10, 129, 16), (2, 24, 3), (10, 64, 15)] {
            let mut body = address_body(family, prefix, 1);
            body.extend_from_slice(&attribute(1, &vec![0; width]));
            assert_eq!(
                for_each_netlink_address(&complete(message(20, 0, &body)), |_| Ok(())),
                Err(crate::errno::EIO)
            );
        }
        assert_eq!(
            for_each_netlink_address(&complete(message(20, 0, &address_body(2, 24, 1))), |_| Ok(
                ()
            )),
            Err(crate::errno::EIO)
        );
        let mut body = address_body(2, 24, 0);
        body.extend_from_slice(&attribute(1, &[127, 0, 0, 1]));
        assert_eq!(
            for_each_netlink_address(&complete(message(20, 0, &body)), |_| Ok(())),
            Err(crate::errno::EIO)
        );
        assert_eq!(
            for_each_netlink_address(
                &complete(message(20, 0, &address_body(99, 0, 1))),
                |_| panic!("unknown family")
            ),
            Ok(())
        );
    }

    #[test]
    fn netlink_dumps_reject_missing_done_truncation_and_late_kernel_errors() {
        let record = message(16, 0, &link_body(1, b"eth0\0"));
        assert_eq!(
            for_each_netlink_link(&record, |_| Ok(())),
            Err(crate::errno::EIO)
        );
        for length in [0u32, 15, u32::MAX] {
            let mut malformed = complete(record.clone());
            malformed[..4].copy_from_slice(&length.to_ne_bytes());
            assert_eq!(
                for_each_netlink_link(&malformed, |_| Ok(())),
                Err(crate::errno::EIO)
            );
        }
        let mut trailing = complete(record.clone());
        trailing.push(0);
        assert_eq!(
            for_each_netlink_link(&trailing, |_| Ok(())),
            Err(crate::errno::EIO)
        );
        for (kind, flags, body, error) in [
            (3, 0x10, vec![], crate::errno::EAGAIN),
            (4, 0, vec![], crate::errno::ENOBUFS),
            (
                2,
                0,
                (-crate::errno::EACCES).to_ne_bytes().to_vec(),
                crate::errno::EACCES,
            ),
            (
                3,
                0,
                (-crate::errno::ENOMEM).to_ne_bytes().to_vec(),
                crate::errno::ENOMEM,
            ),
            (2, 0, vec![0; 3], crate::errno::EIO),
            (2, 0, i32::MIN.to_ne_bytes().to_vec(), crate::errno::EIO),
        ] {
            let mut dump = complete(record.clone());
            dump.extend_from_slice(&message(kind, flags, &body));
            assert_eq!(for_each_netlink_link(&dump, |_| Ok(())), Err(error));
        }
    }

    #[test]
    fn netlink_visitors_propagate_allocation_failures() {
        let dump = complete(message(16, 0, &link_body(1, b"eth0\0")));
        assert_eq!(
            for_each_netlink_link(&dump, |_| Err(crate::errno::ENOMEM)),
            Err(crate::errno::ENOMEM)
        );
        let mut body = address_body(2, 24, 1);
        body.extend_from_slice(&attribute(1, &[192, 0, 2, 1]));
        assert_eq!(
            for_each_netlink_address(&complete(message(20, 0, &body)), |_| Err(
                crate::errno::ENOMEM
            )),
            Err(crate::errno::ENOMEM)
        );
    }

    #[test]
    fn reserved_port_wraps_at_the_floor() {
        let ports: Vec<_> = reserved_port_candidates(512).collect();
        assert_eq!(&ports[..4], &[512, 1023, 1022, 1021]);
        assert_eq!(ports.len(), 512);
        assert_eq!(ports.last(), Some(&513));
    }

    #[test]
    fn reserved_port_clamps_signed_seeds_before_conversion() {
        for seed in [i32::MIN, -1, 0, 511] {
            let ports: Vec<_> = reserved_port_candidates(seed).collect();
            assert_eq!(ports.first(), Some(&512), "seed {seed}");
            assert_eq!(ports.len(), 512);
        }
        for seed in [1024, 65536, i32::MAX] {
            let ports: Vec<_> = reserved_port_candidates(seed).collect();
            assert_eq!(ports.first(), Some(&1023), "seed {seed}");
            assert_eq!(ports.len(), 512);
        }
    }

    // -- Address family validation ------------------------------------------

    #[test]
    fn valid_af_known_families() {
        assert!(valid_address_family(AF_UNSPEC));
        assert!(valid_address_family(AF_UNIX));
        assert!(valid_address_family(AF_INET));
        assert!(valid_address_family(AF_INET6));
        assert!(valid_address_family(AF_NETLINK));
    }

    #[test]
    fn invalid_af_rejects_unknowns() {
        assert!(!valid_address_family(-1));
        assert!(!valid_address_family(3));
        assert!(!valid_address_family(42));
        assert!(!valid_address_family(i32::MAX));
        assert!(!valid_address_family(i32::MIN));
    }

    // -- Socket type validation ---------------------------------------------

    #[test]
    fn valid_socket_type_base_types() {
        assert!(valid_socket_type(SOCK_STREAM));
        assert!(valid_socket_type(SOCK_DGRAM));
        assert!(valid_socket_type(SOCK_RAW));
        assert!(valid_socket_type(SOCK_SEQPACKET));
    }

    #[test]
    fn valid_socket_type_with_flags() {
        assert!(valid_socket_type(SOCK_STREAM | SOCK_NONBLOCK));
        assert!(valid_socket_type(SOCK_DGRAM | SOCK_CLOEXEC));
        assert!(valid_socket_type(SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC));
        assert!(valid_socket_type(SOCK_SEQPACKET | SOCK_CLOEXEC));
    }

    #[test]
    fn invalid_socket_type_rejects_unknowns() {
        assert!(!valid_socket_type(0));
        assert!(!valid_socket_type(4)); // gap between RAW(3) and SEQPACKET(5)
        assert!(!valid_socket_type(6));
        assert!(!valid_socket_type(-1));
        assert!(!valid_socket_type(i32::MAX));
    }

    #[test]
    fn invalid_socket_type_flags_only() {
        // Flags without a valid base type should be rejected.
        assert!(!valid_socket_type(SOCK_NONBLOCK));
        assert!(!valid_socket_type(SOCK_CLOEXEC));
        assert!(!valid_socket_type(SOCK_NONBLOCK | SOCK_CLOEXEC));
    }

    // -- Shutdown how validation --------------------------------------------

    #[test]
    fn valid_shutdown_how_values() {
        assert!(valid_shutdown_how(SHUT_RD));
        assert!(valid_shutdown_how(SHUT_WR));
        assert!(valid_shutdown_how(SHUT_RDWR));
    }

    #[test]
    fn invalid_shutdown_how_values() {
        assert!(!valid_shutdown_how(-1));
        assert!(!valid_shutdown_how(3));
        assert!(!valid_shutdown_how(i32::MAX));
        assert!(!valid_shutdown_how(i32::MIN));
    }

    // -- Backlog clamping ---------------------------------------------------

    #[test]
    fn backlog_clamp_normal() {
        assert_eq!(valid_backlog(0), 0);
        assert_eq!(valid_backlog(1), 1);
        assert_eq!(valid_backlog(128), 128);
        assert_eq!(valid_backlog(SOMAXCONN), SOMAXCONN);
    }

    #[test]
    fn backlog_clamp_negative() {
        assert_eq!(valid_backlog(-1), 0);
        assert_eq!(valid_backlog(-100), 0);
        assert_eq!(valid_backlog(i32::MIN), 0);
    }

    #[test]
    fn backlog_clamp_above_max() {
        assert_eq!(valid_backlog(SOMAXCONN + 1), SOMAXCONN);
        assert_eq!(valid_backlog(100_000), SOMAXCONN);
        assert_eq!(valid_backlog(i32::MAX), SOMAXCONN);
    }

    // -- MSG flags validation -----------------------------------------------

    #[test]
    fn valid_msg_flags_known() {
        assert!(valid_msg_flags(0));
        assert!(valid_msg_flags(MSG_PEEK));
        assert!(valid_msg_flags(MSG_WAITALL));
        assert!(valid_msg_flags(MSG_DONTWAIT));
        assert!(valid_msg_flags(MSG_NOSIGNAL));
    }

    #[test]
    fn valid_msg_flags_combinations() {
        assert!(valid_msg_flags(MSG_PEEK | MSG_DONTWAIT));
        assert!(valid_msg_flags(MSG_WAITALL | MSG_NOSIGNAL));
        assert!(valid_msg_flags(
            MSG_PEEK | MSG_WAITALL | MSG_DONTWAIT | MSG_NOSIGNAL
        ));
    }

    #[test]
    fn invalid_msg_flags_unknown_bits() {
        assert!(!valid_msg_flags(1)); // bit 0 not in any known flag
        assert!(!valid_msg_flags(0x8000)); // unknown high bit
        assert!(!valid_msg_flags(MSG_PEEK | 0x1_0000));
        assert!(!valid_msg_flags(-1)); // all bits set
        assert!(!valid_msg_flags(i32::MIN));
    }

    // -- Constant value spot-checks -----------------------------------------

    #[test]
    fn constant_values() {
        assert_eq!(AF_UNSPEC, 0);
        assert_eq!(AF_UNIX, 1);
        assert_eq!(AF_INET, 2);
        assert_eq!(AF_INET6, 10);
        assert_eq!(AF_NETLINK, 16);

        assert_eq!(SOCK_STREAM, 1);
        assert_eq!(SOCK_DGRAM, 2);
        assert_eq!(SOCK_RAW, 3);
        assert_eq!(SOCK_SEQPACKET, 5);
        assert_eq!(SOCK_NONBLOCK, 0x800);
        assert_eq!(SOCK_CLOEXEC, 0x80000);

        assert_eq!(SHUT_RD, 0);
        assert_eq!(SHUT_WR, 1);
        assert_eq!(SHUT_RDWR, 2);

        assert_eq!(SOL_SOCKET, 1);

        assert_eq!(SO_REUSEADDR, 2);
        assert_eq!(SO_KEEPALIVE, 9);
        assert_eq!(SO_RCVBUF, 8);
        assert_eq!(SO_SNDBUF, 7);
        assert_eq!(SO_RCVTIMEO, 20);
        assert_eq!(SO_SNDTIMEO, 21);
        assert_eq!(SO_ERROR, 4);
        assert_eq!(SO_TYPE, 3);
        assert_eq!(SO_LINGER, 13);

        assert_eq!(MSG_PEEK, 2);
        assert_eq!(MSG_WAITALL, 256);
        assert_eq!(MSG_DONTWAIT, 64);
        assert_eq!(MSG_NOSIGNAL, 0x4000);

        assert_eq!(SOMAXCONN, 4096);
    }

    // ===== glibc parity tests =====
    // Verified against glibc <sys/socket.h>

    #[test]
    fn glibc_address_family_constants() {
        // AF_* constants must match glibc
        assert_eq!(AF_UNSPEC, 0);
        assert_eq!(AF_UNIX, 1);
        assert_eq!(AF_INET, 2);
        assert_eq!(AF_INET6, 10);
        assert_eq!(AF_NETLINK, 16);
    }

    #[test]
    fn glibc_socket_type_constants() {
        // SOCK_* type constants must match glibc
        assert_eq!(SOCK_STREAM, 1);
        assert_eq!(SOCK_DGRAM, 2);
        assert_eq!(SOCK_RAW, 3);
        assert_eq!(SOCK_SEQPACKET, 5);
        assert_eq!(SOCK_NONBLOCK, 0x800);
        assert_eq!(SOCK_CLOEXEC, 0x80000);
    }

    #[test]
    fn glibc_shutdown_constants() {
        // SHUT_* constants must match glibc
        assert_eq!(SHUT_RD, 0);
        assert_eq!(SHUT_WR, 1);
        assert_eq!(SHUT_RDWR, 2);
    }

    #[test]
    fn glibc_socket_option_constants() {
        // SOL_SOCKET and SO_* must match glibc
        assert_eq!(SOL_SOCKET, 1);
        assert_eq!(SO_REUSEADDR, 2);
        assert_eq!(SO_TYPE, 3);
        assert_eq!(SO_ERROR, 4);
        assert_eq!(SO_SNDBUF, 7);
        assert_eq!(SO_RCVBUF, 8);
        assert_eq!(SO_KEEPALIVE, 9);
        assert_eq!(SO_LINGER, 13);
        assert_eq!(SO_RCVTIMEO, 20);
        assert_eq!(SO_SNDTIMEO, 21);
    }

    #[test]
    fn glibc_msg_flag_constants() {
        // MSG_* constants must match glibc
        assert_eq!(MSG_PEEK, 2);
        assert_eq!(MSG_DONTWAIT, 64);
        assert_eq!(MSG_WAITALL, 256);
        assert_eq!(MSG_NOSIGNAL, 0x4000);
    }

    #[test]
    fn glibc_somaxconn() {
        // SOMAXCONN must match glibc (Linux 5.4+)
        assert_eq!(SOMAXCONN, 4096);
    }
}
