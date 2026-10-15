//! Socket runtime bindings shared by native relocations and dynamic lookup.
//!
//! Bind directly to the ABI frontends, not the host's socket wrappers: their
//! cancellation points, membrane validation and errno must stay in the same
//! runtime as the descriptor operations supplied by dlfcn_io.

use crate::socket_abi as socket;

pub(super) fn address(name: &str, version: Option<&str>) -> Option<u64> {
    let introduced = match name {
        "accept4" => "GLIBC_2.10",
        "recvmmsg" => "GLIBC_2.12",
        "sendmmsg" => "GLIBC_2.14",
        _ => "GLIBC_2.2.5",
    };
    let supported = if cfg!(target_arch = "aarch64") {
        "GLIBC_2.17"
    } else {
        introduced
    };
    if version.is_some_and(|version| version != supported) {
        return None;
    }
    // Preserve each function's actual C/C-unwind ABI. In particular, do not
    // put a non-unwinding adapter around blocking cancellation points.
    let function = match name {
        "socket" => socket::socket as *const (),
        "socketpair" => socket::socketpair as *const (),
        "bind" => socket::bind as *const (),
        "listen" => socket::listen as *const (),
        "connect" => socket::connect as *const (),
        "accept" => socket::accept as *const (),
        "accept4" => socket::accept4 as *const (),
        "shutdown" => socket::shutdown as *const (),
        "getsockname" => socket::getsockname as *const (),
        "getpeername" => socket::getpeername as *const (),
        "getsockopt" => socket::getsockopt as *const (),
        "setsockopt" => socket::setsockopt as *const (),
        "send" => socket::send as *const (),
        "recv" => socket::recv as *const (),
        "sendto" => socket::sendto as *const (),
        "recvfrom" => socket::recvfrom as *const (),
        "sendmsg" => socket::sendmsg as *const (),
        "recvmsg" => socket::recvmsg as *const (),
        "sendmmsg" => socket::sendmmsg as *const (),
        "recvmmsg" => socket::recvmmsg as *const (),
        _ => return None,
    };
    Some(function as usize as u64)
}

#[cfg(test)]
mod tests {
    use super::address;

    #[test]
    fn versions_are_per_symbol_not_a_generic_glibc_allowlist() {
        for (name, version) in [
            ("socket", "GLIBC_2.2.5"),
            ("accept4", "GLIBC_2.10"),
            ("recvmmsg", "GLIBC_2.12"),
            ("sendmmsg", "GLIBC_2.14"),
        ] {
            let version = if cfg!(target_arch = "aarch64") {
                "GLIBC_2.17"
            } else {
                version
            };
            assert!(address(name, None).is_some());
            assert_eq!(address(name, Some(version)), address(name, None));
            assert_eq!(address(name, Some("GLIBC_2.34")), None);
            assert_eq!(address(name, Some("GLIBC_PRIVATE")), None);
        }
        assert_eq!(address("not_a_socket_function", None), None);
    }
}
