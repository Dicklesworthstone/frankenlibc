//! Native-loader bindings for compiler-generated fortified calls.
//!
//! These are addresses of the existing checked ABI implementations, not
//! unchecked substitutes. The same allocator, FILE registry, errno provider,
//! and cancellation frontends serve ordinary and fortified plugin calls.

use crate::fortify_abi as checked;

pub(super) fn address(name: &str, version: Option<&str>) -> Option<u64> {
    let function = match name {
        "__memcpy_chk" => checked::__memcpy_chk as *const (),
        "__memmove_chk" => checked::__memmove_chk as *const (),
        "__memset_chk" => checked::__memset_chk as *const (),
        "__mempcpy_chk" => crate::glibc_internal_abi::__mempcpy_chk as *const (),
        "__strcpy_chk" => checked::__strcpy_chk as *const (),
        "__strncpy_chk" => checked::__strncpy_chk as *const (),
        "__strcat_chk" => checked::__strcat_chk as *const (),
        "__strncat_chk" => checked::__strncat_chk as *const (),
        "__stpcpy_chk" => checked::__stpcpy_chk as *const (),
        "__stpncpy_chk" => checked::__stpncpy_chk as *const (),
        "__chk_fail" => checked::__chk_fail as *const (),
        "__stack_chk_fail" => checked::__stack_chk_fail as *const (),
        "__fdelt_chk" => checked::__fdelt_chk as *const (),
        "__read_chk" => checked::__read_chk as *const (),
        "__pread_chk" => checked::__pread_chk as *const (),
        "__pread64_chk" => checked::__pread64_chk as *const (),
        "__recv_chk" => checked::__recv_chk as *const (),
        "__recvfrom_chk" => checked::__recvfrom_chk as *const (),
        "__poll_chk" => checked::__poll_chk as *const (),
        "__ppoll_chk" => checked::__ppoll_chk as *const (),
        "__open_2" => checked::__open_2 as *const (),
        "__open64_2" => checked::__open64_2 as *const (),
        "__openat_2" => checked::__openat_2 as *const (),
        "__openat64_2" => checked::__openat64_2 as *const (),
        "__sprintf_chk" => checked::__sprintf_chk as *const (),
        "__snprintf_chk" => checked::__snprintf_chk as *const (),
        "__vsprintf_chk" => checked::__vsprintf_chk as *const (),
        "__vsnprintf_chk" => checked::__vsnprintf_chk as *const (),
        "__printf_chk" => checked::__printf_chk as *const (),
        "__vprintf_chk" => checked::__vprintf_chk as *const (),
        "__fprintf_chk" => checked::__fprintf_chk as *const (),
        "__vfprintf_chk" => checked::__vfprintf_chk as *const (),
        "__dprintf_chk" => checked::__dprintf_chk as *const (),
        "__vdprintf_chk" => checked::__vdprintf_chk as *const (),
        "__asprintf_chk" => checked::__asprintf_chk as *const (),
        "__vasprintf_chk" => checked::__vasprintf_chk as *const (),
        "__fgets_chk" => checked::__fgets_chk as *const (),
        "__fgets_unlocked_chk" => checked::__fgets_unlocked_chk as *const (),
        "__fread_chk" => checked::__fread_chk as *const (),
        "__fread_unlocked_chk" => checked::__fread_unlocked_chk as *const (),
        "__explicit_bzero_chk" => checked::__explicit_bzero_chk as *const (),
        _ => return None,
    };
    let introduced = match name {
        "__explicit_bzero_chk" => "GLIBC_2.25",
        "__fdelt_chk" => "GLIBC_2.15",
        "__poll_chk" | "__ppoll_chk" => "GLIBC_2.16",
        "__open_2"
        | "__open64_2"
        | "__openat_2"
        | "__openat64_2"
        | "__fread_chk"
        | "__fread_unlocked_chk" => "GLIBC_2.7",
        "__dprintf_chk" | "__vdprintf_chk" | "__asprintf_chk" | "__vasprintf_chk" => "GLIBC_2.8",
        "__stpncpy_chk"
        | "__stack_chk_fail"
        | "__read_chk"
        | "__pread_chk"
        | "__pread64_chk"
        | "__recv_chk"
        | "__recvfrom_chk"
        | "__fgets_chk"
        | "__fgets_unlocked_chk" => "GLIBC_2.4",
        _ => "GLIBC_2.3.4",
    };
    // The earlier introductions collapse to AArch64's baseline, but the
    // later explicit_bzero entry must retain its actual 2.25 version.
    let supported = if cfg!(target_arch = "aarch64") && introduced != "GLIBC_2.25" {
        "GLIBC_2.17"
    } else {
        introduced
    };
    if version.is_some_and(|requested| requested != supported) {
        return None;
    }
    Some(function as usize as u64)
}
