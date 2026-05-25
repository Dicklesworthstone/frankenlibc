#![cfg(all(feature = "standalone", feature = "owned-unwind-stub"))]

use frankenlibc_abi::owned_unwind_abi::{
    __deregister_frame, __deregister_frame_info, __register_frame, __register_frame_info,
    _Unwind_Backtrace, _Unwind_GetIP, OwnedUnwindDecodeError, UnwindContext,
    owned_decode_sleb128_for_tests, owned_decode_uleb128_for_tests,
    owned_find_fde_for_ip_for_tests, owned_first_fde_for_tests,
    owned_frame_is_registered_for_tests, owned_frame_object_for_tests,
    owned_validate_cfi_program_for_tests,
};
use std::ffi::c_void;

const URC_NO_REASON: i32 = 0;

unsafe extern "C" fn collect_frame_ip(ctx: *mut UnwindContext, arg: *mut c_void) -> i32 {
    let frames = unsafe { &mut *(arg.cast::<Vec<usize>>()) };
    let ip = unsafe { _Unwind_GetIP(ctx) };
    if ip != 0 {
        frames.push(ip);
    }
    URC_NO_REASON
}

#[inline(never)]
fn walk_from_inner(frames: &mut Vec<usize>) -> i32 {
    unsafe { _Unwind_Backtrace(Some(collect_frame_ip), (frames as *mut Vec<usize>).cast()) }
}

#[inline(never)]
fn walk_from_outer(frames: &mut Vec<usize>) -> i32 {
    walk_from_inner(frames)
}

#[test]
fn backtrace_walk_reports_real_instruction_pointers() {
    let mut frames = Vec::new();
    let reason = walk_from_outer(&mut frames);

    assert_eq!(reason, 5, "walk should finish with _URC_END_OF_STACK");
    assert!(
        frames.len() >= 2,
        "frame-pointer walk should discover real caller frames, got {frames:?}"
    );
    assert!(
        frames.iter().all(|ip| *ip != 0),
        "reported instruction pointers must be nonzero: {frames:?}"
    );
}

#[test]
fn frame_registration_records_and_removes_fde_sources() {
    let mut fake_fde = 0usize;
    let mut fake_object = 0usize;
    let fde = (&mut fake_fde as *mut usize).cast::<c_void>();
    let object = (&mut fake_object as *mut usize).cast::<c_void>();

    assert!(!owned_frame_is_registered_for_tests(fde.cast_const()));
    assert!(owned_frame_object_for_tests(fde.cast_const()).is_null());

    unsafe { __register_frame(fde) };
    assert!(owned_frame_is_registered_for_tests(fde.cast_const()));
    assert!(owned_frame_object_for_tests(fde.cast_const()).is_null());

    unsafe { __register_frame_info(fde, object) };
    assert!(owned_frame_is_registered_for_tests(fde.cast_const()));
    assert_eq!(owned_frame_object_for_tests(fde.cast_const()), object);

    let removed = unsafe { __deregister_frame_info(fde) };
    assert_eq!(removed, object);
    assert!(!owned_frame_is_registered_for_tests(fde.cast_const()));
    assert!(owned_frame_object_for_tests(fde.cast_const()).is_null());

    unsafe { __register_frame(fde) };
    assert!(owned_frame_is_registered_for_tests(fde.cast_const()));

    unsafe { __deregister_frame(fde) };
    assert!(!owned_frame_is_registered_for_tests(fde.cast_const()));
}

#[test]
fn leb128_decoders_cover_signed_and_unsigned_boundaries() {
    assert_eq!(
        owned_decode_uleb128_for_tests(&[0xe5, 0x8e, 0x26], 0),
        Ok((624485, 3))
    );
    assert_eq!(
        owned_decode_sleb128_for_tests(&[0x9b, 0xf1, 0x59], 0),
        Ok((-624485, 3))
    );
    assert_eq!(
        owned_decode_uleb128_for_tests(&[0x80], 0),
        Err(OwnedUnwindDecodeError::Truncated)
    );
}

#[test]
fn synthetic_eh_frame_fde_lookup_fails_closed_on_bad_cfi() {
    let section_addr = 0x400000usize;
    let pc_begin = 0x401234usize;
    let pc_range = 0x40usize;
    let eh_frame = synthetic_eh_frame(section_addr, pc_begin, pc_range, &[0x41, 0x0e, 0x10]);

    let fde = owned_find_fde_for_ip_for_tests(&eh_frame, section_addr, pc_begin + 1)
        .expect("synthetic FDE should decode")
        .expect("IP should resolve to the synthetic FDE");
    assert_eq!(fde.pc_begin, pc_begin);
    assert_eq!(fde.pc_end, pc_begin + pc_range);
    assert_eq!(fde.cie_offset, 0);
    assert_eq!(
        owned_find_fde_for_ip_for_tests(&eh_frame, section_addr, pc_begin + pc_range),
        Ok(None)
    );
    assert_eq!(
        owned_validate_cfi_program_for_tests(&[0x2c]),
        Err(OwnedUnwindDecodeError::UnsupportedCfiOpcode(0x2c))
    );

    let bad_cfi = synthetic_eh_frame(section_addr, pc_begin, pc_range, &[0x2c]);
    assert_eq!(
        owned_find_fde_for_ip_for_tests(&bad_cfi, section_addr, pc_begin + 1),
        Err(OwnedUnwindDecodeError::UnsupportedCfiOpcode(0x2c))
    );
}

#[test]
fn compiled_test_binary_eh_frame_has_lookupable_fde() {
    let exe = std::env::current_exe().expect("current test binary path");
    let (eh_frame, section_addr) =
        elf_section(&exe, ".eh_frame").expect("current test binary should contain .eh_frame");
    let first = owned_first_fde_for_tests(&eh_frame, section_addr)
        .expect("compiled .eh_frame should parse")
        .expect("compiled .eh_frame should contain at least one FDE");
    let found = owned_find_fde_for_ip_for_tests(&eh_frame, section_addr, first.pc_begin)
        .expect("compiled FDE lookup should parse")
        .expect("first FDE start should resolve");

    assert_eq!(found, first);
    assert!(found.pc_end > found.pc_begin);
}

fn synthetic_eh_frame(
    section_addr: usize,
    pc_begin: usize,
    pc_range: usize,
    cfi: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    let cie_offset = bytes.len();
    let mut cie_body = Vec::new();
    cie_body.extend_from_slice(&0u32.to_le_bytes());
    cie_body.push(1);
    cie_body.extend_from_slice(b"zR\0");
    encode_uleb(1, &mut cie_body);
    encode_sleb(-8, &mut cie_body);
    cie_body.push(16);
    encode_uleb(1, &mut cie_body);
    cie_body.push(0x1b);
    cie_body.extend_from_slice(&[0x0c, 0x07, 0x08]);
    bytes.extend_from_slice(&(cie_body.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&cie_body);

    let fde_offset = bytes.len();
    let cie_pointer_field = fde_offset + 4;
    let pc_field = fde_offset + 8;
    let pc_delta = (pc_begin as isize - (section_addr + pc_field) as isize) as i32;
    let mut fde_body = Vec::new();
    fde_body.extend_from_slice(&((cie_pointer_field - cie_offset) as u32).to_le_bytes());
    fde_body.extend_from_slice(&pc_delta.to_le_bytes());
    fde_body.extend_from_slice(&(pc_range as i32).to_le_bytes());
    fde_body.extend_from_slice(cfi);
    bytes.extend_from_slice(&(fde_body.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&fde_body);
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes
}

fn encode_uleb(mut value: usize, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn encode_sleb(mut value: isize, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        let done = (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0);
        out.push(if done { byte } else { byte | 0x80 });
        if done {
            break;
        }
    }
}

fn elf_section(path: &std::path::Path, name: &str) -> Option<(Vec<u8>, usize)> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.get(0..4)? != b"\x7fELF" || *bytes.get(4)? != 2 || *bytes.get(5)? != 1 {
        return None;
    }

    let section_headers = read_u64_le(&bytes, 0x28)? as usize;
    let section_header_size = read_u16_le(&bytes, 0x3a)? as usize;
    let section_count = read_u16_le(&bytes, 0x3c)? as usize;
    let section_names_index = read_u16_le(&bytes, 0x3e)? as usize;
    let names_header =
        section_headers.checked_add(section_names_index.checked_mul(section_header_size)?)?;
    let names_offset = read_u64_le(&bytes, names_header + 0x18)? as usize;
    let names_size = read_u64_le(&bytes, names_header + 0x20)? as usize;
    let names = bytes.get(names_offset..names_offset.checked_add(names_size)?)?;

    for index in 0..section_count {
        let header = section_headers.checked_add(index.checked_mul(section_header_size)?)?;
        let name_offset = read_u32_le(&bytes, header)? as usize;
        let section_name = c_string_at(names, name_offset)?;
        if section_name != name {
            continue;
        }
        let addr = read_u64_le(&bytes, header + 0x10)? as usize;
        let offset = read_u64_le(&bytes, header + 0x18)? as usize;
        let size = read_u64_le(&bytes, header + 0x20)? as usize;
        return Some((bytes.get(offset..offset.checked_add(size)?)?.to_vec(), addr));
    }

    None
}

fn c_string_at(bytes: &[u8], offset: usize) -> Option<&str> {
    let tail = bytes.get(offset..)?;
    let end = tail.iter().position(|byte| *byte == 0)?;
    std::str::from_utf8(&tail[..end]).ok()
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}
