#![cfg(all(feature = "standalone", feature = "owned-unwind-stub"))]

use frankenlibc_abi::owned_unwind_abi::{
    __deregister_frame, __deregister_frame_info, __register_frame, __register_frame_info,
    _Unwind_Backtrace, _Unwind_GetDataRelBase, _Unwind_GetGR, _Unwind_GetIP,
    _Unwind_GetLanguageSpecificData, _Unwind_GetRegionStart, _Unwind_GetTextRelBase, _Unwind_SetGR,
    _Unwind_SetIP, OwnedPhase1SearchOutcome, OwnedPhase2CleanupOutcome, OwnedUnwindDecodeError,
    UnwindContext, owned_decode_sleb128_for_tests, owned_decode_uleb128_for_tests,
    owned_find_fde_for_ip_for_tests, owned_first_fde_for_tests,
    owned_frame_is_registered_for_tests, owned_frame_object_for_tests,
    owned_phase1_search_for_tests, owned_phase2_cleanup_for_tests,
    owned_summarize_eh_frame_for_tests, owned_validate_cfi_program_for_tests,
};
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::process::Command;

const URC_NO_REASON: i32 = 0;
const URC_FATAL_PHASE1_ERROR: i32 = 3;
const URC_HANDLER_FOUND: i32 = 6;
const URC_INSTALL_CONTEXT: i32 = 7;
const URC_CONTINUE_UNWIND: i32 = 8;
const UA_SEARCH_PHASE: i32 = 1;
const UA_CLEANUP_PHASE: i32 = 2;
const UA_HANDLER_FRAME: i32 = 4;
const TEST_EXCEPTION_CLASS: u64 = 0x4652_4b4e_432b_2b00;
const TEST_LANDING_PAD: usize = 0x5eed_baad;
static TEST_LSDA: [u8; 4] = [0x01, 0x02, 0x03, 0x04];

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
fn phase1_search_invokes_personality_with_lsda_context() {
    let section_addr = 0x500000usize;
    let pc_begin = 0x502000usize;
    let pc_range = 0x80usize;
    let eh_frame = synthetic_personality_eh_frame(
        section_addr,
        pc_begin,
        pc_range,
        handler_personality as *const () as usize,
        TEST_LSDA.as_ptr() as usize,
    );

    let fde = owned_find_fde_for_ip_for_tests(&eh_frame, section_addr, pc_begin + 4)
        .expect("personality FDE should decode")
        .expect("IP should resolve");
    assert_eq!(
        fde.personality,
        Some(handler_personality as *const () as usize)
    );
    assert_eq!(
        fde.language_specific_data,
        Some(TEST_LSDA.as_ptr() as usize)
    );

    let outcome = owned_phase1_search_for_tests(
        &eh_frame,
        section_addr,
        &[pc_begin + 4],
        TEST_EXCEPTION_CLASS,
    )
    .expect("phase1 search should decode");
    assert_eq!(
        outcome,
        OwnedPhase1SearchOutcome::HandlerFound {
            frame_index: 0,
            ip: pc_begin + 4,
            region_start: pc_begin,
            language_specific_data: TEST_LSDA.as_ptr() as usize,
        }
    );
}

#[test]
fn phase1_search_distinguishes_no_handler_and_fatal_personality_results() {
    let section_addr = 0x510000usize;
    let pc_begin = 0x512000usize;
    let pc_range = 0x40usize;
    let no_handler = synthetic_personality_eh_frame(
        section_addr,
        pc_begin,
        pc_range,
        continue_personality as *const () as usize,
        TEST_LSDA.as_ptr() as usize,
    );
    assert_eq!(
        owned_phase1_search_for_tests(&no_handler, section_addr, &[pc_begin + 1], 0)
            .expect("no-handler search should decode"),
        OwnedPhase1SearchOutcome::NoHandler
    );

    let fatal = synthetic_personality_eh_frame(
        section_addr,
        pc_begin,
        pc_range,
        fatal_personality as *const () as usize,
        TEST_LSDA.as_ptr() as usize,
    );
    assert_eq!(
        owned_phase1_search_for_tests(&fatal, section_addr, &[pc_begin + 1], 0)
            .expect("fatal search should decode"),
        OwnedPhase1SearchOutcome::Fatal {
            frame_index: 0,
            code: URC_INSTALL_CONTEXT,
        }
    );
}

#[test]
fn phase2_cleanup_records_install_context_without_transfer() {
    assert_eq!(unsafe { _Unwind_GetGR(std::ptr::null_mut(), 0) }, 0);
    assert_eq!(unsafe { _Unwind_GetGR(std::ptr::null_mut(), -1) }, 0);

    let section_addr = 0x530000usize;
    let pc_begin = 0x532000usize;
    let pc_range = 0x40usize;
    let eh_frame = synthetic_personality_eh_frame(
        section_addr,
        pc_begin,
        pc_range,
        install_context_personality as *const () as usize,
        TEST_LSDA.as_ptr() as usize,
    );

    let outcome =
        owned_phase2_cleanup_for_tests(&eh_frame, section_addr, pc_begin + 1, TEST_EXCEPTION_CLASS)
            .expect("phase2 cleanup should decode");
    match outcome {
        OwnedPhase2CleanupOutcome::InstallRequested {
            frame_index,
            ip,
            general_register_0,
            general_register_1,
        } => {
            assert_eq!(frame_index, 0);
            assert_eq!(ip, TEST_LANDING_PAD);
            assert_ne!(general_register_0, 0);
            assert_eq!(general_register_1, 0x55aa);
        }
        other => panic!("expected install request, got {other:?}"),
    }
}

#[test]
fn phase2_cleanup_classifies_continue_and_fatal_without_transfer() {
    let section_addr = 0x540000usize;
    let pc_begin = 0x542000usize;
    let pc_range = 0x40usize;
    let no_handler = synthetic_personality_eh_frame(
        section_addr,
        pc_begin,
        pc_range,
        continue_personality as *const () as usize,
        TEST_LSDA.as_ptr() as usize,
    );
    assert_eq!(
        owned_phase2_cleanup_for_tests(&no_handler, section_addr, pc_begin + 1, 0)
            .expect("continue cleanup should decode"),
        OwnedPhase2CleanupOutcome::ContinueUnwind
    );

    let fatal = synthetic_personality_eh_frame(
        section_addr,
        pc_begin,
        pc_range,
        phase2_fatal_personality as *const () as usize,
        TEST_LSDA.as_ptr() as usize,
    );
    assert_eq!(
        owned_phase2_cleanup_for_tests(&fatal, section_addr, pc_begin + 1, 0)
            .expect("fatal cleanup should decode"),
        OwnedPhase2CleanupOutcome::Fatal {
            frame_index: 0,
            code: URC_FATAL_PHASE1_ERROR,
        }
    );
}

#[test]
fn unsupported_lsda_pointer_encoding_fails_closed() {
    let section_addr = 0x520000usize;
    let pc_begin = 0x522000usize;
    let bad = synthetic_bad_lsda_encoding_eh_frame(
        section_addr,
        pc_begin,
        0x30,
        handler_personality as *const () as usize,
    );

    assert_eq!(
        owned_phase1_search_for_tests(&bad, section_addr, &[pc_begin + 1], TEST_EXCEPTION_CLASS),
        Err(OwnedUnwindDecodeError::UnsupportedPointerEncoding(0x70))
    );
}

#[test]
fn minimal_throw_catch_fixture_has_phase1_personality_lsda_metadata() {
    let root = workspace_root();
    let fixture = root.join("tests/conformance/fixtures/unwind/minimal_throw_catch.cpp");
    let binary = root.join("target/conformance/minimal_throw_catch");
    std::fs::create_dir_all(binary.parent().expect("target/conformance parent"))
        .expect("create target/conformance");
    let status = Command::new("g++")
        .current_dir(&root)
        .arg("-o")
        .arg(&binary)
        .arg(&fixture)
        .arg("-static-libgcc")
        .arg("-static-libstdc++")
        .status()
        .expect("run g++ for minimal_throw_catch fixture");
    assert!(status.success(), "g++ failed with status {status}");

    let (eh_frame, section_addr) =
        elf_section(&binary, ".eh_frame").expect("minimal fixture should contain .eh_frame");
    let summary = owned_summarize_eh_frame_for_tests(&eh_frame, section_addr)
        .expect("minimal fixture .eh_frame should decode");
    assert!(summary.fde_count > 0, "minimal fixture should have FDEs");
    assert!(
        summary.personality_fde_count > 0,
        "minimal fixture should include personality-backed FDEs"
    );
    assert!(
        summary.lsda_fde_count > 0,
        "minimal fixture should include LSDA-backed FDEs"
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
    encode_uleb(0, &mut fde_body);
    fde_body.extend_from_slice(cfi);
    bytes.extend_from_slice(&(fde_body.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&fde_body);
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes
}

fn synthetic_personality_eh_frame(
    section_addr: usize,
    pc_begin: usize,
    pc_range: usize,
    personality: usize,
    lsda: usize,
) -> Vec<u8> {
    synthetic_personality_eh_frame_with_lsda_encoding(
        section_addr,
        pc_begin,
        pc_range,
        personality,
        lsda,
        0x00,
    )
}

fn synthetic_bad_lsda_encoding_eh_frame(
    section_addr: usize,
    pc_begin: usize,
    pc_range: usize,
    personality: usize,
) -> Vec<u8> {
    synthetic_personality_eh_frame_with_lsda_encoding(
        section_addr,
        pc_begin,
        pc_range,
        personality,
        TEST_LSDA.as_ptr() as usize,
        0x70,
    )
}

fn synthetic_personality_eh_frame_with_lsda_encoding(
    section_addr: usize,
    pc_begin: usize,
    pc_range: usize,
    personality: usize,
    lsda: usize,
    lsda_encoding: u8,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    let cie_offset = bytes.len();
    let mut cie_body = Vec::new();
    cie_body.extend_from_slice(&0u32.to_le_bytes());
    cie_body.push(1);
    cie_body.extend_from_slice(b"zPLR\0");
    encode_uleb(1, &mut cie_body);
    encode_sleb(-8, &mut cie_body);
    cie_body.push(16);
    let augmentation_len_offset = cie_body.len();
    encode_uleb(0, &mut cie_body);
    let augmentation_start = cie_body.len();
    cie_body.push(0x00);
    cie_body.extend_from_slice(&personality.to_le_bytes());
    cie_body.push(lsda_encoding);
    cie_body.push(0x1b);
    let augmentation_len = cie_body.len() - augmentation_start;
    cie_body[augmentation_len_offset] = augmentation_len as u8;
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
    let augmentation_len_offset = fde_body.len();
    encode_uleb(0, &mut fde_body);
    let augmentation_start = fde_body.len();
    if lsda_encoding == 0x00 {
        fde_body.extend_from_slice(&lsda.to_le_bytes());
    } else {
        fde_body.push(0);
    }
    let augmentation_len = fde_body.len() - augmentation_start;
    fde_body[augmentation_len_offset] = augmentation_len as u8;
    fde_body.extend_from_slice(&[0x0c, 0x07, 0x08]);
    bytes.extend_from_slice(&(fde_body.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&fde_body);
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes
}

unsafe extern "C" fn handler_personality(
    version: i32,
    actions: i32,
    exception_class: u64,
    _exception: *mut frankenlibc_abi::owned_unwind_abi::UnwindException,
    ctx: *mut UnwindContext,
) -> i32 {
    let lsda = unsafe { _Unwind_GetLanguageSpecificData(ctx) };
    let region_start = unsafe { _Unwind_GetRegionStart(ctx) };
    let text_rel = unsafe { _Unwind_GetTextRelBase(ctx) };
    let data_rel = unsafe { _Unwind_GetDataRelBase(ctx) };
    if version == 1
        && actions == UA_SEARCH_PHASE
        && exception_class == TEST_EXCEPTION_CLASS
        && !lsda.is_null()
        && region_start != 0
        && text_rel == 0
        && data_rel == 0
    {
        URC_HANDLER_FOUND
    } else {
        URC_FATAL_PHASE1_ERROR
    }
}

unsafe extern "C" fn continue_personality(
    _version: i32,
    _actions: i32,
    _exception_class: u64,
    _exception: *mut frankenlibc_abi::owned_unwind_abi::UnwindException,
    _ctx: *mut UnwindContext,
) -> i32 {
    URC_CONTINUE_UNWIND
}

unsafe extern "C" fn install_context_personality(
    version: i32,
    actions: i32,
    exception_class: u64,
    exception: *mut frankenlibc_abi::owned_unwind_abi::UnwindException,
    ctx: *mut UnwindContext,
) -> i32 {
    if version != 1
        || actions != (UA_CLEANUP_PHASE | UA_HANDLER_FRAME)
        || exception_class != TEST_EXCEPTION_CLASS
        || exception.is_null()
    {
        return URC_FATAL_PHASE1_ERROR;
    }

    unsafe { _Unwind_SetGR(ctx, 0, exception as usize) };
    unsafe { _Unwind_SetGR(ctx, 1, 0x55aa) };
    unsafe { _Unwind_SetGR(ctx, 99, 0xfeed) };
    unsafe { _Unwind_SetGR(ctx, -1, 0xbeef) };
    unsafe { _Unwind_SetIP(ctx, TEST_LANDING_PAD) };

    if unsafe { _Unwind_GetGR(ctx, 0) } == exception as usize
        && unsafe { _Unwind_GetGR(ctx, 1) } == 0x55aa
        && unsafe { _Unwind_GetGR(ctx, 99) } == 0
        && unsafe { _Unwind_GetGR(ctx, -1) } == 0
        && unsafe { _Unwind_GetGR(std::ptr::null_mut(), 0) } == 0
        && unsafe { _Unwind_GetIP(ctx) } == TEST_LANDING_PAD
    {
        URC_INSTALL_CONTEXT
    } else {
        URC_FATAL_PHASE1_ERROR
    }
}

unsafe extern "C" fn phase2_fatal_personality(
    _version: i32,
    _actions: i32,
    _exception_class: u64,
    _exception: *mut frankenlibc_abi::owned_unwind_abi::UnwindException,
    _ctx: *mut UnwindContext,
) -> i32 {
    URC_FATAL_PHASE1_ERROR
}

unsafe extern "C" fn fatal_personality(
    _version: i32,
    _actions: i32,
    _exception_class: u64,
    _exception: *mut frankenlibc_abi::owned_unwind_abi::UnwindException,
    _ctx: *mut UnwindContext,
) -> i32 {
    URC_INSTALL_CONTEXT
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

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
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
