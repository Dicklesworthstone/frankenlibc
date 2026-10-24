//! Arithmetic for native ELF relocations that need a full word or symbol size.
use frankenlibc_core::elf::relocation::{
    Elf64Rela, RelocationContext, RelocationResult, RelocationType, compute_relocation,
    compute_size_relocation,
};

fn relocation(kind: RelocationType, offset: u64, addend: i64) -> Elf64Rela {
    Elf64Rela {
        r_offset: offset,
        r_info: (1u64 << 32) | u64::from(kind.to_u32()),
        r_addend: addend,
    }
}

#[test]
fn pc64_retains_bits_beyond_the_pc32_range() {
    let ctx = RelocationContext::new(0x1000);
    let rel = relocation(RelocationType::Pc64, 0x20, -7);
    for symbol in [0, 0x1010, 0x1_0000_0000, u64::MAX] {
        let expected = ((i128::from(symbol) - 7 - 0x1020) as u128 & u64::MAX as u128) as u64;
        assert_eq!(compute_relocation(&rel, symbol, &ctx), Ok((expected, 8)));
    }
    let narrow = relocation(RelocationType::Pc32, 0x20, -7);
    assert_eq!(
        compute_relocation(&narrow, 0x1_0000_0000, &ctx),
        Err(RelocationResult::Overflow)
    );
    let overflow_place = relocation(RelocationType::Pc64, u64::MAX, 0);
    assert_eq!(
        compute_relocation(&overflow_place, 0, &ctx),
        Err(RelocationResult::Overflow)
    );
}

#[test]
fn size_relocations_take_metadata_not_a_load_biased_address() {
    let ctx = RelocationContext::new(0x7f00_0000_0000);
    for (kind, width) in [(RelocationType::Size32, 4), (RelocationType::Size64, 8)] {
        let rel = relocation(kind, 0x2000, 5);
        assert_eq!(compute_size_relocation(&rel, 37), Ok((42, width)));
        assert_eq!(
            compute_relocation(&rel, 0x7f00_0000_4000, &ctx),
            Err(RelocationResult::Unsupported(kind.to_u32()))
        );
        assert_eq!(RelocationType::from(kind.to_u32()), kind);
        assert!(kind.is_supported() && kind.is_size() && !kind.is_tls());
    }
    assert_eq!(RelocationType::from(24), RelocationType::Pc64);
    assert!(RelocationType::Pc64.is_supported());
    assert!(!RelocationType::Pc64.is_size());
}

#[test]
fn sizes_and_signed_addends_obey_destination_word_width() {
    for size in [0, 1, 37, u32::MAX as u64, 1u64 << 32, u64::MAX] {
        for addend in [i64::MIN, -38, -1, 0, 5, i64::MAX] {
            let wide = ((i128::from(size) + i128::from(addend)) as u128 & u64::MAX as u128) as u64;
            assert_eq!(
                compute_size_relocation(&relocation(RelocationType::Size64, 0, addend), size),
                Ok((wide, 8))
            );
            assert_eq!(
                compute_size_relocation(&relocation(RelocationType::Size32, 0, addend), size),
                Ok((wide & u32::MAX as u64, 4))
            );
        }
    }
    assert_eq!(
        compute_size_relocation(&relocation(RelocationType::R64, 0, 1), 37),
        Err(RelocationResult::Unsupported(1))
    );
}
