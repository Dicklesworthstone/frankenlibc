// AUTO-GENERATED snapshot from tools/stdio_synth/spec/scanf_grammar.json.
// DO NOT EDIT BY HAND UNLESS THE GENERATOR SHAPE CHANGES.

use super::{ScanfArgCategory, ScanfHandler, ScanfRoute};

const INVALID_ROUTE: ScanfRoute = ScanfRoute {
    handler: ScanfHandler::Invalid,
    length_mask: 0,
    skips_leading_whitespace: false,
    arg_category: ScanfArgCategory::None,
};

const fn route(
    handler: ScanfHandler,
    length_mask: u8,
    skips_leading_whitespace: bool,
    arg_category: ScanfArgCategory,
) -> ScanfRoute {
    ScanfRoute {
        handler,
        length_mask,
        skips_leading_whitespace,
        arg_category,
    }
}

pub const SCANF_TABLE: [ScanfRoute; 256] = {
    let mut table = [INVALID_ROUTE; 256];

    table[b'd' as usize] = route(
        ScanfHandler::SignedDecimal,
        0b0111_1111,
        true,
        ScanfArgCategory::SignedInt,
    );
    table[b'i' as usize] = route(
        ScanfHandler::SignedAutoBase,
        0b0111_1111,
        true,
        ScanfArgCategory::SignedInt,
    );
    table[b'u' as usize] = route(
        ScanfHandler::UnsignedDecimal,
        0b0111_1111,
        true,
        ScanfArgCategory::UnsignedInt,
    );
    table[b'o' as usize] = route(
        ScanfHandler::UnsignedOctal,
        0b0111_1111,
        true,
        ScanfArgCategory::UnsignedInt,
    );
    table[b'x' as usize] = route(
        ScanfHandler::UnsignedHex,
        0b0111_1111,
        true,
        ScanfArgCategory::UnsignedInt,
    );
    table[b'X' as usize] = route(
        ScanfHandler::UnsignedHex,
        0b0111_1111,
        true,
        ScanfArgCategory::UnsignedInt,
    );
    table[b'f' as usize] = route(
        ScanfHandler::Float,
        0b1000_0100,
        true,
        ScanfArgCategory::Float,
    );
    table[b'F' as usize] = route(
        ScanfHandler::Float,
        0b1000_0100,
        true,
        ScanfArgCategory::Float,
    );
    table[b'e' as usize] = route(
        ScanfHandler::Float,
        0b1000_0100,
        true,
        ScanfArgCategory::Float,
    );
    table[b'E' as usize] = route(
        ScanfHandler::Float,
        0b1000_0100,
        true,
        ScanfArgCategory::Float,
    );
    table[b'g' as usize] = route(
        ScanfHandler::Float,
        0b1000_0100,
        true,
        ScanfArgCategory::Float,
    );
    table[b'G' as usize] = route(
        ScanfHandler::Float,
        0b1000_0100,
        true,
        ScanfArgCategory::Float,
    );
    table[b'a' as usize] = route(
        ScanfHandler::Float,
        0b1000_0100,
        true,
        ScanfArgCategory::Float,
    );
    table[b'A' as usize] = route(
        ScanfHandler::Float,
        0b1000_0100,
        true,
        ScanfArgCategory::Float,
    );
    table[b'c' as usize] = route(
        ScanfHandler::Character,
        0b0000_0100,
        false,
        ScanfArgCategory::CharBuffer,
    );
    table[b's' as usize] = route(
        ScanfHandler::String,
        0b0000_0100,
        true,
        ScanfArgCategory::StringBuffer,
    );
    table[b'[' as usize] = route(
        ScanfHandler::Scanset,
        0b0000_0100,
        false,
        ScanfArgCategory::StringBuffer,
    );
    table[b'n' as usize] = route(
        ScanfHandler::CharsConsumed,
        0b0111_1111,
        false,
        ScanfArgCategory::Store,
    );
    table[b'p' as usize] = route(ScanfHandler::Pointer, 0, true, ScanfArgCategory::Pointer);

    table
};
