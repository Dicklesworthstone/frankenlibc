// AUTO-GENERATED snapshot from tools/stdio_synth/spec/printf_grammar.json.
// DO NOT EDIT BY HAND UNLESS THE GENERATOR SHAPE CHANGES.

use super::{ArgCategory, PrintfHandler, PrintfRoute};

const INVALID_ROUTE: PrintfRoute = PrintfRoute {
    handler: PrintfHandler::Invalid,
    length_mask: 0,
    flag_mask: 0,
    arg_category: ArgCategory::None,
};

const fn route(
    handler: PrintfHandler,
    length_mask: u8,
    flag_mask: u8,
    arg_category: ArgCategory,
) -> PrintfRoute {
    PrintfRoute {
        handler,
        length_mask,
        flag_mask,
        arg_category,
    }
}

pub const PRINTF_TABLE: [PrintfRoute; 256] = {
    let mut table = [INVALID_ROUTE; 256];

    table[b'd' as usize] = route(
        PrintfHandler::SignedDecimal,
        0b0111_1111,
        0b0001_1111,
        ArgCategory::SignedInt,
    );
    table[b'i' as usize] = route(
        PrintfHandler::SignedDecimal,
        0b0111_1111,
        0b0001_1111,
        ArgCategory::SignedInt,
    );
    table[b'o' as usize] = route(
        PrintfHandler::UnsignedOctal,
        0b0111_1111,
        0b0001_1001,
        ArgCategory::UnsignedInt,
    );
    table[b'u' as usize] = route(
        PrintfHandler::UnsignedDecimal,
        0b0111_1111,
        0b0001_0001,
        ArgCategory::UnsignedInt,
    );
    table[b'x' as usize] = route(
        PrintfHandler::UnsignedHexLower,
        0b0111_1111,
        0b0001_1001,
        ArgCategory::UnsignedInt,
    );
    table[b'X' as usize] = route(
        PrintfHandler::UnsignedHexUpper,
        0b0111_1111,
        0b0001_1001,
        ArgCategory::UnsignedInt,
    );
    table[b'f' as usize] = route(
        PrintfHandler::FloatFixed,
        0b1000_0100,
        0b0001_1111,
        ArgCategory::Float,
    );
    table[b'F' as usize] = route(
        PrintfHandler::FloatFixed,
        0b1000_0100,
        0b0001_1111,
        ArgCategory::Float,
    );
    table[b'e' as usize] = route(
        PrintfHandler::FloatExp,
        0b1000_0100,
        0b0001_1111,
        ArgCategory::Float,
    );
    table[b'E' as usize] = route(
        PrintfHandler::FloatExp,
        0b1000_0100,
        0b0001_1111,
        ArgCategory::Float,
    );
    table[b'g' as usize] = route(
        PrintfHandler::FloatGeneral,
        0b1000_0100,
        0b0001_1111,
        ArgCategory::Float,
    );
    table[b'G' as usize] = route(
        PrintfHandler::FloatGeneral,
        0b1000_0100,
        0b0001_1111,
        ArgCategory::Float,
    );
    table[b'a' as usize] = route(
        PrintfHandler::FloatHex,
        0b1000_0100,
        0b0001_1111,
        ArgCategory::Float,
    );
    table[b'A' as usize] = route(
        PrintfHandler::FloatHex,
        0b1000_0100,
        0b0001_1111,
        ArgCategory::Float,
    );
    table[b'c' as usize] = route(
        PrintfHandler::Character,
        0b0000_0100,
        0b0000_0001,
        ArgCategory::SignedInt,
    );
    table[b's' as usize] = route(
        PrintfHandler::String,
        0b0000_0100,
        0b0000_0001,
        ArgCategory::String,
    );
    table[b'p' as usize] = route(PrintfHandler::Pointer, 0, 0b0000_0001, ArgCategory::Pointer);
    table[b'n' as usize] = route(
        PrintfHandler::StoreCount,
        0b0111_1111,
        0,
        ArgCategory::Store,
    );
    table[b'%' as usize] = route(PrintfHandler::LiteralPercent, 0, 0, ArgCategory::None);

    table
};
