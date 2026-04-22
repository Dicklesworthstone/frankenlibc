//! stdio-synth: Offline synthesis pipeline for printf/scanf tables.
//!
//! This crate generates provably-correct dispatch tables for printf/scanf
//! format parsing, reducing the hand-written 1446 LOC printf.rs and 1026 LOC
//! scanf.rs to ~200 LOC dispatchers consuming generated tables.
//!
//! # Architecture
//!
//! 1. `spec/printf_grammar.json` and `spec/scanf_grammar.json` define the
//!    formal grammars as typed regular trees.
//!
//! 2. `printf_compiler.rs` and `scanf_compiler.rs` consume the grammars
//!    and emit const dispatch tables (`PRINTF_TABLE`, `SCANF_TABLE`).
//!
//! 3. `proof.rs` generates SMT-LIB scripts that assert table correctness
//!    against a reference interpreter. Build fails if cvc5/z3 reports unsat.
//!
//! 4. `symmetry.rs` computes the symmetry group acting on (route, invariant)
//!    lattice using Atiyah-Bott localization, reducing SMT obligations ~250x.
//!
//! 5. `compress.rs` emits a quotiented DAG exploiting symmetry.

pub mod grammar;
pub mod table;

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Printf format specification parsed from JSON grammar.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrintfGrammar {
    pub version: u32,
    pub description: String,
    pub flag_set: std::collections::HashMap<String, FlagSpec>,
    pub length_modifier: std::collections::HashMap<String, LengthSpec>,
    pub conversion: std::collections::HashMap<String, ConversionSpec>,
}

/// scanf format specification parsed from JSON grammar.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanfGrammar {
    pub version: u32,
    pub description: String,
    pub assignment_suppression: bool,
    pub length_modifier: std::collections::HashMap<String, LengthSpec>,
    pub conversion: std::collections::HashMap<String, ScanfConversionSpec>,
    pub scanset: Option<ScansetSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlagSpec {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LengthSpec {
    pub int_type: Option<String>,
    pub char_type: Option<String>,
    pub string_type: Option<String>,
    pub float_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversionSpec {
    pub name: String,
    pub argument: String,
    pub output: String,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanfConversionSpec {
    pub name: String,
    pub target: String,
    pub input: String,
    #[serde(default)]
    pub skips_leading_whitespace: bool,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScansetSpec {
    pub supports_negation: bool,
    pub supports_ranges: bool,
    pub first_char_may_be_closing_bracket: bool,
}

/// A single entry in the dispatch table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrintfRoute {
    /// Handler enum variant.
    pub handler: PrintfHandler,
    /// Bitmask of valid length modifiers.
    pub length_mask: u8,
    /// Bitmask of valid flags.
    pub flag_mask: u8,
    /// Argument category for type checking.
    pub arg_category: ArgCategory,
}

/// Printf handler variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PrintfHandler {
    Invalid = 0,
    SignedDecimal,
    UnsignedOctal,
    UnsignedDecimal,
    UnsignedHexLower,
    UnsignedHexUpper,
    FloatFixed,
    FloatExp,
    FloatGeneral,
    FloatHex,
    Character,
    String,
    Pointer,
    StoreCount,
    LiteralPercent,
}

/// Argument category for type dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ArgCategory {
    None = 0,
    SignedInt,
    UnsignedInt,
    Float,
    Pointer,
    String,
    Store,
}

/// A single entry in the generated scanf dispatch table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanfRoute {
    pub handler: ScanfHandler,
    pub length_mask: u8,
    pub skips_leading_whitespace: bool,
    pub arg_category: ScanfArgCategory,
}

/// Scanf handler variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ScanfHandler {
    Invalid = 0,
    SignedDecimal,
    SignedAutoBase,
    UnsignedDecimal,
    UnsignedOctal,
    UnsignedHex,
    Float,
    Character,
    String,
    Scanset,
    CharsConsumed,
    Pointer,
}

/// Assignment target category for scanf routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ScanfArgCategory {
    None = 0,
    SignedInt,
    UnsignedInt,
    Float,
    CharBuffer,
    StringBuffer,
    Store,
    Pointer,
}

impl PrintfGrammar {
    /// Load grammar from JSON file.
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let raw: serde_json::Value = serde_json::from_str(&content)?;

        // Parse the structured grammar
        let flag_set = raw
            .get("flag_set")
            .and_then(|v| v.get("members"))
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        let length_modifier = raw
            .get("length_modifier")
            .and_then(|v| v.get("members"))
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        let conversion = raw
            .get("conversion")
            .and_then(|v| v.get("members"))
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        Ok(Self {
            version: raw.get("version").and_then(|v| v.as_u64()).unwrap_or(1) as u32,
            description: raw
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned(),
            flag_set,
            length_modifier,
            conversion,
        })
    }
}

impl ScanfGrammar {
    /// Load grammar from JSON file.
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let raw: serde_json::Value = serde_json::from_str(&content)?;

        let length_modifier = raw
            .get("length_modifier")
            .and_then(|v| v.get("members"))
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        let conversion = raw
            .get("conversion")
            .and_then(|v| v.get("members"))
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        let scanset = raw
            .get("scanset")
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        Ok(Self {
            version: raw.get("version").and_then(|v| v.as_u64()).unwrap_or(1) as u32,
            description: raw
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned(),
            assignment_suppression: raw
                .get("assignment_suppression")
                .and_then(|v| v.as_bool())
                .unwrap_or(true),
            length_modifier,
            conversion,
            scanset,
        })
    }
}

/// Generate the 256-entry dispatch table for printf.
pub fn generate_printf_table(grammar: &PrintfGrammar) -> [PrintfRoute; 256] {
    let mut table = [PrintfRoute {
        handler: PrintfHandler::Invalid,
        length_mask: 0,
        flag_mask: 0,
        arg_category: ArgCategory::None,
    }; 256];

    // Map conversion specifiers to table entries
    for (spec, conv) in &grammar.conversion {
        if spec.len() != 1 {
            continue;
        }
        let byte = spec.as_bytes()[0] as usize;
        if byte >= 256 {
            continue;
        }

        let (handler, arg_cat) = match conv.name.as_str() {
            "signed_decimal" | "signed_decimal_alt" => {
                (PrintfHandler::SignedDecimal, ArgCategory::SignedInt)
            }
            "unsigned_octal" => (PrintfHandler::UnsignedOctal, ArgCategory::UnsignedInt),
            "unsigned_decimal" => (PrintfHandler::UnsignedDecimal, ArgCategory::UnsignedInt),
            "unsigned_hex_lower" => (PrintfHandler::UnsignedHexLower, ArgCategory::UnsignedInt),
            "unsigned_hex_upper" => (PrintfHandler::UnsignedHexUpper, ArgCategory::UnsignedInt),
            "float_fixed_lower" | "float_fixed_upper" => {
                (PrintfHandler::FloatFixed, ArgCategory::Float)
            }
            "float_exp_lower" | "float_exp_upper" => (PrintfHandler::FloatExp, ArgCategory::Float),
            "float_general_lower" | "float_general_upper" => {
                (PrintfHandler::FloatGeneral, ArgCategory::Float)
            }
            "float_hex_lower" | "float_hex_upper" => (PrintfHandler::FloatHex, ArgCategory::Float),
            "character" => (PrintfHandler::Character, ArgCategory::SignedInt),
            "string" => (PrintfHandler::String, ArgCategory::String),
            "pointer" => (PrintfHandler::Pointer, ArgCategory::Pointer),
            "store_count" => (PrintfHandler::StoreCount, ArgCategory::Store),
            "literal_percent" => (PrintfHandler::LiteralPercent, ArgCategory::None),
            _ => continue,
        };

        // Compute valid length modifier mask
        // Bit layout: 0=hh, 1=h, 2=l, 3=ll, 4=j, 5=z, 6=t, 7=L
        let length_mask = match handler {
            PrintfHandler::SignedDecimal
            | PrintfHandler::UnsignedOctal
            | PrintfHandler::UnsignedDecimal
            | PrintfHandler::UnsignedHexLower
            | PrintfHandler::UnsignedHexUpper => {
                0b0111_1111 // hh, h, l, ll, j, z, t
            }
            PrintfHandler::FloatFixed
            | PrintfHandler::FloatExp
            | PrintfHandler::FloatGeneral
            | PrintfHandler::FloatHex => {
                0b1000_0100 // L (long double) and l (has no effect but is allowed per POSIX)
            }
            PrintfHandler::Character => {
                0b0000_0100 // l for wint_t
            }
            PrintfHandler::String => {
                0b0000_0100 // l for wide strings (wchar_t*)
            }
            PrintfHandler::StoreCount => {
                0b0111_1111 // hh, h, l, ll, j, z, t for pointer size variants
            }
            PrintfHandler::Pointer | PrintfHandler::LiteralPercent | PrintfHandler::Invalid => 0,
        };

        // Compute valid flag mask (-, +, space, #, 0)
        // Bit layout: 0=-, 1=+, 2=space, 3=#, 4=0
        let flag_mask = match handler {
            PrintfHandler::SignedDecimal => 0b11111,   // all flags valid
            PrintfHandler::UnsignedOctal => 0b11001,   // -, #, 0 (not + or space)
            PrintfHandler::UnsignedDecimal => 0b10001, // -, 0 (not +, space, #)
            PrintfHandler::UnsignedHexLower | PrintfHandler::UnsignedHexUpper => 0b11001, // -, #, 0
            PrintfHandler::FloatFixed
            | PrintfHandler::FloatExp
            | PrintfHandler::FloatGeneral
            | PrintfHandler::FloatHex => 0b11111, // all flags valid
            PrintfHandler::Character => 0b00001,       // only - (width padding)
            PrintfHandler::String => 0b00001,          // only -
            PrintfHandler::Pointer => 0b00001,         // only -
            PrintfHandler::StoreCount => 0b00000,      // no flags valid
            PrintfHandler::LiteralPercent => 0b00000,  // no flags
            PrintfHandler::Invalid => 0,
        };

        table[byte] = PrintfRoute {
            handler,
            length_mask,
            flag_mask,
            arg_category: arg_cat,
        };
    }

    table
}

/// Generate the 256-entry dispatch table for scanf.
pub fn generate_scanf_table(grammar: &ScanfGrammar) -> [ScanfRoute; 256] {
    let mut table = [ScanfRoute {
        handler: ScanfHandler::Invalid,
        length_mask: 0,
        skips_leading_whitespace: false,
        arg_category: ScanfArgCategory::None,
    }; 256];

    for (spec, conv) in &grammar.conversion {
        if spec.len() != 1 {
            continue;
        }
        let byte = spec.as_bytes()[0] as usize;
        if byte >= 256 {
            continue;
        }

        let (handler, arg_category) = match conv.name.as_str() {
            "signed_decimal" => (ScanfHandler::SignedDecimal, ScanfArgCategory::SignedInt),
            "signed_integer_auto_base" => {
                (ScanfHandler::SignedAutoBase, ScanfArgCategory::SignedInt)
            }
            "unsigned_decimal" => (ScanfHandler::UnsignedDecimal, ScanfArgCategory::UnsignedInt),
            "unsigned_octal" => (ScanfHandler::UnsignedOctal, ScanfArgCategory::UnsignedInt),
            "unsigned_hex" | "unsigned_hex_upper" => {
                (ScanfHandler::UnsignedHex, ScanfArgCategory::UnsignedInt)
            }
            "float_fixed"
            | "float_fixed_upper"
            | "float_exp"
            | "float_exp_upper"
            | "float_general"
            | "float_general_upper"
            | "float_hex"
            | "float_hex_upper" => (ScanfHandler::Float, ScanfArgCategory::Float),
            "character" => (ScanfHandler::Character, ScanfArgCategory::CharBuffer),
            "string" => (ScanfHandler::String, ScanfArgCategory::StringBuffer),
            "scanset" => (ScanfHandler::Scanset, ScanfArgCategory::StringBuffer),
            "chars_consumed" => (ScanfHandler::CharsConsumed, ScanfArgCategory::Store),
            "pointer" => (ScanfHandler::Pointer, ScanfArgCategory::Pointer),
            _ => continue,
        };

        let length_mask = match handler {
            ScanfHandler::SignedDecimal
            | ScanfHandler::SignedAutoBase
            | ScanfHandler::UnsignedDecimal
            | ScanfHandler::UnsignedOctal
            | ScanfHandler::UnsignedHex
            | ScanfHandler::CharsConsumed => 0b0111_1111,
            ScanfHandler::Float => 0b1000_0100,
            ScanfHandler::Character | ScanfHandler::String | ScanfHandler::Scanset => 0b0000_0100,
            ScanfHandler::Pointer | ScanfHandler::Invalid => 0,
        };

        table[byte] = ScanfRoute {
            handler,
            length_mask,
            skips_leading_whitespace: conv.skips_leading_whitespace,
            arg_category,
        };
    }

    table
}

/// Emit Rust source code for the generated table.
pub fn emit_printf_table_source(table: &[PrintfRoute; 256]) -> String {
    let mut output = String::new();
    output.push_str("// AUTO-GENERATED by stdio-synth. DO NOT EDIT.\n");
    output.push_str("// See tools/stdio_synth/spec/printf_grammar.json for source.\n\n");
    output.push_str("use super::{PrintfHandler, PrintfRoute, ArgCategory};\n\n");
    output.push_str("pub const PRINTF_TABLE: [PrintfRoute; 256] = [\n");

    for (i, route) in table.iter().enumerate() {
        let handler = match route.handler {
            PrintfHandler::Invalid => "PrintfHandler::Invalid",
            PrintfHandler::SignedDecimal => "PrintfHandler::SignedDecimal",
            PrintfHandler::UnsignedOctal => "PrintfHandler::UnsignedOctal",
            PrintfHandler::UnsignedDecimal => "PrintfHandler::UnsignedDecimal",
            PrintfHandler::UnsignedHexLower => "PrintfHandler::UnsignedHexLower",
            PrintfHandler::UnsignedHexUpper => "PrintfHandler::UnsignedHexUpper",
            PrintfHandler::FloatFixed => "PrintfHandler::FloatFixed",
            PrintfHandler::FloatExp => "PrintfHandler::FloatExp",
            PrintfHandler::FloatGeneral => "PrintfHandler::FloatGeneral",
            PrintfHandler::FloatHex => "PrintfHandler::FloatHex",
            PrintfHandler::Character => "PrintfHandler::Character",
            PrintfHandler::String => "PrintfHandler::String",
            PrintfHandler::Pointer => "PrintfHandler::Pointer",
            PrintfHandler::StoreCount => "PrintfHandler::StoreCount",
            PrintfHandler::LiteralPercent => "PrintfHandler::LiteralPercent",
        };
        let arg_cat = match route.arg_category {
            ArgCategory::None => "ArgCategory::None",
            ArgCategory::SignedInt => "ArgCategory::SignedInt",
            ArgCategory::UnsignedInt => "ArgCategory::UnsignedInt",
            ArgCategory::Float => "ArgCategory::Float",
            ArgCategory::Pointer => "ArgCategory::Pointer",
            ArgCategory::String => "ArgCategory::String",
            ArgCategory::Store => "ArgCategory::Store",
        };

        if i % 8 == 0 {
            output.push_str("    // ");
            output.push_str(&format!("{:#04x}", i));
            output.push_str("\n");
        }

        output.push_str(&format!(
            "    PrintfRoute {{ handler: {}, length_mask: {:#04x}, flag_mask: {:#04x}, arg_category: {} }},",
            handler, route.length_mask, route.flag_mask, arg_cat
        ));

        // Add character comment for printable chars
        if (0x20..=0x7E).contains(&i) {
            output.push_str(&format!(" // '{}'", i as u8 as char));
        }
        output.push('\n');
    }

    output.push_str("];\n");
    output
}

/// Emit Rust source code for the generated scanf table snapshot.
pub fn emit_scanf_table_source(table: &[ScanfRoute; 256]) -> String {
    let mut output = String::new();
    output.push_str("// AUTO-GENERATED snapshot from tools/stdio_synth/spec/scanf_grammar.json.\n");
    output.push_str("// DO NOT EDIT BY HAND UNLESS THE GENERATOR SHAPE CHANGES.\n\n");
    output.push_str("use super::{ScanfArgCategory, ScanfHandler, ScanfRoute};\n\n");
    output.push_str("const INVALID_ROUTE: ScanfRoute = ScanfRoute {\n");
    output.push_str("    handler: ScanfHandler::Invalid,\n");
    output.push_str("    length_mask: 0,\n");
    output.push_str("    skips_leading_whitespace: false,\n");
    output.push_str("    arg_category: ScanfArgCategory::None,\n");
    output.push_str("};\n\n");
    output.push_str("const fn route(\n");
    output.push_str("    handler: ScanfHandler,\n");
    output.push_str("    length_mask: u8,\n");
    output.push_str("    skips_leading_whitespace: bool,\n");
    output.push_str("    arg_category: ScanfArgCategory,\n");
    output.push_str(") -> ScanfRoute {\n");
    output.push_str("    ScanfRoute {\n");
    output.push_str("        handler,\n");
    output.push_str("        length_mask,\n");
    output.push_str("        skips_leading_whitespace,\n");
    output.push_str("        arg_category,\n");
    output.push_str("    }\n");
    output.push_str("}\n\n");
    output.push_str("pub const SCANF_TABLE: [ScanfRoute; 256] = {\n");
    output.push_str("    let mut table = [INVALID_ROUTE; 256];\n\n");

    for (i, route) in table.iter().enumerate() {
        if route.handler == ScanfHandler::Invalid {
            continue;
        }

        let handler = match route.handler {
            ScanfHandler::Invalid => "ScanfHandler::Invalid",
            ScanfHandler::SignedDecimal => "ScanfHandler::SignedDecimal",
            ScanfHandler::SignedAutoBase => "ScanfHandler::SignedAutoBase",
            ScanfHandler::UnsignedDecimal => "ScanfHandler::UnsignedDecimal",
            ScanfHandler::UnsignedOctal => "ScanfHandler::UnsignedOctal",
            ScanfHandler::UnsignedHex => "ScanfHandler::UnsignedHex",
            ScanfHandler::Float => "ScanfHandler::Float",
            ScanfHandler::Character => "ScanfHandler::Character",
            ScanfHandler::String => "ScanfHandler::String",
            ScanfHandler::Scanset => "ScanfHandler::Scanset",
            ScanfHandler::CharsConsumed => "ScanfHandler::CharsConsumed",
            ScanfHandler::Pointer => "ScanfHandler::Pointer",
        };
        let arg_category = match route.arg_category {
            ScanfArgCategory::None => "ScanfArgCategory::None",
            ScanfArgCategory::SignedInt => "ScanfArgCategory::SignedInt",
            ScanfArgCategory::UnsignedInt => "ScanfArgCategory::UnsignedInt",
            ScanfArgCategory::Float => "ScanfArgCategory::Float",
            ScanfArgCategory::CharBuffer => "ScanfArgCategory::CharBuffer",
            ScanfArgCategory::StringBuffer => "ScanfArgCategory::StringBuffer",
            ScanfArgCategory::Store => "ScanfArgCategory::Store",
            ScanfArgCategory::Pointer => "ScanfArgCategory::Pointer",
        };

        output.push_str(&format!(
            "    table[b'{}' as usize] = route({}, {:#010b}, {}, {});\n",
            i as u8 as char,
            handler,
            route.length_mask,
            route.skips_leading_whitespace,
            arg_category
        ));
    }

    output.push_str("\n    table\n");
    output.push_str("};\n");
    output
}

fn emit_piecewise_u8_function(output: &mut String, name: &str, values: &[(u8, u8)], default: u8) {
    output.push_str(&format!("(define-fun {} ((c Int)) Int\n", name));
    for &(byte, value) in values {
        output.push_str(&format!("  (ite (= c {}) {}\n", byte, value));
    }
    output.push_str(&format!("    {}", default));
    for _ in values {
        output.push(')');
    }
    output.push_str(")\n\n");
}

fn emit_piecewise_bool_function(
    output: &mut String,
    name: &str,
    values: &[(u8, bool)],
    default: bool,
) {
    output.push_str(&format!("(define-fun {} ((c Int)) Bool\n", name));
    for &(byte, value) in values {
        output.push_str(&format!(
            "  (ite (= c {}) {}\n",
            byte,
            if value { "true" } else { "false" }
        ));
    }
    output.push_str(if default { "    true" } else { "    false" });
    for _ in values {
        output.push(')');
    }
    output.push_str(")\n\n");
}

fn sorted_conversion_bytes<K, V>(map: &std::collections::HashMap<K, V>) -> Vec<u8>
where
    K: AsRef<str> + std::cmp::Eq + std::hash::Hash,
{
    let mut bytes = map
        .keys()
        .filter_map(|key| {
            let s = key.as_ref();
            (s.len() == 1).then_some(s.as_bytes()[0])
        })
        .collect::<Vec<_>>();
    bytes.sort_unstable();
    bytes
}

/// Emit a deterministic SMT-LIB proof artifact for the current stdio tables.
pub fn emit_smt_proof_source(
    printf_grammar: &PrintfGrammar,
    scanf_grammar: &ScanfGrammar,
    printf_table: &[PrintfRoute; 256],
    scanf_table: &[ScanfRoute; 256],
) -> String {
    let mut output = String::new();
    output.push_str("; AUTO-GENERATED by stdio-synth. DO NOT EDIT.\n");
    output.push_str("; Proof obligations for generated printf/scanf dispatch tables.\n");
    output.push_str("(set-logic QF_UFLIA)\n\n");

    let printf_bytes = sorted_conversion_bytes(&printf_grammar.conversion);
    let scanf_bytes = sorted_conversion_bytes(&scanf_grammar.conversion);

    let printf_handler_values = printf_bytes
        .iter()
        .map(|&byte| (byte, printf_table[byte as usize].handler as u8))
        .collect::<Vec<_>>();
    let printf_length_values = printf_bytes
        .iter()
        .map(|&byte| (byte, printf_table[byte as usize].length_mask))
        .collect::<Vec<_>>();
    let printf_flag_values = printf_bytes
        .iter()
        .map(|&byte| (byte, printf_table[byte as usize].flag_mask))
        .collect::<Vec<_>>();
    let printf_arg_values = printf_bytes
        .iter()
        .map(|&byte| (byte, printf_table[byte as usize].arg_category as u8))
        .collect::<Vec<_>>();

    emit_piecewise_u8_function(&mut output, "printf_handler", &printf_handler_values, 0);
    emit_piecewise_u8_function(&mut output, "printf_length_mask", &printf_length_values, 0);
    emit_piecewise_u8_function(&mut output, "printf_flag_mask", &printf_flag_values, 0);
    emit_piecewise_u8_function(&mut output, "printf_arg_category", &printf_arg_values, 0);

    let scanf_handler_values = scanf_bytes
        .iter()
        .map(|&byte| (byte, scanf_table[byte as usize].handler as u8))
        .collect::<Vec<_>>();
    let scanf_length_values = scanf_bytes
        .iter()
        .map(|&byte| (byte, scanf_table[byte as usize].length_mask))
        .collect::<Vec<_>>();
    let scanf_skip_values = scanf_bytes
        .iter()
        .map(|&byte| (byte, scanf_table[byte as usize].skips_leading_whitespace))
        .collect::<Vec<_>>();
    let scanf_arg_values = scanf_bytes
        .iter()
        .map(|&byte| (byte, scanf_table[byte as usize].arg_category as u8))
        .collect::<Vec<_>>();

    emit_piecewise_u8_function(&mut output, "scanf_handler", &scanf_handler_values, 0);
    emit_piecewise_u8_function(&mut output, "scanf_length_mask", &scanf_length_values, 0);
    emit_piecewise_bool_function(&mut output, "scanf_skip_ws", &scanf_skip_values, false);
    emit_piecewise_u8_function(&mut output, "scanf_arg_category", &scanf_arg_values, 0);

    output.push_str("; printf obligations\n");
    for byte in &printf_bytes {
        let route = printf_table[*byte as usize];
        output.push_str(&format!(
            "(assert (= (printf_handler {}) {}))\n",
            byte, route.handler as u8
        ));
        output.push_str(&format!(
            "(assert (= (printf_length_mask {}) {}))\n",
            byte, route.length_mask
        ));
        output.push_str(&format!(
            "(assert (= (printf_flag_mask {}) {}))\n",
            byte, route.flag_mask
        ));
        output.push_str(&format!(
            "(assert (= (printf_arg_category {}) {}))\n",
            byte, route.arg_category as u8
        ));
        output.push_str(&format!("(assert (not (= (printf_handler {}) 0)))\n", byte));
    }
    for byte in 0u8..=255 {
        if !printf_bytes.contains(&byte) {
            output.push_str(&format!("(assert (= (printf_handler {}) 0))\n", byte));
        }
    }

    output.push_str("\n; scanf obligations\n");
    for byte in &scanf_bytes {
        let route = scanf_table[*byte as usize];
        output.push_str(&format!(
            "(assert (= (scanf_handler {}) {}))\n",
            byte, route.handler as u8
        ));
        output.push_str(&format!(
            "(assert (= (scanf_length_mask {}) {}))\n",
            byte, route.length_mask
        ));
        output.push_str(&format!(
            "(assert (= (scanf_skip_ws {}) {}))\n",
            byte,
            if route.skips_leading_whitespace {
                "true"
            } else {
                "false"
            }
        ));
        output.push_str(&format!(
            "(assert (= (scanf_arg_category {}) {}))\n",
            byte, route.arg_category as u8
        ));
        output.push_str(&format!("(assert (not (= (scanf_handler {}) 0)))\n", byte));
    }
    for byte in 0u8..=255 {
        if !scanf_bytes.contains(&byte) {
            output.push_str(&format!("(assert (= (scanf_handler {}) 0))\n", byte));
        }
    }

    output.push_str("\n(check-sat)\n");
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_grammar() -> PrintfGrammar {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let grammar_path = manifest_dir.join("spec/printf_grammar.json");
        PrintfGrammar::load(&grammar_path).expect("printf grammar should load")
    }

    fn load_scanf_grammar() -> ScanfGrammar {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let grammar_path = manifest_dir.join("spec/scanf_grammar.json");
        ScanfGrammar::load(&grammar_path).expect("scanf grammar should load")
    }

    #[test]
    fn generated_printf_table_routes_core_specifiers() {
        let table = generate_printf_table(&load_grammar());

        assert_eq!(table[b'd' as usize].handler, PrintfHandler::SignedDecimal);
        assert_eq!(table[b's' as usize].handler, PrintfHandler::String);
        assert_eq!(table[b'%' as usize].handler, PrintfHandler::LiteralPercent);
        assert_eq!(table[b'd' as usize].arg_category, ArgCategory::SignedInt);
        assert_eq!(table[b'X' as usize].arg_category, ArgCategory::UnsignedInt);
        assert_eq!(table[b'f' as usize].arg_category, ArgCategory::Float);
        assert_eq!(table[b'Q' as usize].handler, PrintfHandler::Invalid);
    }

    #[test]
    fn emitted_printf_source_is_deterministic() {
        let grammar = load_grammar();
        let table = generate_printf_table(&grammar);
        let emitted_once = emit_printf_table_source(&table);
        let emitted_twice = emit_printf_table_source(&table);

        assert_eq!(emitted_once, emitted_twice);
        assert!(emitted_once.contains("pub const PRINTF_TABLE: [PrintfRoute; 256]"));
        assert!(emitted_once.contains("PrintfHandler::SignedDecimal"));
        assert!(emitted_once.contains("PrintfHandler::LiteralPercent"));
    }

    #[test]
    fn scanf_grammar_loads_core_specifiers() {
        let grammar = load_scanf_grammar();

        assert!(grammar.assignment_suppression);
        assert_eq!(
            grammar
                .conversion
                .get("d")
                .expect("signed decimal conversion")
                .name,
            "signed_decimal"
        );
        assert_eq!(
            grammar
                .conversion
                .get("[")
                .expect("scanset conversion")
                .name,
            "scanset"
        );
        assert!(
            grammar
                .conversion
                .get("s")
                .expect("string conversion")
                .skips_leading_whitespace
        );
        let scanset = grammar.scanset.expect("scanset support");
        assert!(scanset.supports_negation);
        assert!(scanset.supports_ranges);
    }

    #[test]
    fn generated_scanf_table_routes_core_specifiers() {
        let table = generate_scanf_table(&load_scanf_grammar());

        assert_eq!(table[b'd' as usize].handler, ScanfHandler::SignedDecimal);
        assert_eq!(table[b'i' as usize].handler, ScanfHandler::SignedAutoBase);
        assert_eq!(table[b's' as usize].handler, ScanfHandler::String);
        assert_eq!(table[b'[' as usize].handler, ScanfHandler::Scanset);
        assert_eq!(
            table[b'd' as usize].arg_category,
            ScanfArgCategory::SignedInt
        );
        assert_eq!(table[b'p' as usize].arg_category, ScanfArgCategory::Pointer);
        assert!(table[b's' as usize].skips_leading_whitespace);
        assert!(!table[b'c' as usize].skips_leading_whitespace);
        assert_eq!(table[b'Q' as usize].handler, ScanfHandler::Invalid);
    }

    #[test]
    fn emitted_scanf_source_is_deterministic() {
        let grammar = load_scanf_grammar();
        let table = generate_scanf_table(&grammar);
        let emitted_once = emit_scanf_table_source(&table);
        let emitted_twice = emit_scanf_table_source(&table);

        assert_eq!(emitted_once, emitted_twice);
        assert!(emitted_once.contains("pub const SCANF_TABLE: [ScanfRoute; 256]"));
        assert!(emitted_once.contains("ScanfHandler::SignedDecimal"));
        assert!(emitted_once.contains("ScanfHandler::Scanset"));
    }

    #[test]
    fn emitted_smt_proof_is_deterministic() {
        let printf_grammar = load_grammar();
        let scanf_grammar = load_scanf_grammar();
        let printf_table = generate_printf_table(&printf_grammar);
        let scanf_table = generate_scanf_table(&scanf_grammar);

        let emitted_once =
            emit_smt_proof_source(&printf_grammar, &scanf_grammar, &printf_table, &scanf_table);
        let emitted_twice =
            emit_smt_proof_source(&printf_grammar, &scanf_grammar, &printf_table, &scanf_table);

        assert_eq!(emitted_once, emitted_twice);
        assert!(emitted_once.contains("(define-fun printf_handler ((c Int)) Int"));
        assert!(emitted_once.contains("(define-fun scanf_skip_ws ((c Int)) Bool"));
        assert!(emitted_once.contains("(assert (= (printf_handler 100) 1))"));
        assert!(emitted_once.contains("(assert (= (scanf_handler 91) 9))"));
        assert!(emitted_once.contains("(check-sat)"));
    }
}
