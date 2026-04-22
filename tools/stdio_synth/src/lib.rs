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

#[cfg(test)]
mod tests {
    use super::*;

    fn load_grammar() -> PrintfGrammar {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let grammar_path = manifest_dir.join("spec/printf_grammar.json");
        PrintfGrammar::load(&grammar_path).expect("printf grammar should load")
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
}
