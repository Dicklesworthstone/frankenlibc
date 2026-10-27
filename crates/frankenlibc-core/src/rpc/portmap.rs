//! Bounded portmapper v2 registration-list decoding.
//!
//! Parse the complete XDR list before the ABI allocates or publishes C nodes.
//! Wire integers remain unsigned 32-bit values, independent of C long width.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub program: u32,
    pub version: u32,
    pub protocol: u32,
    pub port: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MappingError {
    Truncated,
    TooManyEntries,
    Allocation,
}

fn word(bytes: &[u8], cursor: &mut usize) -> Result<u32, MappingError> {
    let end = cursor.checked_add(4).ok_or(MappingError::Truncated)?;
    let data = bytes.get(*cursor..end).ok_or(MappingError::Truncated)?;
    *cursor = end;
    Ok(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
}

/// Decode an XDR linked list with an explicit entry bound.
///
/// GNU accepts any nonzero list boolean and leaves trailing stream bytes to
/// the enclosing codec. A missing terminator or incomplete entry never yields
/// a partially decoded list.
pub fn decode_mappings(bytes: &[u8], limit: usize) -> Result<Vec<Mapping>, MappingError> {
    let mut cursor = 0;
    let mut result = Vec::new();
    while word(bytes, &mut cursor)? != 0 {
        if result.len() == limit {
            return Err(MappingError::TooManyEntries);
        }
        let mapping = Mapping {
            program: word(bytes, &mut cursor)?,
            version: word(bytes, &mut cursor)?,
            protocol: word(bytes, &mut cursor)?,
            port: word(bytes, &mut cursor)?,
        };
        result
            .try_reserve(1)
            .map_err(|_| MappingError::Allocation)?;
        result.push(mapping);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(values: &[u32]) -> Vec<u8> {
        values.iter().flat_map(|n| n.to_be_bytes()).collect()
    }

    #[test]
    fn mapping_list_preserves_order_and_unsigned_fields() {
        let bytes = words(&[1, 7, 8, 6, 5432, 1, u32::MAX, 10, 17, u32::MAX, 0]);
        assert_eq!(
            decode_mappings(&bytes, 2).unwrap(),
            [
                Mapping {
                    program: 7,
                    version: 8,
                    protocol: 6,
                    port: 5432
                },
                Mapping {
                    program: u32::MAX,
                    version: 10,
                    protocol: 17,
                    port: u32::MAX
                },
            ]
        );
    }

    #[test]
    fn mapping_list_empty_does_not_consume_an_entry() {
        assert_eq!(decode_mappings(&words(&[0]), 0), Ok(Vec::new()));
    }

    #[test]
    fn mapping_list_requires_every_word_and_final_terminator() {
        let bytes = words(&[1, 7, 8, 6, 5432, 1, 9, 10, 17, 1234, 0]);
        for length in 0..bytes.len() {
            assert_eq!(
                decode_mappings(&bytes[..length], 2),
                Err(MappingError::Truncated),
                "{length}"
            );
        }
    }

    #[test]
    fn mapping_list_limit_is_checked_before_growing_output() {
        let bytes = words(&[1, 7, 8, 6, 5432, 1, 9, 10, 17, 1234, 0]);
        assert_eq!(
            decode_mappings(&bytes, 1),
            Err(MappingError::TooManyEntries)
        );
        assert_eq!(
            decode_mappings(&bytes, 0),
            Err(MappingError::TooManyEntries)
        );
        assert_eq!(decode_mappings(&bytes, 2).unwrap().len(), 2);
    }

    #[test]
    fn mapping_list_uses_gnu_boolean_and_prefix_semantics() {
        let bytes = words(&[2, 7, 8, 6, 5432, 0, 0xdeadbeef]);
        assert_eq!(
            decode_mappings(&bytes, 1).unwrap(),
            [Mapping {
                program: 7,
                version: 8,
                protocol: 6,
                port: 5432
            },]
        );
    }
}
