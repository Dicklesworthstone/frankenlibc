//! Incremental ONC RPC record marking (RFC 5531 section 11).
//!
//! TCP reads have no relationship to fragment headers or RPC message boundaries.
//! Keep partial headers and fragment bodies across reads/timeouts, stop exactly
//! at a record boundary, and bound both payload bytes and zero-length fragments.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
    TooLarge,
    TooManyFragments,
    Allocation,
    Truncated,
}

/// Encode a fragment marker, not an XDR integer/boolean pair.
pub fn fragment_header(length: usize, last: bool) -> Result<[u8; 4], RecordError> {
    let length = u32::try_from(length).map_err(|_| RecordError::TooLarge)?;
    if length > 0x7fff_ffff {
        return Err(RecordError::TooLarge);
    }
    Ok((length | if last { 0x8000_0000 } else { 0 }).to_be_bytes())
}

/// One in-progress record. A failed decoder stays failed: following bytes cannot
/// be interpreted as a fresh marker after a rejected or incomplete fragment.
#[derive(Debug)]
pub struct RecordDecoder {
    marker: [u8; 4],
    marker_used: usize,
    remaining: usize,
    last: bool,
    fragments: usize,
    complete: bool,
    failure: Option<RecordError>,
    payload: Vec<u8>,
    byte_limit: usize,
    fragment_limit: usize,
}

impl RecordDecoder {
    pub fn new(byte_limit: usize, fragment_limit: usize) -> Self {
        Self {
            marker: [0; 4],
            marker_used: 0,
            remaining: 0,
            last: false,
            fragments: 0,
            complete: false,
            failure: None,
            payload: Vec::new(),
            byte_limit,
            fragment_limit,
        }
    }

    fn fail<T>(&mut self, error: RecordError) -> Result<T, RecordError> {
        self.failure = Some(error);
        Err(error)
    }

    /// Consume up to the end of ONE record. Unconsumed bytes belong to the next
    /// record and must be submitted again after `take_record` or `discard_record`.
    /// An already-complete decoder consumes zero bytes. No caller storage is
    /// retained. Empty input is harmless, including between partial headers.
    pub fn consume(&mut self, input: &[u8]) -> Result<usize, RecordError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        let mut used = 0;
        while !self.complete {
            if self.marker_used != 4 {
                let count = (4 - self.marker_used).min(input.len() - used);
                self.marker[self.marker_used..self.marker_used + count]
                    .copy_from_slice(&input[used..used + count]);
                self.marker_used += count;
                used += count;
                if self.marker_used != 4 {
                    break;
                }
                if self.fragments == self.fragment_limit {
                    return self.fail(RecordError::TooManyFragments);
                }
                self.fragments += 1;
                let marker = u32::from_be_bytes(self.marker);
                self.last = marker & 0x8000_0000 != 0;
                self.remaining = (marker & 0x7fff_ffff) as usize;
                if self.remaining > self.byte_limit.saturating_sub(self.payload.len()) {
                    return self.fail(RecordError::TooLarge);
                }
            }
            let count = self.remaining.min(input.len() - used);
            // Reserve only bytes actually received, never an untrusted declared
            // fragment length. try_reserve failure is returned, not an OOM abort.
            if self.payload.try_reserve(count).is_err() {
                return self.fail(RecordError::Allocation);
            }
            self.payload.extend_from_slice(&input[used..used + count]);
            used += count;
            self.remaining -= count;
            if self.remaining == 0 {
                self.marker_used = 0;
                self.complete = self.last;
            }
            if used == input.len() {
                break;
            }
        }
        Ok(used)
    }

    pub fn record(&self) -> Option<&[u8]> {
        self.complete.then_some(self.payload.as_slice())
    }

    fn next_record(&mut self) {
        self.marker_used = 0;
        self.remaining = 0;
        self.last = false;
        self.fragments = 0;
        self.complete = false;
    }

    /// Transfer a complete record; never publish a partially received payload.
    pub fn take_record(&mut self) -> Option<Vec<u8>> {
        if !self.complete {
            return None;
        }
        self.next_record();
        Some(std::mem::take(&mut self.payload))
    }

    /// Discard a complete stale-XID reply while retaining its allocation.
    pub fn discard_record(&mut self) -> bool {
        if !self.complete {
            return false;
        }
        self.payload.clear();
        self.next_record();
        true
    }

    /// EOF is clean only at a record boundary. A zero-length non-final fragment
    /// is still an unfinished record even though no payload bytes were received.
    pub fn finish(&mut self) -> Result<(), RecordError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.complete || (self.marker_used == 0 && self.fragments == 0) {
            Ok(())
        } else {
            self.fail(RecordError::Truncated)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fragment(payload: &[u8], last: bool) -> Vec<u8> {
        let mut result = fragment_header(payload.len(), last).unwrap().to_vec();
        result.extend_from_slice(payload);
        result
    }

    #[test]
    fn every_split_preserves_headers_bodies_and_fragment_boundaries() {
        let expected = (0..67).collect::<Vec<u8>>();
        let mut wire = fragment(&expected[..1], false);
        wire.extend(fragment(&[], false));
        wire.extend(fragment(&expected[1..18], false));
        wire.extend(fragment(&expected[18..], true));
        for split in 0..=wire.len() {
            let mut decoder = RecordDecoder::new(67, 4);
            assert_eq!(decoder.consume(&wire[..split]), Ok(split));
            assert_eq!(decoder.consume(&[]), Ok(0));
            assert_eq!(decoder.consume(&wire[split..]), Ok(wire.len() - split));
            assert_eq!(decoder.record(), Some(expected.as_slice()), "split {split}");
            assert_eq!(decoder.finish(), Ok(()));
        }
        for stride in 1..=wire.len() {
            let mut decoder = RecordDecoder::new(67, 4);
            for bytes in wire.chunks(stride) {
                assert_eq!(decoder.consume(bytes), Ok(bytes.len()));
            }
            assert_eq!(decoder.take_record(), Some(expected.clone()));
            assert_eq!(decoder.finish(), Ok(()));
        }
    }

    #[test]
    fn coalesced_records_stop_without_consuming_the_next_marker() {
        let first = fragment(b"abcd", true);
        let second = fragment(b"next", true);
        let wire = [first.as_slice(), second.as_slice()].concat();
        let mut decoder = RecordDecoder::new(4, 1);
        assert_eq!(decoder.consume(&wire), Ok(first.len()));
        assert_eq!(decoder.consume(&second), Ok(0));
        assert_eq!(decoder.take_record().unwrap(), b"abcd");
        assert_eq!(decoder.consume(&second), Ok(second.len()));
        assert_eq!(decoder.record(), Some(b"next".as_slice()));
        assert!(decoder.discard_record());
        assert!(!decoder.discard_record());
        assert_eq!(decoder.finish(), Ok(()));
    }

    #[test]
    fn zero_length_final_records_are_real_boundaries() {
        let mut decoder = RecordDecoder::new(0, 2);
        assert_eq!(decoder.consume(&[0, 0, 0, 0]), Ok(4));
        assert_eq!(decoder.record(), None);
        assert_eq!(decoder.consume(&[0x80, 0, 0, 0]), Ok(4));
        assert_eq!(decoder.take_record(), Some(Vec::new()));
        assert_eq!(fragment_header(0, true), Ok([0x80, 0, 0, 0]));
        assert_eq!(fragment_header(0x7fff_ffff, true), Ok([0xff; 4]));
        assert_eq!(
            fragment_header(0x8000_0000, false),
            Err(RecordError::TooLarge)
        );
    }

    #[test]
    fn cumulative_limits_and_empty_fragment_floods_fail_closed() {
        let mut decoder = RecordDecoder::new(4, 4);
        decoder.consume(&fragment(b"abc", false)).unwrap();
        assert_eq!(
            decoder.consume(&fragment_header(2, true).unwrap()),
            Err(RecordError::TooLarge)
        );
        assert_eq!(decoder.record(), None);
        assert_eq!(
            decoder.consume(&fragment(b"x", true)),
            Err(RecordError::TooLarge)
        );
        assert_eq!(decoder.finish(), Err(RecordError::TooLarge));
        let mut decoder = RecordDecoder::new(32, 2);
        decoder.consume(&[0; 8]).unwrap();
        assert_eq!(
            decoder.consume(&[0x80, 0, 0, 0]),
            Err(RecordError::TooManyFragments)
        );
        assert_eq!(decoder.take_record(), None);
        let mut decoder = RecordDecoder::new(32, 0);
        assert_eq!(
            decoder.consume(&[0x80, 0, 0, 0]),
            Err(RecordError::TooManyFragments)
        );
    }

    #[test]
    fn eof_never_publishes_a_partial_header_or_body() {
        let wire = fragment(b"message", true);
        for length in 1..wire.len() {
            let mut decoder = RecordDecoder::new(32, 2);
            decoder.consume(&wire[..length]).unwrap();
            assert_eq!(decoder.finish(), Err(RecordError::Truncated));
            assert_eq!(decoder.take_record(), None);
        }
        let mut decoder = RecordDecoder::new(0, 1);
        decoder.consume(&[0; 4]).unwrap();
        assert_eq!(decoder.finish(), Err(RecordError::Truncated));
        let mut decoder = RecordDecoder::new(16, 1);
        assert_eq!(
            decoder.consume(&fragment_header(0x7fff_ffff, true).unwrap()),
            Err(RecordError::TooLarge)
        );
        assert_eq!(
            decoder.payload.capacity(),
            0,
            "declared lengths must not allocate"
        );
    }
}
