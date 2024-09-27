use crate::transcript::{Direction, Idx};

/// A provider of plaintext encodings.
pub trait EncodingProvider {
    /// Provides the encoding of a subsequence of plaintext.
    fn provide_encoding(&self, direction: Direction, idx: &Idx) -> Option<Vec<u8>>;

    /// Returns the bytelength of an encoding of a single bit value.
    fn bit_encoding_len(&self) -> usize {
        16
    }
}
