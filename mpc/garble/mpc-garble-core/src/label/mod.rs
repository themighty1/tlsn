//! Types associated with wire labels

mod digest;
//pub(crate) mod encoded;
mod encoder;
mod value;
//pub(crate) mod input;
//pub(crate) mod output;

use std::{
    ops::{BitAnd, BitXor, Deref, Index},
    sync::Arc,
};

//use mpc_circuits::{BitOrder, Input, Output, Value};
use mpc_circuits::types::Value;
use mpc_core::Block;
use rand::{CryptoRng, Rng};

use crate::error::EncodingError;

pub use digest::LabelsDigest;
pub use value::EncodedValue;
//pub use encoded::{Encoded, GroupDecodingInfo};
//pub use encoder::{ChaChaEncoder, Encoder, EncoderRng};
//pub use output::OutputLabelsCommitment;

/// Global binary offset used by the Free-XOR technique to create wire label
/// pairs where W_1 = W_0 ^ Delta.
///
/// In accordance with the (p&p) Point-and-Permute technique, the LSB of Delta is set to 1, so that
/// the pointer bit LSB(W_1) = LSB(W_0) ^ 1
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Delta(Block);

impl Delta {
    /// Creates new random Delta
    pub fn random<R: Rng + CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut block = Block::random(rng);
        block.set_lsb();
        Self(block)
    }

    /// Returns the inner block
    #[inline]
    pub(crate) fn into_inner(self) -> Block {
        self.0
    }
}

impl Deref for Delta {
    type Target = Block;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<[u8; 16]> for Delta {
    #[inline]
    fn from(bytes: [u8; 16]) -> Self {
        Self(Block::from(bytes))
    }
}

pub mod state {
    use super::Delta;

    mod sealed {
        pub trait Sealed {}

        impl Sealed for super::Full {}
        impl Sealed for super::Active {}
    }

    /// Marker trait for label state
    pub trait LabelState: sealed::Sealed {}

    /// Full label state, ie contains both the low and high labels.
    #[derive(Debug, Clone, Copy, PartialEq)]
    pub struct Full {
        pub(super) delta: Delta,
    }

    impl LabelState for Full {}

    /// Active label state
    #[derive(Debug, Clone, Copy, PartialEq)]
    pub struct Active;

    impl LabelState for Active {}
}

use state::*;

/// A collection of labels.
///
/// This type uses an `Arc` reference to the underlying data to make it cheap to clone,
/// and thus more memory efficient when re-using labels between garbled circuit executions.
#[derive(Debug, Clone, PartialEq)]
pub struct Labels<const N: usize, S: LabelState> {
    state: S,
    labels: Arc<[Label; N]>,
}

impl<const N: usize, S> Labels<N, S>
where
    S: LabelState,
{
    /// Returns number of labels
    pub fn len(&self) -> usize {
        self.labels.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Label> {
        self.labels.iter()
    }
}

impl<const N: usize> Labels<N, state::Full> {
    pub(crate) fn new(delta: Delta, labels: [Label; N]) -> Self {
        Self {
            state: state::Full { delta },
            labels: Arc::new(labels),
        }
    }

    pub(crate) fn delta(&self) -> Delta {
        self.state.delta
    }
}

impl<const N: usize> Labels<N, state::Active> {
    pub(crate) fn new(labels: [Label; N]) -> Self {
        Self {
            state: state::Active,
            labels: Arc::new(labels),
        }
    }
}

impl<const N: usize, S: LabelState> Index<usize> for Labels<N, S> {
    type Output = Label;

    fn index(&self, index: usize) -> &Self::Output {
        &self.labels[index]
    }
}

/// Wire label of a garbled circuit
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Label(Block);

impl BitXor<Label> for Label {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Label) -> Self::Output {
        Label(self.0 ^ rhs.0)
    }
}

impl BitXor<&Label> for Label {
    type Output = Label;

    #[inline]
    fn bitxor(self, rhs: &Label) -> Self::Output {
        Label(self.0 ^ rhs.0)
    }
}

impl BitXor<&Label> for &Label {
    type Output = Label;

    #[inline]
    fn bitxor(self, rhs: &Label) -> Self::Output {
        Label(self.0 ^ rhs.0)
    }
}

impl BitAnd<Label> for Label {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Label) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl BitXor<Delta> for Label {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Delta) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl BitAnd<Delta> for Label {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Delta) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl AsRef<Block> for Label {
    fn as_ref(&self) -> &Block {
        &self.0
    }
}

impl From<Block> for Label {
    fn from(block: Block) -> Self {
        Self(block)
    }
}

impl Label {
    pub const LEN: usize = Block::LEN;

    /// Creates a new label
    #[inline]
    pub fn new(value: Block) -> Self {
        Self(value)
    }

    /// Returns inner block
    #[inline]
    pub fn into_inner(self) -> Block {
        self.0
    }

    /// Returns label pointer bit from the Point-and-Permute technique
    #[inline]
    pub fn pointer_bit(&self) -> bool {
        self.0.lsb() == 1
    }

    /// Creates a new random label
    #[inline]
    pub fn random<R: Rng + CryptoRng + ?Sized>(rng: &mut R) -> Self {
        Self(Block::random(rng))
    }

    /// Creates label pair from delta and corresponding truth value
    #[inline]
    pub fn to_pair(self, delta: Delta, level: bool) -> LabelPair {
        let (low, high) = if level {
            (self ^ delta, self)
        } else {
            (self, self ^ delta)
        };

        LabelPair(low, high)
    }
}

/// Pair of garbled circuit labels
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LabelPair(Label, Label);

impl LabelPair {
    /// Creates a new label pair
    #[inline]
    pub(crate) fn new(low: Label, high: Label) -> Self {
        Self(low, high)
    }

    /// Returns delta
    #[inline]
    pub fn delta(&self) -> Delta {
        Delta((self.0 ^ self.1).0)
    }

    /// Returns both labels
    #[inline]
    pub fn to_inner(self) -> [Label; 2] {
        [self.0, self.1]
    }

    /// Returns label corresponding to logical low
    #[inline]
    pub fn low(&self) -> Label {
        self.0
    }

    /// Returns label corresponding to logical high
    #[inline]
    pub fn high(&self) -> Label {
        self.1
    }

    /// Returns label corresponding to provided logic level
    #[inline]
    pub fn select(&self, level: bool) -> Label {
        if level {
            self.1
        } else {
            self.0
        }
    }

    /// Returns labels corresponding to wire truth values
    ///
    /// Panics if wire is not in label collection
    pub fn choose(labels: &[LabelPair], wires: &[usize], values: &[bool]) -> Vec<Label> {
        wires
            .iter()
            .zip(values.iter())
            .map(|(id, value)| labels[*id].select(*value))
            .collect()
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     use rand::SeedableRng;
//     use rand_chacha::ChaCha12Rng;

//     #[test]
//     fn test_free_xor_label() {
//         let mut rng = ChaCha12Rng::seed_from_u64(0);
//         let delta = Delta::random(&mut rng);
//         let a = Labels::<Full>::generate(&mut rng, 8, Some(delta));
//         let b = Labels::<Full>::generate(&mut rng, 8, Some(delta));
//         let c = &a ^ &b;

//         let a_active = a.select(&1u8.into(), BitOrder::Msb0).unwrap();
//         let b_active = b.select(&2u8.into(), BitOrder::Msb0).unwrap();

//         let c_active = a_active ^ b_active;

//         assert_eq!(c_active, c.select(&3u8.into(), BitOrder::Msb0).unwrap());
//     }
// }
