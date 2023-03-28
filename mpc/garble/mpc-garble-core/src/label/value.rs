use rand::{thread_rng, Rng};
use utils::bits::ToBitsIter;

use mpc_circuits::types::{Value, ValueType};
use mpc_core::{utils::blake3, Block};

use crate::label::{state, Delta, Label, LabelState, Labels};

/// Error related to encoded values.
#[derive(Debug, thiserror::Error)]
pub enum ValueError {
    #[error("invalid encoding length, expected: {expected}, actual: {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("invalid commitment")]
    InvalidCommitment,
}

pub trait Encode: ToBitsIter {
    type Encoded;

    fn encode(delta: Delta, labels: &[Label]) -> Result<Self::Encoded, ValueError>;
}

/// An encoded value.
pub enum EncodedValue<S: LabelState> {
    U8(U8<S>),
    U16(U16<S>),
    U32(U32<S>),
    U64(U64<S>),
    U128(U128<S>),
    Array(Vec<EncodedValue<S>>),
}

impl<S: LabelState> EncodedValue<S> {
    pub fn value_type(&self) -> ValueType {
        match self {
            EncodedValue::U8(_) => ValueType::U8,
            EncodedValue::U16(_) => ValueType::U16,
            EncodedValue::U32(_) => ValueType::U32,
            EncodedValue::U64(_) => ValueType::U64,
            EncodedValue::U128(_) => ValueType::U128,
            EncodedValue::Array(v) => ValueType::Array(Box::new(v[0].value_type()), v.len()),
        }
    }

    pub fn iter(&self) -> Box<dyn Iterator<Item = &Label> + '_> {
        match self {
            EncodedValue::U8(v) => Box::new(v.0.iter()),
            EncodedValue::U16(v) => Box::new(v.0.iter()),
            EncodedValue::U32(v) => Box::new(v.0.iter()),
            EncodedValue::U64(v) => Box::new(v.0.iter()),
            EncodedValue::U128(v) => Box::new(v.0.iter()),
            EncodedValue::Array(v) => Box::new(v.iter().flat_map(|v| v.iter())),
        }
    }
}

impl EncodedValue<state::Full> {
    pub fn from_labels(
        value_type: ValueType,
        delta: Delta,
        labels: &[Label],
    ) -> Result<Self, ValueError> {
        if labels.len() != value_type.len() {
            return Err(ValueError::InvalidLength {
                expected: value_type.len(),
                actual: labels.len(),
            });
        }

        let encoded = match value_type {
            ValueType::U8 => {
                EncodedValue::U8(U8::<state::Full>::new(delta, labels.try_into().unwrap()))
            }
            ValueType::U16 => {
                EncodedValue::U16(U16::<state::Full>::new(delta, labels.try_into().unwrap()))
            }
            ValueType::U32 => {
                EncodedValue::U32(U32::<state::Full>::new(delta, labels.try_into().unwrap()))
            }
            ValueType::U64 => {
                EncodedValue::U64(U64::<state::Full>::new(delta, labels.try_into().unwrap()))
            }
            ValueType::U128 => {
                EncodedValue::U128(U128::<state::Full>::new(delta, labels.try_into().unwrap()))
            }
            ValueType::Array(ty, _) => EncodedValue::Array(
                labels
                    .chunks(ty.len())
                    .map(|labels| Self::from_labels((*ty).clone(), delta, labels).unwrap())
                    .collect(),
            ),
            _ => unimplemented!("unimplemented value type: {:?}", value_type),
        };

        Ok(encoded)
    }

    pub fn delta(&self) -> Delta {
        match self {
            EncodedValue::U8(v) => v.0.delta(),
            EncodedValue::U16(v) => v.0.delta(),
            EncodedValue::U32(v) => v.0.delta(),
            EncodedValue::U64(v) => v.0.delta(),
            EncodedValue::U128(v) => v.0.delta(),
            EncodedValue::Array(v) => v[0].delta(),
        }
    }

    pub fn commit(&self) -> EncodingCommitment {
        EncodingCommitment::new(self)
    }
}

impl EncodedValue<state::Active> {
    pub fn from_labels(value_type: ValueType, labels: &[Label]) -> Result<Self, ValueError> {
        if labels.len() != value_type.len() {
            return Err(ValueError::InvalidLength {
                expected: value_type.len(),
                actual: labels.len(),
            });
        }

        let encoded = match value_type {
            ValueType::U8 => EncodedValue::U8(U8::<state::Active>::new(labels.try_into().unwrap())),
            ValueType::U16 => {
                EncodedValue::U16(U16::<state::Active>::new(labels.try_into().unwrap()))
            }
            ValueType::U32 => {
                EncodedValue::U32(U32::<state::Active>::new(labels.try_into().unwrap()))
            }
            ValueType::U64 => {
                EncodedValue::U64(U64::<state::Active>::new(labels.try_into().unwrap()))
            }
            ValueType::U128 => {
                EncodedValue::U128(U128::<state::Active>::new(labels.try_into().unwrap()))
            }
            ValueType::Array(ty, _) => EncodedValue::Array(
                labels
                    .chunks(ty.len())
                    .map(|labels| Self::from_labels((*ty).clone(), labels).unwrap())
                    .collect(),
            ),
            _ => unimplemented!("unimplemented value type: {:?}", value_type),
        };

        Ok(encoded)
    }
}

macro_rules! define_encoded_value {
    ($name:ident, $ty:ty, $len:expr) => {
        pub struct $name<S: LabelState>(Labels<$len, S>);

        impl $name<state::Full> {
            pub(crate) fn new(delta: Delta, labels: [Label; $len]) -> Self {
                Self(Labels::<$len, state::Full>::new(delta, labels))
            }
        }

        impl $name<state::Active> {
            pub(crate) fn new(labels: [Label; $len]) -> Self {
                Self(Labels::<$len, state::Active>::new(labels))
            }
        }

        impl Encode for $ty {
            type Encoded = $name<state::Full>;

            fn encode(delta: Delta, labels: &[Label]) -> Result<Self::Encoded, ValueError> {
                if labels.len() != $len {
                    return Err(ValueError::InvalidLength {
                        expected: $len,
                        actual: labels.len(),
                    });
                }

                let labels = labels.try_into().unwrap();

                Ok(Self::Encoded::new(delta, labels))
            }
        }
    };
}

define_encoded_value!(U8, u8, 8);
define_encoded_value!(U16, u16, 16);
define_encoded_value!(U32, u32, 32);
define_encoded_value!(U64, u64, 64);
define_encoded_value!(U128, u128, 128);

pub enum DecodingInfo {
    U8(U8Decoding),
    U16(U16Decoding),
    U32(U32Decoding),
    U64(U64Decoding),
    U128(U128Decoding),
    Array(Vec<DecodingInfo>),
}

macro_rules! define_decoding_info {
    ($name:ident, $ty:ty) => {
        pub struct $name($ty);
    };
}

define_decoding_info!(U8Decoding, u8);
define_decoding_info!(U16Decoding, u16);
define_decoding_info!(U32Decoding, u32);
define_decoding_info!(U64Decoding, u64);
define_decoding_info!(U128Decoding, u128);

pub enum EncodingCommitment {
    U8(U8Commitment),
    U16(U16Commitment),
    U32(U32Commitment),
    U64(U64Commitment),
    U128(U128Commitment),
    Array(Vec<EncodingCommitment>),
}

impl EncodingCommitment {
    pub(crate) fn new(value: &EncodedValue<state::Full>) -> EncodingCommitment {
        match value {
            EncodedValue::U8(v) => EncodingCommitment::U8(U8Commitment::new(v)),
            EncodedValue::U16(v) => EncodingCommitment::U16(U16Commitment::new(v)),
            EncodedValue::U32(v) => EncodingCommitment::U32(U32Commitment::new(v)),
            EncodedValue::U64(v) => EncodingCommitment::U64(U64Commitment::new(v)),
            EncodedValue::U128(v) => EncodingCommitment::U128(U128Commitment::new(v)),
            EncodedValue::Array(v) => EncodingCommitment::Array(
                v.iter()
                    .map(|v| EncodingCommitment::new(v))
                    .collect::<Vec<_>>(),
            ),
        }
    }
}

macro_rules! define_encoding_commitment {
    ($name:ident, $value_ident:ident, $len:expr) => {
        pub struct $name([[Block; 2]; $len]);

        impl $name {
            pub(crate) fn new(value: &$value_ident<state::Full>) -> Self {
                // randomly shuffle the two labels inside each pair in order to prevent
                // the evaluator from decoding their active labels
                let mut flip = [false; $len];
                thread_rng().fill::<[bool]>(&mut flip);

                let delta = value.0.delta();

                let commitments = std::array::from_fn(|i| {
                    let low = value.0[i];
                    let high = low ^ delta;

                    let low = Self::compute_hash(low.into_inner());
                    let high = Self::compute_hash(high.into_inner());

                    if flip[i] {
                        [low, high]
                    } else {
                        [high, low]
                    }
                });

                Self(commitments)
            }

            /// Validates labels against commitments
            ///
            /// If this function returns an error the generator may be malicious
            pub(crate) fn validate(
                &self,
                value: &$value_ident<state::Active>,
            ) -> Result<(), ValueError> {
                if self.0.iter().zip(value.0.iter()).all(|(pair, label)| {
                    let h = Self::compute_hash(label.into_inner());
                    h == pair[0] || h == pair[1]
                }) {
                    Ok(())
                } else {
                    Err(ValueError::InvalidCommitment)
                }
            }

            /// We use a truncated Blake3 hash to commit to the labels
            ///
            /// TODO: determine whether a salt is necessary
            fn compute_hash(block: Block) -> Block {
                let h = blake3(&block.to_be_bytes());
                let mut commitment = [0u8; 16];
                commitment.copy_from_slice(&h[..16]);
                commitment.into()
            }
        }
    };
}

define_encoding_commitment!(U8Commitment, U8, 8);
define_encoding_commitment!(U16Commitment, U16, 16);
define_encoding_commitment!(U32Commitment, U32, 32);
define_encoding_commitment!(U64Commitment, U64, 64);
define_encoding_commitment!(U128Commitment, U128, 128);
