use rand::{thread_rng, Rng};
use utils::bits::{FromBits, ToBitsIter};

use mpc_circuits::types::{TypeError, Value, ValueType};
use mpc_core::{utils::blake3, Block};

use crate::label::{state, Delta, Label, LabelState, Labels};

/// Error related to encoded values.
#[derive(Debug, thiserror::Error)]
pub enum ValueError {
    #[error(transparent)]
    TypeError(#[from] mpc_circuits::types::TypeError),
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
#[derive(Debug, Clone, PartialEq)]
pub enum EncodedValue<S: LabelState> {
    Bit(Bit<S>),
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
            EncodedValue::Bit(_) => ValueType::Bit,
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
            EncodedValue::Bit(v) => Box::new(v.0.iter()),
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
            ValueType::Bit => {
                EncodedValue::Bit(Bit::<state::Full>::new(delta, labels.try_into().unwrap()))
            }
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
            EncodedValue::Bit(v) => v.0.delta(),
            EncodedValue::U8(v) => v.0.delta(),
            EncodedValue::U16(v) => v.0.delta(),
            EncodedValue::U32(v) => v.0.delta(),
            EncodedValue::U64(v) => v.0.delta(),
            EncodedValue::U128(v) => v.0.delta(),
            EncodedValue::Array(v) => v[0].delta(),
        }
    }

    pub fn select(
        &self,
        value: impl Into<Value>,
    ) -> Result<EncodedValue<state::Active>, ValueError> {
        let value = value.into();

        let active = match (self, &value) {
            (EncodedValue::Bit(enc_v), Value::Bit(v)) => EncodedValue::Bit(enc_v.select(*v)),
            (EncodedValue::U8(enc_v), Value::U8(v)) => EncodedValue::U8(enc_v.select(*v)),
            (EncodedValue::U16(enc_v), Value::U16(v)) => EncodedValue::U16(enc_v.select(*v)),
            (EncodedValue::U32(enc_v), Value::U32(v)) => EncodedValue::U32(enc_v.select(*v)),
            (EncodedValue::U64(enc_v), Value::U64(v)) => EncodedValue::U64(enc_v.select(*v)),
            (EncodedValue::U128(enc_v), Value::U128(v)) => EncodedValue::U128(enc_v.select(*v)),
            (EncodedValue::Array(enc_v), Value::Array(v)) => {
                if enc_v.len() != v.len() {
                    return Err(ValueError::InvalidLength {
                        expected: enc_v.len(),
                        actual: v.len(),
                    });
                }

                EncodedValue::Array(
                    enc_v
                        .iter()
                        .zip(v.iter())
                        .map(|(enc_v, v)| enc_v.select(v.clone()))
                        .collect::<Result<Vec<_>, _>>()?,
                )
            }
            _ => {
                return Err(TypeError::UnexpectedType {
                    expected: self.value_type(),
                    actual: value.value_type(),
                })?;
            }
        };

        Ok(active)
    }

    pub fn decoding(&self) -> DecodingInfo {
        DecodingInfo::new(self)
    }

    pub fn commit(&self) -> EncodingCommitment {
        EncodingCommitment::new(self)
    }

    pub fn iter_blocks(&self) -> Box<dyn Iterator<Item = [Block; 2]> + Send + '_> {
        match self {
            EncodedValue::Bit(v) => Box::new(v.0.iter_blocks()),
            EncodedValue::U8(v) => Box::new(v.0.iter_blocks()),
            EncodedValue::U16(v) => Box::new(v.0.iter_blocks()),
            EncodedValue::U32(v) => Box::new(v.0.iter_blocks()),
            EncodedValue::U64(v) => Box::new(v.0.iter_blocks()),
            EncodedValue::U128(v) => Box::new(v.0.iter_blocks()),
            EncodedValue::Array(v) => Box::new(v.iter().flat_map(|v| v.iter_blocks())),
        }
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
            ValueType::Bit => {
                EncodedValue::Bit(Bit::<state::Active>::new(labels.try_into().unwrap()))
            }
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

    pub fn decode(&self, decoding: &DecodingInfo) -> Result<Value, ValueError> {
        let value = match (self, decoding) {
            (EncodedValue::Bit(v), DecodingInfo::Bit(d)) => v.decode(&d).into(),
            (EncodedValue::U8(v), DecodingInfo::U8(d)) => v.decode(&d).into(),
            (EncodedValue::U16(v), DecodingInfo::U16(d)) => v.decode(&d).into(),
            (EncodedValue::U32(v), DecodingInfo::U32(d)) => v.decode(&d).into(),
            (EncodedValue::U64(v), DecodingInfo::U64(d)) => v.decode(&d).into(),
            (EncodedValue::U128(v), DecodingInfo::U128(d)) => v.decode(&d).into(),
            (EncodedValue::Array(v), DecodingInfo::Array(d)) => Value::Array(
                v.iter()
                    .zip(d)
                    .map(|(v, d)| v.decode(&d))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            (v, d) => {
                return Err(TypeError::UnexpectedType {
                    expected: v.value_type(),
                    actual: d.value_type(),
                })?
            }
        };

        Ok(value)
    }
}

macro_rules! define_encoded_value {
    ($name:ident, $ty:ty, $len:expr) => {
        #[derive(Debug, Clone, PartialEq)]
        pub struct $name<S: LabelState>(Labels<$len, S>);

        impl $name<state::Full> {
            pub(crate) fn new(delta: Delta, labels: [Label; $len]) -> Self {
                Self(Labels::<$len, state::Full>::new(delta, labels))
            }

            pub(crate) fn select(&self, value: $ty) -> $name<state::Active> {
                let mut bits = value.into_lsb0_iter();
                let delta = self.0.delta();
                $name::<state::Active>::new(self.0.labels.map(|label| {
                    if bits.next().unwrap() {
                        label ^ delta
                    } else {
                        label
                    }
                }))
            }

            pub fn iter_block(&self) -> impl Iterator<Item = [Block; 2]> + '_ {
                self.0.iter_blocks()
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

        impl<S: state::LabelState> From<$name<S>> for EncodedValue<S> {
            fn from(value: $name<S>) -> Self {
                EncodedValue::$name(value)
            }
        }

        impl<S: state::LabelState, const N: usize> From<[$name<S>; N]> for EncodedValue<S> {
            fn from(value: [$name<S>; N]) -> Self {
                EncodedValue::Array(value.map(|v| v.into()).to_vec())
            }
        }
    };
}

define_encoded_value!(Bit, bool, 1);
define_encoded_value!(U8, u8, 8);
define_encoded_value!(U16, u16, 16);
define_encoded_value!(U32, u32, 32);
define_encoded_value!(U64, u64, 64);
define_encoded_value!(U128, u128, 128);

#[derive(Debug, Clone, PartialEq)]
pub enum DecodingInfo {
    Bit(BitDecoding),
    U8(U8Decoding),
    U16(U16Decoding),
    U32(U32Decoding),
    U64(U64Decoding),
    U128(U128Decoding),
    Array(Vec<DecodingInfo>),
}

impl DecodingInfo {
    pub(crate) fn new(value: &EncodedValue<state::Full>) -> Self {
        match value {
            EncodedValue::Bit(v) => DecodingInfo::Bit(v.decoding()),
            EncodedValue::U8(v) => DecodingInfo::U8(v.decoding()),
            EncodedValue::U16(v) => DecodingInfo::U16(v.decoding()),
            EncodedValue::U32(v) => DecodingInfo::U32(v.decoding()),
            EncodedValue::U64(v) => DecodingInfo::U64(v.decoding()),
            EncodedValue::U128(v) => DecodingInfo::U128(v.decoding()),
            EncodedValue::Array(v) => DecodingInfo::Array(v.iter().map(|v| v.decoding()).collect()),
        }
    }

    pub fn value_type(&self) -> ValueType {
        match self {
            DecodingInfo::Bit(_) => ValueType::Bit,
            DecodingInfo::U8(_) => ValueType::U8,
            DecodingInfo::U16(_) => ValueType::U16,
            DecodingInfo::U32(_) => ValueType::U32,
            DecodingInfo::U64(_) => ValueType::U64,
            DecodingInfo::U128(_) => ValueType::U128,
            DecodingInfo::Array(v) => ValueType::Array(Box::new(v[0].value_type()), v.len()),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct BitDecoding(bool);

impl Bit<state::Full> {
    pub(crate) fn decoding(&self) -> BitDecoding {
        BitDecoding(self.0[0].pointer_bit())
    }
}

impl Bit<state::Active> {
    pub(crate) fn decode(&self, decoding: &BitDecoding) -> bool {
        self.0[0].pointer_bit() ^ decoding.0
    }
}

macro_rules! define_decoding_info {
    ($name:ident, $value:ident, $ty:ty) => {
        #[derive(Debug, Clone, PartialEq)]
        pub struct $name($ty);

        impl $value<state::Full> {
            pub(crate) fn decoding(&self) -> $name {
                $name(<$ty>::from_lsb0(
                    self.0.iter().map(|label| label.pointer_bit()),
                ))
            }
        }

        impl $value<state::Active> {
            pub(crate) fn decode(&self, decoding: &$name) -> $ty {
                <$ty>::from_lsb0(
                    self.0
                        .iter()
                        .zip(decoding.0.into_lsb0_iter())
                        .map(|(label, dec)| label.pointer_bit() ^ dec),
                )
                .into()
            }
        }
    };
}

define_decoding_info!(U8Decoding, U8, u8);
define_decoding_info!(U16Decoding, U16, u16);
define_decoding_info!(U32Decoding, U32, u32);
define_decoding_info!(U64Decoding, U64, u64);
define_decoding_info!(U128Decoding, U128, u128);

#[derive(Debug, Clone, PartialEq)]
pub enum EncodingCommitment {
    Bit(BitCommitment),
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
            EncodedValue::Bit(v) => EncodingCommitment::Bit(BitCommitment::new(v)),
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

    pub fn value_type(&self) -> ValueType {
        match self {
            EncodingCommitment::Bit(_) => ValueType::Bit,
            EncodingCommitment::U8(_) => ValueType::U8,
            EncodingCommitment::U16(_) => ValueType::U16,
            EncodingCommitment::U32(_) => ValueType::U32,
            EncodingCommitment::U64(_) => ValueType::U64,
            EncodingCommitment::U128(_) => ValueType::U128,
            EncodingCommitment::Array(v) => ValueType::Array(Box::new(v[0].value_type()), v.len()),
        }
    }

    pub fn verify(&self, active: &EncodedValue<state::Active>) -> Result<(), ValueError> {
        match (self, active) {
            (EncodingCommitment::Bit(c), EncodedValue::Bit(a)) => c.verify(a),
            (EncodingCommitment::U8(c), EncodedValue::U8(a)) => c.verify(a),
            (EncodingCommitment::U16(c), EncodedValue::U16(a)) => c.verify(a),
            (EncodingCommitment::U32(c), EncodedValue::U32(a)) => c.verify(a),
            (EncodingCommitment::U64(c), EncodedValue::U64(a)) => c.verify(a),
            (EncodingCommitment::U128(c), EncodedValue::U128(a)) => c.verify(a),
            (EncodingCommitment::Array(c), EncodedValue::Array(a)) if c.len() == a.len() => {
                for (c, a) in c.iter().zip(a.iter()) {
                    c.verify(a)?;
                }

                Ok(())
            }
            _ => Err(TypeError::UnexpectedType {
                expected: self.value_type(),
                actual: active.value_type(),
            })?,
        }
    }
}

macro_rules! define_encoding_commitment {
    ($name:ident, $value_ident:ident, $len:expr) => {
        #[derive(Debug, Clone, PartialEq)]
        pub struct $name([[Block; 2]; $len]);

        impl $value_ident<state::Full> {
            pub(crate) fn commit(&self) -> $name {
                $name::new(self)
            }
        }

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
            pub(crate) fn verify(
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
            fn compute_hash(block: Block) -> Block {
                let salt = b"label commitment";
                let mut bytes = [0u8; 32];
                bytes[..16].copy_from_slice(block.to_be_bytes().as_slice());
                bytes[16..].copy_from_slice(salt);

                let h = blake3(&bytes);
                let mut commitment = [0u8; 16];
                commitment.copy_from_slice(&h[..16]);
                commitment.into()
            }
        }
    };
}

define_encoding_commitment!(BitCommitment, Bit, 1);
define_encoding_commitment!(U8Commitment, U8, 8);
define_encoding_commitment!(U16Commitment, U16, 16);
define_encoding_commitment!(U32Commitment, U32, 32);
define_encoding_commitment!(U64Commitment, U64, 64);
define_encoding_commitment!(U128Commitment, U128, 128);
