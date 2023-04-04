use crate::{circuit::EncryptedGate, label_state, EncodedValue};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum GarbleMessage {
    ActiveValue(EncodedValue<label_state::Active>),
    EncryptedGates(Vec<EncryptedGate>),
}
