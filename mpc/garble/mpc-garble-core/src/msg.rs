use mpc_core::{commit::Opening, msgs::HashCommitment};
use serde::{Deserialize, Serialize};

use crate::{
    circuit::EncryptedGate, label_state, DecodingInfo, Delta, EncodedValue, EqualityCheck,
};

#[derive(Debug, Clone)]
pub enum GarbleMessage {
    ActiveValue(EncodedValue<label_state::Active>),
    ActiveValues(Vec<EncodedValue<label_state::Active>>),
    EncryptedGates(Vec<EncryptedGate>),
    ValueDecoding(DecodingInfo),
    ValueDecodings(Vec<DecodingInfo>),
    EqualityCheck(EqualityCheck),
    HashCommitment(HashCommitment),
    EqualityCheckOpening(Opening<EqualityCheck>),
    EqualityCheckOpenings(Vec<Opening<EqualityCheck>>),
    Delta(Delta),
}

#[derive(Debug, Clone)]
pub enum VmMessage {
    NewThread(String),
    GarbleMessage(GarbleMessage),
}
