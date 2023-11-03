//! Contains message types for communication between leader and follower

use mpz_core::hash::Hash;
use serde::{Deserialize, Serialize};
use tls_core::msgs::enums::ContentType;

/// TLS message record types
#[allow(missing_docs)]
#[derive(Serialize, Deserialize)]
#[serde(remote = "ContentType")]
pub enum ContentTypeDef {
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData,
    Heartbeat,
    Unknown(u8),
}

/// MPC protocol level message types
#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MpcTlsMessage {
    HandshakeCommitment(Hash),
    CommitMessage(CommitMessage),
    EncryptMessage(EncryptMessage),
    DecryptMessage,
    SendCloseNotify(EncryptMessage),
    Close,
}

/// Commit to a received ciphertext.
#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitMessage {
    #[serde(with = "ContentTypeDef")]
    pub typ: ContentType,
    pub explicit_nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub seq: u64,
}

/// Encrypt a message
#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptMessage {
    #[serde(with = "ContentTypeDef")]
    pub typ: ContentType,
    pub seq: u64,
    pub len: usize,
}

/// Decrypt the next message
#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptMessage;
