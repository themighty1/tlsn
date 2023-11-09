//! This library provides the [Backend] trait to encapsulate the cryptography backend of the TLS
//! client.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

use std::any::Any;

use async_trait::async_trait;
use tls_core::{
    cert::ServerCertDetails,
    ke::ServerKxDetails,
    key::PublicKey,
    msgs::{
        enums::{CipherSuite, NamedGroup, ProtocolVersion},
        handshake::Random,
        message::{OpaqueMessage, PlainMessage},
    },
    suites::SupportedCipherSuite,
};

type Result<T> = std::result::Result<T, BackendError>;

/// Possible backend errors
#[allow(missing_docs)]
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum BackendError {
    #[error("Invalid state: {0:?}")]
    InvalidState(String),
    #[error("Unsupported protocol version: {0:?}")]
    UnsupportedProtocolVersion(ProtocolVersion),
    #[error("Unsupported ciphersuite: {0:?}")]
    UnsupportedCiphersuite(CipherSuite),
    #[error("Unsupported curve group: {0:?}")]
    UnsupportedCurveGroup(NamedGroup),
    #[error("Invalid configuration: {0:?}")]
    InvalidConfig(String),
    #[error("Invalid server public keyshare")]
    InvalidServerKey,
    #[error("internal error: {0:?}")]
    InternalError(String),
    #[error("Encryption error: {0:?}")]
    EncryptionError(String),
    #[error("Decryption error: {0:?}")]
    DecryptionError(String),
}

/// Encryption modes for Crypto implementor
#[derive(Debug, Clone)]
pub enum EncryptMode {
    /// Encrypt payload with PSK
    EarlyData,
    /// Encrypt payload with Handshake keys
    Handshake,
    /// Encrypt payload with Application traffic keys
    Application,
}

/// Decryption modes for Crypto implementor
#[derive(Debug, Clone)]
pub enum DecryptMode {
    /// Decrypt payload with Handshake keys
    Handshake,
    /// Decrypt payload with Application traffic keys
    Application,
}

/// Core trait which manages crypto operations for the TLS connection such as key exchange, encryption
/// and decryption.
#[async_trait]
pub trait Backend: Send {
    /// Returns reference to `Any` trait object.
    fn as_any(&self) -> &dyn Any;
    /// Returns mutable reference to `Any` trait object.
    fn as_any_mut(&mut self) -> &mut dyn Any;

    /// Returns true if backend is prepared for encrypting.
    fn is_encrypting(&self) -> bool;

    /// Returns true if backend is prepared for decrypting.
    fn is_decrypting(&self) -> bool;

    /// Signals the backend that it should start encrypting.
    fn start_encrypting(&mut self);

    /// Signals the backend that it should start decrypting.
    fn start_decrypting(&mut self);

    /// Return true if the peer appears to getting close to encrypting
    /// too many messages with this key.
    fn wants_close_before_decrypt(&self) -> bool;

    /// Return true if we are getting close to encrypting too many
    /// messages with our encryption key.
    fn wants_close_before_encrypt(&self) -> bool;

    /// Return true if we outright refuse to do anything with the
    /// encryption key.
    fn encrypt_exhausted(&self) -> bool;

    /// Signals selected protocol version to implementor.
    /// Throws error if version is not supported.
    async fn set_protocol_version(&mut self, version: ProtocolVersion) -> Result<()>;

    /// Signals selected cipher suite to implementor.
    /// Throws error if cipher suite is not supported.
    async fn set_cipher_suite(&mut self, suite: SupportedCipherSuite) -> Result<()>;

    /// Returns configured cipher suite.
    async fn get_suite(&mut self) -> Result<SupportedCipherSuite>;

    /// Set encryption mode
    async fn set_encrypt(&mut self, mode: EncryptMode) -> Result<()>;

    /// Set decryption mode
    async fn set_decrypt(&mut self, mode: DecryptMode) -> Result<()>;

    /// Returns client_random value.
    async fn get_client_random(&mut self) -> Result<Random>;

    /// Returns public client keyshare.
    async fn get_client_key_share(&mut self) -> Result<PublicKey>;

    /// Sets server random.
    async fn set_server_random(&mut self, random: Random) -> Result<()>;

    /// Sets server keyshare.
    async fn set_server_key_share(&mut self, key: PublicKey) -> Result<()>;

    /// Sets the server cert chain
    fn set_server_cert_details(&mut self, cert_details: ServerCertDetails);

    /// Sets the server kx details
    fn set_server_kx_details(&mut self, kx_details: ServerKxDetails);

    /// Sets handshake hash at ClientKeyExchange for EMS.
    async fn set_hs_hash_client_key_exchange(&mut self, hash: &[u8]) -> Result<()>;

    /// Sets handshake hash at ServerHello.
    async fn set_hs_hash_server_hello(&mut self, hash: &[u8]) -> Result<()>;

    /// Returns expected ServerFinished verify_data.
    async fn get_server_finished_vd(&mut self, hash: &[u8]) -> Result<Vec<u8>>;

    /// Returns ClientFinished verify_data.
    async fn get_client_finished_vd(&mut self, hash: &[u8]) -> Result<Vec<u8>>;

    /// Prepares the backend for encryption.
    async fn prepare_encryption(&mut self) -> Result<()>;

    /// Prepares the backend for decryption.
    async fn prepare_decryption(&mut self) -> Result<()>;

    /// Buffer the incoming encrypted TLS message.
    async fn buffer_incoming(&mut self, msg: OpaqueMessage) -> Result<()>;

    /// Returns next incoming message.
    async fn next_incoming(&mut self) -> Result<Option<OpaqueMessage>>;

    /// Perform the encryption over the concerned TLS message.
    async fn encrypt(&mut self, msg: PlainMessage) -> Result<OpaqueMessage>;

    /// Perform the decryption over the concerned TLS message.
    async fn decrypt(&mut self, msg: OpaqueMessage) -> Result<PlainMessage>;
}
