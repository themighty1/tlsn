use async_trait::async_trait;
use tls_backend::{Backend, BackendError, DecryptMode, EncryptMode};
use tls_core::{
    key::PublicKey,
    msgs::{
        base::Payload as TLSPayload,
        enums::{CipherSuite, ContentType, NamedGroup, ProtocolVersion},
        handshake::Random,
        message::{OpaqueMessage, PlainMessage},
    },
    suites::{self, SupportedCipherSuite},
};

/// A TLS backend which supports the TLSNotary protocol.
pub struct TLSNBackend {
    //...
}

#[async_trait]
impl Backend for TLSNBackend {
    async fn set_protocol_version(
        &mut self,
        _version: ProtocolVersion,
    ) -> Result<(), BackendError> {
        todo!()
    }
    async fn set_cipher_suite(&mut self, _suite: SupportedCipherSuite) -> Result<(), BackendError> {
        todo!()
    }
    async fn get_suite(&mut self) -> Result<SupportedCipherSuite, BackendError> {
        todo!()
    }
    async fn set_encrypt(&mut self, _mode: EncryptMode) -> Result<(), BackendError> {
        todo!()
    }
    async fn set_decrypt(&mut self, _mode: DecryptMode) -> Result<(), BackendError> {
        todo!()
    }
    async fn get_client_random(&mut self) -> Result<Random, BackendError> {
        todo!()
    }
    async fn get_client_key_share(&mut self) -> Result<PublicKey, BackendError> {
        todo!()
    }
    async fn set_server_random(&mut self, _random: Random) -> Result<(), BackendError> {
        todo!()
    }
    async fn set_server_key_share(&mut self, _key: PublicKey) -> Result<(), BackendError> {
        todo!()
    }
    async fn set_hs_hash_client_key_exchange(&mut self, _hash: &[u8]) -> Result<(), BackendError> {
        todo!()
    }
    async fn set_hs_hash_server_hello(&mut self, _hash: &[u8]) -> Result<(), BackendError> {
        todo!()
    }
    async fn get_server_finished_vd(&mut self, _hash: &[u8]) -> Result<Vec<u8>, BackendError> {
        todo!()
    }
    async fn get_client_finished_vd(&mut self, _hash: &[u8]) -> Result<Vec<u8>, BackendError> {
        todo!()
    }
    async fn encrypt(
        &mut self,
        _msg: PlainMessage,
        _seq: u64,
    ) -> Result<OpaqueMessage, BackendError> {
        todo!()
    }
    async fn decrypt(
        &mut self,
        _msg: OpaqueMessage,
        _seq: u64,
    ) -> Result<PlainMessage, BackendError> {
        todo!()
    }
}
