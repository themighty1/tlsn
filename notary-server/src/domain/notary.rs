use std::{collections::HashMap, sync::Arc};

use p256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::config::NotarizationProperties;

/// Response object of the /session API
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotarizationSessionResponse {
    /// Unique session id that is generated by notary and shared to prover
    pub session_id: String,
}

/// Request object of the /session API
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotarizationSessionRequest {
    pub client_type: ClientType,
    /// Maximum transcript size in bytes
    pub max_transcript_size: Option<usize>,
}

/// Request query of the /notarize API
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotarizationRequestQuery {
    /// Session id that is returned from /session API
    pub session_id: String,
}

/// Types of client that the prover is using
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClientType {
    /// Client that has access to the transport layer
    Tcp,
    /// Client that cannot directly access transport layer, e.g. browser extension
    Websocket,
}

/// Global data that needs to be shared with the axum handlers
#[derive(Clone, Debug)]
pub struct NotaryGlobals {
    pub notary_signing_key: SigningKey,
    pub notarization_config: NotarizationProperties,
    /// A temporary storage to store configuration data, mainly used for WebSocket client
    pub store: Arc<Mutex<HashMap<String, Option<usize>>>>,
    pub authorization_whitelist_path: Option<String>,
}

impl NotaryGlobals {
    pub fn new(
        notary_signing_key: SigningKey,
        notarization_config: NotarizationProperties,
        authorization_whitelist_path: Option<String>,
    ) -> Self {
        Self {
            notary_signing_key,
            notarization_config,
            store: Default::default(),
            authorization_whitelist_path,
        }
    }
}
