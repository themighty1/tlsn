use actor_ot::{create_ot_pair, OTActorReceiverConfig, OTActorSenderConfig};
use tls_client::{ClientConfig, OwnedTrustAnchor, RootCertStore};
use tls_mpc::MpcTlsLeaderConfig;

pub struct ProverConfig {
    pub client_config: ClientConfig,
    pub mpc_config: MpcTlsLeaderConfig,
    pub ot_sender_config: OTActorSenderConfig,
    pub ot_receiver_config: OTActorReceiverConfig,
    pub prover_run_id: String,
    // ...
}

impl Default for ProverConfig {
    fn default() -> Self {
        let client_config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(add_mozilla_roots())
            .with_no_client_auth();

        Self {
            client_config,
            prover_run_id: String::from("default_id"),
        }
    }
}

fn add_mozilla_roots() -> RootCertStore {
    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
    root_store
}
