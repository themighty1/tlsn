use actor_ot::{OTActorReceiverConfig, OTActorSenderConfig};
use mpc_share_conversion::{ReceiverConfig, SenderConfig};
use tls_client::{ClientConfig, OwnedTrustAnchor, RootCertStore};
use tlsn_tls_mpc::{MpcTlsCommonConfig, MpcTlsLeaderConfig};

pub struct ProverConfig {
    pub client_config: ClientConfig,
    pub mpc_config: MpcTlsLeaderConfig,
    pub ot_config: (OTActorSenderConfig, OTActorReceiverConfig),
    pub p256_config: (SenderConfig, ReceiverConfig),
    pub gf2_config: SenderConfig,
    // ...
}

impl Default for ProverConfig {
    fn default() -> Self {
        let client_config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(add_mozilla_roots())
            .with_no_client_auth();
        let ot_sender_config = OTActorSenderConfig::builder()
            .id("ot/0")
            .initial_count(200_000)
            .build()
            .unwrap();
        let ot_receiver_config = OTActorReceiverConfig::builder()
            .id("ot/0")
            .initial_count(200_000)
            .build()
            .unwrap();
        let p256_config = (
            SenderConfig::builder().id("p256/0").build().unwrap(),
            ReceiverConfig::builder().id("p256/1").build().unwrap(),
        );
        let gf2_config = SenderConfig::builder().id("gf2").build().unwrap();

        let common_config = MpcTlsCommonConfig::builder().id("tlsn").build().unwrap();
        let mpc_config = MpcTlsLeaderConfig::builder()
            .common(common_config.clone())
            .build()
            .unwrap();

        Self {
            client_config,
            mpc_config,
            ot_config: (ot_sender_config, ot_receiver_config),
            p256_config,
            gf2_config,
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
