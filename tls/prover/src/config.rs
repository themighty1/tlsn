use tls_client::{ClientConfig, OwnedTrustAnchor, RootCertStore};

pub struct ProverConfig {
    pub client_config: ClientConfig,
    // ...
}

impl Default for ProverConfig {
    fn default() -> Self {
        let client_config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(add_mozilla_roots())
            .with_no_client_auth();

        Self { client_config }
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
