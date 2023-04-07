use blake3::Hasher;

use mpc_circuits::types::Value;
use serde::{Deserialize, Serialize};

use crate::{label_state, EncodedValue};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EqualityCheck([u8; 32]);

impl EqualityCheck {
    /// Creates a new equality check value from the given encodings and purported
    /// output values.
    pub fn new(
        full: &[EncodedValue<label_state::Full>],
        active: &[EncodedValue<label_state::Active>],
        purported_values: &[Value],
        order: bool,
    ) -> Self {
        assert_eq!(full.len(), active.len());
        assert_eq!(full.len(), purported_values.len());

        let mut hasher = Hasher::new();

        let full_iter =
            full.into_iter()
                .zip(purported_values)
                .flat_map(|(encoded, purported_value)| {
                    encoded
                        .select(purported_value.clone())
                        .unwrap()
                        .iter()
                        .flat_map(|label| label.into_inner().to_be_bytes())
                        .collect::<Vec<u8>>()
                });
        let active_iter = active.into_iter().flat_map(|encoded| {
            encoded
                .iter()
                .flat_map(|label| label.into_inner().to_be_bytes())
        });

        let bytes: Vec<u8> = if order {
            full_iter.chain(active_iter).collect()
        } else {
            active_iter.chain(full_iter).collect()
        };

        hasher.update(&bytes);

        EqualityCheck(hasher.finalize().into())
    }
}
