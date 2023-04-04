use std::collections::HashMap;

use crate::{label_state, ChaChaEncoder, EncodedValue};

pub struct Generator {
    encoder: ChaChaEncoder,
    cache: HashMap<String, EncodedValue<label_state::Full>>,
}

impl Generator {
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            encoder: ChaChaEncoder::new(seed),
            cache: HashMap::new(),
        }
    }
}

pub struct Evaluator {
    cache: HashMap<String, EncodedValue<label_state::Active>>,
}
