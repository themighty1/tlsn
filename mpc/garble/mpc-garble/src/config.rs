use derive_builder::Builder;
use mpc_circuits::types::ValueType;

use crate::types::ValueId;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Visibility {
    /// A value known to all parties
    Public,
    /// A value known by one party
    Private,
}

#[derive(Debug, Clone, Builder)]
pub struct ValueConfig {
    #[builder(default = "0")]
    pub(crate) domain: u64,
    #[builder(setter(custom))]
    pub(crate) id: ValueId,
    pub(crate) value_type: ValueType,
    #[builder(setter(custom), default = "Visibility::Private")]
    pub(crate) visibility: Visibility,
}

impl ValueConfigBuilder {
    pub fn id(&mut self, id: impl AsRef<str>) -> &mut Self {
        self.id = Some(ValueId::new(id.as_ref()).expect("id should be valid"));
        self
    }

    pub fn public(&mut self) -> &mut Self {
        self.visibility = Some(Visibility::Public);
        self
    }

    pub fn private(&mut self) -> &mut Self {
        self.visibility = Some(Visibility::Private);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Role {
    Leader,
    Follower,
}
