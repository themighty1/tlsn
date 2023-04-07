use mpc_circuits::types::ValueType;

#[derive(Debug, Clone, PartialEq)]
pub struct ValueRef {
    id: ValueId,
    value_type: ValueType,
}

impl ValueRef {
    pub(crate) fn new(id: ValueId, value_type: ValueType) -> Self {
        Self { id, value_type }
    }

    pub fn id(&self) -> &ValueId {
        &self.id
    }

    pub fn value_type(&self) -> &ValueType {
        &self.value_type
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IdError {
    #[error("id must be at most 32 bytes: {0}")]
    TooLong(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ValueId([u8; 32]);

impl ValueId {
    pub fn new(id: &str) -> Result<Self, IdError> {
        if id.len() > 32 {
            return Err(IdError::TooLong(id.len()));
        }

        let mut bytes = [0u8; 32];
        bytes[..id.len()].copy_from_slice(id.as_bytes());

        Ok(ValueId(bytes))
    }

    pub(crate) fn new_from_bytes(id: [u8; 32]) -> Self {
        ValueId(id)
    }
}

impl AsRef<str> for ValueId {
    fn as_ref(&self) -> &str {
        std::str::from_utf8(&self.0).unwrap()
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ThreadId(usize);

impl ThreadId {
    pub(crate) fn new(id: usize) -> Self {
        ThreadId(id)
    }

    pub(crate) fn increment(&mut self) -> Self {
        let prev = *self;
        self.0 += 1;
        prev
    }
}

impl AsRef<usize> for ThreadId {
    fn as_ref(&self) -> &usize {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ThreadName(String);

impl ThreadName {
    pub(crate) fn new(id: &str) -> Self {
        ThreadName(id.to_string())
    }
}

impl AsRef<str> for ThreadName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct OperationId(usize);

impl OperationId {
    pub(crate) fn new(id: usize) -> Self {
        OperationId(id)
    }

    pub(crate) fn increment(&mut self) -> Self {
        let prev = *self;
        self.0 += 1;
        prev
    }
}

impl AsRef<usize> for OperationId {
    fn as_ref(&self) -> &usize {
        &self.0
    }
}
