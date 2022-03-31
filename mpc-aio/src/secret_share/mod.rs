pub mod errors;
pub mod master;
pub mod slave;

pub use errors::SecretShareError;
pub use master::SecretShareMaster;
pub use slave::SecretShareSlave;

pub use mpc_core::secret_share::SecretShareMessage;
