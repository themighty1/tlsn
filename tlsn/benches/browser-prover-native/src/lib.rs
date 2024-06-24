//! Types and methods for running the prover in the browser.
//!
//! Conceptually the prover consists of two parts:
//!
//! one is run natively
//! the other runs in a wasm environment
//! The native part is responsible for setting up the wasm part.

pub mod native;
pub use native::BrowserProver;
