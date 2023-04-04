use std::sync::Arc;

use mpc_circuits::{types::Value, Circuit};

enum VmError {}

struct RefValue {}

struct ExecuteCommand {
    circ: Arc<Circuit>,
    public_inputs: Vec<RefValue>,
    private_inputs: Vec<RefValue>,
    public_outputs: Vec<RefValue>,
    private_outputs: Vec<RefValue>,
    decode_outputs: Vec<RefValue>,
}

struct ExecuteResponse {
    public_outputs: Vec<RefValue>,
    private_outputs: Vec<RefValue>,
    decode_outputs: Vec<Value>,
}

trait Vm {
    fn new_value<T>(&mut self) -> Result<RefValue, VmError>;

    fn execute(&mut self, cmd: ExecuteCommand) -> Result<ExecuteResponse, VmError>;
}

#[cfg(test)]
mod tests {
    use super::*;
}
