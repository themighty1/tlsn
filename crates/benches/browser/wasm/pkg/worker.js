import * as Comlink from "./comlink.mjs";

import init, { wasm_main, initThreadPool, setup_tracing_web, init_logging } from './tlsn_benches_browser_wasm.js';

class Worker {
  async init() {
    try {
      await init();
      let obj = {
        level: 'Trace',
        crate_filters: undefined,
        span_events: undefined,
      };
      // Tracing may interfere with the benchmark results. We should enable it only for debugging.
      // setup_tracing_web("debug");
      init_logging(obj);
      await initThreadPool(navigator.hardwareConcurrency);
    } catch (e) {
      console.error(e);
      throw e;
    }
  }

  async run(
      ws_ip,
      ws_port,
      wasm_to_server_port,
      wasm_to_verifier_port,
      wasm_to_native_port
    ) {
    try {
      await wasm_main(
        ws_ip,
        ws_port,
        wasm_to_server_port,
        wasm_to_verifier_port,
        wasm_to_native_port);
    } catch (e) {
      console.error(e);
      throw e;
    }
  }
}

const worker = new Worker();

Comlink.expose(worker);