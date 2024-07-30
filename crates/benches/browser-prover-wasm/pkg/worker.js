import init, { wasm_start, initThreadPool, setup_tracing_web } from './tlsn_benches_browser_prover_wasm.js';

async function run() { 
    await init();
    //setup_tracing_web("debug");
    await initThreadPool(navigator.hardwareConcurrency);
    await wasm_start();
  }

  run();