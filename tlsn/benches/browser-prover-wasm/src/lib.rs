use async_io_stream;
use bytes::{Bytes, BytesMut};
use futures::SinkExt;
use serde::{Deserialize, Serialize};
use serio::{
    codec::{Bincode, Framed},
    stream::IoStreamExt,
    IoDuplex, IoSink, IoStream, Serializer, Sink, SinkExt as _, StreamExt as _,
};
use std::{
    io::{Error, ErrorKind, Result},
    pin::Pin,
    task::{ready, Context, Poll},
};
use tlsn_benches_library::run_prover;
use tokio::io::{duplex, AsyncRead, AsyncWrite, DuplexStream};
use tokio_util::{
    codec::LengthDelimitedCodec,
    compat::{Compat, TokioAsyncReadCompatExt},
};
use wasm_bindgen::prelude::*;
pub use wasm_bindgen_rayon::init_thread_pool;
use ws_stream_wasm::{WsStream, *};

use tlsn_benches_browser_prover_core::{
    msg::{Config, ExpectingConfig, Runtime},
    FramedIo,
};

#[wasm_bindgen]
pub async fn wasm_start() {
    use futures::{SinkExt, StreamExt};
    use web_sys;
    use ws_stream_wasm::*;

    macro_rules! log {
        ( $( $t:tt )* ) => {
            web_sys::console::log_1(&format!( $( $t )* ).into());
        }
    }

    //Set up connections.
    let (_, client_conn_ws) = WsMeta::connect("ws://127.0.0.1:20003/", None)
        .await
        .expect("assume the notary ws connection succeeds");
    let client_conn = client_conn_ws.into_io();

    let (_, io_ws) = WsMeta::connect("ws://127.0.0.1:30003/", None)
        .await
        .expect("assume the notary ws connection succeeds");
    let io = io_ws.into_io();

    log!("connected to ws");

    // Connect to the native component.
    let (_, cmd_ws) = WsMeta::connect("ws://127.0.0.1:40003/", None)
        .await
        .expect("assume the notary ws connection succeeds");
    let mut native_io = FramedIo::new(cmd_ws.into_io());
    native_io.send(ExpectingConfig {}).await.unwrap();

    log!("before cmd_ws.next()");
    let cfg: Config = native_io.expect_next().await.unwrap();
    log!("after cmd_ws.next()");

    use web_time::Instant;

    let start_time = Instant::now();
    _ = run_prover(
        cfg.upload_size as usize,
        cfg.download_size as usize,
        cfg.defer_decryption,
        io,
        client_conn,
    )
    .await;

    native_io
        .send(Runtime(start_time.elapsed().as_secs()))
        .await
        .unwrap();

    log!("run_prover done");
}

#[wasm_bindgen]
pub fn setup_tracing_web(logging_filter: &str) {
    use std::panic;
    use tracing::{debug, error};
    use tracing_subscriber::{
        fmt::{format::Pretty, time::UtcTime},
        prelude::*,
    };
    use tracing_web::{performance_layer, MakeWebConsoleWriter};
    extern crate console_error_panic_hook;
    use tracing_subscriber::EnvFilter;

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false) // Only partially supported across browsers
        .with_timer(UtcTime::rfc_3339()) // std::time is not available in browsers
        // .with_thread_ids(true)
        // .with_thread_names(true)
        .with_writer(MakeWebConsoleWriter::new()); // write events to the console
    let perf_layer = performance_layer().with_details_from_fields(Pretty::default());

    let filter_layer = EnvFilter::builder()
        .parse(logging_filter)
        .unwrap_or_default();

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .with(perf_layer)
        .init(); // Install these as subscribers to tracing events

    // https://github.com/rustwasm/console_error_panic_hook
    panic::set_hook(Box::new(|info| {
        error!("panic occurred: {:?}", info);
        console_error_panic_hook::hook(info);
    }));

    debug!("🪵 Logging set up 🪵")
}
