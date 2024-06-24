use std::{
    future::IntoFuture,
    io::{Read, Write},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};

use anyhow::Context;
use async_trait::async_trait;
use futures::{
    channel::{oneshot, oneshot::Receiver},
    AsyncReadExt as _, AsyncWriteExt as _, Future,
};
use serde::Deserialize;
use tlsn_core::Direction;
use tlsn_server_fixture::{CA_CERT_DER, SERVER_DOMAIN};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio_util::{
    compat::TokioAsyncReadCompatExt,
    io::{InspectReader, InspectWriter},
};

use tlsn_prover::tls::{Prover, ProverConfig};
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};

use std::io::Error as IoError;

use std::{pin::Pin, sync::Mutex};

use tls_core::anchors::RootCertStore;

#[async_trait]
pub trait ProverTrait<S1, S2>
where
    S1: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static,
    S2: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static,
{
    /// Sets up the prover preparing it to be run. Returns a prover ready to be run.
    async fn setup(
        upload_size: usize,
        download_size: usize,
        defer_decryption: bool,
        io: S1,
        client_conn: S2,
    ) -> Self;

    /// Runs the prover. Returns the total run time in seconds.
    async fn run(&mut self) -> u64;
}

pub async fn run_prover<
    S1: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static,
    S2: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static,
>(
    upload_size: usize,
    download_size: usize,
    defer_decryption: bool,
    io: S1,
    client_conn: S2,
) -> anyhow::Result<()> {
    let prover = Prover::new(
        ProverConfig::builder()
            .id("test")
            .server_dns(SERVER_DOMAIN)
            .root_cert_store(root_store())
            .max_sent_data(upload_size + 256)
            .max_recv_data(download_size + 256)
            .build()
            .context("invalid prover config")?,
    )
    .setup(io.compat())
    .await?;

    let (mut mpc_tls_connection, prover_fut) = prover.connect(client_conn.compat()).await.unwrap();

    let prover_ctrl = prover_fut.control();

    #[cfg(target_arch = "wasm32")]
    let prover_task = spawn_wasm(prover_fut);
    #[cfg(not(target_arch = "wasm32"))]
    let prover_task = tokio::spawn(prover_fut);

    let request = format!(
        "GET /bytes?size={} HTTP/1.1\r\nConnection: close\r\nData: {}\r\n\r\n",
        download_size,
        String::from_utf8(vec![0x42u8; upload_size]).unwrap(),
    );

    if defer_decryption {
        prover_ctrl.defer_decryption().await?;
    }

    mpc_tls_connection.write_all(request.as_bytes()).await?;
    mpc_tls_connection.close().await?;

    let mut response = vec![];
    mpc_tls_connection.read_to_end(&mut response).await?;

    let mut prover = prover_task.await??.start_prove();

    prover.reveal(0..prover.sent_transcript().data().len(), Direction::Sent)?;
    prover.reveal(
        0..prover.recv_transcript().data().len(),
        Direction::Received,
    )?;
    prover.prove().await?;
    prover.finalize().await?;

    Ok(())
}

fn root_store() -> RootCertStore {
    let mut root_store = RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();
    root_store
}

/// Spawns a future using `wasm_bindgen_futures`.
pub fn spawn_wasm<F>(fut: F) -> Receiver<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let (result_sender, result_receiver) = oneshot::channel();
    let handled_fut = async {
        let result = fut.await;
        let _ = result_sender.send(result);
    };
    use wasm_bindgen_futures::spawn_local;
    spawn_local(handled_fut);
    result_receiver
}
