use std::{
    io::{Read, Write},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};

use crate::{
    config::{BenchInstance, Config},
    metrics::Metrics,
    set_interface, PROVER_INTERFACE,
};
use anyhow::{Context, Ok as anyhowOk};

use futures::{AsyncReadExt as _, AsyncWriteExt as _};
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

use futures::{channel::oneshot, SinkExt, StreamExt, TryStreamExt};

use std::io::Error as IoError;

use futures::task::{Context as Context2, Poll};
use std::{pin::Pin, sync::Mutex};

use tls_core::anchors::RootCertStore;

use async_trait::async_trait;
use tlsn_benches_library::{run_prover, ProverTrait};

pub struct NativeProver<S1, S2>
where
    S1: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static,
    S2: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static,
{
    upload_size: usize,
    download_size: usize,
    defer_decryption: bool,
    io: Option<S1>,
    client_conn: Option<S2>,
}

#[async_trait]
impl<S1, S2> ProverTrait<S1, S2> for NativeProver<S1, S2>
where
    S1: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static,
    S2: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static,
{
    async fn setup(
        upload_size: usize,
        download_size: usize,
        defer_decryption: bool,
        io: S1,
        client_conn: S2,
    ) -> Self {
        Self {
            upload_size,
            download_size,
            defer_decryption,
            io: Some(io),
            client_conn: Some(client_conn),
        }
    }

    async fn run(&mut self) -> u64 {
        let io = std::mem::take(&mut self.io);
        let client_conn = std::mem::take(&mut self.client_conn);

        let start_time = Instant::now();

        run_prover(
            self.upload_size,
            self.download_size,
            self.defer_decryption,
            io.unwrap(),
            client_conn.unwrap(),
        )
        .await
        .unwrap();
        Instant::now().duration_since(start_time).as_secs()
    }
}

// mod tests {
//     pub trait D: Sized {}
//     #[derive(Default)]
//     struct E {}
//     impl D for E {}

//     trait A<B, C>
//     where
//         B: D,
//         C: D,
//     {
//         fn setup(b: B, c: C) -> Self;
//         fn foo(&self) {}
//     }

//     #[derive(Default)]
//     struct X<K, L>
//     where
//         K: D,
//         L: D,
//     {
//         field1: K,
//         field2: L,
//     }

//     impl<K, L> A<K, L> for X<K, L>
//     where
//         K: D,
//         L: D,
//     {
//         fn setup(b: K, c: L) -> Self {
//             Self {
//                 field1: b,
//                 field2: c,
//             }
//         }

//         fn foo(&self) {}
//     }

//     #[derive(Default)]
//     struct Y {}

//     impl<K, L> A<K, L> for Y
//     where
//         K: D,
//         L: D,
//     {
//         fn setup(b: K, c: L) -> Self {
//             Self {}
//         }

//         fn foo(&self) {}
//     }

//     #[test]
//     fn test() {
//         let arg1 = E::default();
//         let arg2 = E::default();

//         run_setup(arg1, arg2);
//     }

//     fn run_setup<G: D>(io1: G, io2: G) {
//         let x = Y::setup(io1, io2);
//         <Y<G, G> as A<G, G>>::foo(&x);

//         //A::<E, E>::foo(&x);
//         //y.foo();
//     }
// }
