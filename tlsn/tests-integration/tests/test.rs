use std::println;

use hyper::{Body, Request, StatusCode};
use tlsn_notary::{Notary, NotaryConfig};
use tlsn_prover::{Prover, ProverConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::Instrument;
use tracing_subscriber::fmt::format::FmtSpan;

#[tokio::test]
async fn test() {
    let subscriber = tracing_subscriber::fmt()
        .with_span_events(FmtSpan::ACTIVE)
        .with_max_level(tracing::Level::TRACE)
        .init();
    let (socket_0, socket_1) = tokio::io::duplex(2 << 23);

    tokio::join!(prover(socket_0), notary(socket_1));
}

#[tracing::instrument(name = "prover-tests-integration")]
async fn prover<T: AsyncWrite + AsyncRead + Send + Unpin + 'static + std::fmt::Debug>(
    notary_socket: T,
) {
    let dns = "tlsnotary.org";
    let server_socket = tokio::net::TcpStream::connect(dns.to_string() + ":443")
        .await
        .unwrap();
    let server_socket = server_socket.compat();

    let (prover, server_socket) = Prover::new(
        ProverConfig::builder().id("test").build().unwrap(),
        dns,
        server_socket,
        notary_socket.compat(),
    )
    .unwrap();

    tokio::spawn(
        async move {
            if let Err(e) = prover.run().await {
                println!("Error in prover: {}", e);
            }
        }
        .instrument(tracing::info_span!("PROVER::")),
    );

    println!("starting handshake");

    let (mut request_sender, connection) = hyper::client::conn::handshake(server_socket.compat())
        .instrument(tracing::info_span!("HYPER_HANDSHAKE::"))
        .await
        .unwrap();

    println!("handshake done");

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            println!("Error in connection: {}", e);
        }
        .instrument(tracing::info_span!("CONNECTION::"))
    });

    let request = Request::builder()
        .header("Host", "tlsnotary.org")
        .header("Connection", "close")
        .method("GET")
        .body(Body::from(""))
        .unwrap();

    println!("sending request");

    let response = request_sender
        .send_request(request)
        .instrument(tracing::info_span!("SEND_REQUEST::"))
        .await
        .unwrap();

    println!("request sent");

    assert!(response.status() == StatusCode::OK);

    println!("Response: {:?}", response);
}

async fn notary<T: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static + std::fmt::Debug>(
    socket: T,
) {
    let mut notary = Notary::new(NotaryConfig::builder().id("test").build().unwrap());

    let signing_key = p256::ecdsa::SigningKey::from_bytes(&[1u8; 32].into()).unwrap();

    notary
        .run::<_, p256::ecdsa::Signature>(socket.compat(), &signing_key)
        .await
        .unwrap();
}
