use mpc_aio::secret_share::SecretShareSlave;
use mpc_aio::twopc::TwoPCProtocol;
use mpc_core::proto;
use mpc_core::secret_share::SecretShareMessage;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;
use rand::thread_rng;
use tokio;
use tokio::net::TcpListener;
use tokio_util::codec::Framed;
use utils_aio::codec::ProstCodecDelimited;
use ws_stream_tungstenite::WsStream;

#[tokio::main]
async fn main() {
    let addr = "0.0.0.0:3212";

    let listener = TcpListener::bind(addr).await.unwrap();
    println!("Listening on: {}", addr);

    let (stream, _) = listener.accept().await.unwrap();

    let ws = async_tungstenite::tokio::accept_async(stream)
        .await
        .expect("Error during the websocket handshake occurred");

    println!("Connected");

    let ws = WsStream::new(ws);

    let mut stream = Framed::new(
        ws,
        ProstCodecDelimited::<SecretShareMessage, proto::secret_share::SecretShareMessage>::default(
        ),
    );

    let mut slave = SecretShareSlave::new();

    let point = SecretKey::random(&mut thread_rng())
        .public_key()
        .to_projective()
        .to_encoded_point(false);

    let share = slave.run(&mut stream, point).await.unwrap();

    println!("Share: {:?}", share);
}
