mod utils;

use mpc_aio::ot::{OtReceive, OtReceiver, OtSend, OtSender};
use mpc_core::ot::{ChaChaAesOtReceiver, ChaChaAesOtSender, OtMessage};
use mpc_core::proto;
use tokio_util::codec::Framed;
use utils_aio::codec::ProstCodecDelimited;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;
use web_sys::console;
use ws_stream_wasm::WsMeta;

use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;
use rand::thread_rng;

use aes::cipher::{generic_array::GenericArray, NewBlockCipher};
use aes::Aes128;
use mpc_core::ot::*;
use mpc_core::utils::u8vec_to_boolvec;
use mpc_core::Block;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use rand_core::RngCore;

#[wasm_bindgen]
pub fn run() {
    utils::set_panic_hook();
    spawn_local(ot());
}

pub async fn ot() {
    let (ws, wsio) = WsMeta::connect("ws://0.0.0.0:3212", None)
        .await
        .expect_throw("Could not create websocket");

    let mut stream = Framed::new(
        wsio.into_io(),
        ProstCodecDelimited::<OtMessage, proto::ot::OtMessage>::default(),
    );

    let mut receiver = OtReceiver::new(ChaChaAesOtReceiver::default(), stream);

    let received = receiver.receive(&[false, true, false]).await;

    console::log_1(&format!("{:?}", received).into());
}

// pub async fn secret_share() {
//     let point = SecretKey::random(&mut thread_rng())
//         .public_key()
//         .to_projective()
//         .to_encoded_point(false);

//     console::log_1(&"generated key".into());

//     let (ws, wsio) = WsMeta::connect("ws://0.0.0.0:3212", None)
//         .await
//         .expect_throw("Could not create websocket");

//     console::log_1(&"connected".into());

//     let mut stream = Framed::new(
//         wsio.into_io(),
//         ProstCodecDelimited::<SecretShareMessage, proto::secret_share::SecretShareMessage>::default(
//         ),
//     );

//     let mut master = SecretShareMaster::new();

//     let share = master.run(&mut stream, point).await.unwrap();

//     console::log_1(&format!("Done: {}", share).into());
// }
