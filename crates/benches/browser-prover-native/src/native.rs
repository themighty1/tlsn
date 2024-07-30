use anyhow::Context;
use async_trait::async_trait;
use axum::{
    extract::Extension,
    http::{Request, Response, StatusCode},
    routing::{get, post},
    Json, Router,
};
use bytes::{Bytes, BytesMut};
use futures::{channel::oneshot, Future, SinkExt, TryStream};
use rust_embed::RustEmbed;
use serde::Deserialize;
use serio::{
    codec::{Bincode, Framed},
    stream::IoStreamExt,
    IoDuplex, IoSink, IoStream, Serializer, Sink, SinkExt as _, Stream, StreamExt as _,
};
use std::{
    collections::HashMap,
    env,
    io::{BufRead, BufReader, Error},
    marker::PhantomData,
    path::{Path, PathBuf},
    process::{self, Child, Command, Stdio},
    thread,
};
use tlsn_benches_library::{run_prover, ProverTrait};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    sync::Mutex,
};
use tokio_util::{
    codec::LengthDelimitedCodec,
    compat::{Compat, TokioAsyncReadCompatExt},
};
use tower::{Service, ServiceBuilder};
use tower_http::{
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};
use warp::{
    http::header::{self, HeaderMap, HeaderValue},
    Filter, Reply,
};
use web_time::Duration;

use tlsn_benches_browser_prover_core::{
    msg::{Config, ExpectingConfig, Runtime},
    FramedIo,
};

// The `pkg` dir will be embedded into the binary at compile-time.
#[derive(RustEmbed)]
#[folder = "../browser-prover-wasm/pkg"]
struct Data;

pub struct BrowserProver<S1, S2, T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    // Io to communicate with the browser component.
    browser_io: FramedIo<T>,

    /// Child processes spawned by the prover.
    children: Vec<Child>,
    _pd: PhantomData<(S1, S2, T)>,
}

#[async_trait]
impl<S1, S2> ProverTrait<S1, S2> for BrowserProver<S1, S2, DuplexStream>
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
        println!("before websocat");
        //thread::sleep(Duration::from_secs(1000));

        let process1 = spawn_websocat(20003, 20004).unwrap();
        let process2 = spawn_websocat(30003, 30004).unwrap();
        let process3 = spawn_websocat(40003, 40004).unwrap();

        println!("spawned websocat");

        tokio::spawn(async move {
            // Serve embedded files with additional headers.
            let data_serve = warp_embed::embed(&Data);

            let data_serve_with_headers = data_serve
                .map(|reply| {
                    warp::reply::with_header(reply, "Cross-Origin-Opener-Policy", "same-origin")
                })
                .map(|reply| {
                    warp::reply::with_header(reply, "Cross-Origin-Embedder-Policy", "require-corp")
                });

            warp::serve(data_serve_with_headers)
                .run(([0, 0, 0, 0], 8000))
                .await;
        });

        wsport_to_channel(20004, client_conn).await.unwrap();
        wsport_to_channel(30004, io).await.unwrap();

        let (mut receiver, sender) = tokio::io::duplex(1 << 16);
        wsport_to_channel(40004, sender).await.unwrap();

        let browser = spawn_browser().unwrap();

        // Connection to the browser component.
        let mut browser_io = FramedIo::new(receiver);

        let _msg: ExpectingConfig = browser_io.expect_next().await.unwrap();

        browser_io
            .send(Config {
                upload_size,
                download_size,
                defer_decryption,
            })
            .await
            .unwrap();

        Self {
            browser_io: browser_io,
            children: vec![process1, process2, process3, browser],
            _pd: PhantomData,
        }
    }

    async fn run(&mut self) -> u64 {
        let runtime: Runtime = self.browser_io.expect_next().await.unwrap();

        self.clean_up();

        runtime.0
    }
}

impl<S1, S2, T> BrowserProver<S1, S2, T>
where
    S1: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static,
    S2: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static,
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    fn clean_up(&mut self) {
        println!("doing clean up");
        // Kills all the spawned children.
        let _ = self
            .children
            .iter_mut()
            .map(|c| {
                let _ = (*c).kill().map_err(|_| println!("couldnt kill"));
                println!("waiting to kill");
                (*c).wait().unwrap();
            })
            .collect::<Vec<_>>();
    }
}

/// Binds to the given WebSocket `port`, accepts a WebSocket connections and forwards data between the
/// connection and the `channel`.
pub async fn wsport_to_channel<S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    port: u16,
    channel: S,
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .context("failed to bind to port 2")?;

    tokio::spawn(async move {
        let (tcp, _) = listener
            .accept()
            .await
            .context("failed to accept a connection")
            .unwrap();
        println!("accepted connection from {:?}", tcp);

        forward_data(tcp, channel).await
    });

    Ok(())
}

use anyhow::Result;
use tokio::{io, io::copy_bidirectional};

pub async fn forward_data<S1, S2>(mut tcp_stream: S1, mut channel: S2) -> Result<()>
where
    S1: AsyncWrite + AsyncRead + Unpin,
    S2: AsyncWrite + AsyncRead + Unpin,
{
    let (mut tcp_read_half, mut tcp_write_half) = io::split(tcp_stream);
    let (mut channel_read_half, mut channel_write_half) = io::split(channel);

    let tcp_to_channel = async {
        io::copy(&mut tcp_read_half, &mut channel_write_half).await?;
        use tokio::io::AsyncWriteExt;
        channel_write_half.shutdown().await
    };

    let channel_to_tcp = async {
        io::copy(&mut channel_read_half, &mut tcp_write_half).await?;
        use tokio::io::AsyncWriteExt;
        tcp_write_half.shutdown().await
    };

    tokio::try_join!(tcp_to_channel, channel_to_tcp)?;

    Ok(())
}

pub async fn forward_data2<S1, S2>(mut tcp_stream: S1, mut channel: S2) -> Result<()>
where
    S1: AsyncWrite + AsyncRead + Unpin,
    S2: AsyncWrite + AsyncRead + Unpin,
{
    let (mut tcp_read_half, mut tcp_write_half) = io::split(tcp_stream);
    let (mut channel_read_half, mut channel_write_half) = io::split(channel);

    let tcp_to_channel = async {
        io::copy(&mut tcp_read_half, &mut channel_write_half).await?;
        use tokio::io::AsyncWriteExt;
        channel_write_half.shutdown().await
    };

    let channel_to_tcp = async {
        io::copy(&mut channel_read_half, &mut tcp_write_half).await?;
        use tokio::io::AsyncWriteExt;
        tcp_write_half.shutdown().await
    };

    tokio::try_join!(tcp_to_channel, channel_to_tcp)?;

    Ok(())
}

pub fn spawn_websocat(wsport: usize, tcpport: usize) -> anyhow::Result<(Child)> {
    let path = env::var("HOME").unwrap();
    let path = Path::new(&path);
    let path = path.join(".cargo").join("bin").join("websocat");

    let mut child = Command::new(path)
        .arg("--binary")
        .arg(format!("{}{}", "ws-listen:127.0.0.1:", wsport))
        .arg(format!("{}{}", "tcp:127.0.0.1:", tcpport))
        .arg("--exit-on-eof") // websocat complains if this arg is not present
        //.stdout(Stdio::piped())
        .spawn()
        .unwrap();

    // if let Some(stdout) = child.stdout.take() {
    //     // Use a BufReader to read lines from the process's stdout
    //     let reader = BufReader::new(stdout);

    //     for line in reader.lines() {
    //         match line {
    //             Ok(line) => println!("{}", line), // Print each line to the program's stdout
    //             Err(err) => eprintln!("Error reading line: {}", err),
    //         }
    //     }
    // }

    //let _ = child.wait().expect("Command wasn't running");

    Ok(child)
}

pub fn spawn_browser() -> anyhow::Result<(Child)> {
    let chrome_path = env::var("CHROME_PATH")
        .map_err(|_| {
            panic!("Please make sure the envvar CHROME_PATH contains the full path to Chrome");
        })
        .unwrap();
    let mut cmd = Command::new(chrome_path);
    cmd.arg("--headless=new");
    cmd.arg("--no-sandbox");
    cmd.arg("127.0.0.1:8000");
    //cmd.env("DISPLAY", ":1");

    let Ok(mut child) = cmd.spawn() else {
        println!("Failed to start browser. Please make sure that it is installed.");
        //return clean_up();
        panic!();
    };

    Ok(child)
}
