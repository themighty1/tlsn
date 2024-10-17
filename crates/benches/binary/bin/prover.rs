use std::{
    fs::metadata,
    io::Write,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use anyhow::Context;
use hmac_sha256::{MpcPrf, Prf, PrfConfig, Role};
use tlsn_benches::{
    config::{BenchInstance, Config},
    metrics::Metrics,
    set_interface, PROVER_INTERFACE,
};
use tlsn_benches_library::{AsyncIo, ProverTrait};
use tlsn_server_fixture::bind;

use csv::WriterBuilder;
use mpz_common::executor::test_st_executor;
use mpz_garble::{config::Role as DEAPRole, protocol::deap::DEAPThread, Memory};
use mpz_ot::ideal::ot::ideal_ot;
use tokio_util::{
    compat::TokioAsyncReadCompatExt,
    io::{InspectReader, InspectWriter},
};
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};

#[cfg(not(feature = "browser-bench"))]
use tlsn_benches::prover::NativeProver as BenchProver;
#[cfg(feature = "browser-bench")]
use tlsn_benches_browser_native::BrowserProver as BenchProver;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config_path = std::env::var("CFG").unwrap_or_else(|_| "bench.toml".to_string());
    let config: Config = toml::from_str(
        &std::fs::read_to_string(config_path).context("failed to read config file")?,
    )
    .context("failed to parse config")?;

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .init();

    let ip = std::env::var("VERIFIER_IP").unwrap_or_else(|_| "10.10.1.1".to_string());
    let port: u16 = std::env::var("VERIFIER_PORT")
        .map(|port| port.parse().expect("port is valid u16"))
        .unwrap_or(8000);
    let verifier_host = (ip.as_str(), port);

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("metrics.csv")
        .context("failed to open metrics file")?;

    // Preprocess the PRF circuits as they are allocating a lot of memory, which don't need to be accounted for in the benchmarks.
    preprocess_prf_circuits().await;

    {
        let mut metric_wtr = WriterBuilder::new()
            // If file is not empty, assume that the CSV header is already present in the file.
            .has_headers(metadata("metrics.csv")?.len() == 0)
            .from_writer(&mut file);
        for bench in config.benches {
            let instances = bench.flatten();
            for instance in instances {
                println!("{:?}", &instance);

                let io = tokio::net::TcpStream::connect(verifier_host)
                    .await
                    .context("failed to open tcp connection")?;
                metric_wtr.serialize(
                    run_instance(instance, io)
                        .await
                        .context("failed to run instance")?,
                )?;
                metric_wtr.flush()?;
            }
        }
    }

    file.flush()?;

    Ok(())
}

async fn preprocess_prf_circuits() {
    let pms = [42u8; 32];
    let client_random = [69u8; 32];

    let (leader_ctx_0, follower_ctx_0) = test_st_executor(128);
    let (leader_ctx_1, follower_ctx_1) = test_st_executor(128);

    let (leader_ot_send_0, follower_ot_recv_0) = ideal_ot();
    let (follower_ot_send_0, leader_ot_recv_0) = ideal_ot();
    let (leader_ot_send_1, follower_ot_recv_1) = ideal_ot();
    let (follower_ot_send_1, leader_ot_recv_1) = ideal_ot();

    let leader_thread_0 = DEAPThread::new(
        DEAPRole::Leader,
        [0u8; 32],
        leader_ctx_0,
        leader_ot_send_0,
        leader_ot_recv_0,
    );
    let leader_thread_1 = leader_thread_0
        .new_thread(leader_ctx_1, leader_ot_send_1, leader_ot_recv_1)
        .unwrap();

    let follower_thread_0 = DEAPThread::new(
        DEAPRole::Follower,
        [0u8; 32],
        follower_ctx_0,
        follower_ot_send_0,
        follower_ot_recv_0,
    );
    let follower_thread_1 = follower_thread_0
        .new_thread(follower_ctx_1, follower_ot_send_1, follower_ot_recv_1)
        .unwrap();

    // Set up public PMS for testing.
    let leader_pms = leader_thread_0.new_public_input::<[u8; 32]>("pms").unwrap();
    let follower_pms = follower_thread_0
        .new_public_input::<[u8; 32]>("pms")
        .unwrap();

    leader_thread_0.assign(&leader_pms, pms).unwrap();

    let mut leader = MpcPrf::new(
        PrfConfig::builder().role(Role::Leader).build().unwrap(),
        leader_thread_0,
        leader_thread_1,
    );
    let mut follower = MpcPrf::new(
        PrfConfig::builder().role(Role::Follower).build().unwrap(),
        follower_thread_0,
        follower_thread_1,
    );

    futures::join!(
        async {
            leader.setup(leader_pms).await.unwrap();
            leader.set_client_random(Some(client_random)).await.unwrap();
            leader.preprocess().await.unwrap();
        },
        async {
            follower.setup(follower_pms).await.unwrap();
            follower.set_client_random(None).await.unwrap();
            follower.preprocess().await.unwrap();
        }
    );
}

async fn run_instance(instance: BenchInstance, io: impl AsyncIo) -> anyhow::Result<Metrics> {
    let uploaded = Arc::new(AtomicU64::new(0));
    let downloaded = Arc::new(AtomicU64::new(0));
    let io = InspectWriter::new(
        InspectReader::new(io, {
            let downloaded = downloaded.clone();
            move |data| {
                downloaded.fetch_add(data.len() as u64, Ordering::Relaxed);
            }
        }),
        {
            let uploaded = uploaded.clone();
            move |data| {
                uploaded.fetch_add(data.len() as u64, Ordering::Relaxed);
            }
        },
    );

    let BenchInstance {
        name,
        upload,
        upload_delay,
        download,
        download_delay,
        upload_size,
        download_size,
        defer_decryption,
        memory_profile,
    } = instance.clone();

    let _profiler = if memory_profile {
        // Build a testing profiler as it won't output to stderr
        Some(dhat::Profiler::builder().testing().build())
    } else {
        None
    };

    set_interface(PROVER_INTERFACE, upload, 1, upload_delay)?;

    let (client_conn, server_conn) = tokio::io::duplex(1 << 16);
    tokio::spawn(bind(server_conn.compat()));

    let mut prover = BenchProver::setup(
        upload_size,
        download_size,
        defer_decryption,
        Box::new(io),
        Box::new(client_conn),
    )
    .await?;

    let runtime = prover.run().await?;

    let heap_max_bytes = if memory_profile {
        Some(dhat::HeapStats::get().max_bytes)
    } else {
        None
    };

    Ok(Metrics {
        name,
        kind: prover.kind(),
        upload,
        upload_delay,
        download,
        download_delay,
        upload_size,
        download_size,
        defer_decryption,
        runtime,
        uploaded: uploaded.load(Ordering::SeqCst),
        downloaded: downloaded.load(Ordering::SeqCst),
        heap_max_bytes,
    })
}
