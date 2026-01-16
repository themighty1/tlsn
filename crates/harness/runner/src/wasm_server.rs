use std::{env, net::Ipv4Addr, path::PathBuf};

use anyhow::Result;
use axum::{
    Router,
    http::{HeaderName, HeaderValue},
};
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::{services::ServeDir, set_header::SetResponseHeaderLayer};

use crate::network::Namespace;

pub struct WasmServer {
    namespace: Namespace,
    path: PathBuf,
    addr: (Ipv4Addr, u16),
    handle: Option<duct::Handle>,
}

impl WasmServer {
    pub fn new(namespace: Namespace, path: PathBuf, addr: (Ipv4Addr, u16)) -> Self {
        Self {
            namespace,
            path,
            addr,
            handle: None,
        }
    }

    /// Spawns a new wasm server.
    pub fn start(&mut self) -> Result<()> {
        eprintln!("Starting WASM server...");
        eprintln!("  Binary path: {:?}", self.path);
        eprintln!("  Namespace: {}", self.namespace.name());
        eprintln!("  Address: {}:{}", self.addr.0, self.addr.1);

        // Check if binary exists
        if !self.path.exists() {
            eprintln!("❌ ERROR: WASM server binary not found at {:?}", self.path);
            return Err(anyhow::anyhow!("WASM server binary not found at {:?}", self.path));
        }

        // Check if static directory exists (relative to wasm-server binary location)
        if let Some(parent) = self.path.parent() {
            let static_dir = parent.parent().unwrap().join("static");
            eprintln!("  Checking for static directory at: {:?}", static_dir);
            if !static_dir.exists() {
                eprintln!("❌ WARNING: Static directory not found at {:?}", static_dir);
            } else {
                eprintln!("✅ Static directory exists");
                // Check for generated WASM files
                let generated_dir = static_dir.join("generated");
                if generated_dir.exists() {
                    eprintln!("✅ Generated directory exists");
                } else {
                    eprintln!("❌ WARNING: Generated directory not found at {:?}", generated_dir);
                }
            }
        }

        let cmd = duct::cmd!(
            "sudo",
            "ip",
            "netns",
            "exec",
            &self.namespace.name(),
            "env",
            format!("ADDR={}", self.addr.0),
            format!("PORT={}", self.addr.1),
            &self.path,
        );

        let handle = if !cfg!(feature = "debug") {
            cmd.stderr_capture().stdout_capture().start()?
        } else {
            eprintln!("  Running with debug output enabled");
            cmd.start()?
        };

        eprintln!("✅ WASM server process started with PID: {:?}", handle.pids());

        self.handle = Some(handle);

        Ok(())
    }

    /// Shuts down the wasm server.
    pub fn shutdown(&self) {
        self.handle.as_ref().inspect(|handle| {
            _ = handle.kill();
        });
    }
}

impl Drop for WasmServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub async fn main() -> Result<()> {
    let addr = env::var("ADDR")?;
    let port = env::var("PORT")?.parse::<u16>()?;

    let files = ServeDir::new("static");

    let service = ServiceBuilder::new()
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("cross-origin-embedder-policy"),
            HeaderValue::from_static("require-corp"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("cross-origin-opener-policy"),
            HeaderValue::from_static("same-origin"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("cache-control"),
            HeaderValue::from_static("no-store"),
        ))
        .service(files);

    // build our application with a single route
    let app = Router::new().fallback_service(service);

    let listener = TcpListener::bind((addr, port)).await?;

    axum::serve(listener, app).await?;

    Ok(())
}
