//! roBrowserLegacy Remote Client, in Rust.
//!
//! One HTTP port doing three jobs: serving the built client, serving game
//! assets out of GRF archives, and proxying the game socket from WebSocket to
//! TCP.  Everything is same-origin by design, which is why the client needs no
//! CORS handling, no second port and no mixed-content exemption.

use std::sync::Arc;

use robrowser_remoteclient::client::Client;
use robrowser_remoteclient::config::{self, Config};
use robrowser_remoteclient::http::Cors;
use robrowser_remoteclient::routes::{self, AppState};
use robrowser_remoteclient::{error, info, logger, managed::Managed, validator};

fn main() {
    // The blocking pool does the GRF reads; the async runtime does the sockets.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            error!("Failed to start the async runtime: {e}");
            std::process::exit(1);
        }
    };

    let code = runtime.block_on(run());
    std::process::exit(code);
}

async fn run() -> i32 {
    // `.env` first, so it can set NODE_ENV before anything reads it.
    let cwd = std::env::current_dir().unwrap_or_else(|_| ".".into());
    let dotenv_root = std::env::var("SERVER_ROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or(cwd);
    config::load_dotenv(&dotenv_root.join(".env"));

    let bootstrap = if std::env::args().any(|a| a == "--managed") {
        match Managed::bootstrap() {
            Ok(value) => Some(value),
            Err(e) => {
                error!("Managed startup failed: {e}");
                return 1;
            }
        }
    } else {
        None
    };

    let cfg = Arc::new(Config::from_env());
    logger::set_debug(!cfg.is_prod);

    if std::env::args().any(|a| a == "--version" || a == "-V") {
        info!("robrowser-remoteclient {}", env!("CARGO_PKG_VERSION"));
        return 0;
    }

    if std::env::args().any(|a| a == "--capabilities") {
        println!(
            "{}",
            serde_json::json!({
                "service": "robrowser-remoteclient", "version": env!("CARGO_PKG_VERSION"),
                "managedProtocol": robrowser_remoteclient::managed::PROTOCOL,
            })
        );
        return 0;
    }

    info!(
        "Starting roBrowser Remote Client... [{}]\n",
        if cfg.is_prod {
            "production"
        } else {
            "development"
        }
    );

    let started = std::time::Instant::now();
    let (grfs, validation) = {
        let cfg = Arc::clone(&cfg);
        match tokio::task::spawn_blocking(move || validator::validate_and_load(&cfg)).await {
            Ok(result) => result,
            Err(e) => {
                error!("Startup validation panicked: {e}");
                return 1;
            }
        }
    };

    // Verbose in development; in production only speak up when something broke.
    if !cfg.is_prod || !validation.success() {
        validation.print_report();
    }

    if !validation.success() {
        error!("Server cannot start due to configuration errors.");
        return 1;
    }

    let health = Arc::new(validation.status_json());

    let client = {
        let cfg = Arc::clone(&cfg);
        match tokio::task::spawn_blocking(move || Client::new(cfg, grfs)).await {
            Ok(client) => Arc::new(client),
            Err(e) => {
                error!("Failed to build the asset index: {e}");
                return 1;
            }
        }
    };

    let stats = client.index_stats();
    info!(
        "Client initialized in {} ms ({} files, {} index keys across {} archive(s))",
        started.elapsed().as_millis(),
        stats.unique_files,
        stats.total_files,
        stats.grf_count
    );

    let mut managed = match bootstrap {
        Some(bootstrap) => match Managed::start(bootstrap, cfg.port).await {
            Ok((managed, shutdown)) => {
                // The parent keeps stdin open. EOF also covers force-quit and
                // crashes, without a PID-reuse race or platform process scans.
                std::thread::spawn(move || {
                    use std::io::Read;
                    let mut buf = [0u8; 256];
                    let stdin = std::io::stdin();
                    let mut input = stdin.lock();
                    while matches!(input.read(&mut buf), Ok(n) if n > 0) {}
                    let _ = shutdown.send(true);
                });
                Some(managed)
            }
            Err(e) => {
                error!("Managed startup failed: {e}");
                return 1;
            }
        },
        None => None,
    };

    let state = AppState {
        cfg: Arc::clone(&cfg),
        client: Arc::clone(&client),
        cors: Arc::new(Cors::new(cfg.client_public_url.as_deref())),
        health,
    };

    let app = routes::router(state);

    let bind = format!("{}:{}", cfg.bind, cfg.port);
    let listener = match tokio::net::TcpListener::bind(&bind).await {
        Ok(listener) => listener,
        Err(e) => {
            error!("Could not bind {bind}: {e}");
            return 1;
        }
    };

    if let Some(managed) = &managed {
        if let Err(e) = managed.announce() {
            error!("Could not notify parent: {e}");
            return 1;
        }
    }

    let mut banner = format!("Server ready on http://localhost:{}", cfg.port);
    if cfg.enable_static_serve {
        banner.push_str(&format!(
            " | Game: http://localhost:{}/applications/pwa/index.html",
            cfg.port
        ));
    }
    if cfg.enable_wsproxy {
        banner.push_str(&format!(
            " | WS proxy: /ws/ (allowed: {})",
            cfg.ws_allowed_targets.join(", ")
        ));
    }
    info!("{banner}");

    // Warm-up runs after the socket is listening: /api/health must answer
    // before the cache is hot, because that is what a supervisor waits on.
    if cfg.cache_warm_up {
        let client = Arc::clone(&client);
        let limit = cfg.cache_warm_up_limit;
        tokio::task::spawn_blocking(move || {
            let started = std::time::Instant::now();
            let warmed = client.warm_cache(limit);
            info!(
                "Cache warmed with {warmed} files in {} ms",
                started.elapsed().as_millis()
            );
        });
    }

    let os_shutdown = async {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        {
            let mut term =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                    Ok(term) => term,
                    Err(_) => {
                        let _ = ctrl_c.await;
                        return;
                    }
                };
            tokio::select! {
                _ = ctrl_c => {},
                _ = term.recv() => {},
            }
        }
        #[cfg(not(unix))]
        {
            let _ = ctrl_c.await;
        }
    };
    let shutdown = async move {
        let managed_shutdown = async {
            match managed.as_mut() {
                Some(m) => m.stopped().await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! { _ = os_shutdown => {}, _ = managed_shutdown => {} }
        info!("Shutting down.");
        // Upgraded WebSocket sessions can otherwise hold graceful shutdown
        // forever. Bound teardown even when a browser never closes its socket.
        tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            std::process::exit(0);
        });
    };

    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
    {
        error!("Server error: {e}");
        return 1;
    }

    0
}
