use jwt_service::{AppState, MatrixResolver, build_app, read_key_secret};
use std::{
    collections::HashSet,
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    let skip_verify_tls = env::var("LIVEKIT_INSECURE_SKIP_VERIFY_TLS").unwrap_or_default()
        == "YES_I_KNOW_WHAT_I_AM_DOING";
    let (key, secret) = read_key_secret();
    let lk_url = env::var("LIVEKIT_URL").unwrap_or_default();

    // Handle LIVEKIT_FULL_ACCESS_HOMESERVERS with fallback to LIVEKIT_LOCAL_HOMESERVERS
    let full_access_homeservers_str = env::var("LIVEKIT_FULL_ACCESS_HOMESERVERS")
        .or_else(|_| {
            let local = env::var("LIVEKIT_LOCAL_HOMESERVERS");
            if local.is_ok() {
                eprintln!("!!! LIVEKIT_LOCAL_HOMESERVERS is deprecated, please use LIVEKIT_FULL_ACCESS_HOMESERVERS instead !!!");
            }
            local
        })
        .unwrap_or_else(|_| {
            eprintln!("LIVEKIT_FULL_ACCESS_HOMESERVERS not set, defaulting to wildcard (*) for full access");
            "*".to_string()
        });

    let full_access_homeservers = full_access_homeservers_str
        .split([',', ' '])
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect::<HashSet<_>>();

    // Handle LIVEKIT_JWT_BIND with fallback to LIVEKIT_JWT_PORT
    let lk_jwt_bind = if let Ok(bind) = env::var("LIVEKIT_JWT_BIND") {
        if env::var("LIVEKIT_JWT_PORT").is_ok() {
            eprintln!(
                "LIVEKIT_JWT_BIND and LIVEKIT_JWT_PORT environment variables MUST NOT be set together"
            );
            std::process::exit(1);
        }
        bind
    } else {
        let port = env::var("LIVEKIT_JWT_PORT").unwrap_or_else(|_| "8080".to_string());
        if env::var("LIVEKIT_JWT_PORT").is_ok() {
            eprintln!(
                "!!! LIVEKIT_JWT_PORT is deprecated, please use LIVEKIT_JWT_BIND instead !!!"
            );
        }
        format!(":{}", port)
    };

    if key.is_empty()
        || secret.is_empty()
        || lk_url.is_empty()
        || full_access_homeservers.is_empty()
    {
        eprintln!(
            "LIVEKIT_KEY[_FILE], LIVEKIT_SECRET[_FILE], LIVEKIT_URL, and LIVEKIT_FULL_ACCESS_HOMESERVERS must be set"
        );
        std::process::exit(1);
    }

    let filter = tracing_subscriber::EnvFilter::builder().from_env_lossy();
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
    let resolver = Arc::new(MatrixResolver::new().await.unwrap());
    let builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .tls_danger_accept_invalid_certs(skip_verify_tls);
    let federation_client = resolver.create_client_with_builder(builder).unwrap();

    println!("LIVEKIT_URL: {}", lk_url);
    println!("LIVEKIT_JWT_BIND: {}", lk_jwt_bind);
    println!(
        "LIVEKIT_FULL_ACCESS_HOMESERVERS: {:?}",
        full_access_homeservers
    );

    let state = Arc::new(AppState {
        key,
        secret,
        lk_url,
        full_access_homeservers,
        federation_client,
        resolver,
    });

    let app = build_app(state);

    // Parse bind address - could be :port or host:port
    let addr = if let Some(stripped) = lk_jwt_bind.strip_prefix(':') {
        // Just a port, bind to 0.0.0.0
        let port: u16 = stripped.parse().unwrap_or_else(|_| {
            eprintln!("Invalid port in LIVEKIT_JWT_BIND: {}", lk_jwt_bind);
            std::process::exit(1);
        });
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
    } else {
        // Full address
        lk_jwt_bind.parse().unwrap_or_else(|_| {
            eprintln!("Invalid address in LIVEKIT_JWT_BIND: {}", lk_jwt_bind);
            std::process::exit(1);
        })
    };

    println!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

/// Handles graceful shutdown signals (Ctrl+C, SIGTERM).
pub async fn shutdown_signal() {
    use tokio::signal;

    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
