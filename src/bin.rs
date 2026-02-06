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
    let local_homeservers = env::var("LIVEKIT_LOCAL_HOMESERVERS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect::<HashSet<_>>();
    let lk_jwt_port = env::var("LIVEKIT_JWT_PORT").unwrap_or_else(|_| "8080".to_string());

    if key.is_empty() || secret.is_empty() || lk_url.is_empty() || local_homeservers.is_empty() {
        eprintln!(
            "LIVEKIT_KEY[_FILE], LIVEKIT_SECRET[_FILE], LIVEKIT_URL, and LIVEKIT_LOCAL_HOMESERVERS must be set"
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
        .danger_accept_invalid_certs(skip_verify_tls);
    let federation_client = resolver.create_client_with_builder(builder).unwrap();

    let state = Arc::new(AppState {
        key,
        secret,
        lk_url,
        local_homeservers,
        federation_client,
        resolver,
    });

    let app = build_app(state);

    let addr = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        lk_jwt_port.parse().unwrap(),
    );
    println!("Listening on {addr}");

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
