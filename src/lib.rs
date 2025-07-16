mod resolve;

use axum::{
    Router,
    extract::{Extension, Json},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, options},
};
use livekit_api::access_token::VideoGrants;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, env, sync::Arc, time::Duration};
use tracing::{error, info, instrument, trace};
use url::Url;

pub use resolve::MatrixResolver;

#[derive(Clone)]
pub struct AppState {
    pub key: String,
    pub secret: String,
    pub lk_url: String,
    pub local_homeservers: HashSet<String>,
    pub client: reqwest::Client,
    pub resolver: resolve::MatrixResolver,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct OpenIDTokenType {
    pub access_token: String,
    pub token_type: String,
    pub matrix_server_name: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SFURequest {
    pub room: String,
    pub openid_token: OpenIDTokenType,
    pub device_id: String,
}

#[derive(Serialize, Debug)]
pub struct SFUResponse {
    pub url: String,
    pub jwt: String,
}

#[derive(Serialize, Debug)]
pub struct MatrixError {
    pub errcode: String,
    pub error: String,
}

#[instrument]
pub async fn healthcheck() -> impl IntoResponse {
    StatusCode::OK
}

#[instrument]
pub async fn handle_options() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert("Access-Control-Allow-Origin", "*".parse().unwrap());
    headers.insert("Access-Control-Allow-Methods", "POST".parse().unwrap());
    headers.insert(
        "Access-Control-Allow-Headers",
        "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token"
            .parse()
            .unwrap(),
    );
    (StatusCode::OK, headers)
}

#[instrument(skip(state, payload))]
pub async fn handle_post(
    Extension(state): Extension<Arc<AppState>>,
    Json(payload): Json<SFURequest>,
) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert("Access-Control-Allow-Origin", "*".parse().unwrap());
    headers.insert("Content-Type", "application/json".parse().unwrap());

    if payload.room.is_empty() {
        error!(
            errcode = "M_BAD_JSON",
            error = "Missing room parameter",
            "Missing room parameter in request"
        );
        let err = MatrixError {
            errcode: "M_BAD_JSON".to_string(),
            error: "Missing room parameter".to_string(),
        };
        return (StatusCode::BAD_REQUEST, headers, axum::Json(err)).into_response();
    }

    let user_info = match exchange_openid_userinfo(
        &payload.openid_token,
        &state.resolver,
        &state.client,
    )
    .await
    {
        Ok(user) => user,
        Err(e) => {
            error!(errcode = "M_LOOKUP_FAILED", error = %e, server_name = %payload.openid_token.matrix_server_name, "Failed to look up user info from homeserver");
            let err = MatrixError {
                errcode: "M_LOOKUP_FAILED".to_string(),
                error: format!("Failed to look up user info from homeserver: {e}"),
            };
            return (StatusCode::INTERNAL_SERVER_ERROR, headers, axum::Json(err)).into_response();
        }
    };

    let is_local_user = state
        .local_homeservers
        .contains(&payload.openid_token.matrix_server_name);

    let lk_identity = format!("{}:{}", user_info.sub, payload.device_id);

    let token = match get_join_token(
        is_local_user,
        &state.key,
        &state.secret,
        &payload.room,
        &lk_identity,
    ) {
        Ok(t) => t,
        Err(e) => {
            error!(errcode = "M_UNKNOWN", error = %e, "Failed to generate join token");
            let err = MatrixError {
                errcode: "M_UNKNOWN".to_string(),
                error: "Internal Server Error".to_string(),
            };
            return (StatusCode::INTERNAL_SERVER_ERROR, headers, axum::Json(err)).into_response();
        }
    };

    if is_local_user {
        let lk_client = livekit_api::services::room::RoomClient::with_api_key(
            &state.lk_url,
            &state.key,
            &state.secret,
        );
        let options = livekit_api::services::room::CreateRoomOptions {
            empty_timeout: 5 * 60, // 5 Minutes to keep the room open if no one joins
            max_participants: 0,   // unlimited
            ..Default::default()
        };
        match lk_client.create_room(&payload.room, options).await {
            Ok(room) => {
                info!(
                    room_sid = %room.sid,
                    room_name = %room.name,
                    "Created LiveKit room"
                );
            }
            Err(e) => {
                error!(errcode = "M_UNKNOWN", error = %e, room_name = %payload.room, "Unable to create room on SFU");
                let err = MatrixError {
                    errcode: "M_UNKNOWN".to_string(),
                    error: format!("Unable to create room on SFU: {e}"),
                };
                return (StatusCode::INTERNAL_SERVER_ERROR, headers, axum::Json(err))
                    .into_response();
            }
        }
    }

    let res = SFUResponse {
        url: state.lk_url.clone(),
        jwt: token,
    };
    (StatusCode::OK, headers, axum::Json(res)).into_response()
}

// Mocked user info struct and exchange function
#[derive(Debug, Deserialize, Serialize)]
pub struct UserInfo {
    pub sub: String,
}

use thiserror::Error;

/// Error type for Matrix server resolution.
#[derive(Debug, Error)]
pub enum ExchangeOpenIdUserInfoError {
    #[error("Invalid token")]
    InvalidToken,
    #[error("Failed to resolve matrix server: {0}")]
    FailedToResolveMatrixServer(#[from] resolve::ResolveServerError),
    #[error("Bad URL: {0}")]
    BadUrl(#[from] url::ParseError),

    #[error("HTTP client error: {0}")]
    Http(#[from] reqwest::Error),
}

#[instrument(level="debug", skip(token, resolver, client), fields(server = %token.matrix_server_name))]
pub async fn exchange_openid_userinfo(
    token: &OpenIDTokenType,
    resolver: &MatrixResolver,
    client: &reqwest::Client,
) -> Result<UserInfo, ExchangeOpenIdUserInfoError> {
    if token.access_token.is_empty() || token.matrix_server_name.is_empty() {
        error!(
            errcode = "InvalidToken",
            "Access token or matrix server name is empty"
        );
        return Err(ExchangeOpenIdUserInfoError::InvalidToken);
    }
    let server = resolver
        .resolve_actual_dest(token.matrix_server_name.as_str())
        .await?;

    trace!(?server, "Resolved server");

    let url = format!(
        "https://{}/_matrix/federation/v1/openid/userinfo",
        server.string()
    );

    let response = client
        .get(Url::parse_with_params(
            &url,
            &[("access_token", token.access_token.as_str())],
        )?)
        .send()
        .await?;

    trace!("Sent request");

    let user_info = response.json().await?;
    trace!("Parsed response");

    Ok(user_info)
}

#[instrument(skip(api_key, api_secret, room, identity))]
pub fn get_join_token(
    is_local_user: bool,
    api_key: &str,
    api_secret: &str,
    room: &str,
    identity: &str,
) -> Result<String, livekit_api::access_token::AccessTokenError> {
    livekit_api::access_token::AccessToken::with_api_key(api_key, api_secret)
        .with_grants(VideoGrants {
            room: room.to_string(),
            room_create: is_local_user,
            room_join: true,
            can_publish: true,
            can_subscribe: true,
            ..Default::default()
        })
        .with_identity(identity)
        .with_ttl(Duration::from_secs(60 * 60))
        .to_jwt()
}

pub fn read_key_secret() -> (String, String) {
    let key = env::var("LIVEKIT_KEY").unwrap_or_default();
    let secret = env::var("LIVEKIT_SECRET").unwrap_or_default();
    let key_path = env::var("LIVEKIT_KEY_FROM_FILE").unwrap_or_default();
    let secret_path = env::var("LIVEKIT_SECRET_FROM_FILE").unwrap_or_default();
    let key_secret_path = env::var("LIVEKIT_KEY_FILE").unwrap_or_default();

    let (mut key, mut secret) = (key, secret);

    if !key_secret_path.is_empty() {
        if let Ok(contents) = std::fs::read_to_string(&key_secret_path) {
            let parts: Vec<&str> = contents.trim().split(':').collect();
            if parts.len() == 2 {
                key = parts[0].to_string();
                secret = parts[1].to_string();
            }
        }
    } else {
        if !key_path.is_empty() {
            if let Ok(contents) = std::fs::read_to_string(&key_path) {
                key = contents.trim().to_string();
            }
        }
        if !secret_path.is_empty() {
            if let Ok(contents) = std::fs::read_to_string(&secret_path) {
                secret = contents.trim().to_string();
            }
        }
    }
    (key.trim().to_string(), secret.trim().to_string())
}

pub fn build_app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(healthcheck))
        .route("/sfu/get", options(handle_options).post(handle_post))
        .layer(Extension(state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};

    use std::sync::Arc;
    use tower::ServiceExt; // for `oneshot` method

    #[tokio::test]
    async fn test_healthcheck() {
        let state = Arc::new(AppState {
            key: "".to_string(),
            secret: "".to_string(),
            lk_url: "".to_string(),
            local_homeservers: HashSet::new(),
            client: reqwest::Client::new(),
            resolver: MatrixResolver::new().await.unwrap(),
        });
        let app = build_app(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_handle_options() {
        let state = Arc::new(AppState {
            key: "".to_string(),
            secret: "".to_string(),
            lk_url: "".to_string(),
            local_homeservers: HashSet::new(),
            client: reqwest::Client::new(),
            resolver: MatrixResolver::new().await.unwrap(),
        });
        let app = build_app(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/sfu/get")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert_eq!(headers.get("Access-Control-Allow-Origin").unwrap(), "*");
        assert_eq!(headers.get("Access-Control-Allow-Methods").unwrap(), "POST");
    }

    #[tokio::test]
    async fn test_handle_post_missing_params() {
        let state = Arc::new(AppState {
            key: "".to_string(),
            secret: "".to_string(),
            lk_url: "".to_string(),
            local_homeservers: HashSet::new(),
            client: reqwest::Client::new(),
            resolver: MatrixResolver::new().await.unwrap(),
        });
        let app = build_app(state);
        let body = serde_json::json!({}).to_string();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/sfu/get")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(response.status().is_client_error());
    }

    #[tokio::test]
    async fn test_get_join_token() {
        let api_key = "testKey";
        let api_secret = "testSecret";
        let room = "testRoom";
        let identity = "testIdentity@example.com";
        for &is_local_user in &[true, false] {
            let token = get_join_token(is_local_user, api_key, api_secret, room, identity).unwrap();
            assert!(!token.is_empty());
        }
    }
}
