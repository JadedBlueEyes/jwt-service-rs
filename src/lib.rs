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
use sha2::{Digest, Sha256};
use std::{collections::HashSet, env, sync::Arc, time::Duration};
use tracing::{error, info, instrument, trace, warn};
use url::Url;

pub use resolve::MatrixResolver;

#[derive(Clone)]
pub struct AppState {
    pub key: String,
    pub secret: String,
    pub lk_url: String,
    pub full_access_homeservers: HashSet<String>,
    pub federation_client: reqwest::Client,
    pub resolver: Arc<resolve::MatrixResolver>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct OpenIDTokenType {
    pub access_token: String,
    pub token_type: String,
    pub matrix_server_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<i32>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct MatrixRTCMemberType {
    pub id: String,
    pub claimed_user_id: String,
    pub claimed_device_id: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct LegacySFURequest {
    pub room: String,
    pub openid_token: OpenIDTokenType,
    pub device_id: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SFURequest {
    pub room_id: String,
    pub slot_id: String,
    pub openid_token: OpenIDTokenType,
    pub member: MatrixRTCMemberType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delayed_event_id: Option<String>,
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

trait ValidatableSFURequest {
    fn validate(&self) -> Result<(), MatrixError>;
}

impl ValidatableSFURequest for LegacySFURequest {
    fn validate(&self) -> Result<(), MatrixError> {
        if self.room.is_empty() {
            return Err(MatrixError {
                errcode: "M_BAD_JSON".to_string(),
                error: "Missing room parameter".to_string(),
            });
        }
        if self.openid_token.access_token.is_empty()
            || self.openid_token.matrix_server_name.is_empty()
        {
            return Err(MatrixError {
                errcode: "M_BAD_JSON".to_string(),
                error: "Missing OpenID token parameters".to_string(),
            });
        }
        Ok(())
    }
}

impl ValidatableSFURequest for SFURequest {
    fn validate(&self) -> Result<(), MatrixError> {
        if self.room_id.is_empty() || self.slot_id.is_empty() {
            error!(
                room_id = %self.room_id,
                slot_id = %self.slot_id,
                "Missing room_id or slot_id"
            );
            return Err(MatrixError {
                errcode: "M_BAD_JSON".to_string(),
                error: "The request body is missing `room_id` or `slot_id`".to_string(),
            });
        }
        if self.member.id.is_empty()
            || self.member.claimed_user_id.is_empty()
            || self.member.claimed_device_id.is_empty()
        {
            error!(
                member_id = %self.member.id,
                claimed_user_id = %self.member.claimed_user_id,
                claimed_device_id = %self.member.claimed_device_id,
                "Missing member parameters"
            );
            return Err(MatrixError {
                errcode: "M_BAD_JSON".to_string(),
                error: "The request body `member` is missing a `id`, `claimed_user_id` or `claimed_device_id`".to_string(),
            });
        }
        if self.openid_token.access_token.is_empty()
            || self.openid_token.matrix_server_name.is_empty()
        {
            error!(
                access_token_present = !self.openid_token.access_token.is_empty(),
                matrix_server_name = %self.openid_token.matrix_server_name,
                "Missing OpenID token parameters"
            );
            return Err(MatrixError {
                errcode: "M_BAD_JSON".to_string(),
                error: "The request body `openid_token` is missing a `access_token` or `matrix_server_name`".to_string(),
            });
        }
        Ok(())
    }
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

/// Legacy endpoint handler - supports both LegacySFURequest and SFURequest
/// TODO: This is deprecated and will be removed in future versions
#[instrument(skip(state, body))]
pub async fn handle_legacy_post(
    Extension(state): Extension<Arc<AppState>>,
    body: String,
) -> Response {
    info!("Processing legacy /sfu/get request");

    let mut headers = HeaderMap::new();
    headers.insert("Access-Control-Allow-Origin", "*".parse().unwrap());
    headers.insert("Content-Type", "application/json".parse().unwrap());

    // Try to parse as SFURequest first, then LegacySFURequest
    if let Ok(payload) = serde_json::from_str::<SFURequest>(&body) {
        if let Err(e) = payload.validate() {
            error!(errcode = %e.errcode, error = %e.error, "Validation failed");
            return (StatusCode::BAD_REQUEST, headers, axum::Json(e)).into_response();
        }
        return handle_sfu_request(state, payload, headers).await;
    }

    if let Ok(payload) = serde_json::from_str::<LegacySFURequest>(&body) {
        if let Err(e) = payload.validate() {
            error!(errcode = %e.errcode, error = %e.error, "Validation failed");
            return (StatusCode::BAD_REQUEST, headers, axum::Json(e)).into_response();
        }
        return handle_legacy_sfu_request(state, payload, headers).await;
    }

    error!("Failed to parse request body as either SFURequest or LegacySFURequest");
    let err = MatrixError {
        errcode: "M_BAD_JSON".to_string(),
        error:
            "The request body was malformed, missing required fields, or contained invalid values"
                .to_string(),
    };
    (StatusCode::BAD_REQUEST, headers, axum::Json(err)).into_response()
}

/// New MSC4195 endpoint handler - only accepts SFURequest
#[instrument(skip(state, payload))]
pub async fn handle_post(
    Extension(state): Extension<Arc<AppState>>,
    Json(payload): Json<SFURequest>,
) -> Response {
    info!("Processing /get_token request");

    let mut headers = HeaderMap::new();
    headers.insert("Access-Control-Allow-Origin", "*".parse().unwrap());
    headers.insert("Content-Type", "application/json".parse().unwrap());

    if let Err(e) = payload.validate() {
        error!(errcode = %e.errcode, error = %e.error, "Validation failed");
        return (StatusCode::BAD_REQUEST, headers, axum::Json(e)).into_response();
    }

    handle_sfu_request(state, payload, headers).await
}

async fn handle_legacy_sfu_request(
    state: Arc<AppState>,
    payload: LegacySFURequest,
    headers: HeaderMap,
) -> Response {
    let user_info = match exchange_openid_userinfo(
        &payload.openid_token,
        &state.resolver,
        &state.federation_client,
    )
    .await
    {
        Ok(user) => user,
        Err(e) => {
            error!(
                errcode = "M_LOOKUP_FAILED",
                error = %e,
                server_name = %payload.openid_token.matrix_server_name,
                "Failed to look up user info from homeserver"
            );
            let err = MatrixError {
                errcode: "M_LOOKUP_FAILED".to_string(),
                error: format!("Failed to look up user info from homeserver: {e}"),
            };
            return (StatusCode::INTERNAL_SERVER_ERROR, headers, axum::Json(err)).into_response();
        }
    };

    let is_full_access_user = is_full_access_user(
        &state.full_access_homeservers,
        &payload.openid_token.matrix_server_name,
    );

    info!(
        user = %user_info.sub,
        access_level = if is_full_access_user { "full access" } else { "restricted access" },
        "Got Matrix user info"
    );

    let lk_identity = format!("{}:{}", user_info.sub, payload.device_id);

    // For legacy requests, derive the room alias using the same method as new requests
    // This ensures compatibility between old and new clients
    let slot_id = "m.call#ROOM";
    let lk_room_alias = compute_room_alias(&payload.room, slot_id);

    let token = match get_join_token(
        is_full_access_user,
        &state.key,
        &state.secret,
        &lk_room_alias,
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

    if is_full_access_user {
        let lk_client = livekit_api::services::room::RoomClient::with_api_key(
            &state.lk_url,
            &state.key,
            &state.secret,
        );
        let options = livekit_api::services::room::CreateRoomOptions {
            empty_timeout: 5 * 60, // 5 Minutes to keep the room open if no one joins
            ..Default::default()
        };
        match lk_client.create_room(&lk_room_alias, options).await {
            Ok(room) => {
                info!(
                    room_sid = %room.sid,
                    room_name = %room.name,
                    matrix_user = %user_info.sub,
                    lk_identity = %lk_identity,
                    "Created LiveKit room"
                );
            }
            Err(e) => {
                error!(
                    errcode = "M_UNKNOWN",
                    error = %e,
                    room_name = %lk_room_alias,
                    "Unable to create room on SFU"
                );
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

async fn handle_sfu_request(
    state: Arc<AppState>,
    payload: SFURequest,
    headers: HeaderMap,
) -> Response {
    let user_info = match exchange_openid_userinfo(
        &payload.openid_token,
        &state.resolver,
        &state.federation_client,
    )
    .await
    {
        Ok(user) => user,
        Err(e) => {
            error!(
                errcode = "M_UNAUTHORIZED",
                error = %e,
                server_name = %payload.openid_token.matrix_server_name,
                "The request could not be authorised"
            );
            let err = MatrixError {
                errcode: "M_UNAUTHORIZED".to_string(),
                error: "The request could not be authorised.".to_string(),
            };
            return (StatusCode::UNAUTHORIZED, headers, axum::Json(err)).into_response();
        }
    };

    // Check if validated userInfo.Sub matches payload.member.claimed_user_id
    if payload.member.claimed_user_id != user_info.sub {
        error!(
            claimed_user_id = %payload.member.claimed_user_id,
            token_subject = %user_info.sub,
            "Claimed user ID does not match token subject"
        );
        let err = MatrixError {
            errcode: "M_UNAUTHORIZED".to_string(),
            error: "The request could not be authorised.".to_string(),
        };
        return (StatusCode::UNAUTHORIZED, headers, axum::Json(err)).into_response();
    }

    let is_full_access_user = is_full_access_user(
        &state.full_access_homeservers,
        &payload.openid_token.matrix_server_name,
    );

    info!(
        user = %user_info.sub,
        access_level = if is_full_access_user { "full access" } else { "restricted access" },
        "Got Matrix user info"
    );

    // Use base64 encoded hash of user_id|device_id|member_id for identity
    let lk_identity = compute_participant_identity(
        &user_info.sub,
        &payload.member.claimed_device_id,
        &payload.member.id,
    );

    // Use base64 encoded hash of room_id|slot_id for room alias
    let lk_room_alias = compute_room_alias(&payload.room_id, &payload.slot_id);

    let token = match get_join_token(
        is_full_access_user,
        &state.key,
        &state.secret,
        &lk_room_alias,
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

    if is_full_access_user {
        let lk_client = livekit_api::services::room::RoomClient::with_api_key(
            &state.lk_url,
            &state.key,
            &state.secret,
        );
        let options = livekit_api::services::room::CreateRoomOptions {
            empty_timeout: 5 * 60, // 5 Minutes to keep the room open if no one joins
            ..Default::default()
        };
        match lk_client.create_room(&lk_room_alias, options).await {
            Ok(room) => {
                info!(
                    room_sid = %room.sid,
                    room_name = %room.name,
                    matrix_user = %user_info.sub,
                    lk_identity = %lk_identity,
                    "Created LiveKit room"
                );
            }
            Err(e) => {
                error!(
                    errcode = "M_UNKNOWN",
                    error = %e,
                    room_name = %lk_room_alias,
                    "Unable to create room on SFU"
                );
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

#[instrument(level="debug", skip(token, resolver, federation_client), fields(server = %token.matrix_server_name))]
pub async fn exchange_openid_userinfo(
    token: &OpenIDTokenType,
    resolver: &Arc<MatrixResolver>,
    federation_client: &reqwest::Client,
) -> Result<UserInfo, ExchangeOpenIdUserInfoError> {
    if token.access_token.is_empty() || token.matrix_server_name.is_empty() {
        error!(
            errcode = "InvalidToken",
            "Access token or matrix server name is empty"
        );
        return Err(ExchangeOpenIdUserInfoError::InvalidToken);
    }
    let resolution = resolver
        .resolve_server(token.matrix_server_name.as_str())
        .await?;

    trace!(?resolution, "Resolved server");

    // Use the base_url to build the request URL
    let url = format!(
        "{}/_matrix/federation/v1/openid/userinfo",
        resolution.base_url()
    );

    let response = federation_client
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

fn is_full_access_user(
    full_access_homeservers: &HashSet<String>,
    matrix_server_name: &str,
) -> bool {
    // Grant full access if wildcard '*' is present as the only entry
    if full_access_homeservers.len() == 1 && full_access_homeservers.contains("*") {
        return true;
    }

    // Check if the matrixServerName is in the list of full-access homeservers
    full_access_homeservers.contains(matrix_server_name)
}

fn compute_room_alias(room_id: &str, slot_id: &str) -> String {
    let input = format!("{}|{}", room_id, slot_id);
    let hash = Sha256::digest(input.as_bytes());
    base64_url_encode(&hash)
}

fn compute_participant_identity(user_id: &str, device_id: &str, member_id: &str) -> String {
    let input = format!("{}|{}|{}", user_id, device_id, member_id);
    let hash = Sha256::digest(input.as_bytes());
    base64_url_encode(&hash)
}

fn base64_url_encode(data: &[u8]) -> String {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    // Use standard base64 without padding (like Go's base64.StdEncoding.WithPadding(base64.NoPadding))
    STANDARD.encode(data).trim_end_matches('=').to_string()
}

#[instrument(skip(api_key, api_secret, room, identity))]
pub fn get_join_token(
    is_full_access_user: bool,
    api_key: &str,
    api_secret: &str,
    room: &str,
    identity: &str,
) -> Result<String, livekit_api::access_token::AccessTokenError> {
    livekit_api::access_token::AccessToken::with_api_key(api_key, api_secret)
        .with_grants(VideoGrants {
            room: room.to_string(),
            // Only full-access users can create the room
            room_create: is_full_access_user,
            // But all users can join the room
            room_join: true,

            // These defaults are true anyway
            can_publish: true,
            can_subscribe: true,
            can_publish_data: true,

            ..Default::default()
        })
        .with_identity(identity)
        .with_ttl(Duration::from_secs(60 * 60))
        .to_jwt()
}

pub fn read_key_secret() -> (String, String) {
    let key = env::var("LIVEKIT_KEY")
        .or_else(|_| env::var("LIVEKIT_API_KEY"))
        .unwrap_or_default();
    let secret = env::var("LIVEKIT_SECRET")
        .or_else(|_| env::var("LIVEKIT_API_SECRET"))
        .unwrap_or_default();
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
        if !key_path.is_empty()
            && let Ok(contents) = std::fs::read_to_string(&key_path)
        {
            key = contents.trim().to_string();
        }
        if !secret_path.is_empty()
            && let Ok(contents) = std::fs::read_to_string(&secret_path)
        {
            secret = contents.trim().to_string();
        }
    }
    (key.trim().to_string(), secret.trim().to_string())
}

pub fn build_app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(healthcheck))
        .route("/get_token", options(handle_options).post(handle_post))
        .route(
            "/sfu/get",
            options(handle_options).post(
                |Extension(state): Extension<Arc<AppState>>, body: String| {
                    handle_legacy_post(Extension(state), body)
                },
            ),
        )
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
        let resolver = Arc::new(MatrixResolver::new().await.unwrap());
        let federation_client = resolver.create_client().unwrap();

        let state = Arc::new(AppState {
            key: "".to_string(),
            secret: "".to_string(),
            lk_url: "".to_string(),
            full_access_homeservers: HashSet::new(),
            federation_client,
            resolver,
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
        let resolver = Arc::new(MatrixResolver::new().await.unwrap());
        let federation_client = resolver.create_client().unwrap();

        let state = Arc::new(AppState {
            key: "".to_string(),
            secret: "".to_string(),
            lk_url: "".to_string(),
            full_access_homeservers: HashSet::new(),
            federation_client,
            resolver,
        });
        let app = build_app(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/get_token")
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
        let resolver = Arc::new(MatrixResolver::new().await.unwrap());
        let federation_client = resolver.create_client().unwrap();

        let state = Arc::new(AppState {
            key: "".to_string(),
            secret: "".to_string(),
            lk_url: "".to_string(),
            full_access_homeservers: HashSet::new(),
            federation_client,
            resolver,
        });
        let app = build_app(state);
        let body = serde_json::json!({}).to_string();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/get_token")
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
        for &is_full_access_user in &[true, false] {
            let token =
                get_join_token(is_full_access_user, api_key, api_secret, room, identity).unwrap();
            assert!(!token.is_empty());
        }
    }

    #[tokio::test]
    async fn test_compute_room_alias() {
        let room_id = "!test:example.com";
        let slot_id = "m.call#ROOM";
        let alias = compute_room_alias(room_id, slot_id);
        // Verify it's base64 encoded (no padding)
        assert!(!alias.contains('='));
        assert!(!alias.is_empty());
    }

    #[tokio::test]
    async fn test_compute_participant_identity() {
        let user_id = "@user:example.com";
        let device_id = "DEVICE123";
        let member_id = "member456";
        let identity = compute_participant_identity(user_id, device_id, member_id);
        // Verify it's base64 encoded (no padding)
        assert!(!identity.contains('='));
        assert!(!identity.is_empty());
    }

    #[tokio::test]
    async fn test_is_full_access_user_wildcard() {
        let mut homeservers = HashSet::new();
        homeservers.insert("*".to_string());
        assert!(is_full_access_user(&homeservers, "any.server.com"));
    }

    #[tokio::test]
    async fn test_is_full_access_user_specific() {
        let mut homeservers = HashSet::new();
        homeservers.insert("example.com".to_string());
        assert!(is_full_access_user(&homeservers, "example.com"));
        assert!(!is_full_access_user(&homeservers, "other.com"));
    }

    /// Demonstrates client reuse with dynamic DNS resolution.
    ///
    /// The MatrixDnsResolver enables a single reqwest client to handle all
    /// Matrix federation requests by dynamically resolving server names according
    /// to the Matrix spec (.well-known delegation, SRV records, etc.) while
    /// maintaining correct SNI for TLS connections.
    ///
    /// This approach is superior to static `.resolve()` mappings because:
    /// - One client works for all servers (no need for client-per-server)
    /// - Proper SNI is automatically maintained
    /// - DNS resolution follows Matrix spec dynamically
    /// - No need for client caching or LRU eviction
    #[tokio::test]
    async fn test_client_reuse_with_dynamic_dns() {
        use crate::resolve::MatrixResolver;

        // Initialize resolver (wrapped in Arc for sharing)
        let resolver = Arc::new(MatrixResolver::new().await.unwrap());

        // Create ONE client with the Matrix DNS resolver
        // This client can be reused for ALL Matrix federation requests
        let federation_client = resolver.create_client().unwrap();

        // This client dynamically resolves any Matrix server
        let _app_state = AppState {
            key: "test".to_string(),
            secret: "test".to_string(),
            lk_url: "https://localhost".to_string(),
            full_access_homeservers: HashSet::new(),
            federation_client, // Reusable for ALL servers with correct SNI
            resolver,
        };

        // The federation_client will now correctly handle requests to any Matrix server:
        // - It follows .well-known delegation
        // - It performs SRV lookups
        // - It resolves hostnames to IPs
        // - It sends correct SNI based on the URL hostname
        // All without needing per-server client configuration!
    }
}
