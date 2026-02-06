# jwt-service-rs

A Rust implementation of the LiveKit JWT service for Matrix. This service converts Matrix OpenID tokens into LiveKit access tokens for Element Call and other MatrixRTC applications.

This implementation supports MSC4195 (MatrixRTC Transport using LiveKit Backend) and provides both the new `/get_token` endpoint and the legacy `/sfu/get` endpoint for backwards compatibility.

## Features



## Endpoints

- `GET /healthz` - Health check endpoint
- `POST /get_token` - MSC4195 endpoint for obtaining LiveKit tokens (new format)
- `POST /sfu/get` - Legacy endpoint supporting both old and new request formats (deprecated)

## Environment Variables

### Required Configuration

- **`LIVEKIT_KEY`** or **`LIVEKIT_API_KEY`** or **`LIVEKIT_KEY_FROM_FILE`**:  
  The LiveKit API key. Can be provided directly as an environment variable or read from a file.

- **`LIVEKIT_SECRET`** or **`LIVEKIT_API_SECRET`** or **`LIVEKIT_SECRET_FROM_FILE`**:  
  The LiveKit API secret. Can be provided directly as an environment variable or read from a file.

- **`LIVEKIT_KEY_FILE`**:  
  Alternative way to provide both key and secret in format `key:secret` from a file.

- **`LIVEKIT_URL`**:  
  The URL of the LiveKit server (e.g., `https://livekit.example.com`).

- **`LIVEKIT_FULL_ACCESS_HOMESERVERS`**:  
  A comma or space-separated list of homeserver names that are granted full access.  
  Users from these homeservers can create LiveKit rooms.  
  Use `*` to grant full access to all homeservers.  
  If not set, defaults to `*` (all homeservers have full access).  
  
  Examples:
  - `LIVEKIT_FULL_ACCESS_HOMESERVERS=matrix.org,example.com`
  - `LIVEKIT_FULL_ACCESS_HOMESERVERS=*`

- **`LIVEKIT_LOCAL_HOMESERVERS`** (deprecated):  
  Use `LIVEKIT_FULL_ACCESS_HOMESERVERS` instead


### Optional Configuration

- **`LIVEKIT_JWT_BIND`**:  
  The bind address for the JWT service (e.g., `0.0.0.0:8080` or `:8080`).  
  If not set, defaults to `:8080`.  
  This replaces the deprecated `LIVEKIT_JWT_PORT`.

- **`LIVEKIT_JWT_PORT`** (deprecated):  
  The port number for the JWT service to listen on.  
  Use `LIVEKIT_JWT_BIND` instead.

- **`LIVEKIT_INSECURE_SKIP_VERIFY_TLS`**:  
  If set to `YES_I_KNOW_WHAT_I_AM_DOING`, disables TLS certificate verification for outgoing requests.  
  ⚠️ **USE WITH EXTREME CAUTION** - This should only be used in development environments.

## Request Formats

### MSC4195 Format (New `/get_token` endpoint)

```json
{
  "room_id": "!roomid:example.com",
  "slot_id": "m.call#ROOM",
  "openid_token": {
    "access_token": "token",
    "token_type": "Bearer",
    "matrix_server_name": "example.com",
    "expires_in": 3600
  },
  "member": {
    "id": "member_id",
    "claimed_user_id": "@user:example.com",
    "claimed_device_id": "DEVICEID"
  },
  "delayed_event_id": "$event_id" // optional
}
```

### Legacy Format (Deprecated `/sfu/get` endpoint)

```json
{
  "room": "!roomid:example.com",
  "openid_token": {
    "access_token": "token",
    "token_type": "Bearer",
    "matrix_server_name": "example.com"
  },
  "device_id": "DEVICEID"
}
```

## Response Format

Both endpoints return:

```json
{
  "url": "https://livekit.example.com",
  "jwt": "eyJhbGc..."
}
```

## Development Status

This is a Rust reimplementation of the Go-based [lk-jwt-service](https://github.com/element-hq/lk-jwt-service). Use at your own risk.
