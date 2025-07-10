This is a service that converts Matrix OpenID tokens into LiveKit access tokens for Element Call.
Tokens for users from third-party home servers can only join rooms and can't create rooms to prevent infrastructure abuse.

- `LIVEKIT_INSECURE_SKIP_VERIFY_TLS`:
  If set to "YES_I_KNOW_WHAT_I_AM_DOING", disables TLS certificate verification for outgoing requests.

- `LIVEKIT_KEY` or `LIVEKIT_KEY_FILE`:
  Used to provide the LiveKit API key (directly or via file).

- `LIVEKIT_SECRET` or `LIVEKIT_SECRET_FILE`:
  Used to provide the LiveKit API secret (directly or via file).

- `LIVEKIT_URL`:
  The URL of the LiveKit server.

- `LIVEKIT_LOCAL_HOMESERVERS`:
  A comma-separated list of local homeserver addresses. These can create LiveKit rooms.

- `LIVEKIT_JWT_PORT`:
  The port number for the JWT service to listen on (defaults to 8080 if not set).


This currently uses a hackey homebrewed matrix server resolver with no cache. It's also not particularly tested. If you want to try it, feel free to give it a go, but it's not production-ready!
