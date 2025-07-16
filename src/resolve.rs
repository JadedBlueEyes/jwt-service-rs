use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use hickory_resolver::{Resolver, TokioResolver};
use reqwest::{Client, StatusCode};
use serde::Deserialize;

use thiserror::Error;

/// Error type for Matrix server resolution.
#[derive(Debug, Error)]
pub enum ResolveServerError {
    #[error("Failed to parse address: {0}")]
    AddrParse(#[from] std::net::AddrParseError),

    #[error("HTTP client error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("DNS resolution error: {0}")]
    Dns(#[from] hickory_resolver::ResolveError),

    #[error("Invalid port number: {0}")]
    InvalidPort(#[from] std::num::ParseIntError),

    #[error("Malformed .well-known response")]
    MalformedWellKnown,

    #[error("Unexpected error: {0}")]
    Other(String),
}

/// Represents the resolved destination for a Matrix server.
#[derive(Debug, Clone)]
pub enum ResolvedDestination {
    /// A literal IP address and port (e.g., 1.2.3.4:8448)
    Literal(SocketAddr),
    /// A named host and port string (e.g., "matrix.org", ":8448")
    Named(String, String),
}

#[derive(Debug, Clone)]
pub struct Resolution {
    pub destination: ResolvedDestination,
    pub host: String,
}

impl Resolution {
    pub fn string(&self) -> String {
        match &self.destination {
            ResolvedDestination::Literal(addr) => addr.to_string(),
            ResolvedDestination::Named(host, port) => format!("{host}:{port}"),
        }
    }
}

/// The main resolver struct for Matrix server resolution.
#[derive(Clone)]
pub struct MatrixResolver {
    client: Client,
    resolver: TokioResolver,
}

impl MatrixResolver {
    /// Create a new MatrixResolver.
    pub async fn new() -> Result<Self, ResolveServerError> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        let resolver = Resolver::builder_tokio()?.build();

        Ok(MatrixResolver { client, resolver })
    }
    pub async fn new_with_client(client: Client) -> Result<Self, ResolveServerError> {
        let resolver = Resolver::builder_tokio()?.build();

        Ok(MatrixResolver { client, resolver })
    }

    /// Returns: `actual_destination`, host header
    /// Implemented according to the specification at <https://matrix.org/docs/spec/server_server/r0.1.4#resolving-server-names>
    /// Numbers in comments below refer to bullet points in linked section of specification.
    #[tracing::instrument(name = "actual", level = "debug", skip(self))]
    pub async fn resolve_actual_dest(&self, dest: &str) -> Result<Resolution, ResolveServerError> {
        // 1. If the hostname is an IP literal
        if let Some((ip, port)) = get_ip_with_port(dest) {
            let socket = SocketAddr::new(ip, port);
            return Ok(Resolution {
                destination: ResolvedDestination::Literal(socket),
                host: dest.to_owned(),
            });
        }

        // 2. Hostname with explicit port
        if let Some(pos) = dest.find(':') {
            let (host_part, port_part) = dest.split_at(pos);
            let port_str = port_part.trim_start_matches(':');
            return Ok(Resolution {
                destination: ResolvedDestination::Named(host_part.to_owned(), port_str.to_owned()),
                host: dest.to_owned(),
            });
        }

        // 3. Well-known delegation
        if let Some((delegated, delegated_port)) = self.resolve_well_known(dest).await {
            // 3.1 IP literal in .well-known
            if let Some((ip, port)) = get_ip_with_port(&delegated) {
                let socket = SocketAddr::new(ip, delegated_port.unwrap_or(port));
                return Ok(Resolution {
                    destination: ResolvedDestination::Literal(socket),
                    host: delegated.clone(),
                });
            }
            // 3.2 Hostname with port in .well-known
            if let Some(pos) = delegated.find(':') {
                let (host_part, port_part) = delegated.split_at(pos);
                let port_str = port_part.trim_start_matches(':');
                return Ok(Resolution {
                    destination: ResolvedDestination::Named(
                        host_part.to_owned(),
                        port_str.to_owned(),
                    ),
                    host: delegated.clone(),
                });
            }
            // 3.3/3.4: Hostname, no port in .well-known
            if let Some((ref srv_host, srv_port)) = self.query_srv_record(&delegated).await? {
                return Ok(Resolution {
                    destination: ResolvedDestination::Named(srv_host.clone(), srv_port.to_string()),
                    host: delegated.clone(),
                });
            }
            // 3.5: No SRV, fallback to A/AAAA/CNAME + 8448
            return Ok(Resolution {
                destination: ResolvedDestination::Named(delegated.clone(), "8448".to_owned()),
                host: delegated.clone(),
            });
        }

        // 4. SRV lookup on original hostname
        if let Some((srv_host, srv_port)) = self.query_srv_record(dest).await? {
            return Ok(Resolution {
                destination: ResolvedDestination::Named(srv_host, srv_port.to_string()),
                host: dest.to_owned(),
            });
        }

        // 5. Fallback: A/AAAA/CNAME + 8448
        Ok(Resolution {
            destination: ResolvedDestination::Named(dest.to_owned(), "8448".to_owned()),
            host: dest.to_owned(),
        })
    }

    /// Resolve .well-known delegation for a hostname.
    async fn resolve_well_known(&self, hostname: &str) -> Option<(String, Option<u16>)> {
        #[derive(Deserialize)]
        struct WellKnown {
            #[serde(rename = "m.server")]
            m_server: String,
        }
        let url = format!("https://{hostname}/.well-known/matrix/server");
        let resp = match self.client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => return None,
        };
        if resp.status() != StatusCode::OK {
            return None;
        }
        let wk: WellKnown = match resp.json().await {
            Ok(wk) => wk,
            Err(_) => return None,
        };
        let (host, port) = parse_server_name(&wk.m_server);
        Some((host, port))
    }

    /// Query SRV records for a hostname, returning (target, port) if found.
    async fn query_srv_record(
        &self,
        hostname: &str,
    ) -> Result<Option<(String, u16)>, ResolveServerError> {
        let srv_names = [
            format!("_matrix-fed._tcp.{hostname}"),
            format!("_matrix._tcp.{hostname}"),
        ];
        for srv in &srv_names {
            let lookup = self.resolver.srv_lookup(srv).await;
            if let Ok(result) = lookup {
                if let Some(record) = result.iter().next() {
                    let target = record.target().to_utf8();
                    let port = record.port();
                    return Ok(Some((target.trim_end_matches('.').to_owned(), port)));
                }
            }
        }
        Ok(None)
    }
}

/// Parses a Matrix server name into (hostname, Option<port>)
fn parse_server_name(server_name: &str) -> (String, Option<u16>) {
    if let Some((host, port)) = server_name.rsplit_once(':') {
        if let Ok(port) = u16::from_str(port) {
            return (host.to_string(), Some(port));
        }
    }
    (server_name.to_string(), None)
}

/// If the string is an IP literal (with optional port), returns (IpAddr, port).
fn get_ip_with_port(s: &str) -> Option<(IpAddr, u16)> {
    // Try SocketAddr first (IP:port)
    if let Ok(sock) = SocketAddr::from_str(s) {
        return Some((sock.ip(), sock.port()));
    }
    // Try IP only
    if let Ok(ip) = IpAddr::from_str(s) {
        return Some((ip, 8448));
    }
    None
}
