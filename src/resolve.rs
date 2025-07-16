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

    #[tracing::instrument(
        name = "actual",
        level = "debug",
        skip(self),
        fields(dest = %dest)
    )]
    pub async fn resolve_actual_dest(&self, dest: &str) -> Result<Resolution, ResolveServerError> {
        // 1. If the hostname is an IP literal
        if let Some((ip, port)) = get_ip_with_port(dest) {
            tracing::info!(
                ip = %ip,
                port = port,
                step = "ip_literal",
                "Resolved IP literal with port"
            );
            let socket = SocketAddr::new(ip, port.unwrap_or(8448));
            return Ok(Resolution {
                destination: ResolvedDestination::Literal(socket),
                host: dest.to_owned(),
            });
        }

        // 2. Hostname with explicit port
        if let Some(pos) = dest.find(':') {
            let (host_part, port_part) = dest.split_at(pos);
            let port_str = port_part.trim_start_matches(':');
            tracing::info!(
                host = %host_part,
                port = %port_str,
                step = "explicit_port",
                "Resolved hostname with explicit port"
            );
            return Ok(Resolution {
                destination: ResolvedDestination::Named(host_part.to_owned(), port_str.to_owned()),
                host: dest.to_owned(),
            });
        }

        // 3. Well-known delegation
        if let Some(res) = self.resolve_well_known(dest).await {
            tracing::info!(?res, step = "well_known", "Resolved .well-known delegation");
            match res {
                WellKnownServerResult::Ip(ip, port) => {
                    tracing::info!(
                        ip = %ip,
                        port = port.unwrap_or(8448),
                        step = "well_known_ip_literal",
                        "Resolved .well-known IP literal"
                    );
                    let socket = SocketAddr::new(ip, port.unwrap_or(8448));
                    return Ok(Resolution {
                        destination: ResolvedDestination::Literal(socket),
                        host: ip.to_string(),
                    });
                }
                WellKnownServerResult::Domain(domain, None) => {
                    // 3.3/3.4: Hostname, no port in .well-known
                    if let Some((ref srv_host, srv_port)) = self.query_srv_record(&domain).await? {
                        tracing::info!(
                            srv_host = %srv_host,
                            srv_port = srv_port,
                            step = "well_known_host_srv",
                            "Resolved SRV from .well-known hostname without port"
                        );
                        return Ok(Resolution {
                            destination: ResolvedDestination::Named(
                                srv_host.clone(),
                                srv_port.to_string(),
                            ),
                            host: srv_host.clone(),
                        });
                    } else {
                        // 3.5: No SRV, fallback to A/AAAA/CNAME + 8448
                        tracing::debug!(
                            delegated = %domain,
                            step = "well_known_fallback",
                            "Fallback to .well-known host with default port"
                        );
                        return Ok(Resolution {
                            destination: ResolvedDestination::Named(
                                domain.clone(),
                                "8448".to_owned(),
                            ),
                            host: domain.clone(),
                        });
                    }
                }

                WellKnownServerResult::Domain(domain, Some(port)) => {
                    tracing::info!(
                        domain = %domain,
                        port = port,
                        step = "well_known_domain",
                        "Resolved .well-known domain with port"
                    );
                    return Ok(Resolution {
                        destination: ResolvedDestination::Named(domain.clone(), port.to_string()),
                        host: domain,
                    });
                }
            }
        }

        // 4. SRV lookup on original hostname
        if let Some((srv_host, srv_port)) = self.query_srv_record(dest).await? {
            tracing::debug!(
                srv_host = %srv_host,
                srv_port = srv_port,
                step = "srv_lookup",
                "Resolved SRV record on original hostname"
            );
            return Ok(Resolution {
                destination: ResolvedDestination::Named(srv_host, srv_port.to_string()),
                host: dest.to_owned(),
            });
        }

        // 5. Fallback: A/AAAA/CNAME + 8448
        tracing::debug!(
            host = %dest,
            step = "fallback",
            "Fallback to original hostname with default port"
        );
        Ok(Resolution {
            destination: ResolvedDestination::Named(dest.to_owned(), "8448".to_owned()),
            host: dest.to_owned(),
        })
    }

    /// Resolve .well-known delegation for a hostname.
    #[tracing::instrument(
        level = "trace",
        skip(self),
        fields(hostname = %hostname)
    )]
    async fn resolve_well_known(&self, hostname: &str) -> Option<WellKnownServerResult> {
        #[derive(Deserialize)]
        struct WellKnown {
            #[serde(rename = "m.server")]
            m_server: String,
        }
        let url = format!("https://{hostname}/.well-known/matrix/server");
        tracing::debug!(url = %url, "Fetching .well-known matrix server");
        let resp = match self.client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => return None,
        };
        if resp.status() != StatusCode::OK {
            return None;
        }
        let wk: WellKnown = match resp.json().await {
            Ok(wk) => wk,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    url = %url,
                    "Failed to parse .well-known matrix server JSON"
                );
                return None;
            }
        };
        if let Some((ip, port)) = get_ip_with_port(&wk.m_server) {
            tracing::debug!(
                ip = %ip,
                port = ?port,
                "Parsed .well-known matrix server IP and port"
            );
            return Some(WellKnownServerResult::Ip(ip, port));
        }
        let (host, port) = parse_server_name(&wk.m_server);
        tracing::debug!(
            well_known_host = %host,
            well_known_port = ?port,
            "Parsed .well-known matrix server domain"
        );
        Some(WellKnownServerResult::Domain(host, port))
    }

    /// Query SRV records for a hostname, returning (target, port) if found.
    #[tracing::instrument(
        level = "trace",
        skip(self),
        fields(hostname = %hostname)
    )]
    async fn query_srv_record(
        &self,
        hostname: &str,
    ) -> Result<Option<(String, u16)>, ResolveServerError> {
        let srv_names = [
            format!("_matrix-fed._tcp.{hostname}"),
            format!("_matrix._tcp.{hostname}"),
        ];
        for srv in &srv_names {
            tracing::trace!(srv = %srv, "Querying SRV record");
            let lookup = self.resolver.srv_lookup(srv).await;
            if let Ok(result) = lookup {
                if let Some(record) = result.iter().next() {
                    let target = record.target().to_utf8();
                    let port = record.port();
                    return Ok(Some((target.trim_end_matches('.').to_owned(), port)));
                }
            }
        }
        tracing::trace!(hostname = %hostname, "No SRV records found for hostname");
        Ok(None)
    }
}

#[derive(Debug)]
pub enum WellKnownServerResult {
    Ip(IpAddr, Option<u16>),
    Domain(String, Option<u16>),
}
/// Parses a Matrix server name into (hostname, Option<port>)
#[tracing::instrument(
    name = "parse_server_name",
    level = "trace",
    fields(server_name = %server_name)
)]
fn parse_server_name(server_name: &str) -> (String, Option<u16>) {
    if let Some((host, port)) = server_name.rsplit_once(':') {
        if let Ok(port) = u16::from_str(port) {
            return (host.to_string(), Some(port));
        }
    }
    (server_name.to_string(), None)
}

/// If the string is an IP literal (with optional port), returns (IpAddr, port).
#[tracing::instrument(
    name = "get_ip_with_port",
    level = "trace",
    fields(input = %s)
)]
fn get_ip_with_port(s: &str) -> Option<(IpAddr, Option<u16>)> {
    // Try SocketAddr first (IP:port)
    if let Ok(sock) = SocketAddr::from_str(s) {
        tracing::debug!(
            ip = %sock.ip(),
            port = sock.port(),
            "Parsed SocketAddr from input"
        );
        return Some((sock.ip(), Some(sock.port())));
    }
    // Try IP only
    if let Ok(ip) = IpAddr::from_str(s) {
        tracing::debug!(
            ip = %ip,
            port = 8448,
            "Parsed IpAddr from input, using default port"
        );
        return Some((ip, None));
    }
    tracing::debug!(
        input = %s,
        "Input is not an IP literal"
    );
    None
}

#[cfg(test)]
mod tests {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

    use super::*;

    #[test]
    fn test_get_ip_with_port() {
        assert_eq!(
            get_ip_with_port("127.0.0.1:8080"),
            Some((IpAddr::from([127, 0, 0, 1]), Some(8080)))
        );
        assert_eq!(
            get_ip_with_port("[::1]:8080"),
            Some((IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]), Some(8080)))
        );
        assert_eq!(
            get_ip_with_port("127.0.0.1"),
            Some((IpAddr::from([127, 0, 0, 1]), None))
        );
        assert_eq!(
            get_ip_with_port("::1"),
            Some((IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]), None))
        );
        assert_eq!(get_ip_with_port("example.com"), None);
    }

    #[test]
    fn test_get_ip_with_port_invalid() {
        assert_eq!(get_ip_with_port("invalid"), None);
        assert_eq!(get_ip_with_port("127.0.0.1:invalid"), None);
        assert_eq!(get_ip_with_port("::1:invalid"), None);
        assert_eq!(get_ip_with_port("127.0.0.1:8080:invalid"), None);
        assert_eq!(get_ip_with_port("::1:8080:invalid"), None);
    }

    #[tokio::test]
    async fn test_resolve() {
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer())
            .init();
        let resolver = MatrixResolver::new().await.unwrap();
        let _ = dbg!(resolver.resolve_actual_dest("matrix.org").await.unwrap());

        let _ = dbg!(resolver.resolve_actual_dest("ellis.link").await.unwrap());
    }
}
