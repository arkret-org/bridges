//! Platform-neutral inbound media fetch contract.

use std::fmt;
use std::time::Duration;

use arkret_egress_reqwest::EgressGuard;
use async_trait::async_trait;
use futures::StreamExt;

use crate::runtime::{BridgeError, Result, bridge_retry_delay, redact_sensitive_url_values};
use crate::types::{DownloadedMedia, MAX_EXTERNAL_MEDIA_BYTES};

const DEFAULT_MEDIA_FETCH_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_MEDIA_FETCH_ATTEMPTS: u32 = 3;

/// Authentication attached to a platform-resolved media reference.
///
/// This is intentionally closed rather than accepting arbitrary headers: media
/// adapters may select a registered transport credential shape, but cannot
/// smuggle unrelated vendor headers through the shared fetch boundary.
#[derive(Clone)]
pub enum InboundMediaAuthorization {
    Bearer(String),
    Basic { username: String, password: String },
}

impl fmt::Debug for InboundMediaAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bearer(_) => formatter.write_str("Bearer(<redacted>)"),
            Self::Basic { .. } => formatter.write_str("Basic(<redacted>)"),
        }
    }
}

/// A platform-resolved media reference. Platform adapters resolve opaque ids
/// to this shape; the shared fetcher owns transport safety and byte handling.
#[derive(Clone)]
pub struct InboundMediaReference {
    pub url: String,
    pub authorization: Option<InboundMediaAuthorization>,
    pub allowed_hosts: Vec<String>,
}

impl fmt::Debug for InboundMediaReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InboundMediaReference")
            .field("url", &redact_sensitive_url_values(&self.url))
            .field("authorization", &self.authorization)
            .field("allowed_hosts", &self.allowed_hosts)
            .finish()
    }
}

/// Fetch limits shared by every platform adapter.
#[derive(Clone, Copy, Debug)]
pub struct InboundMediaFetchPolicy {
    pub max_bytes: usize,
    pub timeout: Duration,
    pub max_attempts: u32,
}

impl Default for InboundMediaFetchPolicy {
    fn default() -> Self {
        Self {
            max_bytes: MAX_EXTERNAL_MEDIA_BYTES,
            timeout: DEFAULT_MEDIA_FETCH_TIMEOUT,
            max_attempts: DEFAULT_MEDIA_FETCH_ATTEMPTS,
        }
    }
}

/// Platform-independent media transport boundary. It deliberately consumes a
/// resolved vendor reference rather than accepting a URL as downloaded bytes.
#[async_trait]
#[expect(
    clippy::double_must_use,
    reason = "async-trait adds an unconditional must_use attribute to its boxed Future methods."
)]
pub trait InboundMediaFetcher: Send + Sync {
    async fn fetch(
        &self,
        reference: &InboundMediaReference,
        policy: InboundMediaFetchPolicy,
    ) -> Result<DownloadedMedia>;
}

#[derive(Clone)]
pub struct HttpInboundMediaFetcher {
    http: reqwest::Client,
}

impl HttpInboundMediaFetcher {
    pub fn new() -> Result<Self> {
        let http = media_egress_guard()
            .apply_to_client_builder(reqwest::Client::builder())
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| BridgeError::Runtime(format!("build media HTTP client: {error}")))?;
        Ok(Self { http })
    }

    async fn fetch_once(
        &self,
        reference: &InboundMediaReference,
        policy: InboundMediaFetchPolicy,
    ) -> std::result::Result<DownloadedMedia, FetchFailure> {
        let parsed = reqwest::Url::parse(&reference.url)
            .map_err(|_| FetchFailure::fatal("media URL is invalid"))?;
        validate_media_url(&parsed, &reference.allowed_hosts)?;

        let mut request = self.http.get(parsed);
        match reference.authorization.as_ref() {
            Some(InboundMediaAuthorization::Bearer(token)) => {
                request = request.bearer_auth(token);
            }
            Some(InboundMediaAuthorization::Basic { username, password }) => {
                request = request.basic_auth(username, Some(password));
            }
            None => {}
        }
        let response = request
            .send()
            .await
            .map_err(|_| FetchFailure::retryable("media download request failed"))?;
        validate_media_url(response.url(), &reference.allowed_hosts)?;
        let status = response.status();
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
            return Err(FetchFailure::retryable(format!(
                "media download returned retryable status {status}"
            )));
        }
        if !status.is_success() {
            return Err(FetchFailure::fatal(format!(
                "media download returned status {status}"
            )));
        }
        if let Some(size) = response.content_length()
            && size > policy.max_bytes as u64
        {
            return Err(FetchFailure::fatal(format!(
                "media download is {size} bytes; limit is {} bytes",
                policy.max_bytes
            )));
        }
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let mut bytes = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk =
                chunk.map_err(|_| FetchFailure::retryable("media download stream failed"))?;
            if bytes.len() + chunk.len() > policy.max_bytes {
                return Err(FetchFailure::fatal(format!(
                    "media download exceeded {} bytes",
                    policy.max_bytes
                )));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(DownloadedMedia {
            bytes,
            content_type,
        })
    }
}

fn validate_media_url(
    url: &reqwest::Url,
    allowed_hosts: &[String],
) -> std::result::Result<(), FetchFailure> {
    media_egress_guard()
        .validate_url(url, "media download target")
        .map_err(|error| FetchFailure::fatal(error.to_string()))?;
    let host = url
        .host_str()
        .ok_or_else(|| FetchFailure::fatal("media download URL has no host"))?;
    if !host_allowed(host, allowed_hosts) {
        return Err(FetchFailure::fatal(format!(
            "media download host {host} is not allow-listed"
        )));
    }
    Ok(())
}

/// Outbound posture for vendor media downloads.
///
/// The whole parse/judge/resolve/bind sequence — including the connect-time
/// resolver installed by `apply_to_client_builder` — lives in
/// `arkret-egress-reqwest`; the test build relaxes only to loopback so the
/// mock-provider tests can reach `127.0.0.1`.
fn media_egress_guard() -> EgressGuard {
    #[cfg(test)]
    {
        EgressGuard::local_development()
    }
    #[cfg(not(test))]
    {
        EgressGuard::public_https()
    }
}

#[async_trait]
impl InboundMediaFetcher for HttpInboundMediaFetcher {
    async fn fetch(
        &self,
        reference: &InboundMediaReference,
        policy: InboundMediaFetchPolicy,
    ) -> Result<DownloadedMedia> {
        if policy.max_bytes == 0 || policy.max_attempts == 0 || policy.timeout.is_zero() {
            return Err(BridgeError::App(
                "media fetch policy limits must be non-zero".to_owned(),
            ));
        }
        let mut last_error = None;
        for attempt in 0..policy.max_attempts {
            let result =
                tokio::time::timeout(policy.timeout, self.fetch_once(reference, policy)).await;
            match result {
                Ok(Ok(media)) => return Ok(media),
                Ok(Err(error)) if !error.retryable => return Err(BridgeError::App(error.message)),
                Ok(Err(error)) => last_error = Some(error.message),
                Err(_) => last_error = Some("media download timed out".to_owned()),
            }
            if attempt + 1 < policy.max_attempts {
                tokio::time::sleep(bridge_retry_delay(attempt)).await;
            }
        }
        Err(BridgeError::App(
            last_error.unwrap_or_else(|| "media download failed".to_owned()),
        ))
    }
}

struct FetchFailure {
    message: String,
    retryable: bool,
}

impl FetchFailure {
    fn fatal(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retryable: false,
        }
    }

    fn retryable(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retryable: true,
        }
    }
}

fn host_allowed(host: &str, allowed_hosts: &[String]) -> bool {
    allowed_hosts.iter().any(|allowed| {
        let allowed = allowed.trim().trim_start_matches('.');
        !allowed.is_empty()
            && (host.eq_ignore_ascii_case(allowed)
                || host
                    .to_ascii_lowercase()
                    .ends_with(&format!(".{allowed}").to_ascii_lowercase()))
    })
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    async fn mock_provider(
        responses: Vec<&'static str>,
    ) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock provider");
        let address = listener.local_addr().expect("mock provider address");
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for response in responses {
                let (mut socket, _) = listener.accept().await.expect("accept mock request");
                let mut request = [0_u8; 2048];
                let request_len = socket.read(&mut request).await.expect("read mock request");
                requests.push(String::from_utf8_lossy(&request[..request_len]).into_owned());
                socket
                    .write_all(response.as_bytes())
                    .await
                    .expect("write mock response");
                socket.shutdown().await.expect("close mock response");
            }
            requests
        });
        (format!("http://{address}/media"), task)
    }

    #[test]
    fn media_policy_defaults_are_bounded() {
        let policy = InboundMediaFetchPolicy::default();
        assert_eq!(policy.max_bytes, MAX_EXTERNAL_MEDIA_BYTES);
        assert_eq!(policy.timeout, Duration::from_secs(30));
        assert_eq!(policy.max_attempts, 3);
    }

    #[test]
    fn media_host_allowlist_accepts_only_exact_or_subdomain() {
        let allowed = vec!["cdn.example.test".to_owned()];
        assert!(host_allowed("cdn.example.test", &allowed));
        assert!(host_allowed("media.cdn.example.test", &allowed));
        assert!(!host_allowed("cdn.example.test.attacker.invalid", &allowed));
        assert!(!host_allowed("example.test", &allowed));
    }

    #[tokio::test]
    async fn provider_mock_retries_rate_limit_and_preserves_content_type() {
        let (url, provider) = mock_provider(vec![
            "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Type: image/png\r\nConnection: close\r\n\r\npng",
        ])
        .await;
        arkret_bridge_runtime::install_default_crypto_provider();
        let fetcher = HttpInboundMediaFetcher::new().unwrap();
        let media = fetcher
            .fetch(
                &InboundMediaReference {
                    url,
                    authorization: None,
                    allowed_hosts: vec!["127.0.0.1".to_owned()],
                },
                InboundMediaFetchPolicy {
                    max_bytes: 16,
                    timeout: Duration::from_secs(2),
                    max_attempts: 2,
                },
            )
            .await
            .expect("rate-limited fetch retries");
        let requests = provider.await.expect("mock provider task");
        assert_eq!(requests.len(), 2);
        assert_eq!(media.bytes, b"png");
        assert_eq!(media.content_type.as_deref(), Some("image/png"));
    }

    #[tokio::test]
    async fn provider_mock_rejects_declared_oversize_media() {
        let (url, provider) = mock_provider(vec![
            "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\ndata",
        ])
        .await;
        arkret_bridge_runtime::install_default_crypto_provider();
        let fetcher = HttpInboundMediaFetcher::new().unwrap();
        let result = fetcher
            .fetch(
                &InboundMediaReference {
                    url,
                    authorization: None,
                    allowed_hosts: vec!["127.0.0.1".to_owned()],
                },
                InboundMediaFetchPolicy {
                    max_bytes: 3,
                    timeout: Duration::from_secs(2),
                    max_attempts: 1,
                },
            )
            .await;
        let error = match result {
            Ok(_) => panic!("oversize media must fail"),
            Err(error) => error,
        };
        let requests = provider.await.expect("mock provider task");
        assert_eq!(requests.len(), 1);
        assert!(error.to_string().contains("limit is 3 bytes"));
    }

    #[tokio::test]
    async fn provider_mock_receives_basic_authorization() {
        let (url, provider) = mock_provider(vec![
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        ])
        .await;
        arkret_bridge_runtime::install_default_crypto_provider();
        let fetcher = HttpInboundMediaFetcher::new().unwrap();
        let media = fetcher
            .fetch(
                &InboundMediaReference {
                    url,
                    authorization: Some(InboundMediaAuthorization::Basic {
                        username: "bot@example.test".to_owned(),
                        password: "api-secret".to_owned(),
                    }),
                    allowed_hosts: vec!["127.0.0.1".to_owned()],
                },
                InboundMediaFetchPolicy {
                    max_bytes: 16,
                    timeout: Duration::from_secs(2),
                    max_attempts: 1,
                },
            )
            .await
            .expect("basic-authenticated fetch succeeds");
        let requests = provider.await.expect("mock provider task");
        assert_eq!(media.bytes, b"ok");
        assert_eq!(requests.len(), 1);
        let authorization = requests[0]
            .lines()
            .find(|line| line.to_ascii_lowercase().starts_with("authorization: "))
            .expect("authorization header");
        let (_, value) = authorization.split_once(':').expect("authorization value");
        assert_eq!(value.trim(), "Basic Ym90QGV4YW1wbGUudGVzdDphcGktc2VjcmV0");
    }

    #[test]
    fn media_reference_debug_redacts_transport_credentials() {
        let reference = InboundMediaReference {
            url: "https://api.telegram.org/file/botsecret-token/media.png?access_token=secret"
                .to_owned(),
            authorization: Some(InboundMediaAuthorization::Basic {
                username: "bot@example.test".to_owned(),
                password: "api-secret".to_owned(),
            }),
            allowed_hosts: vec!["api.telegram.org".to_owned()],
        };
        let debug = format!("{reference:?}");
        assert!(!debug.contains("secret-token"));
        assert!(!debug.contains("api-secret"));
        assert!(!debug.contains("bot@example.test"));
        assert!(debug.contains("<redacted>"));
    }
}
