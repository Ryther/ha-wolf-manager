//! Native scoped Supervisor bootstrap; no broker or user provisioning.
use crate::mqtt::BrokerConfig;
use serde::{Deserialize, Serialize};
use std::{fs::File, io::Read, os::unix::fs::MetadataExt, path::Path, time::Duration};
use wolf_core::{SafeError, Topics};
fn internal<T>(_: T) -> SafeError {
    SafeError::new("internal_error")
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddonOptions {
    #[serde(default = "default_base")]
    pub topic_base: String,
    #[serde(default = "default_discovery")]
    pub discovery_prefix: String,
}
fn default_base() -> String {
    "wolf-manager/v1".into()
}
fn default_discovery() -> String {
    "homeassistant".into()
}
pub fn parse_options(bytes: &[u8]) -> Result<AddonOptions, SafeError> {
    if bytes.len() > 65536 {
        return Err(SafeError::new("payload_too_large"));
    }
    let options: AddonOptions =
        serde_json::from_slice(bytes).map_err(|_| SafeError::validation())?;
    Topics::new(&options.topic_base, &options.discovery_prefix)?;
    Ok(options)
}
pub fn read_options(path: &Path) -> Result<AddonOptions, SafeError> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(internal)?
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(internal)?;
    parse_options(&bytes)
}
/// Accept exactly one secret source; protected regular files are read without aliases.
pub fn secret_value(
    direct: Option<&str>,
    file: Option<&Path>,
) -> Result<Option<String>, SafeError> {
    if direct.is_some() && file.is_some() {
        return Err(SafeError::validation());
    }
    let result = if let Some(direct) = direct {
        Some(direct.to_owned())
    } else if let Some(path) = file {
        let fd = rustix::fs::openat2(
            rustix::fs::CWD,
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
            rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(internal)?;
        let file = File::from(fd);
        let meta = file.metadata().map_err(internal)?;
        if !meta.is_file()
            || meta.nlink() != 1
            || ![0, rustix::process::geteuid().as_raw()].contains(&meta.uid())
            || meta.mode() & 0o077 != 0
            || meta.len() > 65536
        {
            return Err(SafeError::new("forbidden"));
        }
        let mut bytes = Vec::new();
        file.take(65537).read_to_end(&mut bytes).map_err(internal)?;
        if bytes.len() > 65536 {
            return Err(SafeError::new("payload_too_large"));
        }
        let value = String::from_utf8(bytes).map_err(internal)?;
        Some(value.strip_suffix('\n').unwrap_or(&value).to_owned())
    } else {
        None
    };
    if result
        .as_ref()
        .is_some_and(|s| s.is_empty() || s.len() > 65536 || s.contains(['\0', '\r', '\n']))
    {
        return Err(SafeError::validation());
    }
    Ok(result)
}
#[derive(Deserialize)]
struct SupervisorEnvelope {
    result: String,
    data: Option<MqttService>,
}
#[derive(Deserialize)]
struct MqttService {
    host: String,
    port: Port,
    ssl: bool,
    username: String,
    password: String,
    protocol: String,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Port {
    Number(u16),
    Text(String),
}
pub struct SupervisorClient {
    client: reqwest::Client,
    token: String,
}
impl SupervisorClient {
    pub fn client_builder() -> Result<reqwest::ClientBuilder, SafeError> {
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(internal)?
        .with_root_certificates(roots)
        .with_no_client_auth();
        Ok(reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10)))
    }
    pub fn new(token: String) -> Result<Self, SafeError> {
        let client = Self::client_builder()?.build().map_err(internal)?;
        Self::with_client(client, token)
    }
    /// Inject a resolver-enabled client for isolated tests; the URL remains fixed.
    pub fn with_client(client: reqwest::Client, token: String) -> Result<Self, SafeError> {
        if token.is_empty() || token.len() > 65536 || token.bytes().any(|c| c.is_ascii_control()) {
            return Err(SafeError::validation());
        }
        Ok(Self { client, token })
    }
    /// GET-only least-privilege service lookup; never creates service definitions/users.
    pub async fn mqtt(&self) -> Result<BrokerConfig, SafeError> {
        let mut response = self
            .client
            .get("http://supervisor/services/mqtt")
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(internal)?;
        if !response.status().is_success()
            || response.content_length().is_some_and(|len| len > 65536)
        {
            return Err(SafeError::new("forbidden"));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(internal)? {
            if bytes.len().saturating_add(chunk.len()) > 65536 {
                return Err(SafeError::new("payload_too_large"));
            }
            bytes.extend_from_slice(&chunk);
        }
        let envelope: SupervisorEnvelope =
            serde_json::from_slice(&bytes).map_err(|_| SafeError::validation())?;
        if envelope.result != "ok" {
            return Err(SafeError::new("forbidden"));
        }
        let service = envelope.data.ok_or_else(SafeError::validation)?;
        // Supervisor protocol metadata is not proof of broker MQTT5 support.
        if !matches!(service.protocol.as_str(), "3.1" | "3.1.1" | "5" | "5.0") {
            return Err(SafeError::validation());
        }
        let port = match service.port {
            Port::Number(n) => n,
            Port::Text(s) => s.parse::<u16>().map_err(|_| SafeError::validation())?,
        };
        let config = BrokerConfig {
            host: service.host,
            port,
            username: Some(service.username),
            password: Some(service.password),
            tls: service.ssl,
        };
        config.validate()?;
        Ok(config)
    }
}
