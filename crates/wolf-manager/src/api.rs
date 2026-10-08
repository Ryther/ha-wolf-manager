//! Same-origin HTTP admission. SQLite and password work never run on the reactor.
use crate::{auth::*, store::Store};
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{ConnectInfo, State},
    http::{HeaderMap, Method, Request, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use wolf_core::*;
#[derive(Clone)]
pub enum Deployment {
    Ingress,
    Standalone {
        origin: String,
        bootstrap: BootstrapSecret,
    },
}
#[derive(Clone, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Online,
    Offline,
    Unknown,
}
#[derive(Clone)]
pub struct Observation {
    pub status: Option<HostStatus>,
    pub staged_revision: Option<Revision>,
    pub capabilities: Option<HostCapabilities>,
    pub availability: Availability,
    pub observed_at: i64,
    pub host_availability: Availability,
    pub host_observed_at: i64,
}
#[derive(Clone)]
pub struct AppState {
    pub(crate) store: Arc<Mutex<Store>>,
    pub data: PathBuf,
    pub mode: Deployment,
    pub transport: TransportPolicy,
    pub(crate) observations: Arc<Mutex<BTreeMap<PcId, Observation>>>,
    pub(crate) probes: Arc<Mutex<BTreeMap<uuid::Uuid, crate::coordinator::PendingProbe>>>,
    pub(crate) mqtt_required: Arc<std::sync::atomic::AtomicBool>,
    pub(crate) mqtt_ready: Arc<std::sync::atomic::AtomicBool>,
    pub(crate) accepting: Arc<std::sync::atomic::AtomicBool>,
    pub(crate) tasks: Arc<tokio::sync::Semaphore>,
}
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}
impl AppState {
    pub fn new(store: Store, data: PathBuf, mode: Deployment, transport: TransportPolicy) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
            data,
            mode,
            transport,
            observations: Default::default(),
            probes: Default::default(),
            mqtt_required: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            mqtt_ready: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            accepting: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            tasks: Arc::new(tokio::sync::Semaphore::new(64)),
        }
    }
    pub async fn blocking<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Store) -> Result<T, SafeError> + Send + 'static,
    ) -> Result<T, SafeError> {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            let mut store = store.lock().map_err(|_| SafeError::new("internal_error"))?;
            f(&mut store)
        })
        .await
        .map_err(|_| SafeError::new("internal_error"))?
    }
    pub async fn ready(&self) -> Result<bool, SafeError> {
        if !self.accepting.load(std::sync::atomic::Ordering::Acquire) {
            return Ok(false);
        }
        if self
            .mqtt_required
            .load(std::sync::atomic::Ordering::Acquire)
            && !self.mqtt_ready.load(std::sync::atomic::Ordering::Acquire)
        {
            return Ok(false);
        }
        self.blocking(|s| {
            s.root.verify()?;
            Ok(true)
        })
        .await
    }
    pub async fn administrator_ready(&self) -> Result<Option<bool>, SafeError> {
        match self.mode {
            Deployment::Ingress => Ok(None),
            Deployment::Standalone { .. } => {
                self.blocking(|s| {
                    s.conn
                        .query_row("SELECT EXISTS(SELECT 1 FROM administrator)", [], |r| {
                            r.get::<_, bool>(0)
                        })
                        .map(Some)
                        .map_err(|_| SafeError::new("internal_error"))
                })
                .await
            }
        }
    }
    pub async fn ingest_catalog(
        &self,
        manifest: CatalogManifest,
        attributes: Vec<CatalogAttributes>,
    ) -> Result<(), SafeError> {
        self.blocking(move |s| s.commit_catalog(&manifest, &attributes))
            .await
    }
    pub fn ingest_availability(
        &self,
        pc: PcId,
        availability: Availability,
        observed_at: i64,
    ) -> Result<(), SafeError> {
        if observed_at < 0 {
            return Err(SafeError::validation());
        }
        let mut map = self
            .observations
            .lock()
            .map_err(|_| SafeError::new("internal_error"))?;
        let o = map.entry(pc).or_insert(Observation {
            status: None,
            staged_revision: None,
            capabilities: None,
            availability: Availability::Unknown,
            observed_at: 0,
            host_availability: Availability::Unknown,
            host_observed_at: 0,
        });
        if observed_at >= o.host_observed_at {
            o.host_availability = availability;
            o.host_observed_at = observed_at;
        }
        Ok(())
    }
    pub(crate) fn mark_service_unavailable(&self, pc: &PcId) -> Result<(), SafeError> {
        if let Some(o) = self
            .observations
            .lock()
            .map_err(|_| SafeError::new("internal_error"))?
            .get_mut(pc)
        {
            o.availability = Availability::Offline;
        }
        Ok(())
    }
    pub(crate) fn observe_result(&self, pc: &PcId, result: &RpcResult) -> Result<(), SafeError> {
        let mut map = self
            .observations
            .lock()
            .map_err(|_| SafeError::new("internal_error"))?;
        let o = map.entry(pc.clone()).or_insert(Observation {
            status: None,
            staged_revision: None,
            capabilities: None,
            availability: Availability::Unknown,
            observed_at: 0,
            host_availability: Availability::Unknown,
            host_observed_at: 0,
        });
        match result {
            RpcResult::Preflight(c) => o.capabilities = Some(c.clone()),
            RpcResult::Status(s) | RpcResult::Lifecycle(s) => {
                o.status = Some(s.clone());
                o.staged_revision = s.staged_revision.clone();
                o.availability = Availability::Online;
                o.observed_at = now();
            }
            RpcResult::Applied { staged_revision } => {
                o.staged_revision = Some(staged_revision.clone())
            }
            _ => {}
        }
        Ok(())
    }
    pub(crate) fn observation(&self, pc: &PcId) -> Result<Option<Observation>, SafeError> {
        Ok(self
            .observations
            .lock()
            .map_err(|_| SafeError::new("internal_error"))?
            .get(pc)
            .cloned())
    }
}
pub struct ApiError(pub SafeError, pub Option<uuid::Uuid>);
impl From<SafeError> for ApiError {
    fn from(e: SafeError) -> Self {
        Self(e, None)
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.0.code().as_str() {
            "unauthenticated" | "login_failed" | "invalid_bootstrap_token" => 401,
            "forbidden" | "csrf_failed" | "ingress_peer_forbidden" => 403,
            "not_found" => 404,
            "stale_revision"
            | "busy"
            | "operation_in_progress"
            | "host_key_mismatch"
            | "unknown_interrupted"
            | "bootstrap_completed"
            | "parameter_in_use" => 409,
            "payload_too_large" => 413,
            "unsupported_media_type" => 415,
            "login_rate_limited" => 429,
            "host_unavailable" => 503,
            "internal_error" => 500,
            _ => 400,
        };
        let mut error = json!(self.0);
        if let Some(id) = self.1 {
            error["operation_id"] = json!(id);
        }
        (
            StatusCode::from_u16(status).unwrap(),
            Json(json!({"error":error})),
        )
            .into_response()
    }
}
pub(crate) fn value(v: Value) -> Response {
    Json(v).into_response()
}
pub(crate) fn header(h: &HeaderMap, name: &str) -> String {
    h.get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned()
}
fn session(h: &HeaderMap) -> String {
    let mut values = header(h, "cookie")
        .split(';')
        .filter_map(|v| {
            v.trim()
                .strip_prefix("__Host-wolf_session=")
                .map(str::to_owned)
        })
        .collect::<Vec<_>>();
    if values.len() == 1 {
        values.remove(0)
    } else {
        String::new()
    }
}
pub(crate) fn json_body<T: serde::de::DeserializeOwned>(
    h: &HeaderMap,
    bytes: &[u8],
) -> Result<T, SafeError> {
    if header(h, "content-type")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        != "application/json"
    {
        return Err(SafeError::new("unsupported_media_type"));
    }
    serde_json::from_slice(bytes).map_err(|_| SafeError::new("bad_request"))
}
pub(crate) fn query(uri: &axum::http::Uri) -> Result<BTreeMap<String, String>, SafeError> {
    let mut result = BTreeMap::new();
    for (k, v) in url::form_urlencoded::parse(uri.query().unwrap_or("").as_bytes()) {
        if result.insert(k.into_owned(), v.into_owned()).is_some() {
            return Err(SafeError::new("bad_request"));
        }
    }
    Ok(result)
}
fn auth<'a>(s: &'a mut Store, mode: &Deployment) -> Result<AuthService<'a>, SafeError> {
    match mode {
        Deployment::Ingress => Ok(AuthService::ingress(s)),
        Deployment::Standalone { origin, bootstrap } => {
            AuthService::standalone(s, origin, bootstrap.clone())
        }
    }
}
pub fn router(state: AppState) -> Router {
    Router::new().fallback(handler).with_state(state)
}
async fn handler(State(state): State<AppState>, request: Request<Body>) -> Response {
    match handle(state, request).await {
        Ok(r) => r,
        Err(e) => e.into_response(),
    }
}
async fn handle(state: AppState, request: Request<Body>) -> Result<Response, ApiError> {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|p| p.0.ip())
        .ok_or_else(|| SafeError::new("forbidden"))?;
    state.transport.admit(peer)?;
    if !state.accepting.load(std::sync::atomic::Ordering::Acquire) {
        return Err(SafeError::new("host_unavailable").into());
    }
    let (parts, body) = request.into_parts();
    if parts
        .headers
        .iter()
        .map(|(k, v)| k.as_str().len() + v.len())
        .sum::<usize>()
        > 16 * 1024
    {
        return Err(SafeError::new("payload_too_large").into());
    }
    if parts.method == Method::OPTIONS {
        return Err(SafeError::new("forbidden").into());
    }
    for name in [
        "origin",
        "x-wolf-csrf",
        "cookie",
        "authorization",
        "content-type",
        "x-wolf-origin",
        "x-ingress-path",
    ] {
        if parts.headers.get_all(name).iter().count() > 1 {
            return Err(SafeError::new("bad_request").into());
        }
    }
    let path = parts.uri.path().strip_prefix("/api/v1/");
    if path.is_none() {
        if parts.method != Method::GET {
            return Err(SafeError::new("not_found").into());
        }
        return static_asset(&state, parts.uri.path(), &parts.headers).map_err(Into::into);
    }
    let path = path.unwrap();
    let q = query(&parts.uri)?;
    let bytes = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        to_bytes(body, RPC_MAX_BYTES),
    )
    .await
    .map_err(|_| SafeError::new("host_unavailable"))?
    .map_err(|_| SafeError::new("payload_too_large"))?;
    let headers = parts.headers;
    let origin = header(&headers, "origin");
    let csrf = header(&headers, "x-wolf-csrf");
    let session = session(&headers);
    let mode = state.mode.clone();
    let method = parts.method;
    if matches!(path, "system/health" | "system/ready" | "system/version") && method == Method::GET
    {
        let ready = state.ready().await?;
        let administrator_ready = state.administrator_ready().await?;
        return Ok((if path=="system/ready"&&!ready{StatusCode::SERVICE_UNAVAILABLE}else{StatusCode::OK},Json(json!({"state":if ready{"ready"}else{"unready"},"version":env!("CARGO_PKG_VERSION"),"protocol":1,"mqtt_enabled":state.mqtt_required.load(std::sync::atomic::Ordering::Acquire),"administrator_ready":administrator_ready,"bootstrap_required":administrator_ready==Some(false)}))).into_response());
    }
    if path == "bootstrap/status" && method == Method::GET {
        return Ok(value(
            state
                .blocking(move |s| Ok(json!({"initialized":auth(s,&mode)?.initialized()?})))
                .await?,
        ));
    }
    if path == "auth/login-challenge" && method == Method::GET {
        let purpose = match q.get("purpose").map(String::as_str) {
            Some("login") => Purpose::Login,
            Some("bootstrap") => Purpose::Bootstrap,
            _ => return Err(SafeError::new("bad_request").into()),
        };
        let c = state
            .blocking(move |s| auth(s, &mode)?.issue_challenge(peer, purpose, now()))
            .await?;
        return Ok(value(
            json!({"challenge":c.token,"expires_at":c.expires_at}),
        ));
    }
    if matches!(path, "bootstrap" | "auth/login") && method == Method::POST {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Input {
            password: String,
            challenge: String,
        }
        let input: Input = json_body(&headers, &bytes)?;
        let bearer = header(&headers, "authorization");
        let bootstrap = path == "bootstrap";
        let credentials = state
            .blocking(move |s| {
                let mut auth = auth(s, &mode)?;
                let attempt = LoginAttempt {
                    peer,
                    origin: &origin,
                    challenge: &input.challenge,
                    csrf_header: &csrf,
                    password: &input.password,
                };
                if bootstrap {
                    auth.bootstrap(attempt, bearer.strip_prefix("Bearer ").unwrap_or(""), now())
                } else {
                    auth.login(attempt, now())
                }
            })
            .await?;
        let mut response = (
            if bootstrap {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            },
            Json(json!({"csrf_token":credentials.csrf_token,"expires_at":credentials.expires_at})),
        )
            .into_response();
        response.headers_mut().insert(
            "set-cookie",
            credentials
                .cookie()
                .parse()
                .map_err(|_| SafeError::new("internal_error"))?,
        );
        return Ok(response);
    }
    if path == "auth/csrf" && method == Method::GET {
        let wolf_origin = header(&headers, "x-wolf-origin");
        let c = state
            .blocking(move |s| {
                let mut auth = auth(s, &mode)?;
                match mode {
                    Deployment::Ingress => auth.issue_ingress_csrf(peer, &wolf_origin, now()),
                    _ => auth.issue_session_csrf(&session, now()),
                }
            })
            .await?;
        return Ok(value(
            json!({"csrf_token":c.token,"expires_at":c.expires_at}),
        ));
    }
    if path == "auth/session" && method == Method::GET {
        let info = state
            .blocking(move |s| auth(s, &mode)?.authenticate(&session, now()))
            .await?;
        return Ok(value(
            json!({"authenticated":true,"expires_at":info.expires_at}),
        ));
    }
    let mutation = !matches!(method, Method::GET | Method::HEAD);
    let auth_session = session.clone();
    let auth_origin = origin.clone();
    let auth_csrf = csrf.clone();
    state
        .blocking(move |s| {
            let mut auth = auth(s, &mode)?;
            match mode {
                Deployment::Ingress => {
                    if mutation {
                        auth.require_ingress_mutation(peer, &auth_csrf, &auth_origin, now())?;
                    }
                }
                _ => {
                    if mutation {
                        auth.require_mutation(&auth_session, &auth_csrf, &auth_origin, now())?;
                    } else {
                        auth.authenticate(&auth_session, now())?;
                    }
                }
            }
            Ok(())
        })
        .await?;
    if path == "auth/logout" && method == Method::POST {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Empty {}
        let _: Empty = json_body(&headers, &bytes)?;
        let mode = state.mode.clone();
        state
            .blocking(move |s| auth(s, &mode)?.logout(&session, &csrf, &origin, now()))
            .await?;
        let mut r = StatusCode::NO_CONTENT.into_response();
        r.headers_mut().insert(
            "set-cookie",
            "__Host-wolf_session=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
                .parse()
                .unwrap(),
        );
        return Ok(r);
    }
    if path == "auth/password" && method == Method::POST {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Password {
            current_password: String,
            new_password: String,
        }
        let p: Password = json_body(&headers, &bytes)?;
        let mode = state.mode.clone();
        state
            .blocking(move |s| {
                auth(s, &mode)?.change_password(
                    &session,
                    &csrf,
                    &origin,
                    &p.current_password,
                    &p.new_password,
                    now(),
                )
            })
            .await?;
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    crate::routes::product(state, &method, path, &headers, &bytes, q).await
}
fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\'', "&#39;")
}
fn static_asset(state: &AppState, path: &str, headers: &HeaderMap) -> Result<Response, SafeError> {
    let (kind, body) = match path {
        "/" | "/index.html" => {
            let (mode, base) = match &state.mode {
                Deployment::Ingress => (
                    "ingress",
                    normalize_ingress_prefix(&header(headers, "x-ingress-path"))?,
                ),
                _ => ("standalone", "/".into()),
            };
            (
                "text/html; charset=utf-8",
                include_str!("../../../web/index.html")
                    .replace("__WOLF_MODE__", mode)
                    .replace("__WOLF_BASE__", &escape(&base)),
            )
        }
        "/app.js" => (
            "text/javascript; charset=utf-8",
            include_str!("../../../web/app.js").into(),
        ),
        "/styles.css" => (
            "text/css; charset=utf-8",
            include_str!("../../../web/styles.css").into(),
        ),
        _ => return Err(SafeError::new("not_found")),
    };
    let mut response = body.into_response();
    response
        .headers_mut()
        .insert("content-type", kind.parse().unwrap());
    response
        .headers_mut()
        .insert("x-content-type-options", "nosniff".parse().unwrap());
    response.headers_mut().insert("content-security-policy","default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' https://shared.fastly.steamstatic.com; frame-ancestors 'self'; base-uri 'self'".parse().unwrap());
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    Ok(response)
}
