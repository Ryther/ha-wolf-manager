use axum::{
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use ha_wolf_manager::{
    api::{AppState, Deployment, router},
    auth::{BootstrapSecret, TransportPolicy},
    store::Store,
};
use std::{fs, net::SocketAddr, os::unix::fs::PermissionsExt};
use tempfile::tempdir;
use tower::ServiceExt;
fn request(path: &str, peer: &str) -> Request<Body> {
    let mut req = Request::builder().uri(path).body(Body::empty()).unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
    req
}
#[tokio::test]
async fn actual_http_ingress_peer_gate_runs_before_every_route() {
    let t = tempdir().unwrap();
    let root = t.path().join("data");
    let app = router(AppState::new(
        Store::open(&root, 0).unwrap(),
        root,
        Deployment::Ingress,
        TransportPolicy::Ingress,
    ));
    for path in ["/", "/api/v1/system/health", "/api/v1/auth/csrf", "/app.js"] {
        assert_eq!(
            app.clone()
                .oneshot(request(path, "192.0.2.8:1234"))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    let response = app
        .oneshot(request("/api/v1/bootstrap/status", "172.30.32.2:1234"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
#[tokio::test]
async fn actual_http_standalone_status_and_private_admission() {
    let t = tempdir().unwrap();
    let root = t.path().join("data");
    let secret = t.path().join("secret");
    fs::write(&secret, b"synthetic-bootstrap-token-256bits!").unwrap();
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o400)).unwrap();
    let app = router(AppState::new(
        Store::open(&root, 0).unwrap(),
        root,
        Deployment::Standalone {
            origin: "https://example.test".into(),
            bootstrap: BootstrapSecret::read(&secret).unwrap(),
        },
        TransportPolicy::TrustedProxy(vec!["192.0.2.8".parse().unwrap()]),
    ));
    let response = app
        .clone()
        .oneshot(request("/api/v1/bootstrap/status", "192.0.2.8:1234"))
        .await
        .unwrap();
    let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["initialized"],
        false
    );
    assert_eq!(
        app.oneshot(request("/api/v1/pcs", "192.0.2.8:1234"))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}
fn standalone() -> (tempfile::TempDir, axum::Router) {
    let t = tempdir().unwrap();
    let root = t.path().join("data");
    let secret = t.path().join("secret");
    fs::write(&secret, b"synthetic-bootstrap-token-256bits!").unwrap();
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o400)).unwrap();
    let app = router(AppState::new(
        Store::open(&root, 0).unwrap(),
        root,
        Deployment::Standalone {
            origin: "https://example.test".into(),
            bootstrap: BootstrapSecret::read(&secret).unwrap(),
        },
        TransportPolicy::TrustedProxy(vec!["192.0.2.8".parse().unwrap()]),
    ));
    (t, app)
}
async fn decoded(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap()).unwrap()
}
fn json_request(
    path: &str,
    body: serde_json::Value,
    cookie: &str,
    csrf: &str,
    origin: &str,
) -> Request<Body> {
    let mut r = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header("cookie", cookie)
        .header("origin", origin)
        .header("x-wolf-csrf", csrf)
        .body(Body::from(body.to_string()))
        .unwrap();
    r.extensions_mut()
        .insert(ConnectInfo("192.0.2.8:1234".parse::<SocketAddr>().unwrap()));
    r
}
#[tokio::test]
async fn actual_http_bootstrap_session_csrf_and_logout() {
    let (_t, app) = standalone();
    let challenge = decoded(
        app.clone()
            .oneshot(request(
                "/api/v1/auth/login-challenge?purpose=bootstrap",
                "192.0.2.8:1234",
            ))
            .await
            .unwrap(),
    )
    .await["challenge"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut boot = json_request(
        "/api/v1/bootstrap",
        serde_json::json!({"password":"synthetic-password-for-tests","challenge":challenge}),
        "",
        &challenge,
        "https://example.test",
    );
    boot.headers_mut().insert(
        "authorization",
        "Bearer synthetic-bootstrap-token-256bits!".parse().unwrap(),
    );
    let response = app.clone().oneshot(boot).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let result = decoded(response).await;
    let csrf = result["csrf_token"].as_str().unwrap();
    assert!(!result.to_string().contains("session_token"));
    let body = serde_json::json!({"pc_id":"pc","display_name":"PC","ssh_host":"127.0.0.1","ssh_port":22,"ssh_user":"wolf-manager"});
    assert_eq!(
        app.clone()
            .oneshot(json_request(
                "/api/v1/pcs",
                body.clone(),
                &cookie,
                csrf,
                "https://foreign.test"
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.clone()
            .oneshot(json_request(
                "/api/v1/pcs",
                body,
                &cookie,
                csrf,
                "https://example.test"
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    assert_eq!(
        app.clone()
            .oneshot(json_request(
                "/api/v1/auth/logout",
                serde_json::json!({}),
                &cookie,
                csrf,
                "https://example.test"
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    let mut read = request("/api/v1/pcs", "192.0.2.8:1234");
    read.headers_mut().insert("cookie", cookie.parse().unwrap());
    assert_eq!(
        app.clone().oneshot(read).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let login_challenge = decoded(
        app.clone()
            .oneshot(request(
                "/api/v1/auth/login-challenge?purpose=login",
                "192.0.2.8:1234",
            ))
            .await
            .unwrap(),
    )
    .await["challenge"]
        .as_str()
        .unwrap()
        .to_owned();
    let payload =
        serde_json::json!({"password":"synthetic-password-for-tests","challenge":login_challenge});
    let login = app
        .clone()
        .oneshot(json_request(
            "/api/v1/auth/login",
            payload.clone(),
            "",
            &login_challenge,
            "https://example.test",
        ))
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let cookie = login.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let csrf = decoded(login).await["csrf_token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        app.clone()
            .oneshot(json_request(
                "/api/v1/auth/login",
                payload,
                "",
                &login_challenge,
                "https://example.test"
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let mut session = request("/api/v1/auth/session", "192.0.2.8:1234");
    session
        .headers_mut()
        .insert("cookie", cookie.parse().unwrap());
    assert_eq!(
        decoded(app.clone().oneshot(session).await.unwrap()).await["authenticated"],
        true
    );
    let password = serde_json::json!({"current_password":"synthetic-password-for-tests","new_password":"replacement-password-for-tests"});
    assert_eq!(
        app.clone()
            .oneshot(json_request(
                "/api/v1/auth/password",
                password,
                &cookie,
                &csrf,
                "https://example.test"
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    let mut revoked = request("/api/v1/auth/session", "192.0.2.8:1234");
    revoked
        .headers_mut()
        .insert("cookie", cookie.parse().unwrap());
    assert_eq!(
        app.oneshot(revoked).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}
#[tokio::test]
async fn actual_http_ingress_nonce_origin_and_prefix() {
    let t = tempdir().unwrap();
    let root = t.path().join("data");
    let app = router(AppState::new(
        Store::open(&root, 0).unwrap(),
        root,
        Deployment::Ingress,
        TransportPolicy::Ingress,
    ));
    let mut req = request("/", "172.30.32.2:1234");
    req.headers_mut().insert(
        "x-ingress-path",
        "/api/hassio_ingress/test/".parse().unwrap(),
    );
    let html = String::from_utf8(
        to_bytes(app.clone().oneshot(req).await.unwrap().into_body(), 65536)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(html.contains("<base href=\"/api/hassio_ingress/test/\">"));
    assert!(html.contains("content=\"ingress\""));
    let mut issue = request("/api/v1/auth/csrf", "172.30.32.2:1234");
    issue
        .headers_mut()
        .insert("x-wolf-origin", "https://ha.example.test".parse().unwrap());
    let csrf = decoded(app.clone().oneshot(issue).await.unwrap()).await["csrf_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut mutation = json_request(
        "/api/v1/pcs",
        serde_json::json!({"pc_id":"pc","display_name":"PC","ssh_host":"127.0.0.1","ssh_port":22,"ssh_user":"wolf-manager"}),
        "",
        &csrf,
        "https://ha.example.test",
    );
    mutation.extensions_mut().insert(ConnectInfo(
        "172.30.32.2:1234".parse::<SocketAddr>().unwrap(),
    ));
    assert_eq!(
        app.oneshot(mutation).await.unwrap().status(),
        StatusCode::CREATED
    );
}
#[tokio::test]
async fn coordinator_connect_failure_proves_no_child_was_sent() {
    use wolf_core::*;
    let t = tempdir().unwrap();
    let root = t.path().join("data");
    let mut store = Store::open(&root, 0).unwrap();
    let pc = PcId::new("pc").unwrap();
    store
        .add_pc(
            ha_wolf_manager::domain::PcInput {
                pc_id: pc.clone(),
                display_name: "PC".into(),
                ssh_host: "127.0.0.1".into(),
                ssh_port: 1,
                ssh_user: "wolf-manager".into(),
            },
            0,
        )
        .unwrap();
    let request = RpcRequest {
        version: 1,
        request_id: uuid::Uuid::new_v4(),
        pc_id: pc,
        operation: RpcOperation::Stop(EmptyPayload {}),
    };
    let id = store
        .enqueue_operation(
            &request.pc_id.clone(),
            OperationKind::Stop,
            None,
            &[request],
            0,
        )
        .unwrap();
    let state = AppState::new(store, root, Deployment::Ingress, TransportPolicy::Ingress);
    state.run_operation(id).await.unwrap();
    assert_eq!(
        state
            .blocking(move |s| s.operation_state(id))
            .await
            .unwrap(),
        OperationState::Rejected
    );
    assert!(
        state
            .blocking(move |s| s.operation_children(id))
            .await
            .unwrap()
            .iter()
            .all(|c| c.dispatch_phase == DispatchPhase::NotDispatched)
    );
}
#[tokio::test]
async fn fresh_standalone_is_operationally_ready_while_bootstrap_required() {
    let (_t, app) = standalone();
    let response = app
        .oneshot(request("/api/v1/system/ready", "192.0.2.8:1234"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = decoded(response).await;
    assert_eq!(body["bootstrap_required"], true);
    assert_eq!(body["administrator_ready"], false);
    assert_eq!(body["mqtt_enabled"], false);
}
