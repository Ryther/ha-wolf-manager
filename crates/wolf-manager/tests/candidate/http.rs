//! Real native HTTPS and same-origin authenticated product requests.
use reqwest::{Client, Method, StatusCode};
use serde_json::{Value, json};
use std::{path::Path, time::Duration};
pub struct Api {
    pub client: Client,
    pub origin: String,
    cookie: String,
    csrf: String,
}
impl Api {
    pub fn new(port: u16, ca: &Path) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let certificate = reqwest::Certificate::from_pem(&std::fs::read(ca).unwrap()).unwrap();
        Self {
            client: Client::builder()
                .no_proxy()
                .add_root_certificate(certificate)
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap(),
            origin: format!("https://localhost:{port}"),
            cookie: String::new(),
            csrf: String::new(),
        }
    }
    pub async fn get(&self, path: &str) -> Value {
        let response = self
            .client
            .get(format!("{}{path}", self.origin))
            .header("cookie", &self.cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "GET {path}");
        response.json().await.unwrap()
    }
    pub async fn post(&self, path: &str, body: Value, status: StatusCode) -> Value {
        let request = self
            .client
            .request(Method::POST, format!("{}{path}", self.origin))
            .header("cookie", &self.cookie)
            .header("origin", &self.origin)
            .header("x-wolf-csrf", &self.csrf);
        let request = if path.ends_with("/ssh/probe") {
            request
        } else {
            request.json(&body)
        };
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), status, "POST {path}");
        response.json().await.unwrap()
    }
    pub async fn ready(&self) {
        tokio::time::timeout(Duration::from_secs(25), async {
            loop {
                if let Ok(response) = self
                    .client
                    .get(format!("{}/api/v1/system/ready", self.origin))
                    .send()
                    .await
                    && response.status() == StatusCode::OK
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("exact scratch runtime never became ready");
    }
    pub async fn bootstrap(&mut self, token: &str, password: &str) {
        let challenge = self
            .get("/api/v1/auth/login-challenge?purpose=bootstrap")
            .await["challenge"]
            .as_str()
            .unwrap()
            .to_owned();
        let response = self
            .client
            .post(format!("{}/api/v1/bootstrap", self.origin))
            .header("origin", &self.origin)
            .header("x-wolf-csrf", &challenge)
            .bearer_auth(token)
            .json(&json!({"password":password,"challenge":challenge}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        self.cookie = response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .into();
        self.csrf = response.json::<Value>().await.unwrap()["csrf_token"]
            .as_str()
            .unwrap()
            .into();
        assert_eq!(
            self.get("/api/v1/auth/session").await["authenticated"],
            true
        );
        let refused = self.client.post(format!("{}/api/v1/pcs", self.origin)).header("cookie", &self.cookie).header("origin", &self.origin).header("x-wolf-csrf", uuid::Uuid::new_v4().to_string()).json(&json!({"pc_id":"refused-pc","display_name":"Refused PC","ssh_host":"127.0.0.1","ssh_port":22,"ssh_user":"wolf-manager"})).send().await.unwrap();
        assert_eq!(
            refused.status(),
            StatusCode::FORBIDDEN,
            "session alone cannot authorize mutations"
        );
        assert!(
            self.get("/api/v1/pcs").await["pcs"]
                .as_array()
                .unwrap()
                .is_empty(),
            "refused mutation preserved state"
        );
    }
}
