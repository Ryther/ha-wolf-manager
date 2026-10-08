//! Actual MQTT5 TLS observer, independent of the candidate process.
use rumqttc::v5::{
    AsyncClient, Event, MqttOptions,
    mqttbytes::{QoS, v5::Packet},
};
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
type Publications = Arc<Mutex<Vec<(String, Vec<u8>)>>>;
pub struct Observer {
    pub messages: Publications,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Observer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
pub async fn start(port: u16, ca: &Path, base: &str) -> Observer {
    let mut options = MqttOptions::new(
        format!("candidate-observer-{}", uuid::Uuid::new_v4()),
        "localhost",
        port,
    );
    options.set_transport(rumqttc::Transport::tls_with_config(
        ha_wolf_manager::runtime::client_tls(Some(ca))
            .unwrap()
            .into(),
    ));
    let (client, mut eventloop) = AsyncClient::new(options, 64);
    client
        .subscribe(format!("{base}/#"), QoS::AtLeastOnce)
        .await
        .unwrap();
    let messages = Arc::new(Mutex::new(Vec::new()));
    let shared = messages.clone();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let mut tx = Some(tx);
        loop {
            match eventloop.poll().await {
                Ok(Event::Incoming(Packet::SubAck(_))) => {
                    if let Some(tx) = tx.take() {
                        let _ = tx.send(());
                    }
                }
                Ok(Event::Incoming(Packet::Publish(p))) => shared.lock().unwrap().push((
                    String::from_utf8(p.topic.to_vec()).unwrap(),
                    p.payload.to_vec(),
                )),
                Ok(_) => {}
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    });
    tokio::time::timeout(Duration::from_secs(15), rx)
        .await
        .expect("native TLS observer connection")
        .unwrap();
    Observer { messages, task }
}
impl Observer {
    pub async fn wait(&self, suffix: &str, payload: &[u8]) {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if self
                    .messages
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|(topic, value)| topic.ends_with(suffix) && value == payload)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("actual MQTT publication missing");
    }
}
