use crate::*;
use serde_json::{Value, json};
use uuid::Uuid;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceCommand {
    On,
    Off,
}
pub fn validate_command(payload: &[u8], retained: bool) -> Result<ServiceCommand, SafeError> {
    if retained {
        return Err(SafeError::new("retained_command"));
    }
    match payload {
        b"ON" => Ok(ServiceCommand::On),
        b"OFF" => Ok(ServiceCommand::Off),
        _ => Err(SafeError::validation()),
    }
}
#[derive(Debug, Clone)]
pub struct Topics {
    base: String,
    discovery_prefix: String,
}
fn topic_root(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.split('/').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        })
}
impl Topics {
    pub fn new(base: &str, discovery_prefix: &str) -> Result<Self, SafeError> {
        if !topic_root(base) || !topic_root(discovery_prefix) {
            return Err(SafeError::validation());
        }
        Ok(Self {
            base: base.into(),
            discovery_prefix: discovery_prefix.into(),
        })
    }
    pub fn host_availability(&self, pc: &PcId) -> String {
        format!("{}/{pc}/host/availability", self.base)
    }
    pub fn catalog_manifest(&self, pc: &PcId) -> String {
        format!("{}/{pc}/catalog/manifest", self.base)
    }
    pub fn catalog_state(&self, pc: &PcId, app: &AppId) -> String {
        format!("{}/{pc}/catalog/{app}/state", self.base)
    }
    pub fn catalog_attributes(&self, pc: &PcId, app: &AppId) -> String {
        format!("{}/{pc}/catalog/{app}/attributes", self.base)
    }
    pub fn game_discovery(&self, pc: &PcId, app: &AppId) -> String {
        format!(
            "{}/sensor/wolf_manager_{pc}_game_{app}/config",
            self.discovery_prefix
        )
    }
    pub fn service_availability(&self, pc: &PcId) -> String {
        format!("{}/{pc}/service/availability", self.base)
    }
    pub fn service_state(&self, pc: &PcId) -> String {
        format!("{}/{pc}/service/state", self.base)
    }
    pub fn service_attributes(&self, pc: &PcId) -> String {
        format!("{}/{pc}/service/attributes", self.base)
    }
    pub fn service_command(&self, pc: &PcId) -> String {
        format!("{}/{pc}/service/command", self.base)
    }
    pub fn service_result(&self, pc: &PcId) -> String {
        format!("{}/{pc}/service/result", self.base)
    }
    pub fn switch_discovery(&self, pc: &PcId) -> String {
        format!(
            "{}/switch/wolf_manager_{pc}_service/config",
            self.discovery_prefix
        )
    }
    pub fn manager_availability(&self, instance: Uuid) -> String {
        format!("{}/manager/{instance}/availability", self.base)
    }
    pub fn ha_birth(&self) -> String {
        format!("{}/status", self.discovery_prefix)
    }
    pub fn game_discovery_payload(
        &self,
        pc: &PcId,
        app: &AppId,
        pc_name: &str,
        game_name: &str,
    ) -> Value {
        json!({"name":game_name,"unique_id":format!("wolf_manager_{pc}_game_{app}"),"state_topic":self.catalog_state(pc,app),"json_attributes_topic":self.catalog_attributes(pc,app),"availability_topic":self.host_availability(pc),"device":{"identifiers":[format!("wolf_manager_{pc}")],"name":pc_name,"manufacturer":"HA Wolf Manager"}})
    }
    pub fn switch_discovery_payload(&self, pc: &PcId, pc_name: &str, instance: Uuid) -> Value {
        json!({"name":"Wolf","unique_id":format!("wolf_manager_{pc}_service"),"state_topic":self.service_state(pc),"command_topic":self.service_command(pc),"json_attributes_topic":self.service_attributes(pc),"payload_on":"ON","payload_off":"OFF","optimistic":false,"qos":0,"retain":false,"availability_mode":"all","availability":[{"topic":self.manager_availability(instance)},{"topic":self.service_availability(pc)}],"device":{"identifiers":[format!("wolf_manager_{pc}")],"name":pc_name,"manufacturer":"HA Wolf Manager"}})
    }
}
