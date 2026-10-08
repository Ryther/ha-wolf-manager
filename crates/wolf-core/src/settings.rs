use crate::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParameterDefinition {
    pub label: String,
    pub launch_options: String,
    pub description: String,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugSettings {
    pub test_ball: bool,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GameSettings {
    pub direct_launch: bool,
    pub proton_cachyos: bool,
    pub parameters: Vec<ParameterId>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub debug: DebugSettings,
    pub parameters: BTreeMap<ParameterId, ParameterDefinition>,
    pub games: BTreeMap<AppId, GameSettings>,
}

impl Default for Settings {
    fn default() -> Self {
        let parameters = [
            (
                "fsr4",
                "FSR4",
                "PROTON_FSR4_UPGRADE=1 %command%",
                "Request Proton-CachyOS FSR4 upgrade for games that expose FSR3.",
            ),
            (
                "fsr4_indicator",
                "FSR4 Indicator",
                "PROTON_FSR4_INDICATOR=1 %command%",
                "Show the Proton-CachyOS FSR4 diagnostic indicator.",
            ),
        ]
        .into_iter()
        .map(|(id, label, launch_options, description)| {
            (
                ParameterId::new(id).expect("built-in ID"),
                ParameterDefinition {
                    label: label.into(),
                    launch_options: launch_options.into(),
                    description: description.into(),
                },
            )
        })
        .collect();
        Self {
            debug: DebugSettings::default(),
            parameters,
            games: BTreeMap::new(),
        }
    }
}
impl ParameterDefinition {
    pub fn validate(&self) -> Result<(), SafeError> {
        if self.label.trim().is_empty()
            || self.label.len() > 256
            || self.description.len() > 4096
            || self.launch_options.trim().is_empty()
            || self.launch_options.len() > 4096
            || self.launch_options.contains(['\r', '\n', '\0'])
        {
            return Err(SafeError::validation());
        }
        Ok(())
    }
}
impl Settings {
    pub fn validate_capabilities(&self, capabilities: &HostCapabilities) -> Result<(), SafeError> {
        self.validate()?;
        if capabilities.version != 1
            || (!capabilities.proton_cachyos && self.games.values().any(|game| game.proton_cachyos))
        {
            return Err(SafeError::validation());
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), SafeError> {
        if self.games.len() > 10000 || self.parameters.len() > 1024 {
            return Err(SafeError::validation());
        }
        for definition in self.parameters.values() {
            definition.validate()?;
        }
        for game in self.games.values() {
            let mut seen = std::collections::BTreeSet::new();
            for parameter in &game.parameters {
                if !self.parameters.contains_key(parameter) || !seen.insert(parameter) {
                    return Err(SafeError::validation());
                }
            }
        }
        Ok(())
    }
    pub fn build_overrides(&self) -> Result<Self, SafeError> {
        self.validate()?;
        let mut result = self.clone();
        result.games.retain(|_, game| {
            game.direct_launch || game.proton_cachyos || !game.parameters.is_empty()
        });
        Ok(result)
    }
    pub fn revision(&self) -> Result<Revision, SafeError> {
        self.validate()?;
        revision_of(self)
    }
    pub fn import_legacy(value: &serde_json::Value) -> Result<Self, SafeError> {
        let object = value.as_object().ok_or_else(SafeError::validation)?;
        if object.contains_key("version") {
            return Err(SafeError::validation());
        }
        let mut result = Self::default();
        if let Some(definitions) = object
            .get("parameters")
            .and_then(serde_json::Value::as_object)
        {
            for (id, raw) in definitions {
                let Ok(id) = ParameterId::new(id.trim()) else {
                    continue;
                };
                let Some(raw) = raw.as_object() else { continue };
                let definition = ParameterDefinition {
                    label: legacy_string(raw.get("label"))
                        .unwrap_or_else(|| id.to_string())
                        .trim()
                        .into(),
                    launch_options: legacy_string(raw.get("launch_options"))
                        .unwrap_or_default()
                        .trim()
                        .into(),
                    description: legacy_string(raw.get("description"))
                        .unwrap_or_default()
                        .trim()
                        .into(),
                };
                if definition.validate().is_ok() {
                    result.parameters.insert(id, definition);
                }
            }
        }
        if let Some(games) = object.get("games").and_then(serde_json::Value::as_object) {
            for (id, raw) in games {
                let Ok(id) = AppId::new(id) else { continue };
                let Some(raw) = raw.as_object() else { continue };
                let mut parameters = Vec::new();
                if let Some(selected) = raw.get("parameters").and_then(serde_json::Value::as_array)
                {
                    for item in selected {
                        if let Some(text) = legacy_string(Some(item))
                            && let Ok(id) = ParameterId::new(text)
                            && result.parameters.contains_key(&id)
                            && !parameters.contains(&id)
                        {
                            parameters.push(id);
                        }
                    }
                }
                for builtin in ["fsr4", "fsr4_indicator"] {
                    let id = ParameterId::new(builtin)?;
                    if truthy(raw.get(builtin)) && !parameters.contains(&id) {
                        parameters.push(id);
                    }
                }
                result.games.insert(
                    id,
                    GameSettings {
                        direct_launch: truthy(raw.get("direct_launch")),
                        proton_cachyos: truthy(raw.get("proton_cachyos")),
                        parameters,
                    },
                );
            }
        }
        result.debug.test_ball = truthy(object.get("debug").and_then(|v| v.get("test_ball")));
        result.validate()?;
        Ok(result)
    }
}
fn truthy(value: Option<&serde_json::Value>) -> bool {
    match value {
        None | Some(serde_json::Value::Null) => false,
        Some(serde_json::Value::Bool(v)) => *v,
        Some(serde_json::Value::Number(v)) => v.as_f64().is_some_and(|v| v != 0.0),
        Some(serde_json::Value::String(v)) => !v.is_empty(),
        Some(serde_json::Value::Array(v)) => !v.is_empty(),
        Some(serde_json::Value::Object(v)) => !v.is_empty(),
    }
}
fn legacy_string(value: Option<&serde_json::Value>) -> Option<String> {
    value.map(|v| match v {
        serde_json::Value::String(v) => v.clone(),
        serde_json::Value::Bool(true) => "True".into(),
        serde_json::Value::Bool(false) => "False".into(),
        serde_json::Value::Null => "None".into(),
        _ => v.to_string(),
    })
}
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, SafeError> {
    fn sort(value: serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(map) => {
                serde_json::Value::Object(map.into_iter().map(|(k, v)| (k, sort(v))).collect())
            }
            serde_json::Value::Array(items) => {
                serde_json::Value::Array(items.into_iter().map(sort).collect())
            }
            v => v,
        }
    }
    serde_json::to_vec(&sort(
        serde_json::to_value(value).map_err(|_| SafeError::validation())?,
    ))
    .map_err(|_| SafeError::validation())
}
pub fn revision_of<T: Serialize>(value: &T) -> Result<Revision, SafeError> {
    use sha2::{Digest, Sha256};
    Revision::new(
        Sha256::digest(canonical_json(value)?)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    )
}
