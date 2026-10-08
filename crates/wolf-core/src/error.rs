use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{code}: {message}")]
#[serde(deny_unknown_fields)]
pub struct SafeError {
    pub code: String,
    pub message: String,
}
impl SafeError {
    pub fn new(code: &str) -> Self {
        Self {
            code: code.into(),
            message: match code {
                "payload_too_large" => "The request exceeds the permitted size.",
                "revision_mismatch" => "The requested revision does not match the settings.",
                "pc_id_mismatch" => "The request targets a different PC.",
                "retained_command" => "Retained control messages are refused.",
                _ => "The operation was refused.",
            }
            .into(),
        }
    }
    pub fn validation() -> Self {
        Self {
            code: "validation_failed".into(),
            message: "The supplied data is invalid.".into(),
        }
    }
}
