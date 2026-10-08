use serde::{Deserialize, Deserializer, Serialize};

macro_rules! codes {
    ($($variant:ident => ($code:literal, $message:literal)),+ $(,)?) => {
        /// Closed public error vocabulary. External diagnostics never become messages.
        #[derive(Debug,Clone,Copy,PartialEq,Eq,Serialize,Deserialize)]
        pub enum ErrorCode {$(#[serde(rename=$code)] $variant),+}
        impl ErrorCode {
            pub fn as_str(self)->&'static str {match self {$(Self::$variant=>$code),+}}
            pub fn message(self)->&'static str {match self {$(Self::$variant=>$message),+}}
            fn from_code(code:&str)->Self {match code {$($code=>Self::$variant),+, _=>Self::InternalError}}
        }
    };
}
codes! {
    ValidationFailed => ("validation_failed","The supplied data is invalid."),
    InternalError => ("internal_error","The operation could not be completed."),
    PayloadTooLarge => ("payload_too_large","The request exceeds the permitted size."),
    RevisionMismatch => ("revision_mismatch","The requested revision does not match the settings."),
    PcIdMismatch => ("pc_id_mismatch","The request targets a different PC."),
    RetainedCommand => ("retained_command","Retained control messages are refused."),
    CatalogGenerationConflict => ("catalog_generation_conflict","The catalog generation conflicts with accepted data."),
    BadRequest => ("bad_request","The request is invalid."),
    Unauthenticated => ("unauthenticated","Authentication is required."),
    LoginFailed => ("login_failed","Authentication failed."),
    InvalidBootstrapToken => ("invalid_bootstrap_token","The bootstrap token is invalid."),
    Forbidden => ("forbidden","The request is forbidden."),
    CsrfFailed => ("csrf_failed","The request origin token is invalid."),
    IngressPeerForbidden => ("ingress_peer_forbidden","The connection peer is not permitted."),
    NotFound => ("not_found","The requested resource was not found."),
    StaleRevision => ("stale_revision","The desired revision has changed."),
    OperationInProgress => ("operation_in_progress","A conflicting operation is in progress."),
    HostKeyMismatch => ("host_key_mismatch","The host key differs from the enrolled key."),
    UnknownInterrupted => ("unknown_interrupted","The operation outcome requires reconciliation."),
    BootstrapCompleted => ("bootstrap_completed","Administrator setup is already complete."),
    ParameterInUse => ("parameter_in_use","The parameter is assigned to a game."),
    UnsupportedMediaType => ("unsupported_media_type","The request media type is unsupported."),
    LoginRateLimited => ("login_rate_limited","Authentication attempts are temporarily limited."),
    HostUnavailable => ("host_unavailable","The host is unavailable."),
    RequestIdConflict => ("request_id_conflict","The request identifier is already bound to different data."),
    PrimaryNotDispatched => ("primary_not_dispatched","Settings were staged but the lifecycle request was not dispatched."),
    ChildFailed => ("child_failed","A required child request failed."),
    NotDispatched => ("not_dispatched","The request was not dispatched."),
    RecoveryPending => ("recovery_pending","Recovery must be resolved before this operation."),
    Busy => ("busy","A conflicting operation is in progress."),
}
impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, thiserror::Error)]
#[error("{code}: {message}")]
pub struct SafeError {
    code: ErrorCode,
    message: &'static str,
}
impl SafeError {
    /// Unknown internal codes collapse to the canonical internal error.
    pub fn new(code: &str) -> Self {
        Self::from_code(ErrorCode::from_code(code))
    }
    pub fn from_code(code: ErrorCode) -> Self {
        Self {
            code,
            message: code.message(),
        }
    }
    pub fn validation() -> Self {
        Self::from_code(ErrorCode::ValidationFailed)
    }
    pub fn code(&self) -> ErrorCode {
        self.code
    }
    pub fn message(&self) -> &'static str {
        self.message
    }
}
impl<'de> Deserialize<'de> for SafeError {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Received {
            code: ErrorCode,
            message: String,
        }
        let received = Received::deserialize(d)?;
        if received.message != received.code.message() {
            return Err(serde::de::Error::custom("noncanonical safe error"));
        }
        Ok(Self::from_code(received.code))
    }
}
