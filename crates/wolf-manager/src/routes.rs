//! Closed product DTOs over durable domain state.
use crate::{
    api::{ApiError, AppState, json_body, now, value},
    domain::PcInput,
    history::OperationCursor,
};
use axum::{
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::json;
use std::collections::BTreeMap;
use wolf_core::*;
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    expected_desired_revision: Revision,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GameInput {
    expected_desired_revision: Revision,
    direct_launch: bool,
    proton_cachyos: bool,
    parameters: Vec<ParameterId>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdatePc {
    display_name: String,
    ssh_host: String,
    ssh_port: u16,
    ssh_user: String,
}
pub async fn product(
    state: AppState,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    bytes: &[u8],
    q: BTreeMap<String, String>,
) -> Result<Response, ApiError> {
    let parts = path.split('/').collect::<Vec<_>>();
    let get = *method == Method::GET;
    let post = *method == Method::POST;
    let put = *method == Method::PUT;
    let delete = *method == Method::DELETE;
    if path == "pcs" && get {
        return Ok(value(json!({"pcs":state.blocking(|s|s.pcs()).await?})));
    }
    if path == "pcs" && post {
        let p: PcInput = json_body(headers, bytes)?;
        let id = p.pc_id.clone();
        state.blocking(move |s| s.add_pc(p, now())).await?;
        let pc = state
            .blocking(move |s| {
                s.pcs()?
                    .into_iter()
                    .find(|p| p.pc_id == id)
                    .ok_or_else(|| SafeError::new("not_found"))
            })
            .await?;
        return Ok((StatusCode::CREATED, axum::Json(pc)).into_response());
    }
    if path == "parameters" && get {
        return Ok(value(
            json!({"parameters":state.blocking(|s|s.global_settings()).await?.parameters}),
        ));
    }
    if parts.len() == 2 && parts[0] == "parameters" {
        let id = ParameterId::new(parts[1])?;
        if put {
            let p: ParameterDefinition = json_body(headers, bytes)?;
            let returned = p.clone();
            state
                .blocking(move |s| s.save_parameter(&id, p, now()))
                .await?;
            return Ok(value(
                json!({"definition":returned,"affected_desired_revisions":revisions(&state).await?}),
            ));
        }
        if delete {
            state
                .blocking(move |s| s.delete_parameter(&id, now()))
                .await?;
            return Ok(StatusCode::NO_CONTENT.into_response());
        }
    }
    if path == "settings/debug" && put {
        let debug: DebugSettings = json_body(headers, bytes)?;
        let returned = debug.clone();
        state.blocking(move |s| s.save_debug(debug, now())).await?;
        return Ok(value(
            json!({"debug":returned,"affected_desired_revisions":revisions(&state).await?}),
        ));
    }
    if parts.first() == Some(&"operations") && parts.len() >= 2 {
        let id = uuid::Uuid::parse_str(parts[1]).map_err(|_| SafeError::validation())?;
        if parts.len() == 2 && get {
            return Ok(value(
                serde_json::to_value(state.blocking(move |s| s.operation(id)).await?)
                    .map_err(|_| SafeError::new("internal_error"))?,
            ));
        }
        if parts.len() == 3 && parts[2] == "reconcile" && post {
            let _: Empty = json_body(headers, bytes)?;
            let resolution = state.reconcile(id).await?;
            let operation = state.blocking(move |s| s.operation(id)).await?;
            let children = state.blocking(move |s| s.operation_evidence(id)).await?;
            return Ok(value(
                json!({"state":resolution.state,"operation":operation,"resolution":{"state":resolution.state,"code":resolution.code,"stage_succeeded":resolution.stage_succeeded},"children":children}),
            ));
        }
    }
    if parts.first() != Some(&"pcs") || parts.len() < 2 {
        return Err(SafeError::new("not_found").into());
    }
    let pc = PcId::new(parts[1])?;
    state.endpoint(&pc).await?;
    if parts.len() == 2 {
        if delete {
            let id = pc.clone();
            state.blocking(move |s| s.archive_pc(&id, now())).await?;
            return Ok(StatusCode::NO_CONTENT.into_response());
        }
        if *method == Method::PATCH {
            let p: UpdatePc = json_body(headers, bytes)?;
            let id = pc.clone();
            state
                .blocking(move |s| {
                    s.update_pc(
                        PcInput {
                            pc_id: id,
                            display_name: p.display_name,
                            ssh_host: p.ssh_host,
                            ssh_port: p.ssh_port,
                            ssh_user: p.ssh_user,
                        },
                        now(),
                    )
                })
                .await?;
            state
                .probes
                .lock()
                .map_err(|_| SafeError::new("internal_error"))?
                .retain(|_, p| p.endpoint.pc_id != pc);
            state
                .observations
                .lock()
                .map_err(|_| SafeError::new("internal_error"))?
                .remove(&pc);
            let id = pc.clone();
            let p = state
                .blocking(move |s| {
                    s.pcs()?
                        .into_iter()
                        .find(|p| p.pc_id == id)
                        .ok_or_else(|| SafeError::new("not_found"))
                })
                .await?;
            return Ok(value(
                serde_json::to_value(p).map_err(|_| SafeError::new("internal_error"))?,
            ));
        }
    }
    let leaf = parts.get(2).copied().unwrap_or("");
    if leaf == "ssh" && parts.len() == 4 {
        match parts[3] {
            "public-key" if get => {
                return Ok(value(json!({"public_key":state.public_key(&pc).await?})));
            }
            "probe" if post => {
                if !bytes.is_empty() {
                    return Err(SafeError::new("bad_request").into());
                }
                return Ok(value(state.probe_host(&pc).await?));
            }
            "enroll" if post => {
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Enroll {
                    probe_id: uuid::Uuid,
                    fingerprint: String,
                }
                let p: Enroll = json_body(headers, bytes)?;
                state.enroll(&pc, p.probe_id, p.fingerprint).await?;
                return Ok(value(json!({"enrolled":true})));
            }
            "test" if post => {
                let _: Empty = json_body(headers, bytes)?;
                return queued(&state, pc, OperationKind::Preflight, None).await;
            }
            _ => {}
        }
    }
    if parts.len() == 3 && get {
        match leaf {
            "settings" => {
                let id = pc.clone();
                let settings = state.blocking(move |s| s.settings(&id)).await?;
                let observation = state.observation(&pc)?;
                let staged = observation.as_ref().and_then(|o| o.staged_revision.clone());
                let status = observation.and_then(|o| o.status);
                return Ok(value(
                    json!({"desired_revision":settings.revision()?,"settings":settings,"staged_revision":staged,"running_revision":status.as_ref().and_then(|s|s.running_revision.clone())}),
                ));
            }
            "status" => {
                let o = state
                    .observation(&pc)?
                    .ok_or_else(|| SafeError::new("host_unavailable"))?;
                return Ok(value(
                    json!({"status":o.status.ok_or_else(||SafeError::new("host_unavailable"))?,"capabilities":o.capabilities.ok_or_else(||SafeError::new("host_unavailable"))?,"availability":o.availability,"observed_at":o.observed_at}),
                ));
            }
            "games" => {
                let id = pc.clone();
                let (m, games) = state
                    .blocking(move |s| s.catalog(&id))
                    .await?
                    .ok_or_else(|| SafeError::new("host_unavailable"))?;
                let availability = state
                    .observation(&pc)?
                    .map(|o| o.host_availability)
                    .unwrap_or(crate::api::Availability::Unknown);
                return Ok(value(
                    json!({"games":games,"catalog_generation":m.catalog_generation,"observed_at":m.observed_at_ms,"availability":availability}),
                ));
            }
            "operations" => {
                if q.keys().any(|k| k != "limit" && k != "cursor") {
                    return Err(SafeError::new("bad_request").into());
                }
                let limit = q
                    .get("limit")
                    .map(|v| v.parse::<u16>())
                    .transpose()
                    .map_err(|_| SafeError::validation())?
                    .unwrap_or(20);
                let cursor = q
                    .get("cursor")
                    .map(|v| OperationCursor::parse(v))
                    .transpose()?;
                return Ok(value(
                    serde_json::to_value(
                        state
                            .blocking(move |s| s.operation_page(&pc, limit, cursor.as_ref()))
                            .await?,
                    )
                    .map_err(|_| SafeError::new("internal_error"))?,
                ));
            }
            "logs" => {
                if q.keys().any(|k| k != "lines") {
                    return Err(SafeError::new("bad_request").into());
                }
                let lines = q
                    .get("lines")
                    .map(|v| v.parse::<u16>())
                    .transpose()
                    .map_err(|_| SafeError::validation())?
                    .unwrap_or(100);
                let result = state
                    .read_rpc(&pc, RpcOperation::BoundedLogs(LogsPayload { lines }))
                    .await?;
                if let RpcResult::Logs { lines, truncated } = result {
                    return Ok(value(json!({"lines":lines,"truncated":truncated})));
                }
            }
            _ => {}
        }
    }
    if leaf == "games" && parts.len() == 5 && parts[4] == "settings" && put {
        let app = AppId::new(parts[3])?;
        let p: GameInput = json_body(headers, bytes)?;
        let caps = state
            .observation(&pc)?
            .and_then(|o| o.capabilities)
            .ok_or_else(|| SafeError::new("host_unavailable"))?;
        if p.proton_cachyos && !caps.proton_cachyos {
            return Ok((
                StatusCode::UNPROCESSABLE_ENTITY,
                axum::Json(json!({"error":SafeError::validation()})),
            )
                .into_response());
        }
        let revision = state
            .blocking(move |s| {
                s.save_game(
                    &pc,
                    &app,
                    GameSettings {
                        direct_launch: p.direct_launch,
                        proton_cachyos: p.proton_cachyos,
                        parameters: p.parameters,
                    },
                    &p.expected_desired_revision,
                    &caps,
                    now(),
                )
            })
            .await?;
        return Ok(value(json!({"desired_revision":revision})));
    }
    if post && leaf == "apply" && parts.len() == 3 {
        let p: Expected = json_body(headers, bytes)?;
        return queued(
            &state,
            pc,
            OperationKind::ApplySettings,
            Some(p.expected_desired_revision),
        )
        .await;
    }
    if post && leaf == "service" && parts.len() == 4 {
        let (kind, revision) = match parts[3] {
            "stop" => {
                let _: Empty = json_body(headers, bytes)?;
                (OperationKind::Stop, None)
            }
            "start" | "restart" => {
                let p: Expected = json_body(headers, bytes)?;
                (
                    if parts[3] == "start" {
                        OperationKind::Start
                    } else {
                        OperationKind::Restart
                    },
                    Some(p.expected_desired_revision),
                )
            }
            _ => return Err(SafeError::new("not_found").into()),
        };
        return queued(&state, pc, kind, revision).await;
    }
    Err(SafeError::new("not_found").into())
}
async fn queued(
    state: &AppState,
    pc: PcId,
    kind: OperationKind,
    revision: Option<Revision>,
) -> Result<Response, ApiError> {
    let id = match state.submit(pc.clone(), kind, revision).await {
        Ok(id) => id,
        Err(error) => {
            let active = if matches!(
                error.code(),
                ErrorCode::OperationInProgress | ErrorCode::UnknownInterrupted
            ) {
                state.blocking(move |s| s.active_mutation(&pc)).await?
            } else {
                None
            };
            return Err(ApiError(error, active));
        }
    };
    Ok((
        StatusCode::ACCEPTED,
        axum::Json(json!({"operation_id":id,"state":"queued"})),
    )
        .into_response())
}
async fn revisions(state: &AppState) -> Result<serde_json::Value, SafeError> {
    state
        .blocking(|s| {
            let mut map = serde_json::Map::new();
            for p in s.pcs()? {
                map.insert(
                    p.pc_id.to_string(),
                    json!(s.settings(&p.pc_id)?.revision()?),
                );
            }
            Ok(serde_json::Value::Object(map))
        })
        .await
}
