//! Live broker orchestration over native typed transport events.
use crate::{
    api::{AppState, Availability, Deployment, now},
    ha_bootstrap::{SupervisorClient, read_options, secret_value},
    mqtt::{BrokerConfig, ManagerEvent, ManagerMqtt, Registration},
    runtime::{Cli, Mode, client_tls},
};
use std::{collections::BTreeMap, sync::atomic::Ordering, time::Duration};
use wolf_core::*;
fn internal<T>(_: T) -> SafeError {
    SafeError::new("internal_error")
}
async fn broker(cli: &Cli) -> Result<BrokerConfig, SafeError> {
    match cli.mode {
        Mode::Ingress => {
            let token = secret_value(std::env::var("SUPERVISOR_TOKEN").ok().as_deref(), None)?
                .ok_or_else(|| SafeError::new("unauthenticated"))?;
            SupervisorClient::new(token)?.mqtt().await
        }
        Mode::Standalone => {
            let path = cli.mqtt_password_file.clone();
            let password = tokio::task::spawn_blocking(move || secret_value(None, path.as_deref()))
                .await
                .map_err(internal)??;
            let config = BrokerConfig {
                host: cli.mqtt_host.clone().ok_or_else(SafeError::validation)?,
                port: cli.mqtt_port,
                username: cli.mqtt_username.clone(),
                password,
                tls: cli.mqtt_tls,
            };
            config.validate()?;
            Ok(config)
        }
    }
}
async fn registrations(state: &AppState) -> Result<Vec<Registration>, SafeError> {
    state
        .blocking(|s| {
            Ok(s.pcs()?
                .into_iter()
                .map(|p| Registration {
                    pc_id: p.pc_id,
                    display_name: p.display_name,
                })
                .collect())
        })
        .await
}
async fn build(state: &AppState, cli: &Cli) -> Result<ManagerMqtt, SafeError> {
    let config = broker(cli).await?;
    let topics = if matches!(state.mode, Deployment::Ingress) {
        let options = if let Some(options) = &cli.startup_options {
            options.clone()
        } else {
            let path = cli.options_file.clone();
            tokio::task::spawn_blocking(move || read_options(&path))
                .await
                .map_err(internal)??
        };
        Topics::new(&options.topic_base, &options.discovery_prefix)?
    } else {
        Topics::new(&cli.topic_base, &cli.discovery_prefix)?
    };
    let ca = cli.mqtt_ca_file.clone();
    let tls = if config.tls {
        Some(
            tokio::task::spawn_blocking(move || client_tls(ca.as_deref()))
                .await
                .map_err(internal)??,
        )
    } else {
        None
    };
    let id = state.blocking(|s| s.instance_id()).await?;
    let registered = registrations(state).await?;
    let mut mqtt = ManagerMqtt::new_with_tls(config, topics, id, registered.clone(), tls)?;
    let archived = state.blocking(|s| s.archived_pc_ids()).await?;
    mqtt.seed_archived_pcs(archived)?;
    let catalogs = state
        .blocking(move |s| {
            let mut catalogs = Vec::new();
            for p in registered {
                if let Some(c) = s.catalog(&p.pc_id)? {
                    catalogs.push(c);
                }
            }
            Ok(catalogs)
        })
        .await?;
    for (manifest, attributes) in catalogs {
        mqtt.seed_catalog(manifest, attributes)?;
    }
    Ok(mqtt)
}
async fn event(
    state: &AppState,
    event: ManagerEvent,
) -> Result<Option<(PcId, ErrorCode)>, SafeError> {
    match event {
        ManagerEvent::Connected => state.mqtt_ready.store(true, Ordering::Release),
        ManagerEvent::CatalogReady {
            manifest,
            attributes,
        } => state.ingest_catalog(manifest, attributes).await?,
        ManagerEvent::HostAvailability { pc_id, online } => state.ingest_availability(
            pc_id,
            if online {
                Availability::Online
            } else {
                Availability::Offline
            },
            now(),
        )?,
        ManagerEvent::Command { pc_id, command } => {
            let (kind, revision) = match command {
                ServiceCommand::Off => (OperationKind::Stop, None),
                ServiceCommand::On => {
                    let pc = pc_id.clone();
                    (
                        OperationKind::Start,
                        Some(state.blocking(move |s| s.settings(&pc)?.revision()).await?),
                    )
                }
            };
            if let Err(error) = state.submit(pc_id.clone(), kind, revision).await {
                return Ok(Some((pc_id, error.code())));
            }
        }
        ManagerEvent::Birth => {}
    }
    Ok(None)
}
struct SnapshotEntry {
    registration: Registration,
    observation: Option<crate::api::Observation>,
    operations: Vec<crate::history::Operation>,
}
async fn snapshot(state: AppState) -> Result<Vec<SnapshotEntry>, SafeError> {
    let entries = state
        .blocking(|s| {
            let mut entries = Vec::new();
            for p in s.pcs()? {
                let operations = s.operation_page(&p.pc_id, 100, None)?.operations;
                entries.push((
                    Registration {
                        pc_id: p.pc_id,
                        display_name: p.display_name,
                    },
                    operations,
                ));
            }
            Ok(entries)
        })
        .await?;
    entries
        .into_iter()
        .map(|(registration, operations)| {
            Ok(SnapshotEntry {
                observation: state.observation(&registration.pc_id)?,
                registration,
                operations,
            })
        })
        .collect()
}
fn publish(
    mqtt: &mut ManagerMqtt,
    entries: Vec<SnapshotEntry>,
    published: &mut BTreeMap<PcId, i64>,
    results: &mut BTreeMap<uuid::Uuid, OperationState>,
) -> Result<(), SafeError> {
    if !mqtt.controls_ready() {
        return Ok(());
    }
    let registered = entries
        .iter()
        .map(|e| e.registration.clone())
        .collect::<Vec<_>>();
    match mqtt.sync_registrations(registered.clone()) {
        Err(e) if e.code() == ErrorCode::OperationInProgress => return Ok(()),
        result => result?,
    }
    if !mqtt.controls_ready() {
        return Ok(());
    }
    published.retain(|pc, _| registered.iter().any(|p| p.pc_id == *pc));
    for entry in entries {
        let pc = entry.registration.pc_id;
        if let Some(o) = entry.observation {
            match o.status {
                Some(status)
                    if matches!(o.availability, Availability::Online)
                        && now().saturating_sub(o.observed_at) < 60_000 =>
                {
                    if published.get(&pc) != Some(&o.observed_at) {
                        mqtt.observe_service(&pc, &status, o.observed_at, None)?;
                        published.insert(pc.clone(), o.observed_at);
                    }
                }
                _ => {
                    mqtt.unavailable(&pc)?;
                    published.remove(&pc);
                }
            }
        }
        for op in entry.operations {
            if results.get(&op.operation_id) == Some(&op.state) {
                continue;
            }
            if matches!(op.state, OperationState::Queued | OperationState::Running) {
                continue;
            }
            let code = op
                .sanitized_result
                .as_ref()
                .and_then(|v| v.get("code"))
                .and_then(serde_json::Value::as_str);
            mqtt.operation_result(&pc, op.operation_id, op.state, code, now())?;
            results.insert(op.operation_id, op.state);
        }
    }
    if results.len() > 10_000 {
        results.clear();
    }
    Ok(())
}
pub async fn run(state: AppState, cli: Cli, mut stop: tokio::sync::watch::Receiver<bool>) {
    let mut results = BTreeMap::new();
    loop {
        if *stop.borrow() {
            break;
        }
        let built = tokio::select! {_=stop.changed()=>break,built=build(&state,&cli)=>built};
        let mut mqtt = match built {
            Ok(m) => m,
            Err(_) => {
                state.mqtt_ready.store(false, Ordering::Release);
                tokio::select! {_=stop.changed()=>break,_=tokio::time::sleep(Duration::from_secs(5))=>{}}
                continue;
            }
        };
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        let mut published = BTreeMap::new();
        let mut snapshot_task =
            None::<tokio::task::JoinHandle<Result<Vec<SnapshotEntry>, SafeError>>>;
        let mut event_jobs = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
             _=stop.changed()=>{state.mqtt_ready.store(false,Ordering::Release);if let Some(task)=snapshot_task.take(){task.abort();}event_jobs.abort_all();let _=tokio::time::timeout(Duration::from_secs(5),mqtt.shutdown()).await;return;},
             incoming=mqtt.poll()=>{
              state.mqtt_ready.store(mqtt.controls_ready(),Ordering::Release);
              match incoming{
               Ok(Some(incoming))=>{
                 match incoming {
                     ManagerEvent::Connected=>{state.mqtt_ready.store(true,Ordering::Release);published.clear();results.clear();},
                     ManagerEvent::Birth=>{},
                     ManagerEvent::HostAvailability{pc_id,online}=>{if state.ingest_availability(pc_id,if online{Availability::Online}else{Availability::Offline},now()).is_err(){break;}},
                     incoming=>{
                         if event_jobs.len()>=32 {
                             if let ManagerEvent::Command{pc_id,..}=incoming{if mqtt.command_refused(&pc_id,"busy",now()).is_err(){break;}}else{break;}
                         }else{
                             let state=state.clone();event_jobs.spawn(async move{event(&state,incoming).await});
                         }
                     }
                 }
               },
               Ok(None)=>{},Err(_)=>break
              }
             },
             Some(completed)=event_jobs.join_next(),if !event_jobs.is_empty()=>{
                 match completed{Ok(Ok(Some((pc,code))))=>{if mqtt.command_refused(&pc,code.as_str(),now()).is_err(){break;}},Ok(Ok(None))=>{},_=>break}
             },
             _=tick.tick()=>{if snapshot_task.is_none(){snapshot_task=Some(tokio::spawn(snapshot(state.clone())));}},
             collected=async{snapshot_task.as_mut().unwrap().await},if snapshot_task.is_some()=>{
               snapshot_task=None;
               match collected {
                 Ok(Ok(entries))=>match publish(&mut mqtt,entries,&mut published,&mut results){Err(e)if matches!(e.code(),ErrorCode::PayloadTooLarge|ErrorCode::OperationInProgress)=>{},Err(_)=>break,Ok(())=>{}},
                 _=>break
               }
             }
            }
        }
        if let Some(task) = snapshot_task.take() {
            task.abort();
        }
        event_jobs.abort_all();
        state.mqtt_ready.store(false, Ordering::Release);
        if let Ok(registered) = registrations(&state).await {
            for pc in registered {
                let _ = state.ingest_availability(pc.pc_id, Availability::Unknown, now());
            }
        }
        tokio::select! {_=stop.changed()=>break,_=tokio::time::sleep(Duration::from_secs(2))=>{}}
    }
    state.mqtt_ready.store(false, Ordering::Release);
}
