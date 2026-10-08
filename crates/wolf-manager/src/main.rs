use clap::Parser;
use ha_wolf_manager::{
    api::now,
    runtime::{Cli, Command, read_secret, serve},
};
fn main() {
    let mut cli = Cli::parse();
    let result = ha_wolf_manager::init::prepare(&mut cli).and_then(|()| {
        ha_wolf_manager::logging::initialize()?;
        if cli.command.is_none() {
            tracing::info!(
                version = env!("CARGO_PKG_VERSION"),
                "Manager process admitted"
            );
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|_| wolf_core::SafeError::new("internal_error"))?;
        runtime.block_on(run(cli))
    });
    if let Err(error) = result {
        tracing::error!(code = ?error.code(), "Manager process stopped with a controlled error");
        eprintln!("{error}");
        std::process::exit(1);
    }
}
async fn run(cli: Cli) -> Result<(), wolf_core::SafeError> {
    match &cli.command {
        Some(Command::Healthcheck) => ha_wolf_manager::health::healthcheck(&cli.data),
        Some(Command::Backup { destination }) => {
            let data = cli.data.clone();
            let destination = destination.clone();
            tokio::task::spawn_blocking(move || {
                ha_wolf_manager::bundle::backup(&data, &destination)
            })
            .await
            .map_err(|_| wolf_core::SafeError::new("internal_error"))?
        }
        Some(Command::RestorePreview { bundle }) => {
            let bundle = bundle.clone();
            tokio::task::spawn_blocking(move || ha_wolf_manager::bundle::preview(&bundle))
                .await
                .map_err(|_| wolf_core::SafeError::new("internal_error"))?
        }
        Some(Command::Restore { bundle }) => {
            let bundle = bundle.clone();
            let target = cli.data.clone();
            let rollback = tokio::task::spawn_blocking(move || {
                ha_wolf_manager::bundle::restore(&bundle, &target)
            })
            .await
            .map_err(|_| wolf_core::SafeError::new("internal_error"))??;
            if let Some(path) = rollback {
                println!("Rollback directory: {}", path.display());
            }
            Ok(())
        }
        Some(Command::ResetPassword { password_file }) => {
            let data = cli.data.clone();
            let path = password_file.clone();
            tokio::task::spawn_blocking(move || {
                let bytes = read_secret(&path, 1024)?;
                let password = std::str::from_utf8(&bytes)
                    .map_err(|_| wolf_core::SafeError::validation())?
                    .trim_end_matches(['\r', '\n']);
                ha_wolf_manager::recovery::Recovery::open(&data, now())?
                    .reset_password(password, now())
            })
            .await
            .map_err(|_| wolf_core::SafeError::new("internal_error"))?
        }
        Some(Command::ImportPreview {
            source,
            format_version,
        }) => {
            let bytes = read_secret(source, 4 * 1024 * 1024)?;
            let settings = ha_wolf_manager::imports::preview(*format_version, &bytes)?;
            println!(
                "{}",
                serde_json::json!({"format_version":format_version,"settings":settings})
            );
            Ok(())
        }
        Some(Command::ImportLegacy {
            source,
            format_version,
            pc,
            expected_revision,
        }) => {
            let source = source.clone();
            let version = *format_version;
            let pc = wolf_core::PcId::new(pc.clone())?;
            let revision = wolf_core::Revision::new(expected_revision.clone())?;
            let data = cli.data.clone();
            let revision = tokio::task::spawn_blocking(move || {
                std::fs::symlink_metadata(data.join("manager.sqlite3"))
                    .map_err(|_| wolf_core::SafeError::validation())?;
                let bytes = read_secret(&source, 4 * 1024 * 1024)?;
                let mut store = ha_wolf_manager::store::Store::open(&data, now())?;
                store.import_legacy_settings(&pc, &revision, version, &bytes, now())
            })
            .await
            .map_err(|_| wolf_core::SafeError::new("internal_error"))??;
            println!("{}", serde_json::json!({"desired_revision":revision}));
            Ok(())
        }
        None => {
            tracing::info!("Manager runtime starting");
            let result = serve(cli).await;
            tracing::info!("Manager runtime stopped; uncertain operations retained");
            result
        }
    }
}
