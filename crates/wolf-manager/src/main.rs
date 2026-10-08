use clap::Parser;
use ha_wolf_manager::{
    api::now,
    runtime::{Cli, Command, read_secret, serve},
};
fn main() {
    let mut cli = Cli::parse();
    let result = ha_wolf_manager::init::prepare(&mut cli).and_then(|()| {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|_| wolf_core::SafeError::new("internal_error"))?;
        runtime.block_on(run(cli))
    });
    if let Err(error) = result {
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
        None => serve(cli).await,
    }
}
