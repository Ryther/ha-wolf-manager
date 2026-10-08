use clap::Parser;
use ha_wolf_manager::{
    api::now,
    runtime::{Cli, Command, read_secret, serve},
};
#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let result = match &cli.command {
        Some(Command::Healthcheck) => ha_wolf_manager::health::healthcheck(&cli.data),
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
            .unwrap_or_else(|_| Err(wolf_core::SafeError::new("internal_error")))
        }
        None => serve(cli).await,
    };
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
