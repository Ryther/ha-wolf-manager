use clap::Parser;
fn main() {
    if wolf_manager_host::cli::run(wolf_manager_host::cli::Cli::parse()).is_err() {
        eprintln!("Host operation refused or incomplete; inspect the retained recovery records.");
        std::process::exit(1);
    }
}
