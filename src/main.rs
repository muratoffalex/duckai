mod client;
mod config;
mod error;
mod model;
mod route;
mod serve;

use argh::FromArgs;
pub use error::Error;
use std::path::PathBuf;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(FromArgs)]
/// Duckai
struct Opt {
    /// run command
    #[argh(subcommand)]
    pub commands: Commands,
}

#[derive(FromArgs, Debug)]
/// Commands for duckai
#[argh(subcommand)]
pub enum Commands {
    /// Run server
    Run(RunCommand),
    /// Generate config template file (yaml format file)
    GT(GTCommand),
}

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "run")]
/// Arguments for run command
pub struct RunCommand {
    /// configuration filepath
    #[argh(positional, default = "PathBuf::from(\"duckai.yaml\")")]
    pub config_path: PathBuf,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "gt")]
/// Arguments for GT command
pub struct GTCommand {
    /// configuration filepath
    #[argh(positional, default = "PathBuf::from(\"duckai.yaml\")")]
    pub config_path: PathBuf,
}

fn main() -> Result<()> {
    let opt: Opt = argh::from_env();
    match opt.commands {
        Commands::Run(args) => serve::run(args.config_path),
        Commands::GT(args) => config::generate_template(args.config_path),
    }
}
