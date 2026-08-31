use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use tracing_subscriber::EnvFilter;

use htp_agent::agent::deregister;
use htp_agent::cli::Cli;
use htp_agent::client::Client;
use htp_agent::config::Config;
use htp_agent::runtime::HttpRuntimeFactory;
use htp_agent::supervisor::Supervisor;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    init_logging(cli.debug);

    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!("agent exited: {error:#}");

            ExitCode::FAILURE
        }
    }
}

fn init_logging(debug: bool) {
    let default_level = if debug { "debug" } else { "info" };

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| default_level.into()))
        .init();
}

async fn run(cli: Cli) -> Result<()> {
    let config = Config::load(&cli.config, &cli.state, cli.overrides())?;
    let factory = HttpRuntimeFactory;

    if cli.de_register {
        let transport = factory
            .build_transport(&config)
            .context("building the HTTP transport")?;
        let Some(token) = config.token() else {
            bail!("nothing to deregister: no token in the state file");
        };

        let client = Client::with_token(transport, token);
        deregister(&client, &config).await?;

        return Ok(());
    }

    let mut supervisor = Supervisor::bootstrap(factory, config).await?;
    supervisor.run().await?;

    Ok(())
}
