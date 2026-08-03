use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use tracing_subscriber::EnvFilter;

use htp_agent::agent::{Agent, deregister};
use htp_agent::cli::Cli;
use htp_agent::client::Client;
use htp_agent::config::Config;
use htp_agent::download::HttpDownloader;
use htp_agent::provisioner::DiskProvisioner;
use htp_agent::transport::HttpTransport;

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

    let url = config.require_url()?;
    let transport = HttpTransport::new(url).context("building the HTTP transport")?;

    if cli.de_register {
        let Some(token) = config.token() else {
            bail!("nothing to deregister: no token in the state file");
        };

        let client = Client::with_token(transport, token);
        deregister(&client, &config).await?;

        return Ok(());
    }

    let downloader = HttpDownloader::new(reqwest::Client::new(), transport.url());
    let provisioner = DiskProvisioner::new(config.settings().paths.clone(), downloader);

    let mut agent = Agent::bootstrap(transport, config, provisioner).await?;
    agent.run().await?;

    Ok(())
}
