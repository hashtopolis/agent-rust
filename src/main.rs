use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use tracing_subscriber::EnvFilter;

use htp_agent::agent::{Agent, deregister};
use htp_agent::backend::hashcat::AutoPipePolicy;
use htp_agent::cli::Cli;
use htp_agent::client::Client;
use htp_agent::config::{Config, Settings};
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

    let provisioner = {
        let settings = config.settings();

        let ProvisionerSettings {
            hashcat_path,
            auto_pipe,
            rsync_mount,
        } = read_settings(settings);

        DiskProvisioner::builder(settings.paths.clone(), downloader)
            .hashcat_fallback(hashcat_path)
            .auto_pipe(auto_pipe)
            .rsync_mount(rsync_mount)
            .build()
    };

    let mut agent = Agent::bootstrap(transport, config, provisioner).await?;
    agent.run().await?;

    Ok(())
}

struct ProvisionerSettings {
    hashcat_path: Option<std::path::PathBuf>,
    auto_pipe: Option<AutoPipePolicy>,
    rsync_mount: Option<std::path::PathBuf>,
}

fn read_settings(settings: &Settings) -> ProvisionerSettings {
    let hashcat_path = settings.cracker.hashcat_path.clone();

    if hashcat_path.is_some() && !cfg!(target_os = "macos") {
        tracing::warn!("hashcat_path is only used on macOS; ignoring it on this platform");
    }

    let auto_pipe = settings.behavior.allow_piping.then_some(AutoPipePolicy {
        util_threshold: settings.behavior.piping_threshold,
    });

    let rsync_mount = if settings.behavior.rsync {
        settings.behavior.rsync_path.clone()
    } else {
        None
    };

    ProvisionerSettings {
        hashcat_path,
        auto_pipe,
        rsync_mount,
    }
}
