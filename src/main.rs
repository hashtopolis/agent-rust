use std::process::ExitCode;

use anyhow::{Context, Result, bail};

use htp_agent::agent::{Agent, Exit, deregister};
use htp_agent::backend::hashcat::AutoPipePolicy;
use htp_agent::cli::Cli;
use htp_agent::client::Client;
use htp_agent::config::{Config, Settings};
use htp_agent::download::HttpDownloader;
use htp_agent::http::HttpSettings;
use htp_agent::log::Verbosity;
use htp_agent::provisioner::DiskProvisioner;
use htp_agent::transport::HttpTransport;
use htp_agent::update::PendingRestart;

fn main() -> ExitCode {
    let cli = Cli::parse();

    let verbosity = match (cli.trace, cli.debug) {
        (true, _) => Verbosity::Trace,
        (false, true) => Verbosity::Debug,
        (false, false) => Verbosity::Normal,
    };

    // The log file is configured in the config file, so logging starts after
    // loading it. If that fails, a log file given on the command line still
    // records why.
    let config = Config::load(&cli.config, &cli.state, cli.overrides());

    let log_file = match &config {
        Ok(config) => config.settings().log.clone(),
        Err(_) => cli.log_file_from_flags(),
    };

    let log = match htp_agent::log::init(verbosity, log_file.as_ref()) {
        Ok(log) => log,
        Err(error) => {
            tracing::error!("agent exited: {error}");

            return ExitCode::FAILURE;
        }
    };

    let exit = config
        .map_err(anyhow::Error::from)
        .and_then(|config| run(&cli, config));

    match exit {
        Ok(Exit::Shutdown) => ExitCode::SUCCESS,
        Ok(Exit::Restart(update)) => {
            tracing::info!("restarting into the installed update");
            log.flush();

            match update.restart() {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    tracing::error!("agent exited: restarting into the update failed: {error:#}");

                    ExitCode::FAILURE
                }
            }
        }
        Err(error) => {
            tracing::error!("agent exited: {error:#}");

            ExitCode::FAILURE
        }
    }
}

/// Run the agent on its own runtime. The runtime is dropped before this
/// returns, which ends every task (and the crackers they started), so a restart
/// begins from a settled process.
fn run(cli: &Cli, config: Config) -> Result<Exit<PendingRestart>> {
    let runtime = tokio::runtime::Runtime::new().context("starting the async runtime")?;

    runtime.block_on(run_agent(cli, config))
}

async fn run_agent(cli: &Cli, config: Config) -> Result<Exit<PendingRestart>> {
    let url = config.require_url()?;
    let http = HttpSettings::from_server(&config.settings().server)?;

    if http.sends_credentials_in_clear(url) {
        tracing::warn!("server.url is plain http: basic auth credentials are sent unencrypted");
    }

    let transport = HttpTransport::new(url, &http).context("building the HTTP transport")?;

    if cli.de_register {
        let Some(token) = config.token() else {
            bail!("nothing to deregister: no token in the state file");
        };

        let client = Client::with_token(transport, token);
        deregister(&client, &config).await?;

        return Ok(Exit::Shutdown);
    }

    // No timeout here: downloads may stream for many minutes.
    let downloader = {
        let client = http
            .client_builder()
            .build()
            .context("building the download client")?;

        HttpDownloader::new(client, transport.url()).with_auth(http.auth().cloned())
    };

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

    Ok(agent.run().await?)
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
