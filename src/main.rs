use std::fmt;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};

use htp_agent::agent::{Agent, Exit, deregister};
use htp_agent::backend::hashcat::AutoPipePolicy;
use htp_agent::banner::Banner;
use htp_agent::cli::Cli;
use htp_agent::client::Client;
use htp_agent::config::{Config, Settings, Verbosity};
use htp_agent::download::HttpDownloader;
use htp_agent::http::HttpSettings;
use htp_agent::log::RawPrinter;
use htp_agent::provisioner::DiskProvisioner;
use htp_agent::schedule::{ActiveHours, ScheduleFile};
use htp_agent::transport::HttpTransport;
use htp_agent::update::PendingRestart;
use jiff::Timestamp;
use jiff::tz::TimeZone;

fn main() -> ExitCode {
    let cli = Cli::parse();

    let verbosity = match (cli.trace, cli.debug) {
        (true, _) => Verbosity::Trace,
        (false, true) => Verbosity::Debug,
        (false, false) => Verbosity::Normal,
    };

    // The config names the log file, so logging starts after loading it. If
    // that fails, a `--log-file` still records why.
    let config = Config::load(&cli.config, &cli.state, cli.overrides());

    let log_file = match &config {
        Ok(config) => config.settings().log.clone(),
        Err(_) => cli.log_file_from_flags(),
    };

    let (printer, log) = match htp_agent::log::init(verbosity, log_file.as_ref()) {
        Ok(handles) => handles,
        Err(error) => return failed(error),
    };

    let config = match config {
        Ok(config) => config,
        Err(error) => return failed(error),
    };

    match run(&cli, config, &printer) {
        Ok(Exit::Shutdown) => ExitCode::SUCCESS,
        Ok(Exit::Restart(update)) => {
            tracing::info!("restarting into the installed update");
            log.flush();

            match update.restart() {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => failed(format_args!("restarting into the update failed: {error}")),
            }
        }
        Err(error) => failed(format_args!("{error:#}")),
    }
}

fn failed(reason: impl fmt::Display) -> ExitCode {
    tracing::error!("agent exited: {reason}");

    ExitCode::FAILURE
}

/// Run the agent on its own runtime. The runtime is dropped before this
/// returns, which ends every task (and the crackers they started), so a restart
/// begins from a settled process.
#[tokio::main]
async fn run(cli: &Cli, config: Config, printer: &RawPrinter) -> Result<Exit<PendingRestart>> {
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

    log_time_zone();

    let active_hours = {
        let file = ScheduleFile::load(config.schedule_file_path());

        if file.schedule().is_some() {
            tracing::info!(path = %file.path().display(), "active hours loaded");
        } else {
            tracing::debug!(path = %file.path().display(), "no active hours");
        }

        ActiveHours::new(file)
    };

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

    let config_path = std::path::absolute(&cli.config).unwrap_or_else(|_| cli.config.clone());

    printer.print(Banner {
        settings: config.settings(),
        config_path: &config_path,
    });

    let mut agent = Agent::bootstrap(transport, config, provisioner)
        .await?
        .with_active_hours(active_hours);

    Ok(agent.run().await?)
}

/// Without a system time zone, jiff falls back to one that behaves like UTC, and
/// only says so through the `log` crate, which goes nowhere.
fn log_time_zone() {
    match TimeZone::try_system() {
        Ok(zone) => {
            let time_zone = zone.iana_name().map_or_else(
                || format!("UTC{}", zone.to_offset(Timestamp::now())),
                str::to_string,
            );

            tracing::info!(time_zone, "system time zone");
        }
        // jiff's error doesn't name the value it failed to resolve.
        Err(error) => match std::env::var("TZ") {
            Ok(tz) => tracing::info!(tz, %error, "system time zone unknown, using UTC"),
            Err(_) => tracing::info!(%error, "system time zone unknown, using UTC"),
        },
    }
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
