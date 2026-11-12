//! The startup banner: five lines that mark each start in the log, including
//! the restart after a self-update, with the version and the settings worth
//! knowing at a glance.

use std::fmt;
use std::path::Path;

use reqwest::Url;

use crate::config::Settings;
use crate::identity::{agent_target, agent_version};
use crate::sysinfo;

const ART: [&str; 5] = [
    r" _   _        ",
    r"| |_| |_ _ __ ",
    r"| ' \  _| '_ \",
    r"|_||_\__| .__/",
    r"        |_|   ",
];

pub struct Banner<'a> {
    pub settings: &'a Settings,
    pub config_path: &'a Path,
}

impl fmt::Display for Banner<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let settings = self.settings;
        let behavior = &settings.behavior;

        let server = settings
            .server
            .url
            .as_deref()
            .map_or_else(String::new, without_credentials);
        let name = settings
            .agent
            .name
            .clone()
            .unwrap_or_else(sysinfo::hostname);

        let info = [
            format!("hashtopolis agent {} ({})", agent_version(), agent_target()),
            format!("server  {server}"),
            format!("name    {name}"),
            format!(
                "flags   update {}, cpu-only {}, piping {}",
                on_off(!behavior.disable_update),
                on_off(behavior.cpu_only),
                on_off(behavior.allow_piping),
            ),
            format!("config  {}", self.config_path.display()),
        ];

        for (art, info) in ART.iter().zip(info) {
            writeln!(f, "{art}   {info}")?;
        }

        Ok(())
    }
}

/// The server url without any user or password, which the banner must never
/// print. An unparsable url is not shown at all, since it cannot be stripped.
fn without_credentials(raw: &str) -> String {
    let Ok(mut url) = Url::parse(raw) else {
        return "<invalid url>".to_string();
    };

    let _ = url.set_username("");
    let _ = url.set_password(None);

    url.to_string()
}

fn on_off(enabled: bool) -> &'static str {
    if enabled { "on" } else { "off" }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> Settings {
        let mut settings = Settings::default();
        settings.server.url = Some("https://example.com/api/server.php".to_string());
        settings.agent.name = Some("cruncher".to_string());

        settings
    }

    #[test]
    fn renders_the_art_beside_version_and_settings() {
        let mut settings = settings();
        settings.behavior.disable_update = true;
        settings.behavior.allow_piping = true;

        let banner = Banner {
            settings: &settings,
            config_path: Path::new("/opt/agent/config.json"),
        };

        let expected = format!(
            concat!(
                " _   _           hashtopolis agent {} ({})\n",
                "| |_| |_ _ __    server  https://example.com/api/server.php\n",
                "| ' \\  _| '_ \\   name    cruncher\n",
                "|_||_\\__| .__/   flags   update off, cpu-only off, piping on\n",
                "        |_|      config  /opt/agent/config.json\n",
            ),
            agent_version(),
            agent_target(),
        );

        assert_eq!(banner.to_string(), expected);
    }

    #[test]
    fn hides_credentials_in_the_server_url() {
        let mut settings = settings();
        settings.server.url = Some("https://user:secret@example.com/api/server.php".to_string());

        let banner = Banner {
            settings: &settings,
            config_path: Path::new("config.json"),
        };

        let rendered = banner.to_string();

        assert!(rendered.contains("server  https://example.com/api/server.php"));
        assert!(!rendered.contains("user"));
        assert!(!rendered.contains("secret"));
    }
}
