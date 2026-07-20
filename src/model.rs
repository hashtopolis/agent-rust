use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "u8", try_from = "u8")]
pub enum Os {
    Linux,
    Windows,
    Darwin,
}

impl Os {
    pub const fn code(self) -> u8 {
        match self {
            Os::Linux => 0,
            Os::Windows => 1,
            Os::Darwin => 2,
        }
    }

    pub const fn binary_extension(self) -> &'static str {
        match self {
            Os::Windows => ".exe",
            Os::Linux | Os::Darwin => "",
        }
    }

    pub const fn detect() -> Option<Self> {
        if cfg!(target_os = "linux") {
            Some(Os::Linux)
        } else if cfg!(target_os = "windows") {
            Some(Os::Windows)
        } else if cfg!(target_os = "macos") {
            Some(Os::Darwin)
        } else {
            None
        }
    }
}

impl From<Os> for u8 {
    fn from(os: Os) -> u8 {
        os.code()
    }
}

impl TryFrom<u8> for Os {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Os::Linux),
            1 => Ok(Os::Windows),
            2 => Ok(Os::Darwin),
            other => Err(format!("unknown OS code: {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BenchmarkType {
    Speed,
    Run,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskId {
    None,
    HealthCheck,
    Id(u64),
}

impl TaskId {
    pub const HEALTH_CHECK: i64 = -1;

    pub fn from_raw(raw: Option<i64>) -> Self {
        match raw {
            None => TaskId::None,
            Some(Self::HEALTH_CHECK) => TaskId::HealthCheck,
            Some(id) if id >= 0 => TaskId::Id(id as u64),
            Some(_) => TaskId::None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chunk {
    pub id: u64,
    pub skip: u64,
    pub length: u64,
}
