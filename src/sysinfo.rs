//! OS and device inventory for registration / `updateInformation`.

use crate::model::Os;

pub fn detect_os() -> Os {
    Os::detect()
}

pub fn hostname() -> String {
    gethostname::gethostname().to_string_lossy().into_owned()
}

pub fn collect_devices(configured: Option<&[String]>, _cpu_only: bool) -> Vec<String> {
    match configured {
        Some(devices) if !devices.is_empty() => devices.to_vec(),
        _ => {
            tracing::warn!("no device inventory configured; reporting an empty list");

            Vec::new()
        }
    }
}
