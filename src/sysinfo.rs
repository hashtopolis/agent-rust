//! OS and device inventory for registration / `updateInformation`.

use ::sysinfo::{CpuRefreshKind, RefreshKind, System};
use pci_ids::Device as PciId;
use pci_info::PciDevice;
use pci_info::PciInfo;
use pci_info::pci_enums::PciDeviceClass;

use crate::model::Os;

pub fn detect_os() -> Os {
    Os::detect()
}

pub fn hostname() -> String {
    gethostname::gethostname().to_string_lossy().into_owned()
}

pub fn collect_devices(configured: Option<&[String]>, cpu_only: bool) -> Vec<String> {
    if let Some(devices) = configured
        && !devices.is_empty()
    {
        tracing::info!(?devices, "using configured devices");

        return devices.to_vec();
    }

    let mut devices = collect_cpus();

    if !cpu_only {
        devices.extend(collect_gpus());
    }

    if devices.is_empty() {
        tracing::warn!("no devices detected");
    } else {
        tracing::info!(?devices, "collected devices");
    }

    devices
}

pub struct CpuSampler {
    system: System,
}

impl CpuSampler {
    pub fn new() -> Self {
        Self {
            system: System::new_with_specifics(
                RefreshKind::nothing().with_cpu(CpuRefreshKind::nothing().with_cpu_usage()),
            ),
        }
    }

    /// Global CPU utilisation as a percentage in `0.0..=100.0`, rounded to one
    /// decimal to match the reference agent.
    pub fn sample(&mut self) -> f64 {
        self.system.refresh_cpu_usage();

        let usage = self.system.global_cpu_usage() as f64;

        (usage * 10.0).round() / 10.0
    }
}

impl Default for CpuSampler {
    fn default() -> Self {
        Self::new()
    }
}

fn collect_cpus() -> Vec<String> {
    let system =
        System::new_with_specifics(RefreshKind::nothing().with_cpu(CpuRefreshKind::everything()));

    let mut brands: Vec<String> = system
        .cpus()
        .iter()
        .map(|cpu| cpu.brand().trim().to_owned())
        .filter(|brand| !brand.is_empty())
        .collect();

    brands.sort();
    brands.dedup();

    brands
}

fn collect_gpus() -> Vec<String> {
    let info = match PciInfo::enumerate_pci() {
        Ok(info) => info,

        Err(error) => {
            tracing::warn!(%error, "failed to enumerate PCI devices");

            return Vec::new();
        }
    };

    info.into_iter()
        .flatten()
        .filter(|device| matches!(device.device_class(), Ok(PciDeviceClass::DisplayController)))
        .filter_map(gpu_name)
        .collect()
}

fn gpu_name(device: PciDevice) -> Option<String> {
    let entry = PciId::from_vid_pid(device.vendor_id(), device.device_id())?;

    Some(format!("{} {}", entry.vendor().name(), entry.name()))
}

#[cfg(test)]
mod tests {
    use super::CpuSampler;

    #[test]
    fn cpu_sampler_reports_a_percentage() {
        let mut sampler = CpuSampler::new();

        // First read may be near zero (no prior delta); a second read after a
        // short wait exercises the real path. Either way the value is a valid
        // percentage.
        let _ = sampler.sample();
        std::thread::sleep(std::time::Duration::from_millis(250));
        let usage = sampler.sample();

        assert!(usage.is_finite());
        assert!(
            (0.0..=100.0).contains(&usage),
            "usage out of range: {usage}"
        );
        // Rounded to one decimal place.
        assert_eq!(usage, (usage * 10.0).round() / 10.0);
    }
}
