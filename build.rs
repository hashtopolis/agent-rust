use std::env;

fn main() {
    // Expose the target triple this binary is compiled for so the agent can
    // report it on registration and pick the matching binary on self-update.
    // `TARGET` is only set for build scripts, so we forward it as a regular
    // compile-time env var readable via `env!("TARGET_TRIPLE")`.
    let target = env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=TARGET_TRIPLE={target}");
}
