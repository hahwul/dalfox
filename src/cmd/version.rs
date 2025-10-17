use clap::Args;

/// Show the current dalfox version (same as `dalfox -V`)
#[derive(Args, Debug, Clone, Default)]
pub struct VersionArgs {}

/// Print the current version to stdout.
/// This uses the Cargo package version embedded at compile time.
pub fn run_version(_: VersionArgs) {
    // Keep output simple to ease scripting: just the version string
    // Example: 3.0.0
    println!("{}", env!("CARGO_PKG_VERSION"));
}
