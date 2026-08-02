//! Give the `dalfox` binary a larger main-thread stack on Windows.
//!
//! Windows links executables with a 1 MiB default stack, where Linux and macOS
//! give the main thread 8 MiB. That is not enough for clap: the derive macro
//! expands the ~90 `scan` flags into a single `augment_args` function that
//! builds every `Arg` in one stack frame, so the frame grows with the CLI
//! surface and is paid on *every* invocation — `dalfox --version` included.
//!
//! Adding one flag (`--state-file`, #1275) pushed it over the edge: the
//! Windows binary began aborting at startup with "thread 'main' has overflowed
//! its stack" before parsing anything. Raising the reservation to 8 MiB makes
//! Windows match the platforms the tests normally run on, so the next flag
//! does not re-break it.
//!
//! This lives in `build.rs` rather than `.cargo/config.toml` deliberately:
//! config rustflags apply only to builds run from inside this workspace, so a
//! `cargo install dalfox` on Windows would still produce a binary that cannot
//! start. `build.rs` ships with the published crate.
//!
//! `rustc-link-arg-bins` targets the binary only — the library, its tests, and
//! every downstream consumer are untouched. The reservation is address space,
//! not committed memory: pages are only backed as the stack actually grows.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let target = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target != "windows" {
        return;
    }

    // 8 MiB, matching the Linux/macOS main-thread default.
    match std::env::var("CARGO_CFG_TARGET_ENV")
        .unwrap_or_default()
        .as_str()
    {
        // MSVC's linker takes reserve[,commit]; commit is left at the default
        // so the process still starts with a small committed stack.
        "msvc" => println!("cargo:rustc-link-arg-bins=/STACK:8388608"),
        // The GNU toolchain (`*-pc-windows-gnu`) goes through ld.
        _ => println!("cargo:rustc-link-arg-bins=-Wl,--stack,8388608"),
    }
}
