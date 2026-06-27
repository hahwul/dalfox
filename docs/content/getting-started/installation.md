+++
title = "Installation"
description = "Install Dalfox on macOS, Linux, Windows, NixOS, Arch Linux, or build from source."
weight = 2
toc = true
+++

Pick the installer that fits your platform. Dalfox ships as a single self-contained binary, with no runtime to manage.

## Homebrew (macOS & Linux)

```bash
brew install dalfox
```

The Homebrew formula tracks the latest stable release. Source: [formulae.brew.sh/formula/dalfox](https://formulae.brew.sh/formula/dalfox).

## Snap (Ubuntu / Linux)

```bash
sudo snap install dalfox
```

## Arch Linux (AUR)

Using an AUR helper (recommended):

```bash
yay -S dalfox
# or
paru -S dalfox
```

Manual build from the [AUR package](https://aur.archlinux.org/packages/dalfox):

```bash
git clone https://aur.archlinux.org/dalfox.git
cd dalfox
makepkg -si
```

## Nix & NixOS

```bash
# Run once without installing
nix-shell -p dalfox

# Nix flakes: run the latest from GitHub
nix run github:hahwul/dalfox -- scan https://example.com

# Install into your profile
nix profile install github:hahwul/dalfox

# Drop into a dev shell with Dalfox available
nix develop github:hahwul/dalfox
```

Dalfox lives in nixpkgs. The newest releases land in `unstable` first.

## Cargo (from crates.io)

```bash
cargo install dalfox
```

Requires a recent Rust toolchain (stable is fine). Builds into `~/.cargo/bin/dalfox`.

## Prebuilt binaries

Grab a release archive for your OS/arch from [github.com/hahwul/dalfox/releases](https://github.com/hahwul/dalfox/releases), extract it, and drop the binary somewhere on your `PATH` (`/usr/local/bin`, `~/.local/bin`, etc.).

We publish the following Linux variants per release:

- `linux-x86_64` (glibc)
- `linux-x86_64-musl` (statically linked, recommended for Alpine, Docker, and CI)
- `linux-aarch64` (glibc)
- `linux-aarch64-musl` (statically linked)

## Build from source

```bash
git clone https://github.com/hahwul/dalfox
cd dalfox
cargo build --release
# Binary at ./target/release/dalfox
```

You'll need Rust (2024 edition). Install with [rustup](https://rustup.rs/) if you don't have it.

## Verify

```bash
dalfox --version
```

You should see something like `dalfox 3.1.2` along with the Dalfox banner.

## Update shell completions (optional)

Dalfox uses [clap](https://github.com/clap-rs/clap), so help is always accessible:

```bash
dalfox --help
dalfox scan --help
```

## Next steps

Run your first scan in the [Quick Start](../quick-start/). If you want to tune defaults before scanning, jump to [Configuration](../configuration/).
