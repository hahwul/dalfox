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

The project's own tap builds the same release and also installs the man page and shell completions:

```bash
brew install hahwul/dalfox/dalfox
```

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
```

Dalfox lives in nixpkgs. The newest releases land in `unstable` first, so the flake above is ahead of `nixpkgs` between releases.

The flake builds for `x86_64-linux`, `aarch64-linux` and `aarch64-darwin`. Intel macOS is not among them because nixpkgs `unstable` dropped `x86_64-darwin` — use the `macos-x86_64` release archive below instead.

To build Dalfox against your own `nixpkgs` instead of the one this flake pins, use the overlay. In your system flake:

```nix
# flake.nix
{
  inputs.dalfox.url = "github:hahwul/dalfox";

  outputs = { self, nixpkgs, dalfox, ... }@inputs: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      specialArgs = { inherit inputs; };
      modules = [ ./configuration.nix ];
    };
  };
}
```

Then, in a module that receives `inputs`:

```nix
# configuration.nix
{ pkgs, inputs, ... }:
{
  nixpkgs.overlays = [ inputs.dalfox.overlays.default ];
  environment.systemPackages = [ pkgs.dalfox ];
}
```

The flake also exposes a development shell for working on Dalfox itself — the Rust toolchain, [`just`](https://github.com/casey/just) and the Crystal runtime the test harnesses need, but not the `dalfox` binary:

```bash
git clone https://github.com/hahwul/dalfox && cd dalfox
nix develop
```

With [direnv](https://direnv.net) installed, `direnv allow` picks the same shell up automatically from the repo's `.envrc`.

## Docker

Multi-arch images (`linux/amd64`, `linux/arm64`) are published to Docker Hub and GitHub Container Registry. The binary sits at `/app/dalfox` and the image has no entrypoint, so name it in the command:

```bash
docker run --rm hahwul/dalfox:latest ./dalfox scan https://example.com

# or from GHCR
docker run --rm ghcr.io/hahwul/dalfox:latest ./dalfox scan https://example.com
```

Release tags are available as `v3.2.3` (plus `v3.2` and `v3` on Docker Hub). `ghcr.io/hahwul/dalfox:main` tracks the `main` branch.

## Cargo (from crates.io)

```bash
cargo install dalfox
```

Requires Rust 1.93 or newer (the crate's `rust-version`). Builds into `~/.cargo/bin/dalfox`.

## Prebuilt binaries

Grab a release archive for your OS/arch from [github.com/hahwul/dalfox/releases](https://github.com/hahwul/dalfox/releases), extract it, and drop the binary somewhere on your `PATH` (`/usr/local/bin`, `~/.local/bin`, etc.).

We publish the following per release:

- `macos-x86_64`, `macos-aarch64`
- `linux-x86_64` (glibc), `linux-x86_64-musl` (statically linked, recommended for Alpine, Docker, and CI)
- `linux-aarch64` (glibc), `linux-aarch64-musl` (statically linked)
- `windows-x86_64`

Archives are named `dalfox-v<version>-<platform>`: `.tar.gz` on macOS and Linux, `.zip` on Windows. Linux also gets `.deb` and `.rpm` packages for both architectures, every archive and package ships with a `.sha256` alongside a combined `checksum.txt`, and each release carries a CycloneDX SBOM (`dalfox.cdx.xml`).

## Build from source

```bash
git clone https://github.com/hahwul/dalfox
cd dalfox
cargo build --release
# Binary at ./target/release/dalfox
```

You'll need Rust 1.93 or newer (2024 edition). Install with [rustup](https://rustup.rs/) if you don't have it.

## Verify

```bash
dalfox --version
```

You should see a single line such as `dalfox 3.2.3`.

## Shell completions

The `hahwul/dalfox` Homebrew tap, the AUR package, the `.deb` / `.rpm` packages and the Nix flake install bash, zsh and fish completions (and the `dalfox(1)` man page) for you — nothing else to do.

Installed another way (the core `brew install dalfox` formula, Snap, Docker, Cargo, a release archive, a source build)? Generate them yourself:

```bash
dalfox completion bash > /etc/bash_completion.d/dalfox
dalfox completion zsh > "${fpath[1]}/_dalfox"
dalfox completion fish > ~/.config/fish/completions/dalfox.fish
```

`powershell` and `elvish` are supported too — see the [CLI reference](../../reference/cli/).

## Getting help

Dalfox uses [clap](https://github.com/clap-rs/clap), so help is always accessible:

```bash
dalfox --help
dalfox scan --help
```

## Next steps

Run your first scan in the [Quick Start](../quick-start/). If you want to tune defaults before scanning, jump to [Configuration](../configuration/).
