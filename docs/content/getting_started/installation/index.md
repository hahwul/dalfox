+++
title = "Installation"
description = "How to install Dalfox on your system"
weight = 2
sort_by = "weight"

[extra]
+++

## Cargo (Recommended)

```bash
cargo install dalfox
```

{% alert_info() %}
Requires Rust. Install from [rustup.rs](https://rustup.rs/)
{% end %}

## Homebrew

```bash
brew install dalfox
```

## Snap

```bash
sudo snap install dalfox
```

## Nix

### Using Nixpkgs

```bash
nix-shell -p dalfox
```

### Using Nix Flakes

```bash
# Install from the repository
nix profile install github:hahwul/dalfox

# Or run directly without installing
nix run github:hahwul/dalfox -- scan https://example.com

# Development environment
nix develop github:hahwul/dalfox
```

For local development with flakes:
```bash
# Clone the repository
git clone https://github.com/hahwul/dalfox.git
cd dalfox

# Enter development shell
nix develop

# Or use direnv for automatic environment loading
echo "use flake" > .envrc
direnv allow
```

## Docker

```bash
docker run --rm hahwul/dalfox:latest scan https://example.com
```

Mount volumes for files:
```bash
docker run --rm -v $(pwd):/app hahwul/dalfox:latest scan -i file /app/urls.txt -o /app/results.txt
```

## Build from Source

```bash
git clone https://github.com/hahwul/dalfox.git
cd dalfox
cargo build --release
# Binary at ./target/release/dalfox
```

Install to system:
```bash
cargo install --path .
```

## Verify

```bash
dalfox --version
```

## Next Steps

See the [Quick Start Guide](/getting_started/quick_start) to perform your first scan, or explore [Commands](/usage/commands) to learn about all available features.
