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

```bash
nix-shell -p dalfox
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

See [Basic XSS Scanning](/usage_guides/basic_xss_scanning) to start scanning.
