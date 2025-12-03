+++
title = "Installation"
description = "How to install Dalfox on your system"
weight = 2
sort_by = "weight"

[extra]
+++

Dalfox can be installed using various package managers and methods. Choose the one that best fits your system and workflow.

## Cargo (Recommended for Latest Version)

Install Dalfox using Rust's package manager:

```bash
cargo install dalfox
```

This will compile and install the latest version from [crates.io](https://crates.io/crates/dalfox).

{% alert_info() %}
Make sure you have Rust installed. Visit [rustup.rs](https://rustup.rs/) to install Rust and Cargo.
{% end %}

## Homebrew (macOS/Linux)

For macOS and Linux users with Homebrew:

```bash
brew install dalfox
```

View the formula on [Homebrew Formulae](https://formulae.brew.sh/formula/dalfox).

## Snapcraft (Ubuntu/Linux)

Install via Snap on Ubuntu and other Linux distributions:

```bash
sudo snap install dalfox
```

## Nixpkgs (NixOS)

A package is available for Nix or NixOS users. Keep in mind that the latest releases might only be present in the `unstable` channel.

```bash
nix-shell -p dalfox
```

Or add to your NixOS configuration:

```nix
environment.systemPackages = with pkgs; [
  dalfox
];
```

## Docker

Run Dalfox using Docker without installation:

```bash
docker run --rm hahwul/dalfox:latest scan https://example.com
```

{% collapse(title="Docker Usage Examples") %}
**Scan a single URL:**
```bash
docker run --rm hahwul/dalfox:latest scan https://example.com -b https://callback.com
```

**Use a file with URLs:**
```bash
docker run --rm -v $(pwd):/app hahwul/dalfox:latest scan -i file /app/urls.txt
```

**Save output to a file:**
```bash
docker run --rm -v $(pwd):/output hahwul/dalfox:latest scan https://example.com -o /output/results.txt
```
{% end %}

## Build from Source

For developers or those who want the absolute latest code:

### Prerequisites
- Rust 1.75 or later
- Git

### Steps

1. Clone the repository:
```bash
git clone https://github.com/hahwul/dalfox.git
cd dalfox
```

2. Build the project:
```bash
cargo build --release
```

3. The binary will be available at `./target/release/dalfox`

4. (Optional) Install to your system:
```bash
cargo install --path .
```

## Verify Installation

After installation, verify that Dalfox is working correctly:

```bash
dalfox --version
```

You should see output similar to:
```
dalfox 3.0.0
```

## Next Steps

Now that you have Dalfox installed, check out the [Basic XSS Scanning](/usage_guides/basic_xss_scanning) guide to get started with your first scan.

## Troubleshooting

{% collapse(title="Cargo install fails with compilation error") %}
Make sure you have the latest version of Rust installed:
```bash
rustup update stable
```

If you're still experiencing issues, check the [GitHub Issues](https://github.com/hahwul/dalfox/issues) page.
{% end %}

{% collapse(title="Command not found after installation") %}
For Cargo installations, ensure `~/.cargo/bin` is in your PATH:
```bash
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

For other package managers, consult their documentation.
{% end %}

{% collapse(title="Docker permission denied") %}
If you get a permission denied error with Docker, either:
1. Run with `sudo`: `sudo docker run ...`
2. Add your user to the docker group: `sudo usermod -aG docker $USER`
{% end %}
