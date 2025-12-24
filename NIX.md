# Nix Flake Support for Dalfox

This repository includes a Nix flake for reproducible builds and development environments.

## Prerequisites

You need Nix with flakes enabled. To enable flakes, add this to your Nix configuration:

```nix
# In ~/.config/nix/nix.conf or /etc/nix/nix.conf
experimental-features = nix-command flakes
```

Or use flakes temporarily:

```bash
nix --extra-experimental-features 'nix-command flakes' ...
```

## Usage

### Run Without Installing

```bash
nix run github:hahwul/dalfox -- scan https://example.com
```

### Install to Profile

```bash
nix profile install github:hahwul/dalfox
```

### Development Environment

Enter a development shell with all dependencies:

```bash
nix develop github:hahwul/dalfox
```

Or for local development:

```bash
git clone https://github.com/hahwul/dalfox.git
cd dalfox
nix develop
```

### With direnv

For automatic environment loading when entering the project directory:

```bash
# Install direnv: https://direnv.net/
cd dalfox
direnv allow
```

The `.envrc` file is already configured to use the flake.

## Building

Build the package locally:

```bash
nix build
```

The result will be in `./result/bin/dalfox`.

## What's Included

The flake provides:

- **Package**: Complete Dalfox build with all dependencies
- **Development Shell**: Rust toolchain, cargo tools (cargo-watch, cargo-edit), and just
- **App**: Direct execution via `nix run`

## Updating

To update the flake inputs:

```bash
nix flake update
```

## Troubleshooting

### Build fails with Cargo.lock issues

The flake uses the committed `Cargo.lock` file. If you update dependencies, make sure to commit the updated `Cargo.lock`.

### Missing system dependencies

The flake includes OpenSSL and macOS-specific frameworks. If you encounter missing dependencies, please open an issue.

## Contributing

When making changes that affect dependencies:

1. Update `Cargo.toml` and `Cargo.lock` as needed
2. Test the flake build: `nix build`
3. Test the development environment: `nix develop`
4. Commit all changes including `Cargo.lock`

See [CONTRIBUTING.md](CONTRIBUTING.md) for general contribution guidelines.
