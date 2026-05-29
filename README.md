<div align="center">
  <br>
  <img src="docs/static/images/logo.webp" alt="dalfox" width="400px;">
</div>
<p align="center">
  <a href="https://github.com/hahwul/dalfox/blob/main/CONTRIBUTING.md"><img src="https://img.shields.io/badge/CONTRIBUTIONS-WELCOME-30365e?style=for-the-badge&labelColor=%2330365e&color=%2330365e"></a>
  <a href="https://github.com/hahwul/dalfox/releases/latest"><img src="https://img.shields.io/github/v/release/hahwul/dalfox?style=for-the-badge&logoColor=%2330365e&label=dalfox&labelColor=%2330365e&color=%2330365e"></a>
  <a href="https://www.rust-lang.org"><img src="https://img.shields.io/badge/Rust-30365e?style=for-the-badge&logo=rust&logoColor=white&labelColor=%2330365e"></a>
</p>

> **Looking for the Go (v2.x) version?** Dalfox v3 is a complete rewrite in Rust. The Go codebase is preserved on the [`v2` branch](https://github.com/hahwul/dalfox/tree/v2) and continues to receive security backports. See [SECURITY.md](./SECURITY.md) for the support policy.

Dalfox is a powerful open-source tool that focuses on automation, making it ideal for quickly scanning for XSS flaws and analyzing parameters. Its advanced testing engine and niche features are designed to streamline the process of detecting and verifying vulnerabilities.

## Key features

* Subcommands: `scan` (URL / file / pipe / raw-HTTP, auto-detected), `server`, `payload`, `mcp`
* Discovery: Parameter analysis, static analysis, BAV testing, parameter mining
* XSS Scanning: Reflected, Stored (SXSS), DOM-based, with optimization and DOM/AST verification
* WAF: Fingerprinting with confidence scoring, bypass tracking, and tunable `--waf-min-confidence`
* HTTP Options: Custom headers, cookies, methods, proxy, and more
* Output: JSON/JSONL/Plain/Markdown/SARIF/TOML formats, silence mode, detailed reports
* Extensibility: REST API, MCP stdio server, custom payloads, remote wordlists

And the various options required for the testing :D

## Installation
### Homebrew (macOS/Linux)
```bash
brew install dalfox

# https://formulae.brew.sh/formula/dalfox
```

### Snapcraft (Ubuntu)
```bash
sudo snap install dalfox
```

### Arch Linux (AUR)

```bash
yay -S dalfox
# or
paru -S dalfox
```

See the [Installation guide](https://dalfox.hahwul.com/docs/installation/) for manual build instructions.

### Nixpkgs (NixOS)

A package is available for Nix or NixOS users. Keep in mind that the latest releases might only
be present in the `unstable` channel.

```bash
nix-shell -p dalfox
```

### Nix Flakes

For Nix users with flakes enabled:

```bash
# Run directly
nix run github:hahwul/dalfox -- scan https://example.com

# Install
nix profile install github:hahwul/dalfox

# Development environment
nix develop github:hahwul/dalfox
```

See [Installation guide](https://dalfox.hahwul.com/docs/installation/) for details.

Prebuilt binaries (including statically-linked musl variants for Linux) are available on the [GitHub Releases](https://github.com/hahwul/dalfox/releases) page.

## Usage
```bash
dalfox [mode] [target] [flags]
```

* Single URL: `dalfox scan http://example.com -b https://callback`
* File Mode: `dalfox scan urls.txt --custom-payload mypayloads.txt`
* Pipeline: `cat urls.txt | dalfox scan --headers "AuthToken: xxx"`

Check the [Usage](https://dalfox.hahwul.com/page/usage/) and [Running](https://dalfox.hahwul.com/page/running/) documents for more examples.

## Contributing
if you want to contribute to this project, please see [CONTRIBUTING.md](https://github.com/hahwul/dalfox/blob/main/CONTRIBUTING.md) and Pull-Request with cool your contents.

[![](docs/static/images/CONTRIBUTORS.svg)](https://github.com/hahwul/dalfox/graphs/contributors)

## About the Name
As for the name, Dal([달](https://en.wiktionary.org/wiki/달)) is the Korean word for "moon," while "Fox" stands for "Finder Of XSS" or 🦊

![](docs/images/illust.webp)
