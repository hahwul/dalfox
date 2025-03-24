<div align="center">
  <br>
  <img src="docs/images/logo.png" alt="dalfox" width="400px;">
</div>
<p align="center">
  <a href="https://github.com/hahwul/dalfox/releases/latest"><img src="https://img.shields.io/github/v/release/hahwul/dalfox?style=for-the-badge&logoColor=%2330365e&label=dalfox&labelColor=%2330365e&color=%2330365e"></a>
  <a href="https://dalfox.hahwul.com/page/overview/"><img src="https://img.shields.io/badge/documents---.svg?style=for-the-badge&labelColor=%2330365e&color=%2330365e"></a>
  <a href="https://x.com/intent/follow?screen_name=hahwul"><img src="https://img.shields.io/twitter/follow/hahwul?style=for-the-badge&logo=x&labelColor=%2330365e&color=%2330365e"></a>
  <a href="https://github.com/hahwul/dalfox/blob/main/CONTRIBUTING.md"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=for-the-badge&labelColor=%2330365e&color=%2330365e"></a>
</p>

Dalfox is a powerful open-source tool that focuses on automation, making it ideal for quickly scanning for XSS flaws and analyzing parameters. Its advanced testing engine and niche features are designed to streamline the process of detecting and verifying vulnerabilities.

## Key features

* Modes: `URL`, `SXSS`, `Pipe`, `File`, `Server`, `Payload`
* Discovery: Parameter analysis, static analysis, BAV testing, parameter mining
* XSS Scanning: Reflected, Stored, DOM-based, with optimization and DOM/headless verification
* HTTP Options: Custom headers, cookies, methods, proxy, and more
* Output: JSON/Plain formats, silence mode, detailed reports
* Extensibility: REST API, custom payloads, remote wordlists

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

### From Source

```bash
go install github.com/hahwul/dalfox/v2@latest
```

See [Installation guide](https://dalfox.hahwul.com/docs/installation/) for details.

## Usage
```bash
dalfox [mode] [target] [flags] 
```

* Single URL: `dalfox url http://example.com -b https://callback`
* File Mode: `dalfox file urls.txt --custom-payload mypayloads.txt`
* Pipeline: `cat urls.txt | dalfox pipe -H "AuthToken: xxx"`

Check the [Usage](https://dalfox.hahwul.com/page/usage/) and [Running](https://dalfox.hahwul.com/page/running/) documents for more examples.

## Contributing
if you want to contribute to this project, please see [CONTRIBUTING.md](https://github.com/hahwul/dalfox/blob/main/CONTRIBUTING.md) and Pull-Request with cool your contents.

[![](/CONTRIBUTORS.svg)](https://github.com/hahwul/dalfox/graphs/contributors)

## About the Name
As for the name, Dal([달](https://en.wiktionary.org/wiki/달)) is the Korean word for "moon," while "Fox" stands for "Finder Of XSS" or 🦊

![](docs/images/illust.jpg)
