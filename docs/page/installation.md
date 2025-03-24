---
title: Installation
redirect_from: /docs/installation/
nav_order: 2
toc: true
layout: page
---

# Installation Guide

This guide provides detailed instructions on how to install Dalfox using various methods. Choose the method that best suits your environment and technical preferences.

## Using Homebrew

Homebrew is a popular package manager for macOS and Linux. If you're using a system with Homebrew available, this is the quickest and easiest way to install Dalfox.

### Install Homebrew

If you haven't installed Homebrew yet, you can install it by running the following command in your terminal:

```shell
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
```

### Install Dalfox

Once Homebrew is installed, you can install Dalfox with a single command:

```shell
brew install dalfox
```

After installation, verify it's working by running:

```shell
dalfox --version
```

For more details about the Dalfox Homebrew package, you can visit the [Homebrew Formula page for Dalfox](https://formulae.brew.sh/formula/dalfox).

## Using Snapcraft

Snapcraft is a package manager for Linux that works across many distributions. It provides containerized applications that run consistently regardless of the underlying system.

### Install Snapcraft

To install Snapcraft on your Linux distribution, please refer to the official documentation: [Installing snapd](https://snapcraft.io/docs/installing-snapd).

### Install Dalfox

Once Snapcraft is installed, you can install Dalfox by running:

```shell
sudo snap install dalfox
```

Verify the installation with:

```shell
dalfox --version
```

## From Source

Building from source gives you the most up-to-date version of Dalfox and allows for customization if needed.

### Prerequisites

Ensure you have Go (version 1.16 or later recommended) installed on your system. You can download it from the [official Go website](https://golang.org/dl/).

### Install Dalfox

To install the latest version of Dalfox from source, run:

```bash
go install github.com/hahwul/dalfox/v2@latest
```

Make sure your Go bin directory is in your PATH. If you haven't set it up, you can add the following to your shell configuration file (e.g., `.bashrc` or `.zshrc`):

```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

Note: The installed version might differ slightly from the latest release as `go install` references the main branch.

## Using Docker

Docker provides a consistent environment for running Dalfox without worrying about dependencies or system configurations. This is especially useful for CI/CD pipelines or isolated testing environments.

### Pull the Latest Docker Image

To pull the latest Docker image of Dalfox, run:

```bash
# From Docker Hub
docker pull hahwul/dalfox:latest

# Or from GitHub Container Registry
docker pull ghcr.io/hahwul/dalfox:latest
```

### Run Dalfox Using Docker

You can run Dalfox using Docker with the following command:

```bash
# Using Docker Hub image
docker run -it hahwul/dalfox:latest /app/dalfox url https://www.example.com

# Using GitHub Container Registry image
docker run -it ghcr.io/hahwul/dalfox:latest /app/dalfox url https://www.example.com
```

For scanning local files or directories, you'll need to mount them to the container:

```bash
docker run -it -v $(pwd):/data hahwul/dalfox:latest /app/dalfox file /data/targets.txt
```

### Interactive Docker Shell

For an interactive shell within the Docker container (useful for more complex operations):

```bash
# Using Docker Hub image
docker run -it hahwul/dalfox:latest /bin/bash

# Using GitHub Container Registry image
docker run -it ghcr.io/hahwul/dalfox:latest /bin/bash
```

Once inside the container, you can run Dalfox directly:

```bash
./dalfox --help
```

## Troubleshooting Common Installation Issues

If you encounter issues during installation, try the following:

1. **PATH Issues**: Ensure the installation directory is in your PATH
2. **Permission Errors**: Use `sudo` for commands that require elevated privileges
3. **Version Conflicts**: Check if you have multiple versions installed

For more help, please open an issue on the [Dalfox GitHub repository](https://github.com/hahwul/dalfox/issues).
