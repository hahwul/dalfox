---
title: Installation
redirect_from: /docs/installation/
nav_order: 2
toc: true
layout: page
---

# Installation Guide

This guide provides detailed instructions on how to install Dalfox using various methods. Choose the method that best suits your environment.

## Using Homebrew
Homebrew is a package manager for macOS (or Linux). On devices using Homebrew, you can easily install or update Dalfox using the `brew` command.

### Install Homebrew
If you haven't installed Homebrew yet, you can install it by running the following command in your terminal:
```shell
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
```

### Install Dalfox
Once Homebrew is installed, you can install Dalfox by running:
```shell
brew install dalfox
```
For more details, you can visit the [Homebrew Formula page for Dalfox](https://formulae.brew.sh/formula/dalfox).

## Using Snapcraft
Snapcraft is a package manager for Linux. Unlike `apt` and `yum`, it can be used independently of the deployment OS version.

### Install Snapcraft
To install Snapcraft, please refer to the official documentation: [Installing snapd](https://snapcraft.io/docs/installing-snapd).

### Install Dalfox
Once Snapcraft is installed, you can install Dalfox by running:
```shell
sudo snap install dalfox
```

## From Source
If you prefer to build Dalfox from the source, you can do so using the `go` command.

### Prerequisites
Ensure you have Go installed on your system. You can download it from the [official Go website](https://golang.org/dl/).

### Install Dalfox
To install the latest version of Dalfox from the source, run:
```bash
go install github.com/hahwul/dalfox/v2@latest
```
Note: The actual release might slightly differ as `go install` references the main branch.

## Using Docker
Dalfox provides Docker images by version. This method allows you to use Dalfox with minimal setup.

### Pull the Latest Docker Image
To pull the latest Docker image of Dalfox, run:
```bash
docker pull hahwul/dalfox:latest
```

### Run Dalfox Using Docker
You can run Dalfox using Docker with the following command:
```bash
docker run -it hahwul/dalfox:latest /app/dalfox url https://www.hahwul.com
```

### Interactive Docker Shell
For an interactive shell within the Docker container, run:
```bash
docker run -it hahwul/dalfox:latest /bin/bash
```
Once inside the container, you can run Dalfox:
```bash
./dalfox
```
