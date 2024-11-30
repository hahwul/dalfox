---
title: Update
redirect_from: /docs/update/
nav_order: 2
toc: true
layout: page
---

# Update Guide

This guide provides detailed instructions on how to update Dalfox using various methods. Choose the method that best suits your environment.

## Using Homebrew
If you installed Dalfox using Homebrew, you can easily update it with the following command:
```bash
brew upgrade dalfox
```
This command will upgrade Dalfox to the latest version available in the Homebrew repository.

## Using Snapcraft
If you installed Dalfox using Snapcraft, you can update it with the following command:
```bash
sudo snap refresh dalfox
```
This command will refresh the Dalfox snap to the latest version available in the Snapcraft store.

## Using Go
If you installed Dalfox from the source using Go, you can update it depending on your Go version.

### For Go 1.17 and Later
To update Dalfox, run:
```bash
go install github.com/hahwul/dalfox/v2@latest
```
This command will install the latest version of Dalfox from the source.

### For Go 1.16 and Earlier
To update Dalfox, run:
```bash
GO111MODULE=on go get github.com/hahwul/dalfox/v2
```
This command will fetch and install the latest version of Dalfox from the source.

## Using Docker
If you are using Dalfox with Docker, you can update it by pulling the latest Docker image:
```bash
docker pull hahwul/dalfox:latest
```
This command will download the latest Dalfox Docker image.

### Running the Updated Docker Image
After pulling the latest image, you can run Dalfox using the updated Docker image:
```bash
docker run -it hahwul/dalfox:latest /app/dalfox url https://www.hahwul.com
```

## Additional Resources
For more information and advanced usage, please refer to the [official Dalfox documentation](https://github.com/hahwul/dalfox).