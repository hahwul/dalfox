---
title: Update
redirect_from: /docs/update/
nav_order: 2
toc: true
layout: page
---

# Keeping Dalfox Updated

## Why Update Dalfox?

Regularly updating Dalfox provides several important benefits:

- **New Features**: Access to the latest scanning capabilities and improvements
- **Security Fixes**: Protection against vulnerabilities in the tool itself
- **Bug Fixes**: Elimination of known issues from previous versions
- **Performance Improvements**: Better scanning efficiency and reduced resource usage
- **New Payload Patterns**: Enhanced detection of the latest XSS techniques and bypasses

This guide provides detailed instructions on how to update Dalfox using various installation methods.

## Version Information

Before updating, you may want to check your current version and compare it with the latest release:

```bash
# Check your current Dalfox version
dalfox version

# Compare with the latest GitHub release
curl -s https://api.github.com/repos/hahwul/dalfox/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/'
```

## Update Methods

### Using Homebrew

If you installed Dalfox using Homebrew on macOS or Linux, updating is straightforward:

```bash
# Update Homebrew's formula list
brew update

# Upgrade Dalfox to the latest version
brew upgrade dalfox
```

After upgrading, verify the new version:

```bash
dalfox version
```

### Using Snapcraft

For Linux systems using Snap packages, update Dalfox with:

```bash
# Update Dalfox snap package
sudo snap refresh dalfox
```

Verify the update:

```bash
dalfox version
```

### Using Go Install

If you installed Dalfox from source using Go, you can update it with the `go install` command:

```bash
# Install the latest version
go install github.com/hahwul/dalfox/v2@latest
```

If you encounter any issues, try clearing the module cache first:

```bash
# Clear the module cache (optional)
go clean -modcache

# Install the latest version
go install github.com/hahwul/dalfox/v2@latest
```

Verify that your PATH includes Go's bin directory:

```bash
# Check if the Go bin directory is in your PATH
echo $PATH | grep -q "$(go env GOPATH)/bin" && echo "Go bin is in PATH" || echo "Go bin is NOT in PATH"

# If missing, add it to your PATH (for bash/zsh)
echo 'export PATH=$PATH:'"$(go env GOPATH)/bin" >> ~/.bashrc
source ~/.bashrc
```

### Using Docker

If you're using Dalfox with Docker, update by pulling the latest image:

```bash
# Update from Docker Hub
docker pull hahwul/dalfox:latest

# OR update from GitHub Container Registry
docker pull ghcr.io/hahwul/dalfox:latest
```

To verify you have the latest version:

```bash
# Check Docker image version
docker run --rm hahwul/dalfox:latest /app/dalfox version
```

#### Running the Updated Docker Image

After pulling the latest image, run Dalfox using the updated container:

```bash
# Run with Docker Hub image
docker run -it hahwul/dalfox:latest /app/dalfox url https://example.com

# OR run with GitHub Container Registry image
docker run -it ghcr.io/hahwul/dalfox:latest /app/dalfox url https://example.com
```

For persistent storage of results, mount a volume:

```bash
docker run -it -v "$(pwd):/output" hahwul/dalfox:latest /app/dalfox url https://example.com -o /output/results.txt
```

## Updating to a Specific Version

If you need to use a specific version of Dalfox rather than the latest:

### Using Go

```bash
# Install a specific version (e.g., v2.8.0)
go install github.com/hahwul/dalfox/v2@v2.8.0
```

### Using Docker

```bash
# Pull a specific version (e.g., v2.8.0)
docker pull hahwul/dalfox:v2.8.0
```

## Post-Update Steps

After updating Dalfox, consider taking these additional steps:

1. **Review new features**: Check the [release notes](https://github.com/hahwul/dalfox/releases) to understand new capabilities
2. **Update configuration files**: Make any necessary adjustments to your configuration files for compatibility with new features
3. **Clear cached data**: Remove any temporary files from previous scans
4. **Run a test scan**: Perform a quick scan to verify the updated version works correctly

```bash
# Test the updated installation
dalfox url https://example.com --format json -o test-result.json
```

## Update Automation

You can create simple scripts to automate Dalfox updates:

### Homebrew Update Script

```bash
#!/bin/bash
# update-dalfox.sh
echo "Updating Dalfox..."
brew update && brew upgrade dalfox
dalfox version
echo "Dalfox update completed."
```

### Docker Update Script

```bash
#!/bin/bash
# update-dalfox-docker.sh
echo "Updating Dalfox Docker image..."
docker pull hahwul/dalfox:latest
echo "Dalfox Docker image updated to:"
docker run --rm hahwul/dalfox:latest /app/dalfox version
```

## Troubleshooting Update Issues

If you encounter issues during the update process:

### Common Problems and Solutions

1. **Permission errors**:
   - Use `sudo` for operations requiring elevated privileges
   - Check file/directory permissions

2. **Path issues**:
   - Ensure the installation directory is in your PATH
   - Verify that older versions aren't shadowing the new one

3. **Dependency conflicts**:
   - Update Go to the latest version if using `go install`
   - Check for conflicting packages if using package managers

### Getting Help

If you continue experiencing problems updating Dalfox:

- Check the [GitHub Issues](https://github.com/hahwul/dalfox/issues) for similar problems
- Join the [Dalfox community discussions](https://github.com/hahwul/dalfox/discussions)
- Report a new issue if your problem hasn't been addressed

## Checking for Updates Automatically

You can add this function to your shell configuration to check for Dalfox updates when opening a terminal:

```bash
# Add to ~/.bashrc or ~/.zshrc
check_dalfox_update() {
  if command -v dalfox &> /dev/null; then
    local current_version=$(dalfox version | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+')
    local latest_version=$(curl -s https://api.github.com/repos/hahwul/dalfox/releases/latest | grep -Eo '"tag_name": "v[0-9]+\.[0-9]+\.[0-9]+"' | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+')
    
    if [[ "$current_version" != "$latest_version" ]]; then
      echo "📢 Dalfox update available: $current_version → $latest_version"
    fi
  fi
}

# Run the check when starting a shell
check_dalfox_update
```

## Community Resources

For additional help and information about Dalfox:

- [Official Dalfox GitHub Repository](https://github.com/hahwul/dalfox)
- [Dalfox Documentation](https://dalfox.hahwul.com)
- [Dalfox Community Discussions](https://github.com/hahwul/dalfox/discussions)
- [Issue Tracker](https://github.com/hahwul/dalfox/issues)