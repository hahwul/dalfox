---
title: Caido Active Workflow
redirect_from: /docs/caido/
parent: Running
nav_order: 7
toc: true
layout: page
---

# Dalfox Caido Integration
{: .d-inline-block }

New (v2.12.0)
{: .label .label-blue }

## Overview

Dalfox now supports direct integration with [Caido](https://caido.io/), enabling powerful, automated XSS scanning as part of your Caido active workflows. This integration streamlines web security testing by allowing you to invoke Dalfox’s advanced XSS detection on HTTP requests intercepted or crafted within Caido, and view actionable results right in your workflow.

## What is Caido?

Caido is a modern web security toolkit for penetration testers and bug bounty hunters. It provides an intuitive interface for intercepting, modifying, and replaying HTTP requests, and supports extensibility through active workflows and external tool integrations.

By integrating Dalfox with Caido, you can:

- Automatically scan HTTP requests for XSS vulnerabilities
- Receive structured, actionable scan results within Caido
- Enhance your security testing workflow with minimal manual effort

## Setting Up Dalfox with Caido

### Prerequisites

- **Dalfox v2.12.0 or later** installed on your system
- **Caido** installed and running
- **jq** installed on your system

### Installation

If you haven’t installed Dalfox yet, use one of the following methods:

```bash
# From source
go install github.com/hahwul/dalfox/v2@latest

# Homebrew
brew install dalfox

# Snapcraft
snap install dalfox
```

*[Installation](/page/installation/)*

## Configuring the Active Workflow

To use Dalfox as an active workflow in Caido:

1. **Set your Dalfox binary path**
Update the workflow script with the path to your Dalfox executable (you can find it with `which dalfox`):

```bash
DALFOX_PATH="/path/to/your/dalfox"
```

2. **Configure the Caido workflow**
   Use the following shell script in your Caido active workflow configuration:
   ```bash
   cat - | jq -r .request | $DALFOX_PATH pipe --rawdata --silence --report --report-format=md
   ```
   This script takes the intercepted HTTP request from Caido, pipes it to Dalfox, and outputs the results in Markdown format.

3. **Save and activate the workflow**
   Ensure your workflow is enabled in Caido’s interface.

#### Example Workflow Configuration

![Caido Workflow Configuration](/images/page/running/caido/workflow.jpg)

```bash
# Set your dalfox path
DALFOX_PATH="/opt/homebrew/bin/dalfox"

# Run dalfox and store the entire output in a variable
# Use $(...) for correct command substitution
RESULT=$(cat - | jq -r .request | "$DALFOX_PATH" pipe --rawdata --silence --report --report-format=md)

# Check if the result contains the string "PoC1"
# Use [[ ... ]] for safer and more efficient string comparison
if [[ "$RESULT" == *"PoC1"* ]]; then
    # If "PoC1" is found, print the entire captured result
    echo "$RESULT"
else
    # Otherwise, print the string "false"
    false
fi
```

## Using Dalfox in Caido

Once configured, you can trigger Dalfox scans directly from Caido’s UI. When you send a request through Caido, the active workflow will automatically invoke Dalfox and display the scan results.

#### Running from the Context Menu

You can also run the Dalfox workflow directly from Caido’s context menu. Simply right-click on a request, select `Run workflow`, and choose `XSS Scan`.

![Run Dalfox Workflow from Context Menu](/images/page/running/caido/context.jpg)

#### Example Scan Result in Caido

![Dalfox Scan Result in Caido](/images/page/running/caido/finding.jpg)

## Advanced Usage

You can customize Dalfox’s behavior by modifying the workflow script to include additional flags, such as custom headers, cookies, or Blind XSS callbacks. For example:

```bash
cat - | jq -r .request | $DALFOX_PATH pipe --rawdata --silence --report --report-format=md --header "Authorization: Bearer <token>" -b your-callback.com
```

## Best Practices

1. **Keep Dalfox Updated**: Use the latest version for improved detection and features.
2. **Validate Results**: Manually verify critical findings for accuracy.
3. **Respect Target Systems**: Avoid scanning production systems without permission.
4. **Leverage Caido Context**: Use Caido’s request manipulation features to test various scenarios before scanning.
5. **Secure Sensitive Data**: Be mindful of sensitive information in scan results.

---

By integrating Dalfox with Caido, you can supercharge your web security assessments with automated, reliable XSS detection—right where you need it most.
