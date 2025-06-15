# AI Agent Guide for Dalfox

> **Version:** 1.0
> **Purpose:** This document is the primary guide for AI agents to understand, interact with, and contribute to the Dalfox project. It outlines the project's philosophy, architecture, and common development patterns.

---

## 1. Core Philosophy & Guiding Principles

To contribute effectively, understand the principles that guide Dalfox's development:

* 🚀 **Performance First:** Dalfox is built to be fast. Contributions should prioritize efficient algorithms and minimize unnecessary overhead. Concurrency is used where appropriate.
* ⛓️ **Minimal Dependencies:** The project relies on the Go standard library as much as possible. Avoid adding new third-party dependencies unless absolutely necessary and well-justified.
* 🎯 **Actionable & Clear Output:** Scan results must be clear, concise, and easy to parse, both for humans and for other tools. The JSON output format is critical for this.
* 🔧 **Flexibility Through Flags:** New features or behaviors should primarily be exposed through command-line flags rather than requiring code changes for users. This makes the tool highly configurable for various use cases.
* ✅ **Reliable Verification:** Vulnerability reports must be trustworthy. The verification process (e.g., using a headless browser) is a core component for reducing false positives.

---

## 2. Project Overview

Dalfox is a powerful, open-source automation tool for XSS (Cross-Site Scripting) vulnerability scanning and parameter analysis. It is designed to quickly identify XSS flaws, analyze injectable parameters, and provide reliable verification of found vulnerabilities.

**Key Features:**

* **Multi-Modal Scanning:** Supports various inputs: a single URL, a file of URLs, piped input (stdin), and a full-featured server mode with a REST API.
* **Advanced Discovery:** Performs parameter mining from JavaScript, HTML forms, and headers. It also features advanced techniques like Blind XSS (BAV) detection.
* **Comprehensive Scanning:** Detects Reflected, Stored, and DOM-based XSS. It uses optimization techniques and headless browser verification.
* **Flexible Configuration:** Allows deep customization of HTTP requests (headers, cookies, methods, proxy) and scanning behavior (custom payloads, timeouts).
* **Structured Reporting:** Offers plain text and JSON output formats, making it suitable for both manual review and automated pipelines.

---

## 3. Getting Started: Environment & Workflow

Follow these steps to set up a development environment, build, and test the project.

### Environment Setup
1.  **Install Go:** Ensure you have a recent version of Go installed (e.g., Go 1.18 or later).
2.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/hahwul/dalfox.git](https://github.com/hahwul/dalfox.git)
    cd dalfox
    ```
3.  **Install Dependencies:** Go modules will handle dependencies automatically. You can pre-fetch them if needed:
    ```bash
    go mod download
    ```

### Building & Testing
* **Build from Source:** To create the `dalfox` executable in the root directory:
    ```bash
    go build .
    ```
* **Run All Tests:** To ensure the codebase is healthy, run the full test suite:
    ```bash
    go test ./...
    ```
* **Code Formatting:** All contributed code must be formatted with `go fmt`.
    ```bash
    go fmt ./...
    ```

### Contribution Workflow
1.  Create a new branch for your feature or fix.
2.  Write or modify the code, ensuring it adheres to the project's philosophy.
3.  Add or update tests to cover your changes.
4.  Ensure all tests pass (`go test ./...`).
5.  Format your code (`go fmt ./...`).
6.  Submit a Pull Request with a clear description of the changes.

---

## 4. Codebase Architecture

Dalfox follows a clean separation of concerns. A typical command-line execution flows from command parsing (`cmd`), to the main scanning engine (`pkg`), to output formatting (`internal`).

### Directory Breakdown

* **/cmd**: **(Entry Points)**
    * **Purpose:** Defines the command-line interface (CLI) using the Cobra library. Each subcommand (`url`, `file`, `pipe`, etc.) is a separate file.
    * **Key Files:** `root.go`, `url.go`, `file.go`, `args.go` (flag definitions).
    * **AI Interaction:** This is where you would add a new command or modify CLI flags.

* **/pkg**: **(Core Logic & Public API)**
    * **Purpose:** Contains the main, reusable logic of the application. If Dalfox were a library, this would be its public API.
    * `/model`: Defines the core data structures (`Options`, `Result`, `Param`). **Start here to understand the data flow.**
    * `/scanning`: The heart of Dalfox. Contains the scanning engine, parameter analysis, payload injection, and verification logic.
    * `/server`: Implements the REST API server mode.
    * **AI Interaction:** Most modifications to *how* Dalfox scans will happen in `pkg/scanning`.

* **/internal**: **(Internal Logic)**
    * **Purpose:** Houses supporting packages that are not meant to be imported by other projects.
    * `/payload`: Manages the built-in XSS payloads and Blind XSS vectors.
    * `/printing`: Handles all console output, logging, banners, and result formatting.
    * `/verification`: Logic for verifying vulnerabilities, often using the headless browser.
    * **AI Interaction:** Modify this to change output formats or add new default payloads.

* **/lib**: **(General Utilities)**
    * **Purpose:** Contains general-purpose helper functions that are not specific to the Dalfox domain.

* **/docs**: User-facing documentation (for the website). Useful for understanding features from a user's perspective.
* **`.github/workflows`**: CI/CD pipelines (GitHub Actions). Useful for understanding the automated testing and release process.
* **`justfile`**: A command runner script (like `Makefile`) for common development tasks. Review this for helpful shortcuts.

---

## 5. Common Development Tasks & Scenarios

This section outlines how to approach common tasks programmatically or via the command line.

**Scenario 1: Scanning a single URL**
* **Goal:** Test a specific URL for XSS.
* **Command:** `dalfox url http://testphp.vulnweb.com/listproducts.php?cat=1 --json`
* **Key Flags for AI:**
    * `--json`: **Always use this for programmatic parsing.**
    * `-b your-callback.com`: To enable Blind XSS detection.
    * `--header "Cookie: session=123"`: To provide authentication tokens.
    * `--silence`: To suppress the banner and informational output, leaving only results.

**Scenario 2: Using custom payloads**
* **Goal:** Test with a specific list of XSS vectors.
* **Command:** `dalfox url http://example.com --custom-payload ./my_vectors.txt`
* **Code Pointer:** The logic for loading custom payloads is handled via flags in `cmd/args.go` and applied within the `pkg/scanning` engine. To add *new built-in* payloads, modify `internal/payload/xss.go`.

**Scenario 3: Integrating Dalfox via API**
* **Goal:** Use Dalfox as a continuous scanning service.
* **Command to Start:** `dalfox server --server-port 6664`
* **Interaction:** Send a `POST` request to the `/scan` endpoint. Refer to the official documentation or `pkg/server/scan.go` for the API specification.

**Scenario 4: Interpreting JSON results**
* **Goal:** Programmatically understand the scan findings.
* **Key Fields in JSON Output:**
    * `"type": "vulnerable"`: A confirmed XSS vulnerability. This is the most important result.
    * `"type": "weak"`: A potential vulnerability that may have been partially mitigated.
    * `"param_name"`: The vulnerable parameter.
    * `"payload"`: The payload that triggered the finding.
    * `"evidence"`: Snippet of the response confirming the vulnerability.
* **Code Pointer:** The structure of the JSON output is defined by `pkg/model/result.go`.

---

## 6. Architectural Patterns & Anti-Patterns

Follow these rules to ensure your contributions align with the project's design.

### ✅ Do This

* **Pass Options via Struct:** Use the `pkg/model.Options` struct to pass settings down through the application. Avoid passing individual arguments.
* **Use the `printing` Package for Output:** Do not use `fmt.Println` directly within the `pkg/scanning` logic. Instead, create a `pkg/model.Result` object and pass it to the `printing` package. This separates logic from presentation.
* **Write Unit Tests:** Any new function or logic change in the `pkg` or `internal` directories should be accompanied by a `_test.go` file with relevant test cases.
* **Define Interfaces for Major Components:** While not universally applied yet, new major components (like a new reporting method) should be defined behind an interface to allow for future extensibility.

### ❌ Avoid This

* **Modifying Payloads Directly in `xss.go` for One-Time Use:** If you just want to *use* custom payloads, always use the `--custom-payload` flag. Only modify the code if you are adding a new, permanent set of general-purpose payloads.
* **Introducing Global State:** Avoid using global variables. All state should be managed within the scope of a scan and passed explicitly.
* **Making Breaking API Changes:** If you need to modify the server API (`/pkg/server`) or the JSON output structure (`/pkg/model/result.go`), it must be discussed with the maintainers as it can break user integrations.
* **Adding Heavy Dependencies:** A new dependency is a significant cost. Propose and justify it in a GitHub Issue before adding it to `go.mod`.
