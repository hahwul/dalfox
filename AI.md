# AI Agent Guide for Dalfox

This document provides guidance for AI Agents to understand and interact with the Dalfox project.

## 1. Project Overview

Dalfox is a powerful open-source tool focused on automation for XSS (Cross-Site Scripting) vulnerability scanning and parameter analysis. It is designed to quickly scan for XSS flaws, analyze parameters, and verify vulnerabilities.

**Key Features:**

*   **Multiple Scanning Modes:** Supports various input methods like single URL, list of URLs from a file, piped input (stdin), server mode for API interaction, and payload mode for specific payload testing.
*   **Advanced Discovery:** Includes parameter analysis, static code analysis (from JavaScript files), Blind XSS (BAV) testing, and parameter mining from various sources (JS files, HTML forms, etc.).
*   **Comprehensive XSS Scanning:** Capable of detecting Reflected, Stored, and DOM-based XSS vulnerabilities. It uses optimization techniques and can perform verification using a headless browser.
*   **Flexible HTTP Configuration:** Allows customization of HTTP requests with custom headers, cookies, user-agents, HTTP methods, and proxy settings.
*   **Varied Output Options:** Supports JSON and plain text output formats, a quiet/silent mode for minimal output, and detailed reporting.
*   **Extensibility:** Offers a REST API for integration, supports custom payloads, and can fetch wordlists from remote URLs.

## 2. Project Structure

Understanding the project's directory structure is key to navigating and modifying the codebase.

*   **`/cmd`**: Contains the main application entry points and command-line argument parsing.
    *   `root.go`: The root command setup using Cobra.
    *   `url.go`, `file.go`, `pipe.go`, `server.go`, `sxss.go`, `payload.go`: Specific command implementations (e.g., `dalfox url`, `dalfox file`).
    *   `args.go`: Defines and parses command-line flags.
*   **`/internal`**: Houses the core logic and internal packages of Dalfox. This code is not intended to be imported by other projects.
    *   `/har`: Logic for HTTP Archive (HAR) file generation.
    *   `/optimization`: Code related to optimizing scan parameters and techniques.
    *   `/payload`: Management and generation of XSS payloads, including BAV (Blind XSS) payloads and remote payload fetching.
    *   `/printing`: Handles output formatting, logging, banners, and Proof-of-Concept (PoC) generation.
    *   `/report`: Logic for generating scan reports.
    *   `/utils`: Utility functions used across the project.
    *   `/verification`: Code for verifying found vulnerabilities, often using headless browser interactions.
*   **`/pkg`**: Contains library code that can be potentially used by external applications (though Dalfox is primarily a standalone tool).
    *   `/model`: Defines data structures like `Options`, `Param`, `Result`.
    *   `/scanning`: The core XSS scanning engine, including logic for different scan types (reflected, stored, DOM), parameter analysis, CSP checking, and interaction with headless browsers.
    *   `/server`: Implements the Dalfox server mode, including API endpoints.
*   **`/lib`**: Contains supporting library functions. In this project, it seems to be more general-purpose Go functions rather than Dalfox-specific core logic.
    *   `func.go`: General utility functions.
    *   `interface.go`: Defines interfaces used in the library.
*   **`/docs`**: Contains user-facing documentation, likely for the Dalfox website (dalfox.hahwul.com). This is a good resource for understanding features in-depth but is not aimed at AI code interaction.
*   **`/samples`**: Example files for various Dalfox features, such as custom payloads, configs, and target lists.
*   **`dalfox.go`**: The main entry point of the application.
*   **`go.mod`, `go.sum`**: Go module files defining project dependencies.
*   **`justfile`**: Contains commands for building, testing, and other development tasks (similar to a `Makefile`).
*   **`Dockerfile`**: For building Dalfox as a Docker container.
*   **`.github/workflows`**: GitHub Actions workflows for CI/CD, testing, and releases.

## 3. Common Scenarios & How to Approach Them

This section outlines how an AI agent might approach common tasks using Dalfox, primarily by constructing and executing command-line calls.

**Scenario 1: Scanning a single URL**

*   **Goal:** Test a specific URL for XSS vulnerabilities.
*   **Command Structure:** `dalfox url <target_url> [flags]`
*   **Example:** `dalfox url http://testphp.vulnweb.com/listproducts.php?cat=1`
*   **Key Flags to Consider:**
    *   `-b <your_callback_url>`: For Blind XSS detection (e.g., `-b yourdomain.com/callback`).
    *   `--header "Cookie: session=123"`: To send custom headers.
    *   `--user-agent "MyCustomAgent"`: To set a specific User-Agent.
    *   `--output <filename>`: To save results to a file.
    *   `--json`: To get output in JSON format.
    *   `--silence`: For minimal output.
    *   `--deep-domxss`: For more intensive DOM XSS checking (can be slower).
*   **Relevant Code:**
    *   Command parsing: `cmd/url.go`, `cmd/args.go`
    *   Scanning logic: `pkg/scanning/scan.go`

**Scenario 2: Scanning multiple URLs from a file**

*   **Goal:** Test a list of URLs provided in a text file.
*   **Command Structure:** `dalfox file <filepath> [flags]`
*   **Example:** `dalfox file list_of_urls.txt -b mycallback.com`
*   **File Format:** Plain text file with one URL per line.
*   **Relevant Code:**
    *   Command parsing: `cmd/file.go`, `cmd/args.go`

**Scenario 3: Scanning from piped input (stdin)**

*   **Goal:** Use Dalfox in a toolchain, receiving URLs from another program's output.
*   **Command Structure:** `cat list_of_urls.txt | dalfox pipe [flags]` or `another_tool | dalfox pipe [flags]`
*   **Example:** `echo "http://testphp.vulnweb.com" | dalfox pipe --skip-bav`
*   **Relevant Code:**
    *   Command parsing: `cmd/pipe.go`, `cmd/args.go`

**Scenario 4: Using custom XSS payloads**

*   **Goal:** Test with a specific set of XSS vectors.
*   **Command Structure:** `dalfox <mode> <target> --custom-payload ./payloads.txt [flags]`
*   **Payload File Format:** Plain text file with one payload string per line.
*   **Example:** `dalfox url http://example.com --custom-payload my_xss_vectors.txt`
*   **Relevant Code:**
    *   Payload loading/handling is managed by the CLI flags and core scanning logic. For programmatic changes to default payloads, see `internal/payload/xss.go`.
    *   Flag parsing: `cmd/args.go`

**Scenario 5: Parameter mining and analysis**

*   **Goal:** Discover potential parameters to test for XSS.
*   **Command Structure:** Dalfox automatically performs parameter analysis. To control its depth or sources:
    *   `--mining-dict-word <wordlist_file>`: Provide a custom wordlist for parameter name guessing.
    *   `--mining-from-response`, `--mining-from-header`: Extract potential parameters from server responses/headers.
*   **Example:** `dalfox url http://example.com --mining-dict-word custom_params.txt --mining-from-response`
*   **Relevant Code:**
    *   Parameter analysis: `pkg/scanning/parameterAnalysis.go`
    *   Discovery: `pkg/scanning/discovery.go`

**Scenario 6: Using Server Mode for API-driven scans**

*   **Goal:** Integrate Dalfox scanning capabilities into another tool via its API.
*   **Command Structure:** `dalfox server [flags]`
*   **Default API Port:** `6664` (can be changed with `--server-port <port>`)
*   **Interaction:** Send scan requests to the Dalfox API endpoints (refer to Dalfox documentation for API specs).
*   **Relevant Code:**
    *   Server setup: `cmd/server.go`
    *   API logic: `pkg/server/`

**Scenario 7: Interpreting Scan Results**

*   **Output:** Dalfox prints found vulnerabilities to stdout. If `--output <filename>` is used, it saves there. `--json` provides structured JSON output.
*   **Key Information in Output:**
    *   `[VULN]`: Indicates a verified XSS vulnerability.
    *   `[WEAK]`: Indicates a potential XSS point that might require manual verification or has some mitigation in place.
    *   `[INFO]`: General information.
    *   `GParam`: The parameter where the vulnerability was found.
    *   `Payload`: The XSS payload that triggered the vulnerability.
    *   `Evidence`: Context or evidence of the vulnerability.
*   **JSON Output:** More structured and easier for programmatic parsing. Contains fields like `type` (`vulnerable`, `weak`, `info`), `method`, `url`, `param_name`, `payload`, `evidence`, etc.
*   **Relevant Code:**
    *   Output formatting: `internal/printing/`
    *   Result structure: `pkg/model/result.go`

## 4. Key Files for AI Modification/Interaction

If an AI agent needs to modify Dalfox's behavior beyond command-line flags, these are some key areas:

*   **Adding or Changing Command-Line Flags:**
    *   `cmd/args.go`: Define new flags here.
    *   Relevant `cmd/<command_name>.go` (e.g., `cmd/url.go`): Implement the logic for the new flag within the specific command.
    *   `pkg/model/options.go`: Update the `Options` struct if the flag introduces a new global option.

*   **Modifying Core Scanning Logic:**
    *   `pkg/scanning/scan.go`: Main orchestrator for a scan.
    *   `pkg/scanning/scanning.go`: Contains various scanning functions (e.g., for different types of XSS).
    *   `pkg/scanning/queries.go`: Logic related to constructing and sending HTTP requests with payloads.
    *   `pkg/scanning/parameterAnalysis.go`: If changing how parameters are discovered or analyzed.
    *   `pkg/scanning/headless.go`: For changes related to DOM XSS verification using the headless browser.

*   **Changing or Adding XSS Payloads (Programmatically):**
    *   `internal/payload/xss.go`: Default XSS payloads and logic for generating variations.
    *   `internal/payload/bav.go`: For Blind XSS (BAV) specific payloads.
    *   `internal/payload/entity.go`: Structures for payloads.
    *   *Note:* For simply *using* custom payloads, the `--custom-payload` flag is preferred over code modification.

*   **Altering Output and Reporting:**
    *   `internal/printing/logger.go`: Handles how messages are printed to the console.
    *   `internal/printing/poc.go`: Generates the "Proof of Concept" output.
    *   `internal/report/report.go`: If Dalfox were to generate more structured report files (currently, it's mostly stdout or simple file output).
    *   `pkg/model/result.go`: The `Result` struct defines what data is captured for each finding.

*   **Introducing New Scan Types or Checks:**
    *   This would likely involve adding new functions or packages within `pkg/scanning/` and potentially new command structures in `cmd/`.

*   **Modifying Server Mode API Endpoints or Behavior:**
    *   `pkg/server/server.go`: Main server logic.
    *   `pkg/server/scan.go`: API endpoint for initiating scans.
    *   `pkg/server/mcp.go`: Multi-Connection Proxy logic, if applicable.
    *   `pkg/server/docs/swagger.yaml` or `swagger.json`: API documentation (needs to be kept in sync if API changes).

## 5. Building and Testing

For an AI agent that might need to build from source or verify changes:

*   **Building from Source:**
    *   Dalfox is a Go project. The standard way to build is using `go build`.
    *   `go build .` in the root directory will create a `dalfox` (or `dalfox.exe` on Windows) executable in the same directory.
    *   `go install github.com/hahwul/dalfox/v2@latest` can also be used to build and install to the Go bin directory.
    *   The project uses a `justfile`. If `just` is installed, running `just build` might perform the build (check `justfile` for specifics).

*   **Running Tests:**
    *   Go projects typically use `go test ./...` to run all tests in the current directory and subdirectories.
    *   `just test` or similar might be defined in the `justfile` for a more streamlined testing process, potentially including linters or other checks.
    *   Individual package tests: `go test ./pkg/scanning/` (for example).
    *   Test files are usually named `*_test.go`.

## 6. Documentation Pointers

*   **This Document (`AI.md`):** The primary source for AI-specific guidance.
*   **Official User Documentation (`/docs` directory & website):** For comprehensive information on features, flags, and usage scenarios, refer to the user documentation found in the `/docs` directory of this repository or at the official website (https://dalfox.hahwul.com). While aimed at human users, it provides valuable context.
*   **Command-Line Help:**
    *   `dalfox --help`: General help and list of modes.
    *   `dalfox <mode> --help` (e.g., `dalfox url --help`): Help for a specific mode, listing all relevant flags.
*   **Source Code Comments:** The Go source code contains comments that can provide insights into specific functions and logic.
