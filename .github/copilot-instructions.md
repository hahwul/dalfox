# Dalfox XSS Scanner

Dalfox is a powerful, open-source automation tool for XSS (Cross-Site Scripting) vulnerability scanning and parameter analysis built in Go. It focuses on automation, making it ideal for quickly scanning for XSS flaws and analyzing parameters with advanced testing engines and verification features.

**ALWAYS follow these instructions first and only fallback to additional search and context gathering if the information in these instructions is incomplete or found to be in error.**

## Working Effectively

### Initial Setup
- **Working Directory:** All commands assume you are in the repository root directory (`/home/runner/work/dalfox/dalfox` or equivalent)
- **Repository Clone:** If not already cloned: `git clone https://github.com/hahwul/dalfox.git && cd dalfox`

### Bootstrap, Build, and Test
- **NEVER CANCEL BUILDS OR TESTS** - Wait for completion as documented below
- Install Go 1.23+ if not available: Download from https://golang.org/dist/
- Clone repository: `git clone https://github.com/hahwul/dalfox.git && cd dalfox`
- Get dependencies: `go mod download` (optional, automatic on build)
- **Build dalfox binary:** `go build -v .` -- takes 60 seconds. NEVER CANCEL. Set timeout to 90+ seconds.
- **Run unit tests:** `go test ./...` -- takes 11 seconds. NEVER CANCEL. Set timeout to 30+ seconds.
  - Note: Some tests may fail due to network restrictions (DNS lookup failures for www.hahwul.com, dalfox.hahwul.com) - this is expected in sandboxed environments
- **Format code:** `go fmt ./...` -- takes under 1 second
- **Vet code:** `go vet ./...` -- takes 4 seconds. Set timeout to 15+ seconds.

### Core Commands and Functionality Testing
- **Test version:** `./dalfox version`
- **Test help:** `./dalfox --help` or `./dalfox -h`
- **Test single URL scanning:** `./dalfox url "http://example.com/test?param=value" --timeout 5 --silence --format json`
- **Test file mode:** `./dalfox file samples/sample_target.txt --timeout 3 --silence --format json` 
- **Test payload enumeration:** `./dalfox payload --enum-common`
- **Test server mode:** `./dalfox server --server-port 8889 --timeout 2` (start server for API testing)

### Optional Build Tools
- **Just command runner:** Install from https://github.com/casey/just if needed
  - Alternative commands: `just build`, `just test`, `just fix` (equivalent to manual commands above)
- **golangci-lint:** Not required but available for additional linting
- **Functional tests:** Require Ruby and Bundler (RSpec tests in spec/functional_tests/)

## Validation

- **Always manually validate XSS scanning functionality** after making changes to core scanning logic
- **ALWAYS run through complete end-to-end XSS scanning scenarios** when modifying pkg/scanning or internal/verification
- **CRITICAL: Required validation scenarios after any code changes:**
  1. **Basic URL scanning:** `./dalfox url "http://example.com/test?param=value" --timeout 10 --silence --format json` - verify JSON output structure is valid (should output `[{}]` minimum)
  2. **Parameter discovery:** `./dalfox url "http://example.com/search" --only-discovery --silence --format json` - verify parameter mining works without errors
  3. **Custom payload testing:** `./dalfox url "http://example.com/test?q=1" --custom-payload samples/sample_custompayload.txt --timeout 5 --silence --format json` - verify custom payloads load correctly
  4. **File mode functionality:** `./dalfox file samples/sample_target.txt --timeout 3 --silence --format json` - verify batch processing works
  5. **Pipe mode:** `echo "http://example.com/test?param=value" | ./dalfox pipe --timeout 5 --silence --format json` - verify stdin input processing
  6. **Payload enumeration:** `./dalfox payload --enum-common | head -10` - verify payload generation produces XSS vectors
  7. **Configuration file:** `./dalfox url "http://example.com/test" --config samples/sample_config.json --timeout 5 --silence --format json` - verify config file loading
  8. **Version and help:** `./dalfox version` and `./dalfox --help` - verify basic CLI functionality
  9. **Error handling:** `./dalfox unknown-command` - should show helpful error message and exit gracefully
- **Always test with --silence --format json flags** for clean programmatic validation of output structure
- **Always run `go fmt ./...` and `go vet ./...`** before completing changes or CI (.github/workflows/ci_go.yml) will fail
- **Server mode validation:** `./dalfox server --server-port 8889 &` - verify server starts without errors (use & for background, kill after test)
- Test builds and functionality work correctly - do not assume success without validation
- **Expected outputs:** Most scanning commands with minimal/restricted network will output `[{}]` in JSON format - this indicates the scanner ran successfully but found no vulnerabilities (expected in sandbox environments)

## Common Tasks

### Key Directories and Files
```
/
├── cmd/                 # CLI commands and argument parsing (Cobra-based)
│   ├── root.go         # Main command setup
│   ├── url.go          # Single URL scanning mode  
│   ├── file.go         # File batch scanning mode
│   ├── server.go       # API server mode
│   ├── payload.go      # Payload generation/enumeration
│   └── args.go         # Flag definitions and parsing
├── pkg/                # Core library and public API
│   ├── model/          # Data structures (Options, Result, Param)
│   ├── scanning/       # Main XSS scanning engine
│   └── server/         # REST API implementation
├── internal/           # Internal supporting packages
│   ├── payload/        # Built-in XSS payloads and vectors
│   ├── printing/       # Output formatting and logging
│   ├── verification/   # Headless browser verification
│   ├── optimization/   # Request optimization and caching
│   └── utils/          # General utilities
├── samples/            # Example configurations and test data
├── docs/               # Documentation (Jekyll site)
└── spec/               # Functional tests (Ruby/RSpec)
```

### Architecture Patterns
- **Entry flow:** CLI (cmd/) → Core Logic (pkg/) → Output (internal/printing)
- **Data flow:** Options struct → Scanning engine → Results → Formatted output
- **Main scanning modes:** URL (single), File (batch), Pipe (stdin), Server (API), SXSS (stored), Payload (generation)
- **Key data structures:** pkg/model.Options (configuration), pkg/model.Result (scan findings), pkg/model.Param (parameters)

### Making Changes
- **XSS payload modifications:** Edit internal/payload/xss.go for built-in payloads
- **New scanning features:** Modify pkg/scanning/ package
- **CLI flag additions:** Update cmd/args.go and relevant command files
- **Output format changes:** Modify internal/printing/ and pkg/model/result.go
- **Server API changes:** Update pkg/server/ (consider backward compatibility)

### Development Workflow Commands
```bash
# Full development cycle
go mod download                    # Get dependencies  
go build -v .                     # Build binary (60s) 
go test ./...                     # Run tests (11s)
go fmt ./...                      # Format code (<1s)
go vet ./...                      # Vet code (4s)

# Test core functionality
./dalfox version                  # Verify build works
./dalfox url "http://example.com/?test=1" --timeout 5 --silence --format json

# Payload testing and enumeration  
./dalfox payload --enum-common          # Generate common XSS payloads
./dalfox payload --enum-html            # HTML context payloads
./dalfox payload --enum-attr            # Attribute context payloads (large output ~2500+ lines)
./dalfox payload --enum-injs            # JavaScript context payloads
./dalfox payload --entity-event-handler # Enumerate event handlers for XSS
./dalfox payload --entity-useful-tags   # Enumerate useful HTML tags for XSS
./dalfox payload --entity-special-chars # Enumerate special characters for XSS

# Server mode testing
./dalfox server --server-port 8080 &  # Start API server
curl -X POST localhost:8080/scan -d '{"target":"http://example.com"}'
```

### Sample Usage Examples
```bash
# Basic XSS scanning
./dalfox url "http://example.com/search?q=test" --format json

# Batch file scanning  
./dalfox file targets.txt --output results.json --format json

# Pipe mode (stdin input)
echo "http://example.com/test?param=value" | ./dalfox pipe --silence --format json

# Custom payloads
./dalfox url "http://example.com" --custom-payload custom_xss.txt

# Blind XSS with callback
./dalfox url "http://example.com" --blind "https://your-callback.com"

# Parameter mining only
./dalfox url "http://example.com" --only-discovery --format json

# Configuration file usage  
./dalfox url "http://example.com" --config samples/sample_config.json

# API server mode
./dalfox server --server-port 6664
```

### Timing Expectations
- **Build time:** ~60 seconds (NEVER CANCEL - set 90+ second timeout)
- **Unit test time:** ~11 seconds (NEVER CANCEL - set 30+ second timeout)  
- **Code formatting:** <1 second
- **Code vetting:** ~4 seconds
- **Basic scanning:** 5-30 seconds depending on target and options
- **Payload enumeration:** 1-5 seconds
- **Server startup:** Immediate

### Configuration Files
- **Sample config:** samples/sample_config.json (JSON configuration template)
- **Custom payloads:** samples/sample_custompayload.txt (XSS payload examples)
- **Target lists:** samples/sample_target.txt (URL list format)
- **Grep patterns:** samples/sample_grep.json (custom vulnerability patterns)

### Dependencies and Requirements
- **Go 1.23+** (required)
- **Chrome/Chromium** (for headless verification - optional but recommended)
- **Ruby + Bundler** (for functional tests - optional)
- **Just** (command runner - optional, provides shortcuts)

### Common Pitfalls
- Do not modify built-in payloads in internal/payload/xss.go for one-time use - use --custom-payload flag instead
- Network-dependent tests may fail in restricted environments (expected)
- Always use --format json for programmatic parsing and validation
- Set appropriate timeouts for scanning operations to avoid premature cancellation
- Some scanning features require network access and may not work in isolated environments