# Copilot Instructions for Dalfox (v3/Rust)

This is the v3 branch of Dalfox - a complete Rust rewrite of the powerful open-source XSS scanner. These instructions help GitHub Copilot better understand the project structure and conventions.

## Project Overview

Dalfox is a powerful open-source XSS (Cross-Site Scripting) scanner and utility focused on automation. The v3 branch represents a ground-up rewrite in Rust for improved performance, memory safety, and concurrency.

**Key Features:**
- Multiple scanning modes: URL, File, Pipe, Server, Payload
- Parameter discovery and analysis
- XSS testing with reflection detection
- DOM-based XSS verification
- JSON output format for automation
- Concurrent scanning with tokio async runtime

## Technology Stack

- **Language:** Rust (edition 2024)
- **Async Runtime:** tokio with full features
- **HTTP Client:** reqwest
- **CLI Framework:** clap with derive features
- **HTML Parsing:** scraper
- **Testing:** cargo test with integrated unit tests
- **Build Tool:** cargo with justfile for common tasks

## Project Structure

```
src/
├── main.rs                    # Entry point and CLI definition
├── cmd/                       # Command implementations
│   ├── scan.rs               # Main scanning command
│   ├── url.rs                # Single URL scanning
│   ├── file.rs               # Batch file scanning
│   ├── pipe.rs               # Pipeline mode
│   ├── server.rs             # Server/API mode
│   └── payload.rs            # Payload generation
├── parameter_analysis/        # Parameter discovery and mining
│   ├── discovery.rs          # Parameter discovery logic
│   └── mining.rs             # Parameter mining from responses
├── payload/                   # XSS payload management
│   ├── xss.rs                # XSS payload definitions
│   └── mining.rs             # Payload extraction/mining
├── scanning/                  # Core scanning engine
│   ├── check_reflection.rs   # Reflection detection
│   ├── check_dom_verification.rs  # DOM-based verification
│   ├── common.rs             # Common scanning utilities
│   └── result.rs             # Result structures
└── target_parser/             # URL and target parsing
    └── mod.rs                # Target parsing logic
```

## Development Workflow

### Building
```bash
# Development build
cargo build
# or
just dev

# Release build
cargo build --release
# or
just build
```

### Testing
```bash
# Run all tests
cargo test
# or
just test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_name
```

### Code Quality
```bash
# Format code (run before committing)
cargo fmt

# Check formatting
cargo fmt --check

# Run clippy (linter)
cargo clippy -- --deny warnings

# Fix clippy suggestions
cargo clippy --fix --allow-dirty
```

## Code Conventions

### Rust Style
- Follow standard Rust naming conventions (snake_case for functions/variables, PascalCase for types)
- Use `cargo fmt` for consistent formatting
- Address all clippy warnings before committing
- Prefer explicit error handling with `Result<T, E>` over panicking
- Use `?` operator for error propagation

### Async/Await
- All I/O operations should be async using tokio
- Use `#[tokio::main]` for the main function
- Prefer `tokio::spawn` for concurrent tasks
- Use `Arc<Mutex<T>>` or `Arc<RwLock<T>>` for shared state across async tasks

### Error Handling
- Create specific error types when needed
- Use `anyhow` or custom error types for error handling
- Provide descriptive error messages
- Log errors appropriately

### Testing
- Write unit tests in the same file as the implementation using `#[cfg(test)]`
- Test module should be named `tests`
- Use descriptive test function names starting with `test_`
- Mock HTTP responses when testing network code
- Aim for high test coverage on core scanning logic

## Common Development Tasks

### Adding a New XSS Payload
1. Edit `src/payload/xss.rs`
2. Add the payload to the appropriate vector/collection
3. Ensure payload is properly categorized (reflected, DOM-based, etc.)
4. Add tests to verify payload generation

### Adding a New Command
1. Create a new file in `src/cmd/` (e.g., `new_command.rs`)
2. Define the command args struct with clap derives
3. Implement the run function
4. Add the command to the `Commands` enum in `src/main.rs`
5. Update the match statement in `main()` to handle the new command

### Modifying Scanning Logic
1. Core scanning logic is in `src/scanning/`
2. Reflection checks are in `check_reflection.rs`
3. DOM verification is in `check_dom_verification.rs`
4. Common utilities are in `common.rs`
5. Results are structured in `result.rs`
6. Always add tests for new scanning logic

### Adding Parameter Analysis Features
1. Discovery logic is in `src/parameter_analysis/discovery.rs`
2. Mining logic is in `src/parameter_analysis/mining.rs`
3. Add appropriate tests for new analysis methods

## Important Notes

### Performance Considerations
- This is a performance-focused tool - avoid unnecessary allocations
- Use `&str` instead of `String` when possible for parameters
- Clone only when necessary (prefer borrowing)
- Consider using `Arc` for shared immutable data
- Profile performance-critical code paths

### Concurrency
- Use tokio's async runtime for I/O operations
- Spawn concurrent tasks for parallel scanning
- Be mindful of rate limiting and connection pooling
- Use semaphores or other primitives to control concurrency levels

### Output Format
- Maintain JSON output format compatibility where possible
- Results should be serializable with serde
- Support both human-readable and machine-parsable output

## Testing Guidelines

### Before Committing
```bash
# 1. Format code
cargo fmt

# 2. Run tests
cargo test

# 3. Check with clippy
cargo clippy -- --deny warnings

# 4. Build release version
cargo build --release
```

### Running Manual Tests
```bash
# Test basic scanning
./target/release/dalfox scan <target_url>

# Test with custom options
./target/release/dalfox scan <target_url> --method POST --data "param=value"

# Test file mode
./target/release/dalfox file urls.txt

# Test pipe mode
echo "https://example.com" | ./target/release/dalfox pipe
```

## Dependencies

Key dependencies and their purposes:
- **clap**: Command-line argument parsing with derive macros
- **tokio**: Async runtime for concurrent operations
- **reqwest**: HTTP client for making requests
- **scraper**: HTML parsing and manipulation
- **serde/serde_json**: Serialization and JSON handling
- **url**: URL parsing and manipulation
- **indicatif**: Progress bars and indicators

## Tool Calling Best Practices

When GitHub Copilot makes tool calls:
- **Multiple Independent Operations**: Call tools in parallel when actions don't depend on each other
- **File Operations**: Read multiple files simultaneously when exploring the codebase
- **Sequential Dependencies**: Call tools sequentially when parameters depend on previous results
- **Build and Test**: Use `timeout` parameter (180-300s) for cargo build/test commands

## Additional Resources

- [Rust Book](https://doc.rust-lang.org/book/) - Comprehensive Rust guide
- [Tokio Documentation](https://tokio.rs) - Async runtime documentation
- [Cargo Book](https://doc.rust-lang.org/cargo/) - Cargo package manager guide
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/) - API design patterns

## Migration Notes (v2 Go → v3 Rust)

If you're familiar with the Go version (v2):
- Go's goroutines → Rust's tokio tasks
- Go's interfaces → Rust's traits
- Go's error handling → Rust's Result/Option types
- Go's panic/recover → Rust's unwinding/Result propagation
- Go's defer → Rust's Drop trait and RAII

The core functionality remains the same, but implementation details differ due to language paradigms.
