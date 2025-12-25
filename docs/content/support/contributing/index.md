+++
title = "Contributing"
description = "How to contribute to Dalfox"
weight = 4
sort_by = "weight"

[extra]
+++

We welcome contributions to Dalfox! This page provides guidelines for contributing to the project.

## Ways to Contribute

### 1. Report Bugs

Found a bug? Please report it!

- Check [existing issues](https://github.com/hahwul/dalfox/issues) first
- Use the bug report template
- Include reproduction steps, expected vs actual behavior
- Provide version info: `dalfox --version`

### 2. Suggest Features

Have an idea for improvement?

- Check [feature requests](https://github.com/hahwul/dalfox/issues?q=is%3Aissue+label%3Aenhancement)
- Use the feature request template
- Explain the use case and benefit
- Provide examples if possible

### 3. Submit Code

Ready to code? Great!

**Process**:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

**Guidelines**:
- Follow Rust conventions and style (`cargo fmt`)
- Add tests for new features
- Update documentation
- Keep changes focused and atomic
- Write clear commit messages

### 4. Improve Documentation

Documentation improvements are always welcome!

- Fix typos or unclear explanations
- Add examples
- Improve existing guides
- Translate content

### 5. Help Others

- Answer questions in issues
- Help with troubleshooting
- Share your experiences and use cases

## Development Setup

### Prerequisites

- Rust (latest stable): [rustup.rs](https://rustup.rs/)
- Git

### Clone and Build

```bash
git clone https://github.com/hahwul/dalfox.git
cd dalfox

# Build
cargo build

# Run tests
cargo test

# Run locally
cargo run -- scan https://example.com
```

### Development Tools

**Format code**:
```bash
cargo fmt
```

**Lint**:
```bash
cargo clippy -- --deny warnings
```

**Run tests**:
```bash
cargo test                    # All tests
cargo test --lib             # Unit tests
cargo test --test integration # Integration tests
```

**Build release**:
```bash
cargo build --release
```

## Code Guidelines

### Rust Style

- Follow standard Rust naming conventions
- Use `cargo fmt` for formatting
- Resolve all `cargo clippy` warnings
- Prefer `Result<T, E>` over panics
- Use async/await for I/O operations

### Testing

- Add unit tests for new functions
- Add integration tests for new features
- Ensure all tests pass before submitting
- Test edge cases and error conditions

### Documentation

- Document public APIs with rustdoc comments
- Update user documentation when adding features
- Include code examples in documentation
- Keep README.md up to date

## Pull Request Process

1. **Create Branch**: `git checkout -b feature/your-feature-name`
2. **Make Changes**: Implement your feature or fix
3. **Test**: Run `cargo test` and manual testing
4. **Format**: Run `cargo fmt` and `cargo clippy`
5. **Commit**: Write clear commit messages
6. **Push**: `git push origin feature/your-feature-name`
7. **PR**: Open pull request with description

### PR Checklist

- [ ] Tests pass (`cargo test`)
- [ ] Code formatted (`cargo fmt`)
- [ ] No clippy warnings (`cargo clippy`)
- [ ] Documentation updated
- [ ] CHANGELOG.md updated (if applicable)
- [ ] Clear PR description

## Project Structure

```
dalfox/
├── src/
│   ├── main.rs              # Entry point
│   ├── lib.rs               # Library exports
│   ├── cmd/                 # Commands (scan, server, mcp, payload)
│   ├── parameter_analysis/  # Parameter discovery & mining
│   ├── scanning/            # XSS scanning engine
│   ├── payload/             # Payload generation
│   ├── encoding/            # Encoders
│   └── utils/               # Utilities
├── tests/                   # Integration tests
├── docs/                    # Documentation site
├── Cargo.toml              # Dependencies
└── README.md
```

## Areas Needing Help

**Current priorities**:
- Additional payload patterns
- More output formats
- Performance optimizations
- Documentation improvements
- Integration examples
- Bug fixes

Check [Good First Issue](https://github.com/hahwul/dalfox/labels/good%20first%20issue) label for beginner-friendly tasks.

## Code of Conduct

Please read and follow our [Code of Conduct](https://github.com/hahwul/dalfox/blob/main/CODE_OF_CONDUCT.md).

Be respectful, inclusive, and constructive in all interactions.

## Communication

- **Issues**: [GitHub Issues](https://github.com/hahwul/dalfox/issues)
- **Discussions**: [GitHub Discussions](https://github.com/hahwul/dalfox/discussions)
- **Twitter**: [@hahwul](https://twitter.com/hahwul)

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.

See [LICENSE](https://github.com/hahwul/dalfox/blob/main/LICENSE.txt) for details.

## Recognition

Contributors are recognized in:
- GitHub contributors page
- Release notes
- Documentation

Thank you for contributing to Dalfox! 🦊

## See Also

- [GitHub Repository](https://github.com/hahwul/dalfox)
- [Code of Conduct](https://github.com/hahwul/dalfox/blob/main/CODE_OF_CONDUCT.md)
- [Changelog](/support/changelog)
