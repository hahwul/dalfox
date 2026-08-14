# Contributing

Thanks for helping make Dalfox better! Here's the short version.

## Workflow

1. Fork it (<https://github.com/hahwul/dalfox/fork>)
2. Create a feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'feat: add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Open a Pull Request against `main`

## Development

Dalfox v3 is written in Rust. The Go (v2.x) sources live on the [`v2` branch](https://github.com/hahwul/dalfox/tree/v2) and only receive critical security backports.

```bash
just build    # cargo build --release
just dev      # cargo build (debug)
just test     # unit + integration tests
just lint     # cargo fmt --check + clippy -D warnings (read-only, matches CI)
```

The hidden `dalfox man` subcommand renders a roff man page directly from the Clap command definition. To preview it locally:

```bash
just man                  # writes target/man/dalfox.1
man target/man/dalfox.1
```

The man page is **not** committed. Every packaging path (`.deb`/`.rpm`, AUR, Homebrew, Nix) renders it from the freshly built binary, so it can never drift from the CLI definition.

Before opening a PR, please run `just fix` (runs `cargo fmt` + `cargo clippy --fix`) and `just test`. To check formatting and lints without modifying files, run `just lint`.

## Reporting Issues

* Bugs and feature requests: [GitHub Issues](https://github.com/hahwul/dalfox/issues)
* Security issues: see [SECURITY.md](./SECURITY.md)

## Code of Conduct

Be respectful. Assume good intent. Keep discussions on-topic.
