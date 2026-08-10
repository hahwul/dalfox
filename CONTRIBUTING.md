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
```

To regenerate the `dalfox` man page from the current CLI definition:

```bash
just man             # cargo run -- man > man/dalfox.1
man ./man/dalfox.1   # preview
```

The hidden `dalfox man` subcommand renders the roff page straight from the
clap `Command`, so the man page never drifts from the real flags.

Before opening a PR, please run `just fix` (runs `cargo fmt` + `cargo clippy --fix`) and `just test`.

## Reporting Issues

* Bugs and feature requests: [GitHub Issues](https://github.com/hahwul/dalfox/issues)
* Security issues: see [SECURITY.md](./SECURITY.md)

## Code of Conduct

Be respectful. Assume good intent. Keep discussions on-topic.
