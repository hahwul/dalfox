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
just build    # cargo build
just dev      # cargo run
just test     # unit + integration tests
```

Before opening a PR, please run `just fix` (runs `cargo fmt` + `cargo clippy --fix`) and `just test`.

## Reporting Issues

* Bugs and feature requests: [GitHub Issues](https://github.com/hahwul/dalfox/issues)
* Security issues: see [SECURITY.md](./SECURITY.md)

## Code of Conduct

Be respectful. Assume good intent. Keep discussions on-topic.
