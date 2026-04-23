+++
title = "Configuration"
+++

Hwaro is configured through a `config.toml` file in your project root.

## Basic Configuration

```toml
title = "My Documentation"
description = "Project documentation"
base_url = "https://docs.example.com"
```

## Search Configuration

```toml
[search]
enabled = true
format = "fuse_json"
fields = ["title", "content"]
```

## SEO Configuration

```toml
[sitemap]
enabled = true

[robots]
enabled = true
```

## Full Reference

See the [Configuration Reference](/reference/config/) for all available options.