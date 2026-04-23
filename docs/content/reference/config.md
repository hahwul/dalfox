+++
title = "Configuration Reference"
+++

Complete reference for `config.toml` options.

## Site Settings

```toml
title = "Site Title"
description = "Site description"
base_url = "https://example.com"
```

| Key | Type | Description |
|-----|------|-------------|
| `title` | string | Site title |
| `description` | string | Site description |
| `base_url` | string | Production URL |

## Search

```toml
[search]
enabled = true
format = "fuse_json"
fields = ["title", "content"]
filename = "search.json"
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | false | Enable search index |
| `format` | string | "fuse_json" | Index format |
| `fields` | array | ["title"] | Fields to index |

## Sitemap

```toml
[sitemap]
enabled = true
filename = "sitemap.xml"
changefreq = "weekly"
priority = 0.5
```

## RSS/Atom Feeds

```toml
[feeds]
enabled = true
type = "rss"
limit = 10
sections = ["posts"]
```

## Taxonomies

```toml
[[taxonomies]]
name = "tags"
feed = true

[[taxonomies]]
name = "categories"
paginate_by = 10
```