+++
title = "Quick Start"
+++

Get up and running with Hwaro in minutes.

## Create a New Project

```bash
hwaro init my-docs --scaffold docs
cd my-docs
```

## Project Structure

```
my-docs/
├── config.toml          # Site configuration
├── content/             # Markdown content files
│   ├── index.md
│   ├── getting-started/
│   └── guide/
├── templates/           # Jinja2 templates
└── static/              # Static assets
```

## Build Your Site

```bash
hwaro build
```

The generated site will be in the `public/` directory.

## Preview Locally

```bash
hwaro serve
```

Visit `http://localhost:3000` to see your site.

## Next Steps

- Read about [Configuration](/getting-started/configuration/)
- Learn about [Content Management](/guide/content-management/)