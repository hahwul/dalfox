+++
title = "CLI Commands"
+++

Reference for all Hwaro command-line commands.

## hwaro init

Initialize a new Hwaro project.

```bash
hwaro init [path] [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--scaffold TYPE` | Scaffold type: simple, blog, blog-dark, docs, docs-dark, book, book-dark (default: simple) |
| `--force` | Overwrite existing files |
| `--skip-sample-content` | Don't create sample content |

**Examples:**

```bash
hwaro init my-site
hwaro init my-blog --scaffold blog
hwaro init my-blog --scaffold blog-dark
hwaro init my-docs --scaffold docs --force
hwaro init my-docs --scaffold docs-dark
hwaro init my-book --scaffold book
hwaro init my-book --scaffold book-dark
```

## hwaro build

Build the static site.

```bash
hwaro build [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--config FILE` | Use a custom config file |
| `--output DIR` | Output directory (default: public) |

## hwaro serve

Start a development server.

```bash
hwaro serve [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--port PORT` | Server port (default: 3000) |
| `--host HOST` | Server host (default: localhost) |

## hwaro new

Create a new content file.

```bash
hwaro new [path]
```

Creates a new Markdown file with front matter template.