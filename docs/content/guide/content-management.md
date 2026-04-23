+++
title = "Content Management"
+++

Learn how to organize and write content in Hwaro.

## Content Directory

All content files live in the `content/` directory:

```
content/
├── index.md              # Homepage
├── getting-started/      # Section
│   ├── _index.md         # Section index
│   ├── installation.md   # Page
│   └── quick-start.md    # Page
└── guide/
    └── ...
```

## Front Matter

Each content file starts with front matter in TOML format:

```markdown
+++
title = "Page Title"
date = "2026-04-23"
description = "Page description for SEO"
+++

# Your Content Here
```

## Sections

Sections are directories containing related content. Each section should have an `_index.md` file.

## Links

Link to other pages using relative paths:

```markdown
[Installation](/getting-started/installation/)
```

## Images

Place images in `static/` and reference them:

```markdown
![Diagram](/images/diagram.png)
```