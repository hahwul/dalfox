+++
title = "Templates"
+++

Hwaro uses Jinja2-compatible templates (via Crinja) for rendering pages.

## Template Directory

Templates are stored in `templates/`:

```
templates/
├── base.html       # Base template with common structure
├── page.html       # Regular pages
├── section.html    # Section indexes
├── partials/       # Partial templates
│   └── nav.html
└── shortcodes/     # Shortcode templates
```

## Available Variables

In templates, you have access to:

| Flat Variable | Object Access | Description |
|---------------|---------------|-------------|
| `page_title` | `page.title` | Current page title |
| `site_title` | `site.title` | Site title from config |
| `content` | — | Rendered page content |
| `base_url` | `site.base_url` | Site base URL |

## Template Inheritance

Extend base templates:

```jinja
{% extends "base.html" %}
{% block content %}{{ content }}{% endblock %}
```

## Including Partials

Include other templates:

```jinja
{% include "partials/nav.html" %}
```

## Customization

Modify templates to change the site layout, add navigation, or include custom scripts.