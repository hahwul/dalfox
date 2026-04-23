+++
title = "Shortcodes"
+++

Shortcodes are reusable content snippets you can embed in your Markdown.

## Using Shortcodes

In your Markdown content:

```jinja
{{ alert(type="info", body="This is an info alert") }}
```

## Built-in Shortcodes

### Alert

Display an alert box:

```jinja
{{ alert(type="warning", body="Be careful!") }}
```

Types: `info`, `warning`, `tip`, `note`

## Creating Custom Shortcodes

1. Create a template in `templates/shortcodes/`:

```jinja
{# templates/shortcodes/highlight.html #}
<mark class="highlight">{{ text }}</mark>
```

2. Use it in your content:

```jinja
{{ highlight(text="Important text here") }}
```

## Advanced Example

```jinja
{# templates/shortcodes/alert.html #}
{% if type and body %}
<div class="alert alert-{{ type }}">
  {{ body | safe }}
</div>
{% endif %}
```

## Best Practices

- Keep shortcodes simple and focused
- Document your custom shortcodes
- Use semantic HTML in shortcode templates
- Use the `safe` filter for HTML content