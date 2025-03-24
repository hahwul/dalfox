---
title: Parameter Mining
redirect_from: /docs/parameter-mining/
nav_order: 1
parent: Features
toc: true
layout: page
---

# Parameter Mining

## What is Parameter Mining?

Parameter mining is an advanced feature in Dalfox that automatically discovers potential injection points in web applications. Instead of only testing parameters that are visible in the URL, parameter mining helps identify hidden, undocumented, or forgotten parameters that might be vulnerable to XSS attacks.

Effective parameter discovery is crucial for thorough security testing because:

- Many vulnerabilities exist in parameters that aren't immediately visible
- Developers may inadvertently leave testing parameters in production
- Legacy parameters might remain functional but undocumented
- Frontend code might reveal parameters used by APIs and background processes

Dalfox implements two complementary parameter mining techniques:

1. **Dictionary-based Mining**: Tests common parameter names from wordlists
2. **DOM-based Mining**: Analyzes JavaScript code to extract parameter names

Both techniques are enabled by default to maximize discovery potential.

## Dictionary-based Parameter Mining

This technique involves testing a curated list of common parameter names against the target application.

### Default Wordlist

By default, Dalfox uses parameter lists from [Gf-Patterns](https://github.com/1ndianl33t/Gf-Patterns), specifically optimized for XSS vulnerability discovery. These lists include common parameter names like:

- `q`, `search`, `query` (search functionality)
- `redirect`, `url`, `next` (redirection)
- `id`, `user`, `page` (content identifiers)
- Many other parameters commonly associated with XSS vulnerabilities

### Using Custom Wordlists

For more targeted testing, you can provide your own parameter wordlist:

```bash
dalfox url https://example.com --mining-dict-word=./my-params.txt
```

Your custom wordlist should contain one parameter name per line:

```
search
q
query
keyword
id
page
user
name
redirect_to
callback
...
```

### Using Remote Wordlists

Dalfox can also retrieve and use wordlists from well-known security resources:

```bash
# Use one remote wordlist
dalfox url https://example.com --remote-wordlists=burp

# Use multiple remote wordlists
dalfox url https://example.com --remote-wordlists=burp,assetnote
```

Available remote wordlists:

| Source | Description | Parameter Count |
|--------|-------------|----------------|
| `burp` | Parameters from Burp Suite's Param Miner | ~6,000 parameters |
| `assetnote` | Assetnote's comprehensive parameter collection | ~15,000 parameters |

### Parameter Testing Methodology

When mining parameters, Dalfox:

1. Takes each parameter from the wordlist
2. Appends it to the target URL with a special marker value
3. Analyzes the response for reflections or changes in behavior
4. Flags potential injection points for further testing

For example, if the target is `https://example.com`, Dalfox might test:
```
https://example.com?search=DalfoxParameterCheck
https://example.com?q=DalfoxParameterCheck
https://example.com?id=DalfoxParameterCheck
...
```

## DOM-based Parameter Mining

DOM-based mining is a more sophisticated approach that analyzes JavaScript code to find parameters used by the application.

### How DOM Mining Works

Dalfox performs the following steps:

1. Downloads and parses all JavaScript files linked from the target page
2. Analyzes JavaScript code for parameter access patterns and URL manipulations
3. Extracts parameter names from functions like `URLSearchParams`, `getElementById`, event handlers, etc.
4. Tests discovered parameters for XSS vulnerabilities

This technique is especially effective for modern single-page applications (SPAs) and JavaScript-heavy websites.

### Example JavaScript Patterns Detected

```javascript
// URL parameter retrieval
const urlParams = new URLSearchParams(window.location.search);
const paramValue = urlParams.get('myParameter');

// DOM element access with parameter IDs
document.getElementById('search-input').value;

// Direct location search parsing
var query = location.search.split('query=')[1].split('&')[0];

// Event handlers for form elements
searchForm.addEventListener('submit', function(e) {
  // Form parameter handling
});
```

## Controlling Parameter Mining

### Fine-tuning Mining Behavior

Dalfox provides several options to control the parameter mining process:

```bash
# Disable only DOM-based mining
dalfox url https://example.com --skip-mining-dom

# Disable only dictionary-based mining
dalfox url https://example.com --skip-mining-dict

# Disable all parameter mining
dalfox url https://example.com --skip-mining-all
```

### When to Disable Mining

Consider disabling parameter mining in these scenarios:

- When you only want to test specific known parameters (`-p` flag)
- For very large applications where mining might take too long
- When testing API endpoints with a strict parameter structure
- During focused testing of already identified vulnerabilities

## Advanced Mining Techniques

### Combined Approach

For most effective parameter discovery, combine multiple techniques:

```bash
dalfox url https://example.com --remote-wordlists=burp,assetnote --mining-dict-word=./custom-params.txt
```

### Mining with Specified Parameters

You can combine parameter mining with specific parameter testing:

```bash
dalfox url https://example.com -p knownparam1 -p knownparam2
```

Dalfox will test both the specified parameters and any discovered through mining.

### Mining in Different Contexts

Parameter mining works across different scan modes:

```bash
# URL mode with mining
dalfox url https://example.com

# File mode with mining (multiple URLs)
dalfox file urls.txt

# Pipe mode with mining
cat urls.txt | dalfox pipe
```

## Practical Examples

### Basic Parameter Discovery

```bash
# Discover and test parameters on a target website
dalfox url https://example.com
```

Output example:
```
[*] Using dictionary mining option [list=GF-Patterns] 📚⛏
[*] Using DOM mining option 📦⛏
[I] Found testing point in DOM: searchQuery
[I] Found testing point in DOM: redirectUrl
[I] Found testing point by dictionary mining: q
[I] Found reflected parameter: searchQuery
```

### Advanced Discovery with Custom Parameters

```bash
# Combine known parameters with mining
dalfox url https://example.com -p admin -p token --remote-wordlists=burp
```

### Mining with Output Filtering

```bash
# Only show discovered parameters, skip testing
dalfox url https://example.com --only-discovery
```

## Best Practices

1. **Start Broad, Then Focus**: Begin with default mining, then focus on promising parameters
2. **Combine Approaches**: Use both dictionary and DOM-based mining for best results
3. **Custom Wordlists**: Create industry-specific wordlists for specialized applications
4. **Manage Resource Usage**: For large applications, consider testing in batches
5. **Verify Manually**: Some parameters might need manual verification

## Troubleshooting

### Common Issues

- **Too Many Parameters**: If mining discovers too many parameters, focus on those that show reflection
- **Slow Mining**: For large sites, try using smaller wordlists or increasing workers (`-w` flag)
- **False Positives**: Some parameters might be detected but not actually processed by the application

### Optimizing Mining Performance

```bash
# Faster mining with more workers
dalfox url https://example.com -w 200

# Use only the most common parameters
dalfox url https://example.com --mining-dict-word=./common-top100.txt
```
