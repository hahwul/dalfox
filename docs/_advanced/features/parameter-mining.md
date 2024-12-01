---
title: Parameter Mining
redirect_from: /docs/parameter-mining/
nav_order: 1
parent: Features
toc: true
layout: page
---

# Parameter Mining

Dalfox performs parameter mining by default when scanning. This is based on the [Gf-patterns](https://github.com/1ndianl33t/Gf-Patterns) XSS parameter and custom/remote word lists are available depending on flag usage. Additionally, there is a mining function through DOM Analysis, which is also enabled by default.

## Using Custom Wordlist

You can specify a custom wordlist for parameter mining using the `--mining-dict-word` option.

### Command

```bash
dalfox url https://example.com --mining-dict-word=./params.txt
```

## Using Remote Wordlist

You can use remote wordlists for parameter mining with the `--remote-wordlists` option.

### Command

```bash
dalfox url https://example.com --remote-wordlists=burp,assetnote
```

### Supported Resources

- **`burp`**: Use the wordlist of Param Miner in BurpSuite.
- **`assetnote`**: Use the wordlist of Assetnote.

## Disabling Mining

If you do not want to perform parameter mining, you can disable it using the following options:

### Disable DOM Mining

```bash
dalfox url https://example.com --skip-mining-dom
```

### Disable Dictionary Mining (Gf-Patterns)

```bash
dalfox url https://example.com --skip-mining-dict
```

### Disable All Mining Processes

```bash
dalfox url https://example.com --skip-mining-all
```
