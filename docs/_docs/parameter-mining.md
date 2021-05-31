---
title: Parameter Mining
permalink: /docs/parameter-mining/
---

## Parameter Mining
### (Default) Gf-Patterns and DOM Mining 
Dalfox performs parameter mining by default when scanning. This is based on the [Gf-patterns](https://github.com/1ndianl33t/Gf-Patterns) XSS parameter and custom/remote word list is available depending on flag usage. In addition, there is a Mining function through DOM Analysis, which is also the default mining.

## Use custom wordlist
```
▶ dalfox url https://example.com --mining-dict-word=./params.txt
```

## Use remote wordlist
```
▶ dalfox url https://example.com --remote-wordlists=burp,assetnote
```

### Supported resources
* `burp` : Use wordlist of Param Miner in BurpSuite
* `assetnote` : Usee wordlist of Assetnote

## Disable Mining
### Disable DOM-Mining
```
▶ dalfox url https://example.com --remote-wordlists=burp,assetnote
```
### Disable Dict Mining (Gf-Patterns)
```
▶ dalfox url https://example.com --skip-mining-dict
```
### Disable All Mining Process
```
▶ dalfox url https://example.com --skip-mining-all
```
