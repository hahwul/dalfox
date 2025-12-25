+++
title = "Pipelining"
description = "Integrate Dalfox with other security tools"
weight = 2
sort_by = "weight"

[extra]
+++

Learn how to integrate Dalfox into security tool pipelines for automated workflows and comprehensive security testing.

## Pipe Mode

Dalfox supports pipe input (`-i pipe`) for seamless integration with other tools:

```bash
tool1 | tool2 | dalfox scan -i pipe
```

## Common Integration Patterns

### Subdomain Enumeration + XSS Scanning

**With subfinder and httpx**:
```bash
subfinder -d example.com | \
  httpx -silent | \
  dalfox scan -i pipe -f jsonl -o results.jsonl
```

**With amass**:
```bash
amass enum -d example.com -silent | \
  httpx -silent | \
  dalfox scan -i pipe
```

**With assetfinder**:
```bash
assetfinder --subs-only example.com | \
  httpx -silent | \
  dalfox scan -i pipe -f json -o results.json
```

### URL Discovery + XSS Scanning

**With gau (Get All URLs)**:
```bash
gau example.com | \
  dalfox scan -i pipe
```

**With waybackurls**:
```bash
waybackurls example.com | \
  grep "=" | \
  dalfox scan -i pipe -f jsonl -o results.jsonl
```

**With hakrawler**:
```bash
echo https://example.com | \
  hakrawler -plain | \
  grep "?" | \
  dalfox scan -i pipe
```

### Parameter Discovery + Testing

**With ParamSpider**:
```bash
python3 paramspider.py -d example.com | \
  dalfox scan -i pipe
```

**With Arjun**:
```bash
arjun -u https://example.com -oJ params.json
cat params.json | jq -r '.url' | \
  dalfox scan -i pipe
```

### Spider + XSS Scanning

**With gospider**:
```bash
gospider -s https://example.com -c 10 -d 2 | \
  grep -E "\[url\]" | \
  cut -d ' ' -f 3 | \
  grep "?" | \
  dalfox scan -i pipe
```

**With katana**:
```bash
katana -u https://example.com | \
  grep "?" | \
  dalfox scan -i pipe
```

## Proxy Integration

### Burp Suite

Forward all requests through Burp for manual inspection:

```bash
dalfox scan https://example.com \
  --proxy http://localhost:8080 \
  -F
```

Pipeline with Burp:
```bash
cat urls.txt | \
  dalfox scan -i pipe \
    --proxy http://localhost:8080 \
    -f json -o results.json
```

### OWASP ZAP

```bash
dalfox scan https://example.com \
  --proxy http://localhost:8090
```

### mitmproxy

```bash
dalfox scan https://example.com \
  --proxy http://localhost:8080
```

## Output Format Integration

### JSON for Programmatic Processing

**With jq**:
```bash
dalfox scan https://example.com -f json -o results.json

# Extract vulnerable parameters
cat results.json | jq -r '.[].param'

# Filter by severity
cat results.json | jq '.[] | select(.severity == "High")'

# Count findings
cat results.json | jq 'length'
```

### JSONL for Streaming

```bash
cat urls.txt | \
  dalfox scan -i pipe -f jsonl | \
  while read line; do
    echo $line | jq .
    # Process each result immediately
  done
```

### SARIF for Security Tools

**Upload to GitHub Code Scanning**:
```bash
dalfox scan https://example.com -f sarif -o results.sarif
# Upload results.sarif via GitHub Actions
```

**With SonarQube**:
```bash
dalfox scan https://example.com -f sarif -o dalfox.sarif
# Import into SonarQube
```

## Complete Workflows

### Bug Bounty Reconnaissance

```bash
#!/bin/bash
DOMAIN=$1

# 1. Subdomain enumeration
subfinder -d $DOMAIN -silent > subdomains.txt

# 2. Live host detection
cat subdomains.txt | httpx -silent > live.txt

# 3. URL discovery
cat live.txt | gau | grep "=" > urls.txt

# 4. XSS scanning
dalfox scan -i file urls.txt \
  --remote-payloads portswigger,payloadbox \
  --remote-wordlists burp \
  -e url,html \
  -f jsonl \
  -o xss-findings.jsonl

# 5. Process results
cat xss-findings.jsonl | jq -r '.poc' > pocs.txt
```

### CI/CD Security Pipeline

```yaml
# .github/workflows/security.yml
name: Security Scan

on: [push, pull_request]

jobs:
  xss-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Install Dalfox
        run: |
          cargo install dalfox
      
      - name: Run XSS Scan
        run: |
          dalfox scan ${{ secrets.STAGING_URL }} \
            -S \
            -f sarif \
            -o dalfox.sarif
      
      - name: Upload Results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: dalfox.sarif
```

### Continuous Monitoring

```bash
#!/bin/bash
# monitor.sh - Run hourly via cron

DOMAIN="example.com"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Discover + scan
subfinder -d $DOMAIN -silent | \
  httpx -silent | \
  gau | \
  grep "=" | \
  dalfox scan -i pipe \
    -f json \
    -o "scan_${TIMESTAMP}.json"

# Alert on new findings
if [ -s "scan_${TIMESTAMP}.json" ]; then
  # Send alert (email, Slack, etc.)
  echo "XSS vulnerabilities found!" | mail -s "XSS Alert" security@example.com
fi
```

### Multi-Tool Security Suite

```bash
#!/bin/bash
TARGET=$1

echo "[*] Starting comprehensive scan on $TARGET"

# 1. Recon
echo "[+] Running subfinder..."
subfinder -d $TARGET -silent > subs.txt

echo "[+] Checking live hosts..."
cat subs.txt | httpx -silent -status-code > live.txt

# 2. XSS Scanning
echo "[+] Running Dalfox XSS scan..."
cat live.txt | cut -d' ' -f1 | \
  dalfox scan -i pipe \
    --remote-payloads portswigger \
    -f json -o xss.json

# 3. Other security tests
echo "[+] Running nuclei..."
nuclei -l live.txt -silent -o nuclei.txt

echo "[+] Running nikto..."
cat live.txt | while read url; do
  nikto -h $url -output nikto_$(echo $url | md5sum | cut -d' ' -f1).txt
done

# 4. Report generation
echo "[+] Generating report..."
echo "## XSS Findings" > report.md
cat xss.json | jq -r '.[] | "- [\(.severity)] \(.param) in \(.method) \(.inject_type)"' >> report.md

echo "[*] Scan complete!"
```

## Integration with Web Frameworks

### Testing Frameworks

**Selenium + Dalfox**:
```python
from selenium import webdriver
import subprocess
import json

driver = webdriver.Chrome()
driver.get("https://example.com")

# Get URLs from Selenium
urls = [link.get_attribute('href') for link in driver.find_elements_by_tag_name('a')]

# Test with Dalfox
with open('urls.txt', 'w') as f:
    f.write('\n'.join(urls))

result = subprocess.run(['dalfox', 'scan', '-i', 'file', 'urls.txt', '-f', 'json'], 
                       capture_output=True, text=True)
findings = json.loads(result.stdout)
```

**Playwright + Dalfox**:
```javascript
const { chromium } = require('playwright');
const { execSync } = require('child_process');

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  await page.goto('https://example.com');
  
  const links = await page.$$eval('a', as => as.map(a => a.href));
  
  // Save URLs
  require('fs').writeFileSync('urls.txt', links.join('\n'));
  
  // Run Dalfox
  const result = execSync('dalfox scan -i file urls.txt -f json').toString();
  const findings = JSON.parse(result);
  
  console.log(`Found ${findings.length} XSS vulnerabilities`);
  await browser.close();
})();
```

## REST API Integration

**Python Script**:
```python
import requests
import time

# Start server mode
# dalfox server --api-key secret

API_URL = "http://localhost:6664"
API_KEY = "secret"

def scan_url(url):
    # Submit scan
    response = requests.post(
        f"{API_URL}/scan",
        headers={"X-API-KEY": API_KEY},
        json={"url": url, "options": {"worker": 50}}
    )
    scan_id = response.json()["msg"]
    
    # Poll for results
    while True:
        result = requests.get(
            f"{API_URL}/result/{scan_id}",
            headers={"X-API-KEY": API_KEY}
        ).json()
        
        if result["data"]["status"] == "done":
            return result["data"]["results"]
        
        time.sleep(2)

# Use in pipeline
urls = ["https://example.com", "https://test.com"]
for url in urls:
    findings = scan_url(url)
    print(f"{url}: {len(findings)} findings")
```

## Best Practices

### 1. Filter Input

Pre-filter URLs to reduce noise:
```bash
gau example.com | \
  grep -E "\?(.*=|.*%)" | \
  grep -v -E "\.(jpg|png|css|js|svg|ico)$" | \
  dalfox scan -i pipe
```

### 2. Use Silence Mode

Reduce output in pipelines:
```bash
cat urls.txt | dalfox scan -i pipe -S -f json
```

### 3. Handle Errors

```bash
cat urls.txt | dalfox scan -i pipe 2> errors.log -f json -o results.json
```

### 4. Batch Processing

For large URL sets:
```bash
split -l 100 urls.txt batch_
for f in batch_*; do
  dalfox scan -i file $f -f jsonl >> all_results.jsonl
done
```

### 5. Parallel Execution

```bash
cat urls.txt | parallel -j 4 "dalfox scan {} -f json" | jq -s 'add' > results.json
```

## See Also

- [Scan Command](/usage/commands/scan)
- [Server Command](/usage/commands/server)
- [Examples](/usage/examples)
- [Performance Optimization](/advanced/performance_optimization)
