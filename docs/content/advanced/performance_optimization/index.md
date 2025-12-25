+++
title = "Performance Optimization"
description = "Optimize Dalfox for speed and efficiency"
weight = 1
sort_by = "weight"

[extra]
+++

Learn how to optimize Dalfox for maximum performance while maintaining reliability and effectiveness.

## Understanding Concurrency

Dalfox uses multiple levels of concurrency control:

1. **Workers** (`--workers`): Concurrent async tasks for parameter analysis (default: 50)
2. **Max Concurrent Targets** (`--max-concurrent-targets`): Global limit for scanning targets simultaneously (default: 50)
3. **Max Targets Per Host** (`--max-targets-per-host`): Per-host cap to avoid overwhelming single hosts (default: 100)

## High-Performance Configuration

### Fast Scanning

For maximum speed on robust targets:

```bash
dalfox scan -i file urls.txt \
  --workers 200 \
  --max-concurrent-targets 100 \
  --max-targets-per-host 500 \
  --timeout 5 \
  --delay 0
```

**Configuration File**:
```toml
workers = 200
max_concurrent_targets = 100
max_targets_per_host = 500
timeout = 5
delay = 0
```

### Balanced Performance

For most production scenarios:

```bash
dalfox scan -i file urls.txt \
  --workers 100 \
  --max-concurrent-targets 50 \
  --max-targets-per-host 200 \
  --timeout 10
```

### Rate-Limited Scanning

For sensitive or rate-limited targets:

```bash
dalfox scan https://example.com \
  --workers 5 \
  --max-concurrent-targets 2 \
  --delay 2000 \
  --timeout 30
```

## Optimization Strategies

### 1. Skip Unnecessary Phases

Skip discovery/mining when testing known parameters:

```bash
dalfox scan "https://example.com?id=1" \
  -p id \
  --skip-discovery \
  --skip-mining
```

Skip specific discovery types:
```bash
dalfox scan https://example.com \
  --skip-reflection-header \
  --skip-reflection-cookie \
  --skip-reflection-path
```

### 2. Use Preflight Checks

Dalfox automatically performs preflight HEAD requests to detect Content-Type and skip non-HTML content. Disable with `--deep-scan` only when necessary.

**Default behavior** (recommended):
- Skips `application/json`, `text/plain`, images, etc.
- Reads CSP headers for early filtering
- Fast rejection of non-vulnerable targets

**Deep scan** (slower, more thorough):
```bash
dalfox scan https://example.com --deep-scan
```

### 3. Optimize Encoder Selection

Choose minimal encoders for faster scanning:

```bash
# Fast: URL encoding only
dalfox scan https://example.com -e url

# Balanced: URL + HTML
dalfox scan https://example.com -e url,html

# Thorough: All encoders (slower)
dalfox scan https://example.com -e url,html,2url,base64

# No encoding (fastest)
dalfox scan https://example.com -e none
```

### 4. Remote Resource Management

Remote payloads/wordlists are fetched once per run. Use strategically:

```bash
# Skip remote resources for speed
dalfox scan https://example.com

# Use remote resources selectively
dalfox scan https://example.com --remote-payloads portswigger

# Full remote resources (slower initial load)
dalfox scan https://example.com \
  --remote-payloads portswigger,payloadbox \
  --remote-wordlists burp,assetnote
```

### 5. Host Grouping

Dalfox automatically groups targets by host and applies per-host limits. This prevents overwhelming single servers while maintaining global throughput.

**Automatic optimization**: Targets are distributed across hosts for optimal concurrency.

### 6. Timeout Tuning

Balance between speed and reliability:

```bash
# Aggressive (fast, may miss slow responses)
--timeout 5

# Balanced (default)
--timeout 10

# Conservative (slower, more reliable)
--timeout 30
```

### 7. Skip AST Analysis

AST-based DOM XSS analysis adds processing time. Skip for reflection-only testing:

```bash
dalfox scan https://example.com --skip-ast-analysis
```

## Performance Benchmarks

### Small Target Set (1-10 URLs)

**Recommended**:
```bash
--workers 50
--max-concurrent-targets 10
--timeout 10
```

**Time**: 30 seconds - 2 minutes per URL

### Medium Target Set (10-100 URLs)

**Recommended**:
```bash
--workers 100
--max-concurrent-targets 25
--max-targets-per-host 200
--timeout 10
```

**Time**: 1-5 minutes total

### Large Target Set (100-1000 URLs)

**Recommended**:
```bash
--workers 200
--max-concurrent-targets 50
--max-targets-per-host 300
--timeout 5
```

**Time**: 5-20 minutes total

### Massive Target Set (1000+ URLs)

**Recommended**:
```bash
--workers 200
--max-concurrent-targets 100
--max-targets-per-host 500
--timeout 5
--delay 0
--skip-mining
```

**Strategy**: Split into batches or use distributed scanning

## Resource Usage

### Memory

- Base: ~50MB
- Per concurrent target: ~5-10MB
- Remote resources: ~10-50MB (cached)

**Estimate**: 50MB + (concurrent_targets × 10MB)

### CPU

- Rust's async runtime efficiently uses available cores
- AST parsing is CPU-intensive (can be skipped with `--skip-ast-analysis`)
- Multiple workers scale across CPU cores

### Network

- Concurrent connections: workers × concurrent_targets
- Bandwidth: Depends on payload size and target responses
- Connection pooling: Handled by reqwest (HTTP client)

## Common Performance Issues

### Issue: Slow Scanning

**Symptoms**: Scanning takes much longer than expected

**Solutions**:
1. Increase `--workers` and `--max-concurrent-targets`
2. Reduce `--timeout` for faster targets
3. Skip mining: `--skip-mining`
4. Use `--skip-ast-analysis`
5. Reduce encoders: `-e url`

### Issue: Connection Timeouts

**Symptoms**: Many timeout errors

**Solutions**:
1. Increase `--timeout` value
2. Reduce concurrent connections
3. Add delay: `--delay 1000`
4. Check network/proxy configuration

### Issue: Rate Limiting

**Symptoms**: 429 responses or connection resets

**Solutions**:
1. Reduce workers: `--workers 5`
2. Add delay: `--delay 2000`
3. Reduce per-host limit: `--max-targets-per-host 50`
4. Lower global concurrency: `--max-concurrent-targets 10`

### Issue: Memory Usage

**Symptoms**: High memory consumption

**Solutions**:
1. Reduce `--max-concurrent-targets`
2. Process in batches
3. Skip remote resources
4. Use JSONL format for streaming output

## Best Practices

### 1. Start Conservative, Then Optimize

```bash
# First run: baseline
dalfox scan https://example.com

# Measure and adjust based on target behavior
```

### 2. Use Configuration Files

Save optimized settings for repeated use:

```toml
# ~/.config/dalfox/config.toml
workers = 100
max_concurrent_targets = 50
timeout = 10
encoders = ["url", "html"]
```

### 3. Profile Your Targets

- **Fast APIs**: High concurrency, low timeout
- **Slow Apps**: Lower concurrency, higher timeout
- **Rate-Limited**: Very low concurrency, add delay
- **Diverse Set**: Use defaults, let host grouping optimize

### 4. Monitor and Adjust

Watch for patterns:
- Frequent timeouts → Increase timeout or reduce concurrency
- Fast completion → Increase concurrency
- Rate limit errors → Add delay, reduce workers

### 5. Batch Large Scans

For 1000+ targets, split into batches:

```bash
split -l 100 urls.txt batch_

for batch in batch_*; do
  dalfox scan -i file $batch -f jsonl >> results.jsonl
done
```

## See Also

- [Configuration](/usage/configuration)
- [Examples](/usage/examples)
- [Pipelining](/advanced/pipelining)
