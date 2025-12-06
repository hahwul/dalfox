# SARIF Output Format Support

Dalfox now supports outputting scan results in SARIF (Static Analysis Results Interchange Format) v2.1.0, a standardized JSON format for static analysis tools.

## What is SARIF?

SARIF is an OASIS standard format designed to streamline the sharing of results from static analysis tools. It provides a common format that can be:
- Consumed by various security tools and CI/CD platforms
- Integrated with code review systems like GitHub, GitLab, and Azure DevOps
- Analyzed by security dashboards and reporting tools
- Archived for compliance and audit purposes

Specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

## Usage

Use the `-f sarif` or `--format sarif` flag to output results in SARIF format:

```bash
# Basic usage
dalfox scan https://example.com -f sarif

# Save to file
dalfox scan https://example.com -f sarif -o results.sarif

# Include HTTP request/response in SARIF properties
dalfox scan https://example.com -f sarif --include-request --include-response

# Pipe mode
cat urls.txt | dalfox scan -f sarif

# File mode
dalfox scan -i file -f sarif urls.txt
```

## SARIF Output Structure

The SARIF output includes:

### Tool Information
- **Name**: Dalfox
- **Version**: Current version from Cargo.toml
- **Information URI**: GitHub repository URL
- **Rules**: Defined security rules (e.g., CWE-79 for XSS)

### Results
Each finding includes:
- **Rule ID**: `dalfox/cwe-79` (based on CWE)
- **Level**: Mapped from Dalfox severity:
  - High/Critical → `error`
  - Medium → `warning`
  - Low/Info → `note`
- **Message**: Description of the finding with optional evidence
- **Locations**: URL and payload snippet
- **Properties**: Additional metadata including:
  - `type`: V (Vulnerability) or R (Reflection)
  - `inject_type`: Context where XSS was found (inHTML, inJS, etc.)
  - `method`: HTTP method used
  - `param`: Parameter name
  - `payload`: The XSS payload that triggered the finding
  - `severity`: Original Dalfox severity level
  - `request`: Full HTTP request (if `--include-request` is used)
  - `response`: Full HTTP response (if `--include-response` is used)

## Example Output

```json
{
  "version": "2.1.0",
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Dalfox",
          "informationUri": "https://github.com/hahwul/dalfox",
          "version": "3.0.0-dev.1",
          "rules": [
            {
              "id": "dalfox/cwe-79",
              "name": "CrossSiteScripting",
              "shortDescription": {
                "text": "Cross-site Scripting (XSS)"
              },
              "fullDescription": {
                "text": "The application reflects user input in HTML responses without proper encoding, allowing attackers to inject malicious scripts."
              },
              "help": {
                "text": "Ensure all user input is properly encoded before being rendered in HTML context. Use context-aware output encoding based on where the data is placed (HTML body, attributes, JavaScript, CSS, or URL)."
              },
              "defaultConfiguration": {
                "level": "error"
              },
              "properties": {
                "tags": ["security", "xss", "injection"],
                "precision": "high"
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "dalfox/cwe-79",
          "ruleIndex": 0,
          "level": "error",
          "message": {
            "text": "XSS vulnerability detected. Evidence: Found script tag in response"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "https://example.com?q=test"
                },
                "region": {
                  "snippet": {
                    "text": "<script>alert(1)</script>"
                  }
                }
              }
            }
          ],
          "partialFingerprints": {
            "messageId": "606"
          },
          "properties": {
            "type": "V",
            "inject_type": "inHTML",
            "method": "GET",
            "param": "q",
            "payload": "<script>alert(1)</script>",
            "severity": "High"
          }
        }
      ]
    }
  ]
}
```

## Integration Examples

### GitHub Actions

```yaml
- name: Run Dalfox scan
  run: dalfox scan https://example.com -f sarif -o dalfox.sarif

- name: Upload SARIF results
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: dalfox.sarif
```

### GitLab CI

```yaml
dalfox-scan:
  script:
    - dalfox scan $TARGET_URL -f sarif -o gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

### Azure DevOps

The SARIF output can be uploaded and displayed in Azure DevOps using the SARIF SAST Scans Tab extension.

## Benefits

1. **Standardization**: SARIF is an industry standard, making it easier to integrate with various tools
2. **Rich Metadata**: Includes detailed information about findings, locations, and remediation guidance
3. **Tool Interoperability**: Results can be consumed by multiple security platforms
4. **CI/CD Integration**: Native support in GitHub, GitLab, and Azure DevOps
5. **Compliance**: Standardized format for security audits and compliance reporting

## Comparison with Other Formats

| Feature | SARIF | JSON | JSONL | Plain | Markdown |
|---------|-------|------|-------|-------|----------|
| Structured | ✅ | ✅ | ✅ | ❌ | ⚠️ |
| Industry Standard | ✅ | ❌ | ❌ | ❌ | ❌ |
| CI/CD Native Support | ✅ | ❌ | ❌ | ❌ | ⚠️ |
| Human Readable | ⚠️ | ⚠️ | ❌ | ✅ | ✅ |
| Tool Metadata | ✅ | ❌ | ❌ | ❌ | ❌ |
| Rule Definitions | ✅ | ❌ | ❌ | ❌ | ❌ |
| Stream Processing | ❌ | ❌ | ✅ | ❌ | ❌ |
| Pretty Output | ❌ | ✅ | ❌ | ✅ | ✅ |

## See Also

- [SARIF Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [SARIF Tutorials](https://github.com/microsoft/sarif-tutorials)
- [GitHub Code Scanning](https://docs.github.com/en/code-security/code-scanning)
- [Dalfox Documentation](https://github.com/hahwul/dalfox)
