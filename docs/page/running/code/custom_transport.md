---
title: Custom Tranport Feature
redirect_from: /docs/code/custom_tranport
parent: In the Code
nav_order: 1
toc: true
layout: page
---

# Custom Transport Feature
{: .d-inline-block }

New (v2.10.0) 
{: .label .label-blue }

Dalfox now supports custom HTTP transports, allowing you to customize the HTTP client behavior for your scanning needs. This feature is particularly useful when integrating Dalfox with other pipelines for HTTP control flow, retry mechanisms, and non-trivial authentication scenarios.

## What is a Transport?

In Go's HTTP client, a transport specifies how HTTP requests are made. It handles details like connection pooling, timeouts, TLS configuration, and more. By customizing the transport, you can control how Dalfox makes HTTP requests.

## Benefits for Pipeline Integration

Custom transports provide several benefits when integrating Dalfox into larger security testing pipelines:

1. **HTTP Control Flow**: Customize how requests are made, including adding custom headers, modifying request bodies, or implementing custom routing logic.
2. **Retry Mechanisms**: Implement resilient scanning by automatically retrying failed requests with configurable backoff strategies.
3. **Authentication**: Handle complex authentication flows like OAuth2, JWT, or custom token-based authentication.
4. **Rate Limiting**: Control the rate of requests to avoid being blocked by target systems.
5. **Logging and Monitoring**: Add custom logging or monitoring to track requests and responses.
6. **Proxy Integration**: Seamlessly integrate with custom proxy solutions or service meshes.

## How to Use Custom Transports

### 1. Using a Custom Transport with a Custom TLS Configuration

```go
// Create a custom transport with a custom TLS configuration
customTransport := scanning.CreateDefaultTransport(10) // 10 seconds timeout
customTransport.TLSClientConfig = &tls.Config{
    InsecureSkipVerify: true,
    MinVersion:         tls.VersionTLS12,
    MaxVersion:         tls.VersionTLS13,
}

// Create options with the custom transport
options := model.Options{
    CustomTransport: customTransport,
    Timeout:         10,
}

// Use the options in a scan
Scan("https://example.com", options, "1")
```

### 2. Using a Transport Chain

You can chain multiple transports together to apply multiple transformations to your requests:

```go
// Create a base transport
baseTransport := scanning.CreateDefaultTransport(10)

// Create multiple header transports
headerTransport1 := &scanning.HeaderTransport{
    Transport: baseTransport,
    Headers: map[string]string{
        "X-Custom-Header1": "Value1",
    },
}

headerTransport2 := &scanning.HeaderTransport{
    Transport: baseTransport,
    Headers: map[string]string{
        "X-Custom-Header2": "Value2",
    },
}

// Create a transport chain with both transports
transportChain := scanning.CreateTransportChain(headerTransport1, headerTransport2)

// Create options with the transport chain
options := model.Options{
    CustomTransport: transportChain,
    Timeout:         10,
}

// Use the options in a scan
Scan("https://example.com", options, "1")
```

### 3. Using a Retry Transport for Resilient Scanning

Implement automatic retries for failed requests:

```go
// Create a base transport
baseTransport := scanning.CreateDefaultTransport(10)

// Create a retry transport
retryTransport := &scanning.RetryTransport{
    Transport:    baseTransport,
    MaxRetries:   3,
    RetryDelay:   time.Second,
    RetryBackoff: 2, // Exponential backoff
}

// Create options with the retry transport
options := model.Options{
    CustomTransport: retryTransport,
    Timeout:         10,
}

// Use the options in a scan
Scan("https://example.com", options, "1")
```

### 4. Using an OAuth2 Transport for Authenticated Scanning

Handle OAuth2 authentication flows:

```go
// Create a base transport
baseTransport := scanning.CreateDefaultTransport(10)

// Create an OAuth2 transport
oauth2Transport := &scanning.OAuth2Transport{
    Transport:     baseTransport,
    TokenEndpoint: "https://auth.example.com/token",
    ClientID:      "client_id",
    ClientSecret:  "client_secret",
    Scope:         "read write",
}

// Create options with the OAuth2 transport
options := model.Options{
    CustomTransport: oauth2Transport,
    Timeout:         10,
}

// Use the options in a scan
Scan("https://example.com", options, "1")
```

### 5. Using a Rate Limiting Transport

Control the rate of requests to avoid being blocked:

```go
// Create a base transport
baseTransport := scanning.CreateDefaultTransport(10)

// Create a rate limit transport
rateLimitTransport := &scanning.RateLimitTransport{
    Transport:      baseTransport,
    RequestsPerSec: 5, // 5 requests per second
}

// Create options with the rate limit transport
options := model.Options{
    CustomTransport: rateLimitTransport,
    Timeout:         10,
}

// Use the options in a scan
Scan("https://example.com", options, "1")
```

### 6. Using a Logging Transport for Debugging

Add detailed logging for debugging:

```go
// Create a base transport
baseTransport := scanning.CreateDefaultTransport(10)

// Create a logging transport
loggingTransport := &scanning.LoggingTransport{
    Transport: baseTransport,
    LogWriter: os.Stdout, // Or any io.Writer
}

// Create options with the logging transport
options := model.Options{
    CustomTransport: loggingTransport,
    Timeout:         10,
}

// Use the options in a scan
Scan("https://example.com", options, "1")
```

## Creating Your Own Custom Transport

You can create your own custom transport by implementing the `http.RoundTripper` interface:

```go
// MyCustomTransport is a custom transport that does something special
type MyCustomTransport struct {
    Transport http.RoundTripper
    // Add any fields you need
}

// RoundTrip implements the http.RoundTripper interface
func (t *MyCustomTransport) RoundTrip(req *http.Request) (*http.Response, error) {
    // Clone the request to avoid modifying the original
    reqClone := req.Clone(req.Context())

    // Do something special with the request
    // ...

    // Use the underlying transport
    return t.Transport.RoundTrip(reqClone)
}
```

## Integration Examples

### Integrating with a Corporate Proxy

```go
// Create a base transport
baseTransport := scanning.CreateDefaultTransport(10)

// Configure the proxy
baseTransport.Proxy = http.ProxyURL(&url.URL{
    Scheme: "http",
    Host:   "corporate-proxy.example.com:8080",
    User:   url.UserPassword("username", "password"),
})

// Create options with the proxy transport
options := model.Options{
    CustomTransport: baseTransport,
    Timeout:         10,
}

// Use the options in a scan
Scan("https://example.com", options, "1")
```

### Integrating with a CI/CD Pipeline

```go
// Create a base transport
baseTransport := scanning.CreateDefaultTransport(10)

// Create a CI/CD integration transport
cicdTransport := &CICDTransport{
    Transport:  baseTransport,
    BuildID:    os.Getenv("CI_BUILD_ID"),
    JobID:      os.Getenv("CI_JOB_ID"),
    ResultsAPI: "https://ci-results.example.com/api/v1/results",
}

// Create options with the CI/CD transport
options := model.Options{
    CustomTransport: cicdTransport,
    Timeout:         10,
}

// Use the options in a scan
Scan("https://example.com", options, "1")
```

## Notes

- If you provide a custom transport, Dalfox will still apply proxy settings if specified, but only if your transport is of type `*http.Transport`.
- If you provide a custom transport, Dalfox will still apply the HAR writer if specified.
- The custom transport feature is designed to be used with the library mode of Dalfox. If you're using the CLI, you'll need to create a custom application that uses the library mode.
- When implementing custom transports, always clone the request before modifying it to avoid side effects.
- For complex authentication flows, consider implementing a transport that handles token refresh and retry logic. 