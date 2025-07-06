package cmd

// Args represents the command-line arguments and configuration options for DalFox
type Args struct {
	// String slice options
	Header       []string // Custom HTTP headers to add to requests
	P            []string // Parameters to test for XSS vulnerabilities
	IgnoreParams []string // Parameters to ignore during scanning

	// String options
	Config                    string // Path to configuration file
	Cookie                    string // Custom cookies for HTTP requests
	Data                      string // POST data for requests
	CustomPayload             string // Path to custom payload file
	CustomAlertValue          string // Custom value for XSS alert function
	CustomAlertType           string // Type of custom alert (str, none, etc.)
	UserAgent                 string // Custom User-Agent header
	Blind                     string // Blind XSS callback URL
	Output                    string // Output file path
	Format                    string // Output format (plain, json, jsonl)
	FoundAction               string // Command to execute when vulnerability is found
	FoundActionShell          string // Shell for executing found action
	Proxy                     string // Proxy server URL
	Grep                      string // Custom grep patterns file
	IgnoreReturn              string // HTTP status codes to ignore
	MiningWord                string // Custom wordlist for parameter mining
	Method                    string // HTTP method (GET, POST, etc.)
	CookieFromRaw             string // Load cookies from raw HTTP request file
	RemotePayloads            string // Remote payload sources
	RemoteWordlists           string // Remote wordlist sources
	OnlyPoC                   string // Show only PoC for specific patterns
	PoCType                   string // PoC output format
	ReportFormat              string // Report format (plain, json, markdown, md)
	HarFilePath               string // Path to save HAR files
	CustomBlindXSSPayloadFile string // Path to custom blind XSS payload file

	// Integer options
	Timeout     int // Request timeout in seconds
	Delay       int // Delay between requests in milliseconds
	Concurrence int // Number of concurrent workers
	MaxCPU      int // Maximum CPU cores to use

	// Boolean options
	OnlyDiscovery             bool // Only perform parameter discovery
	Silence                   bool // Minimal output mode
	Mining                    bool // Enable parameter mining
	FindingDOM                bool // Enable DOM-based parameter mining
	FollowRedirect            bool // Follow HTTP redirects
	NoColor                   bool // Disable colored output
	NoSpinner                 bool // Disable spinner animation
	UseBAV                    bool // Enable Basic Another Vulnerability scanning
	SkipBAV                   bool // Skip Basic Another Vulnerability scanning
	SkipMiningDom             bool // Skip DOM-based parameter mining
	SkipMiningDict            bool // Skip dictionary-based parameter mining
	SkipMiningAll             bool // Skip all parameter mining
	SkipXSSScan               bool // Skip XSS scanning
	OnlyCustomPayload         bool // Use only custom payloads
	SkipGrep                  bool // Skip built-in grepping
	Debug                     bool // Enable debug mode
	SkipHeadless              bool // Skip headless browser tests
	UseDeepDXSS               bool // Enable deep DOM XSS testing
	OutputAll                 bool // Write all output
	WAFEvasion                bool // Enable WAF evasion techniques
	ReportBool                bool // Generate detailed report
	OutputRequest             bool // Include HTTP requests in output
	OutputResponse            bool // Include HTTP responses in output
	SkipDiscovery             bool // Skip parameter discovery phase
	ForceHeadlessVerification bool // Force headless browser verification
	DetailedAnalysis          bool // Enable detailed parameter analysis (Issue #695)
	FastScan                  bool // Enable fast scanning mode for URL lists (Issue #764)
	MagicCharTest             bool // Enable magic character testing
	ContextAware              bool // Enable context-aware payload selection
}
