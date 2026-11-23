package server

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/labstack/echo/v4"
)

// requestSourceGuard rejects requests that a web page the operator merely
// visits could send. Binding to loopback keeps the network out, not the
// operator's own browser. It is installed only when no API key is set.
// Non-browser clients send no Origin or Sec-Fetch-Site, so only the Host
// check applies to them: addressing the server by a name other than
// localhost or --host needs --allowed-hosts. See GHSA-c98c-mph6-6hm9.
func requestSourceGuard(options *model.Options) echo.MiddlewareFunc {
	origins := newOriginMatcher(options.AllowedOrigins)
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			req := c.Request()
			// Host first: the same-origin allowance in checkCrossSite is only
			// sound once the Host is known not to be a rebound name.
			if reason := checkHost(req, options); reason != "" {
				return denySource(c, options, reason)
			}
			if reason := checkCrossSite(req, options, origins); reason != "" {
				return denySource(c, options, reason)
			}
			return next(c)
		}
	}
}

func denySource(c echo.Context, options *model.Options, reason string) error {
	res := Res{Code: http.StatusForbidden, Msg: "Forbidden: " + reason}
	return respondJSONorJSONP(c, http.StatusForbidden, res, options)
}

// checkCrossSite blocks cross-site browser requests, the ones a page can send
// without a CORS preflight (<img>, <script>, <form>). Today none of them can
// start a scan (POST /scan needs a JSON body), so this is defence in depth
// that keeps it that way as routes change.
func checkCrossSite(req *http.Request, options *model.Options, origins originMatcher) string {
	// JSONP exists to be read cross-origin through <script src>, which sends
	// no Origin to validate; enabling it opts reads out of this check. Only
	// reads: <script> cannot POST or DELETE.
	if options.JSONP && (req.Method == http.MethodGet || req.Method == http.MethodHead) {
		return ""
	}
	if origin := req.Header.Get("Origin"); origin != "" {
		// Same-origin requests carry an Origin too (the bundled Swagger UI's
		// POST and DELETE calls do).
		if sameOrigin(origin, req.Host) || origins.allows(origin) {
			return ""
		}
		return "cross-site request (Origin: " + origin + ")"
	}
	// No Origin: fall back to fetch metadata. "none" is the operator typing
	// the URL; "same-origin" is a page served by this server.
	if site := strings.TrimSpace(req.Header.Get("Sec-Fetch-Site")); site != "" {
		if !strings.EqualFold(site, "same-origin") && !strings.EqualFold(site, "none") {
			return "cross-site request (Sec-Fetch-Site: " + site + ")"
		}
	}
	return ""
}

// sameOrigin reports whether origin names the host the request was sent to.
// Browsers omit default ports in Origin, while a Host header (or a proxy)
// may spell them out, so :80 / :443 are filled in on both sides.
func sameOrigin(origin, host string) bool {
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || host == "" {
		return false
	}
	defaultPort := "80"
	if u.Scheme == "https" {
		defaultPort = "443"
	}
	oh, op := splitHostPortDefault(u.Host, defaultPort)
	rh, rp := splitHostPortDefault(host, defaultPort)
	return strings.EqualFold(oh, rh) && op == rp
}

func splitHostPortDefault(authority, defaultPort string) (string, string) {
	if h, p, err := net.SplitHostPort(authority); err == nil {
		return hostName(h), p
	}
	return hostName(authority), defaultPort
}

// originMatcher accepts exactly what --allowed-origins lets through the echo
// CORS middleware: "*", exact origins, and '*' / '?' wildcards. Keep the two
// in step: anything this accepts that CORS rejects still runs server-side.
type originMatcher struct {
	any      bool
	exact    []string
	patterns []*regexp.Regexp
}

func newOriginMatcher(allowed []string) originMatcher {
	var m originMatcher
	for _, a := range allowed {
		a = strings.TrimSpace(a)
		if a == "*" {
			m.any = true
			continue
		}
		m.exact = append(m.exact, a)
		pattern := regexp.QuoteMeta(a)
		pattern = strings.ReplaceAll(pattern, `\*`, ".*")
		pattern = strings.ReplaceAll(pattern, `\?`, ".")
		if re, err := regexp.Compile("^" + pattern + "$"); err == nil {
			m.patterns = append(m.patterns, re)
		}
	}
	return m
}

func (m originMatcher) allows(origin string) bool {
	if m.any {
		return true
	}
	for _, e := range m.exact {
		if e == origin {
			return true
		}
	}
	// Same pre-check as echo CORS before it tries patterns.
	if len(origin) > 253+3+5 || !strings.Contains(origin, "://") {
		return false
	}
	for _, re := range m.patterns {
		if re.MatchString(origin) {
			return true
		}
	}
	return false
}

// checkHost stops DNS rebinding: after evil.example re-resolves to
// 127.0.0.1 the browser treats requests as same-origin and sends no Origin,
// so only the Host header still names the attacker. An IP literal cannot be
// rebound; a name must be localhost, the bind host, or in --allowed-hosts.
func checkHost(req *http.Request, options *model.Options) string {
	authority := strings.TrimSpace(req.Host)
	if authority == "" {
		return ""
	}
	name := hostName(authority)
	if name == "" {
		return "untrusted Host header (" + authority + ")"
	}
	if net.ParseIP(name) != nil || strings.EqualFold(name, "localhost") {
		return ""
	}
	if strings.EqualFold(name, hostName(options.ServerHost)) {
		return ""
	}
	for _, h := range options.AllowedHosts {
		if strings.EqualFold(hostName(h), name) {
			return ""
		}
	}
	return "untrusted Host header (" + authority + "); add it with --allowed-hosts"
}

// hostName reduces a Host header or a configured host to a bare name: no
// port, no IPv6 brackets, no trailing root dot.
func hostName(authority string) string {
	name := strings.TrimSpace(authority)
	if h, _, err := net.SplitHostPort(name); err == nil {
		name = h
	}
	name = strings.TrimSuffix(strings.TrimPrefix(name, "["), "]")
	return strings.TrimSuffix(name, ".")
}

// isLoopbackHost reports whether the bind address only accepts local
// connections. An empty host binds every interface.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"))
	return ip != nil && ip.IsLoopback()
}

// serverExposureWarnings lists startup warnings for risky combinations.
func serverExposureWarnings(options *model.Options) []string {
	var warns []string
	if options.APIKey == "" && !isLoopbackHost(options.ServerHost) {
		warns = append(warns, fmt.Sprintf(
			"REST API is listening on %q without --api-key. Anyone who can reach this port can make dalfox send requests to any host it can reach, including internal ones. Set --api-key or bind to 127.0.0.1.",
			options.ServerHost))
	}
	if options.JSONP && options.APIKey == "" {
		warns = append(warns, "--jsonp is enabled without --api-key: any web page can read scan results through <script src>. Use it only on a trusted network.")
	}
	return warns
}

func printServerWarnings(options *model.Options) {
	for _, w := range serverExposureWarnings(options) {
		fmt.Fprintln(os.Stderr, "[WARN] "+w)
	}
}
