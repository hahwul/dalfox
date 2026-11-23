package server

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/labstack/echo/v4"
)

// requestSourceGuard rejects requests that a web page the operator merely
// visits could send. Binding to loopback keeps the network out, not the
// operator's own browser, so this runs whether or not an API key is set.
// Non-browser clients (curl, scripts, CI) send none of the headers checked
// here and are unaffected. See GHSA-c98c-mph6-6hm9.
func requestSourceGuard(options *model.Options) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			req := c.Request()
			if reason := checkHost(req, options); reason != "" {
				return denySource(c, options, reason)
			}
			if reason := checkCrossSite(req, options); reason != "" {
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

// checkCrossSite blocks cross-site browser requests. A form POST or <img>
// GET needs no CORS preflight, so without this any page could start a scan.
func checkCrossSite(req *http.Request, options *model.Options) string {
	// JSONP exists to be read cross-origin through <script src>, which sends
	// no Origin to validate; enabling it is an explicit opt-out.
	if options.JSONP {
		return ""
	}
	if origin := req.Header.Get("Origin"); origin != "" {
		if originAllowed(origin, options.AllowedOrigins) {
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

func originAllowed(origin string, allowed []string) bool {
	for _, a := range allowed {
		if a == "*" || strings.EqualFold(strings.TrimRight(a, "/"), origin) {
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
	name := authority
	if h, _, err := net.SplitHostPort(authority); err == nil {
		name = h
	}
	name = strings.TrimSuffix(strings.TrimPrefix(name, "["), "]")
	if net.ParseIP(name) != nil || strings.EqualFold(name, "localhost") {
		return ""
	}
	if strings.EqualFold(name, options.ServerHost) {
		return ""
	}
	for _, h := range options.AllowedHosts {
		if strings.EqualFold(strings.TrimSpace(h), name) {
			return ""
		}
	}
	return "untrusted Host header (" + authority + "); add it with --allowed-hosts"
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
		warns = append(warns, "--jsonp is enabled without --api-key: any web page can read scan results through <script src>.")
	}
	return warns
}

func printServerWarnings(options *model.Options) {
	for _, w := range serverExposureWarnings(options) {
		fmt.Fprintln(os.Stderr, "[WARN] "+w)
	}
}
