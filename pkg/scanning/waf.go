package scanning

import (
	"net/http"
	"regexp"
)

// WAFPattern is type of WAF Patterns
type WAFPattern struct {
	Name   string
	Body   string
	Header string
}

func checkWAF(header http.Header, body string) (bool, string) {
	var patterns []WAFPattern
	patterns = append(patterns, WAFPattern{
		Name:   "360 Web Application Firewall (360)",
		Body:   "/wzws-waf-cgi/",
		Header: "X-Powered-By-360wzb",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "aeSecure",
		Body:   "aesecure_denied.png",
		Header: "aeSecure-code",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "Airlock",
		Body:   "",
		Header: "AL[_-]?(SESS|LB)",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "Anquanbao Web Application Firewall",
		Body:   "",
		Header: "X-Powered-By-Anquanba",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "Armor Protection (Armor Defense)",
		Body:   "This request has been blocked by website protection from Armor",
		Header: "",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "Application Security Manager (F5 Networks)",
		Body:   "The requested URL was rejected. Please consult with your administrator.",
		Header: "",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "Amazon Web Services Web Application Firewall (Amazon)",
		Body:   "",
		Header: "AWS",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "Yunjiasu Web Application Firewall (Baidu)",
		Body:   "",
		Header: "yunjiasu-nginx",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "Barracuda Web Application Firewall (Barracuda Networks)",
		Body:   "",
		Header: "barra_counter_session=",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "BIG-IP Application Security Manager (F5 Networks)",
		Body:   "",
		Header: "BigIP",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "BinarySEC Web Application Firewall (BinarySEC)",
		Body:   "",
		Header: "binarysec",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "BlockDoS",
		Body:   "",
		Header: "BlockDos.net",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "ChinaCache (ChinaCache Networks)",
		Body:   "",
		Header: "Powered-By-ChinaCache",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "Cisco ACE XML Gateway (Cisco Systems)",
		Body:   "",
		Header: "ACE XML Gateway",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "Cloudbric Web Application Firewall (Cloudbric)",
		Body:   "Cloudbric",
		Header: "",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "CloudFlare Web Application Firewall (CloudFlare)",
		Body:   "Attention Required!",
		Header: "cloudflare|__cfduid=|cf-ray",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "CloudFront (Amazon)",
		Body:   "",
		Header: "Error from cloudfront",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "Comodo Web Application Firewall (Comodo)",
		Body:   "",
		Header: "Protected by COMODO WAF",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "CrawlProtect (Jean-Denis Brun)",
		Body:   "This site is protected by CrawlProtect",
		Header: "",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "IBM WebSphere DataPower (IBM)",
		Body:   "",
		Header: "X-Backside-Transport",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "Deny All Web Application Firewall (DenyAll)",
		Body:   "Condition Intercepted",
		Header: "sessioncookie",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "Distil Web Application Firewall Security (Distil Networks)",
		Body:   "",
		Header: "x-distil-cs",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "DOSarrest (DOSarrest Internet Security)",
		Body:   "",
		Header: "DOSarrest|X-DIS-Request-ID",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "dotDefender (Applicure Technologies)",
		Body:   "dotDefender Blocked Your Request",
		Header: "X-dotDefender-denied",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "EdgeCast Web Application Firewall (Verizon)",
		Body:   "",
		Header: "SERVER.*?ECDF",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "ExpressionEngine (EllisLab)",
		Body:   "Invalid (GET|POST) Data",
		Header: "",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "FortiWeb Web Application Firewall (Fortinet)",
		Body:   "",
		Header: "FORTIWAFSID=|cookiesession1=",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "Hyperguard Web Application Firewall (art of defence)",
		Body:   "",
		Header: "ODSESSION=",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "Incapsula Web Application Firewall (Incapsula/Imperva)",
		Body:   "",
		Header: "X-Iinfo|incap_ses|visid_incap",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "ISA Server (Microsoft)",
		Body:   "The server denied the specified Uniform Resource Locator (URL)",
		Header: "",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "Jiasule Web Application Firewall (Jiasule)",
		Body:   "",
		Header: "jiasule-WAF|__jsluid=|jsl_tracking",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "KS-WAF (Knownsec)",
		Body:   "ks-waf-error.png'",
		Header: "",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "KONA Security Solutions (Akamai Technologies)",
		Body:   "",
		Header: "AkamaiGHost",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "ModSecurity: Open Source Web Application Firewall (Trustwave)",
		Body:   "",
		Header: "Mod_Security|NOYB",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "NAXSI (NBS System)",
		Body:   "",
		Header: "NCI__SessionId=",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "NetScaler (Citrix Systems)",
		Body:   "",
		Header: "ns_af=|citrix_ns_id|NSC_|NS-CACHE",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "Newdefend Web Application Firewall (Newdefend)",
		Body:   "",
		Header: "newdefend",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "NSFOCUS Web Application Firewall (NSFOCUS)",
		Body:   "",
		Header: "NSFocus",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "Palo Alto Firewall (Palo Alto Networks)",
		Body:   "has been blocked in accordance with company policy",
		Header: "",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "Profense Web Application Firewall (Armorlogic)",
		Body:   "",
		Header: "PLBSID=|Profense",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "AppWall (Radware)",
		Body:   "Unauthorized Activity Has Been Detected",
		Header: "X-SL-CompState",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "Reblaze Web Application Firewall (Reblaze)",
		Body:   "",
		Header: "rbzid=|Reblaze Secure Web Gateway",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "ASP.NET RequestValidationMode (Microsoft)",
		Body:   "ASP.NET has detected data in the request that is potentially dangerous|Request Validation has detected a potentially dangerous client input value|HttpRequestValidationException",
		Header: "",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "Safe3 Web Application Firewall",
		Body:   "",
		Header: "Safe3",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "Safedog Web Application Firewall (Safedog)",
		Body:   "",
		Header: "WAF/2.0|safedog",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "SecureIIS Web Server Security (BeyondTrust)",
		Body:   "SecureIIS.*?Web Server Protection|http://www.eeye.com/SecureIIS/|?subject=[^>]*SecureIIS Error",
		Header: "",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "SEnginx (Neusoft Corporation)",
		Body:   "SENGINX-ROBOT-MITIGATION",
		Header: "",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "TrueShield Web Application Firewall (SiteLock)",
		Body:   "SiteLock Incident ID|sitelock-site-verification|sitelock_shield_logo",
		Header: "",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "SonicWALL (Dell)",
		Body:   "This request is blocked by the SonicWALL|#shd|#nsa_banner|Web Site Blocked.*?nsa_banner",
		Header: "SonicWALL",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "UTM Web Protection (Sophos)",
		Body:   "Powered by UTM Web Protection",
		Header: "",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "Stingray Application Firewall (Riverbed / Brocade)",
		Body:   "",
		Header: "X-Mapping-",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "CloudProxy WebSite Firewall (Sucuri)",
		Body:   "Access Denied.*?Sucuri Website Firewall|Sucuri WebSite Firewall.*?Access Denied|Questions?.*?cloudproxy@sucuri.net",
		Header: "Sucuri/Cloudproxy|X-Sucuri",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "Tencent Cloud Web Application Firewall (Tencent Cloud Computing)",
		Body:   "waf.tencent-cloud.com",
		Header: "",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "Teros/Citrix Application Firewall Enterprise (Teros/Citrix Systems)",
		Body:   "",
		Header: "st8(id|_wat|_wlf)",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "TrafficShield (F5 Networks)",
		Body:   "",
		Header: "F5-TrafficShield|ASINFO=",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "UrlScan (Microsoft)",
		Body:   "Rejected-By-UrlScan",
		Header: "Rejected-By-UrlScan",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "USP Secure Entry Server (United Security Providers)",
		Body:   "",
		Header: "Secure Entry Server",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "Varnish FireWall (OWASP)",
		Body:   "Request rejected by xVarnish-WAF",
		Header: "",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "Wallarm Web Application Firewall (Wallarm)",
		Body:   "",
		Header: "nginx-wallarm",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "WatchGuard (WatchGuard Technologies)",
		Body:   "",
		Header: "WatchGuard",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "WebKnight Application Firewall (AQTRONIX)",
		Body:   "WebKnight Application Firewall Alert|AQTRONIX WebKnight",
		Header: "WebKnight",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "Wordfence (Feedjit)",
		Body:   "This response was generated by Wordfence|Your access to this site has been limited",
		Header: "",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "Zenedge Web Application Firewall (Zenedge)",
		Body:   "",
		Header: "ZENEDGE",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "Yundun Web Application Firewall (Yundun)",
		Body:   "",
		Header: "YUNDUN",
	})
	patterns = append(patterns, WAFPattern{
		Name:   "Yunsuo Web Application Firewall (Yunsuo)",
		Body:   "",
		Header: "yunsuo_session",
	})

	for _, p := range patterns {
		matchBody := false
		matchHeader := false
		if p.Body != "" {
			matchBody, _ = regexp.MatchString(p.Body, body)
		}
		if p.Header != "" {
			for k, v := range header {
				km, _ := regexp.MatchString(p.Header, k)
				vm := false
				for _, vh := range v {
					headerValueMatch, _ := regexp.MatchString(p.Header, vh)
					if headerValueMatch {
						vm = true
					}
				}
				matchHeader = km || vm
			}
		}

		if matchBody || matchHeader {
			return true, p.Name
		}
	}
	return false, ""
}
