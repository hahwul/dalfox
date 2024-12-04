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

var patterns = []WAFPattern{
	{Name: "360 Web Application Firewall (360)", Body: "/wzws-waf-cgi/", Header: "X-Powered-By-360wzb"},
	{Name: "aeSecure", Body: "aesecure_denied.png", Header: "aeSecure-code"},
	{Name: "Airlock", Body: "", Header: "AL[_-]?(SESS|LB)"},
	{Name: "Anquanbao Web Application Firewall", Body: "", Header: "X-Powered-By-Anquanba"},
	{Name: "Armor Protection (Armor Defense)", Body: "This request has been blocked by website protection from Armor", Header: ""},
	{Name: "Application Security Manager (F5 Networks)", Body: "The requested URL was rejected. Please consult with your administrator.", Header: ""},
	{Name: "Amazon Web Services Web Application Firewall (Amazon)", Body: "", Header: "AWS"},
	{Name: "Yunjiasu Web Application Firewall (Baidu)", Body: "", Header: "yunjiasu-nginx"},
	{Name: "Barracuda Web Application Firewall (Barracuda Networks)", Body: "", Header: "barra_counter_session="},
	{Name: "BIG-IP Application Security Manager (F5 Networks)", Body: "", Header: "BigIP"},
	{Name: "BinarySEC Web Application Firewall (BinarySEC)", Body: "", Header: "binarysec"},
	{Name: "BlockDoS", Body: "", Header: "BlockDos.net"},
	{Name: "ChinaCache (ChinaCache Networks)", Body: "", Header: "Powered-By-ChinaCache"},
	{Name: "Cisco ACE XML Gateway (Cisco Systems)", Body: "", Header: "ACE XML Gateway"},
	{Name: "Cloudbric Web Application Firewall (Cloudbric)", Body: "Cloudbric", Header: ""},
	{Name: "CloudFlare Web Application Firewall (CloudFlare)", Body: "Attention Required!", Header: "cloudflare|__cfduid=|cf-ray"},
	{Name: "CloudFront (Amazon)", Body: "", Header: "Error from cloudfront"},
	{Name: "Comodo Web Application Firewall (Comodo)", Body: "", Header: "Protected by COMODO WAF"},
	{Name: "CrawlProtect (Jean-Denis Brun)", Body: "This site is protected by CrawlProtect", Header: ""},
	{Name: "IBM WebSphere DataPower (IBM)", Body: "", Header: "X-Backside-Transport"},
	{Name: "Deny All Web Application Firewall (DenyAll)", Body: "Condition Intercepted", Header: "sessioncookie"},
	{Name: "Distil Web Application Firewall Security (Distil Networks)", Body: "", Header: "x-distil-cs"},
	{Name: "DOSarrest (DOSarrest Internet Security)", Body: "", Header: "DOSarrest|X-DIS-Request-ID"},
	{Name: "dotDefender (Applicure Technologies)", Body: "dotDefender Blocked Your Request", Header: "X-dotDefender-denied"},
	{Name: "EdgeCast Web Application Firewall (Verizon)", Body: "", Header: "SERVER.*?ECDF"},
	{Name: "ExpressionEngine (EllisLab)", Body: "Invalid (GET|POST) Data", Header: ""},
	{Name: "FortiWeb Web Application Firewall (Fortinet)", Body: "", Header: "FORTIWAFSID=|cookiesession1="},
	{Name: "Hyperguard Web Application Firewall (art of defence)", Body: "", Header: "ODSESSION="},
	{Name: "Incapsula Web Application Firewall (Incapsula/Imperva)", Body: "", Header: "X-Iinfo|incap_ses|visid_incap"},
	{Name: "ISA Server (Microsoft)", Body: "The server denied the specified Uniform Resource Locator (URL)", Header: ""},
	{Name: "Jiasule Web Application Firewall (Jiasule)", Body: "", Header: "jiasule-WAF|__jsluid=|jsl_tracking"},
	{Name: "KS-WAF (Knownsec)", Body: "ks-waf-error.png'", Header: ""},
	{Name: "KONA Security Solutions (Akamai Technologies)", Body: "", Header: "AkamaiGHost"},
	{Name: "ModSecurity: Open Source Web Application Firewall (Trustwave)", Body: "", Header: "Mod_Security|NOYB"},
	{Name: "NAXSI (NBS System)", Body: "", Header: "NCI__SessionId="},
	{Name: "NetScaler (Citrix Systems)", Body: "", Header: "ns_af=|citrix_ns_id|NSC_|NS-CACHE"},
	{Name: "Newdefend Web Application Firewall (Newdefend)", Body: "", Header: "newdefend"},
	{Name: "NSFOCUS Web Application Firewall (NSFOCUS)", Body: "", Header: "NSFocus"},
	{Name: "Palo Alto Firewall (Palo Alto Networks)", Body: "has been blocked in accordance with company policy", Header: ""},
	{Name: "Profense Web Application Firewall (Armorlogic)", Body: "", Header: "PLBSID=|Profense"},
	{Name: "AppWall (Radware)", Body: "Unauthorized Activity Has Been Detected", Header: "X-SL-CompState"},
	{Name: "Reblaze Web Application Firewall (Reblaze)", Body: "", Header: "rbzid=|Reblaze Secure Web Gateway"},
	{Name: "ASP.NET RequestValidationMode (Microsoft)", Body: "ASP.NET has detected data in the request that is potentially dangerous|Request Validation has detected a potentially dangerous client input value|HttpRequestValidationException", Header: ""},
	{Name: "Safe3 Web Application Firewall", Body: "", Header: "Safe3"},
	{Name: "Safedog Web Application Firewall (Safedog)", Body: "", Header: "WAF/2.0|safedog"},
	{Name: "SecureIIS Web Server Security (BeyondTrust)", Body: "SecureIIS.*?Web Server Protection|http://www.eeye.com/SecureIIS/|?subject=[^>]*SecureIIS Error", Header: ""},
	{Name: "SEnginx (Neusoft Corporation)", Body: "SENGINX-ROBOT-MITIGATION", Header: ""},
	{Name: "TrueShield Web Application Firewall (SiteLock)", Body: "SiteLock Incident ID|sitelock-site-verification|sitelock_shield_logo", Header: ""},
	{Name: "SonicWALL (Dell)", Body: "This request is blocked by the SonicWALL|#shd|#nsa_banner|Web Site Blocked.*?nsa_banner", Header: "SonicWALL"},
	{Name: "UTM Web Protection (Sophos)", Body: "Powered by UTM Web Protection", Header: ""},
	{Name: "Stingray Application Firewall (Riverbed / Brocade)", Body: "", Header: "X-Mapping-"},
	{Name: "CloudProxy WebSite Firewall (Sucuri)", Body: "Access Denied.*?Sucuri Website Firewall|Sucuri WebSite Firewall.*?Access Denied|Questions?.*?cloudproxy@sucuri.net", Header: "Sucuri/Cloudproxy|X-Sucuri"},
	{Name: "Tencent Cloud Web Application Firewall (Tencent Cloud Computing)", Body: "waf.tencent-cloud.com", Header: ""},
	{Name: "Teros/Citrix Application Firewall Enterprise (Teros/Citrix Systems)", Body: "", Header: "st8(id|_wat|_wlf)"},
	{Name: "TrafficShield (F5 Networks)", Body: "", Header: "F5-TrafficShield|ASINFO="},
	{Name: "UrlScan (Microsoft)", Body: "Rejected-By-UrlScan", Header: "Rejected-By-UrlScan"},
	{Name: "USP Secure Entry Server (United Security Providers)", Body: "", Header: "Secure Entry Server"},
	{Name: "Varnish FireWall (OWASP)", Body: "Request rejected by xVarnish-WAF", Header: ""},
	{Name: "Wallarm Web Application Firewall (Wallarm)", Body: "", Header: "nginx-wallarm"},
	{Name: "WatchGuard (WatchGuard Technologies)", Body: "", Header: "WatchGuard"},
	{Name: "WebKnight Application Firewall (AQTRONIX)", Body: "WebKnight Application Firewall Alert|AQTRONIX WebKnight", Header: "WebKnight"},
	{Name: "Wordfence (Feedjit)", Body: "This response was generated by Wordfence|Your access to this site has been limited", Header: ""},
	{Name: "Zenedge Web Application Firewall (Zenedge)", Body: "", Header: "ZENEDGE"},
	{Name: "Yundun Web Application Firewall (Yundun)", Body: "", Header: "YUNDUN"},
	{Name: "Yunsuo Web Application Firewall (Yunsuo)", Body: "", Header: "yunsuo_session"},
}

func checkWAF(header http.Header, body string) (bool, string) {
	for _, p := range patterns {
		matchBody := false
		matchHeader := false
		var err error

		if p.Body != "" {
			matchBody, err = regexp.MatchString(p.Body, body)
			if err != nil {
				continue
			}
		}

		if p.Header != "" {
			for k, v := range header {
				km, err := regexp.MatchString(p.Header, k)
				if err != nil {
					continue
				}
				if km {
					matchHeader = true
					break
				}
				for _, vh := range v {
					headerValueMatch, err := regexp.MatchString(p.Header, vh)
					if err != nil {
						continue
					}
					if headerValueMatch {
						matchHeader = true
						break
					}
				}
				if matchHeader {
					break
				}
			}
		}

		if matchBody || matchHeader {
			return true, p.Name
		}
	}
	return false, ""
}
