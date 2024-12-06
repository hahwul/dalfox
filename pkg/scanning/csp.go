package scanning

import (
	"strings"
)

// checkCSP is bypass CSP for StaticAnalysis
func checkCSP(policy string) string {
	domains := []string{
		".doubleclick.net", ".googleadservices.com", "cse.google.com", "accounts.google.com", "*.google.com",
		"www.blogger.com", "*.blogger.com", "translate.yandex.net", "api-metrika.yandex.ru", "api.vk.com",
		"*.vk.com", "*.yandex.ru", "*.yandex.net", "app-sjint.marketo.com", "app-e.marketo.com", "*.marketo.com",
		"detector.alicdn.com", "suggest.taobao.com", "ount.tbcdn.cn", "bebezoo.1688.com", "wb.amap.com",
		"a.sm.cn", "api.m.sm.cn", "*.alicdn.com", "*.taobao.com", "*.tbcdn.cn", "*.1688.com", "*.amap.com",
		"*.sm.cn", "mkto.uber.com", "*.uber.com", "ads.yap.yahoo.com", "mempf.yahoo.co.jp", "suggest-shop.yahooapis.jp",
		"www.aol.com", "df-webservices.comet.aol.com", "api.cmi.aol.com", "ui.comet.aol.com", "portal.pf.aol.com",
		"*.yahoo.com", "*.yahoo.jp", "*.yahooapis.jp", "*.aol.com", "search.twitter.com", "twitter.com", "*.twitter.com",
		"ajax.googleapis.com", "*.googleapis.com",
	}

	var arr []string
	for _, domain := range domains {
		if strings.Contains(policy, domain) {
			arr = append(arr, domain)
		}
	}

	if len(arr) > 0 {
		result := strings.Join(arr, " ")
		result += "\n    Needs manual testing. please refer to it. https://t.co/lElLxtainw?amp=1"
		return result
	}

	return ""
}
