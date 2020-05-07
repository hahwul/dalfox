package scanning

import (
	"strings"
)

// checkCSP is bypass CSP for StaticAnalysis
func checkCSP(policy string) string {
	var result string
	var arr []string
	if strings.Contains(policy, ".doubleclick.net") {
		arr = append(arr, ".doubleclick.net")
	}
	if strings.Contains(policy, ".googleadservices.com") {
		arr = append(arr, ".googleadservices.com")
	}
	if strings.Contains(policy, "cse.google.com") {
		arr = append(arr, "cse.google.com")
	}
	if strings.Contains(policy, "accounts.google.com") {
		arr = append(arr, "accounts.google.com")
	}
	if strings.Contains(policy, "*.google.com") {
		arr = append(arr, "*.google.com")
	}
	if strings.Contains(policy, "www.blogger.com") {
		arr = append(arr, "www.blogger.com")
	}
	if strings.Contains(policy, "*.blogger.com") {
		arr = append(arr, "*.blogger.com")
	}
	if strings.Contains(policy, "translate.yandex.net") {
		arr = append(arr, "translate.yandex.net")
	}
	if strings.Contains(policy, "api-metrika.yandex.ru") {
		arr = append(arr, "api-metrika.yandex.ru")
	}
	if strings.Contains(policy, "api.vk.comm") {
		arr = append(arr, "api.vk.com")
	}
	if strings.Contains(policy, "*.vk.com") {
		arr = append(arr, "*.vk.com")
	}
	if strings.Contains(policy, "*.yandex.ru") {
		arr = append(arr, "*.yandex.ru")
	}
	if strings.Contains(policy, "*.yandex.net") {
		arr = append(arr, "*.yandex.het")
	}
	if strings.Contains(policy, "app-sjint.marketo.com") {
		arr = append(arr, "app-sjint.marketo.com")
	}
	if strings.Contains(policy, "app-e.marketo.com") {
		arr = append(arr, "app-e.marketo.com")
	}
	if strings.Contains(policy, "*.marketo.com") {
		arr = append(arr, "*.marketo.com")
	}
	if strings.Contains(policy, "detector.alicdn.com") {
		arr = append(arr, "detector.alicdn.com")
	}
	if strings.Contains(policy, "suggest.taobao.com") {
		arr = append(arr, "suggest.taobao.com")
	}
	if strings.Contains(policy, "ount.tbcdn.cn") {
		arr = append(arr, "ount.tbcdn.cn")
	}
	if strings.Contains(policy, "bebezoo.1688.com") {
		arr = append(arr, "bebezoo.1688.com")
	}
	if strings.Contains(policy, "wb.amap.com") {
		arr = append(arr, "wb.amap.com")
	}
	if strings.Contains(policy, "a.sm.cn") {
		arr = append(arr, "a.sm.cn")
	}
	if strings.Contains(policy, "api.m.sm.cn") {
		arr = append(arr, "api.m.sm.cn")
	}
	if strings.Contains(policy, "*.alicdn.com") {
		arr = append(arr, "*.alicdn.com")
	}
	if strings.Contains(policy, "*.taobao.com") {
		arr = append(arr, "*.taobao.com")
	}
	if strings.Contains(policy, "*.tbcdn.cn") {
		arr = append(arr, "*.tbcdn.cn")
	}
	if strings.Contains(policy, "*.1688.com") {
		arr = append(arr, "*.1688.com")
	}
	if strings.Contains(policy, "*.amap.com") {
		arr = append(arr, "*.amap.com")
	}
	if strings.Contains(policy, "*.sm.cn") {
		arr = append(arr, "*.sm.cn")
	}
	if strings.Contains(policy, "mkto.uber.com") {
		arr = append(arr, "mkto.uber.com")
	}
	if strings.Contains(policy, "*.uber.com") {
		arr = append(arr, "*.uber.com")
	}
	if strings.Contains(policy, "ads.yap.yahoo.com") {
		arr = append(arr, "ads.yap.yahoo.com")
	}
	if strings.Contains(policy, "mempf.yahoo.co.jp") {
		arr = append(arr, "mempf.yahoo.co.jp")
	}
	if strings.Contains(policy, "suggest-shop.yahooapis.jp") {
		arr = append(arr, "suggest-shop.yahooapis.jp")
	}
	if strings.Contains(policy, "www.aol.com") {
		arr = append(arr, "www.aol.com")
	}
	if strings.Contains(policy, "df-webservices.comet.aol.com") {
		arr = append(arr, "df-webservices.comet.aol.com")
	}
	if strings.Contains(policy, "api.cmi.aol.com") {
		arr = append(arr, "api.cmi.aol.com")
	}
	if strings.Contains(policy, "ui.comet.aol.com") {
		arr = append(arr, "ui.comet.aol.com")
	}
	if strings.Contains(policy, "portal.pf.aol.com") {
		arr = append(arr, "portal.pf.aol.com")
	}
	if strings.Contains(policy, "*.yahoo.com") {
		arr = append(arr, "*.yahoo.com")
	}
	if strings.Contains(policy, "*.yahoo.jp") {
		arr = append(arr, "*.yahoo.jp")
	}
	if strings.Contains(policy, "*.yahooapis.jp") {
		arr = append(arr, "*.yahooapis.jp")
	}
	if strings.Contains(policy, "*.aol.com") {
		arr = append(arr, "*.aol.com")
	}
	if strings.Contains(policy, "search.twitter.com") {
		arr = append(arr, "search.twitter.com")
	}
	if strings.Contains(policy, "twitter.com") {
		arr = append(arr, "twitter.com")
	}
	if strings.Contains(policy, "*.twitter.com") {
		arr = append(arr, "*.twitter.com")
	}
	if strings.Contains(policy, "ajax.googleapis.com") {
		arr = append(arr, "ajax.googleapis.com")
	}
	if strings.Contains(policy, "*.googleapis.com") {
		arr = append(arr, "*googleapis.com")
	}
	if len(arr) > 0 {
		result = strings.Join(arr[:], " ")
		result = result + "\n" + "    Needs manual testing. please refer to it. https://t.co/lElLxtainw?amp=1"
	}
	// https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/jsonp_endpoint.txt
	return result
}
