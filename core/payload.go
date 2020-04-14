package core

func getCommonPayload() []string {
	payload := []string{
		"<svg/onload=alert(45)>",
	}
	return payload
}

func getInJsPayload() []string {
	payload := []string{
		"'+alert(45)+'",
	}
	return payload
}
