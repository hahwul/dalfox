package scanning

import "regexp"

// Grepping is function for checking pattern
func Grepping(data, regex string) []string {
	byteData := []byte(data)
	var bodySlice []string
	var pattern = regexp.MustCompile(regex)
	result := pattern.FindAllIndex(byteData, -1)
	_ = result

	for _, v := range result {
		bodySlice = append(bodySlice, data[v[0]:v[1]])
	}
	return bodySlice
}

// builtinGrep is dalfox build-in grep pattern
func builtinGrep(data string) map[string][]string {
	// "pattern name":["list of grep"]
	result := make(map[string][]string)
	// "pattern name":"regex"
	pattern := map[string]string{
		"dalfox-ssti":     "2958816",
		"dalfox-rsa-key":  "-----BEGIN RSA PRIVATE KEY-----|-----END RSA PRIVATE KEY-----",
		"dalfox-priv-key": "-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----",
	}

	for k, v := range pattern {
		resultArr := Grepping(data, v)
		if len(resultArr) > 0 {
			result[k] = resultArr
		}
	}

	return result
}

// customGrep is user custom grep pattern
func customGrep(data string, pattern map[string]string) map[string][]string {
	// "pattern name":""
	result := make(map[string][]string)
	for k, v := range pattern {
		resultArr := Grepping(data, v)
		if len(resultArr) > 0 {
			result[k] = resultArr
		}
	}
	return result
}
