package core

import (
	"net/url"
	"strings"
)

func MakeRequestQuery(target, param, payload string) string {
	u, _ := url.Parse(target)
	data := u.String()
	temp_p := u.Query()
	//fmt.Println(temp_p[param])
	data = strings.Replace(data, param+"="+temp_p[param][0], param+"="+temp_p[param][0]+payload, 1)
	temp_url, _ := url.Parse(data)
	temp_q := temp_url.Query()
	temp_url.RawQuery = temp_q.Encode()
	return temp_url.String()
}

func Optimization() [1]string {
	a := getCommonPayload()
	return a
}
