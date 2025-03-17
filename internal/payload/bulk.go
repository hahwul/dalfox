package payload

import (
	"strconv"
	"strings"
)

type objectPayload struct {
	Listener func() ([]string, int)
}

// GenerateBulkPayload is func of Make Bulk Payload
func GenerateBulkPayload() ([]string, int) {
	var result []string
	size := 0
	var objs = []objectPayload{
		{Listener: GetPortswiggerPayloadWithSize},
		{Listener: GetCommonPayloadWithSize},
		{Listener: GetHTMLPayloadWithSize},
		{Listener: GetInJsPayloadWithSize},
		{Listener: GetAttrPayloadWithSize},
	}
	seq := 0

	for _, obj := range objs {
		lst, _ := obj.Listener()
		nlst, outSeq := setPayloadVauleForBulk(lst, seq)
		seq = outSeq
		result = append(result, nlst...)
		size += len(nlst)
	}
	return result, size
}

// setPayloadVauleForBulk is change alert/prompt/confirm value using sequence
func setPayloadVauleForBulk(payloads []string, inSeq int) ([]string, int) {
	var result []string
	seq := inSeq
	replacements := []string{
		"alert(1)", "alert(document.domain)", "\\u0061lert(1)", "\\u{61}lert(1)", "\\u{0000000061}lert(1)",
		"1lert(1)", "alert()", "\\/@PortSwiggerRes\\/", "throw 1", "alert`1`", "alert,1", "alert\\x281",
	}

	for _, payload := range payloads {
		temp := payload
		for _, r := range replacements {
			temp = strings.ReplaceAll(temp, r, "alert(DALFOX_ALERT_VALUE)")
		}

		if strings.Contains(temp, "DALFOX_ALERT_VALUE") {
			tmp := strings.ReplaceAll(temp, "DALFOX_ALERT_VALUE", strconv.Itoa(seq))
			result = append(result, tmp)
			seq++
		}
	}
	return result, seq
}
