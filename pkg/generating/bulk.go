package generating

import (
	"strconv"
	"strings"

	"github.com/hahwul/dalfox/v2/pkg/scanning"
)

type objectPayload struct {
	Listener func() ([]string, int)
}

// GenerateBulkPayload is func of Make Bulk Payload
func GenerateBulkPayload() ([]string, int) {
	var result []string
	size := 0
	var objs []objectPayload
	seq := 0
	outSeq := 0
	_ = outSeq
	objs = append(objs, objectPayload{Listener: scanning.GetPortswiggerPayload})
	objs = append(objs, objectPayload{Listener: scanning.GetCommonPayload})
	objs = append(objs, objectPayload{Listener: scanning.GetHTMLPayload})
	objs = append(objs, objectPayload{Listener: scanning.GetInJsPayload})
	objs = append(objs, objectPayload{Listener: scanning.GetAttrPayload})
	for _, obj := range objs {
		lst, _ := obj.Listener()
		nlst, outSeq := setPayloadVauleForBulk(lst, seq)
		seq = outSeq
		for i, v := range nlst {
			size = size + i
			result = append(result, v)
		}
	}
	return result, size
}

// setPayloadVauleForBulk is change alert/prompt/conrifm value using sequence
func setPayloadVauleForBulk(payloads []string, inSeq int) ([]string, int) {
	var result []string
	seq := inSeq
	for _, payload := range payloads {
		temp := strings.ReplaceAll(payload, "alert(1)", "alert(DALFOX_ALERT_VALUE)")
		temp = strings.ReplaceAll(temp, "alert(document.domain)", "alert(DALFOX_ALERT_VALUE)")
		temp = strings.ReplaceAll(temp, "\\u0061lert(1)", "\\u0061lert(DALFOX_ALERT_VALUE)")
		temp = strings.ReplaceAll(temp, "\\u{61}lert(1)", "\\u{61}lert(DALFOX_ALERT_VALUE)")
		temp = strings.ReplaceAll(temp, "\\u{0000000061}lert(1)", "\\u{0000000061}lert(DALFOX_ALERT_VALUE)")
		temp = strings.ReplaceAll(temp, "1lert(1)", "1lert(DALFOX_ALERT_VALUE)")
		temp = strings.ReplaceAll(temp, "alert()", "alert(DALFOX_ALERT_VALUE)")
		temp = strings.ReplaceAll(temp, "\\/@PortSwiggerRes\\/", "\\/DALFOX_ALERT_VALUE\\/")
		temp = strings.ReplaceAll(temp, "throw 1", "throw DALFOX_ALERT_VALUE")
		temp = strings.ReplaceAll(temp, "alert`1`", "alert`DALFOX_ALERT_VALUE`")
		temp = strings.ReplaceAll(temp, "alert,1", "alert,DALFOX_ALERT_VALUE")
		temp = strings.ReplaceAll(temp, "alert\\x281", "alert\\x28DALFOX_ALERT_VALUE")

		if strings.Contains(temp, "DALFOX_ALERT_VALUE") {
			tmp := strings.ReplaceAll(temp, "DALFOX_ALERT_VALUE", strconv.Itoa(seq))
			result = append(result, tmp)
			seq = seq + 1
		}
	}
	return result, seq
}
