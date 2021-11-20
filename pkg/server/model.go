package server

import "github.com/hahwul/dalfox/v2/pkg/model"

// Req is struct of request
type Req struct {
	URL     string        `json:"url"`
	Options model.Options `json:"options"`
}

// Res is struct of response
type Res struct {
	Code int         `json:"code"`
	Msg  string      `json:"msg"`
	Data []model.PoC `json:"data"`
}

// Scans is struct of scan
type Scans struct {
	Code  int      `json:"code"`
	Scans []string `json:"scans"`
}
