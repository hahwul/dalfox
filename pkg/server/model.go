package server

import "github.com/hahwul/dalfox/pkg/model"

type Req struct {
	URL string `json:"url"`
	Options map[string]interface{} `json:"options"`
}

type Res struct {
	Code int `json:"code"`
	Msg string `json:"msg"`
	Data []model.Issue `json:"data"`
}
