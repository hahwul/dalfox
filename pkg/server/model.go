package server

type Req struct {
	URL string `json:"url"`
	Options map[string]interface{} `json:"options"`
}

type Res struct {
	Code int `json:"code"`
	Msg string `json:"msg"`
	Data map[string]interface{} `json:"data"`
}
