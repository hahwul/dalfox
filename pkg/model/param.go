package model

// ParamType represents different parameter types
type ParamType string

const (
	// URL parameter types
	ParamTypeURL   ParamType = "URL"
	ParamTypeQuery ParamType = "QUERY"
	ParamTypePath  ParamType = "PATH"
	ParamTypeHash  ParamType = "HASH"

	// Form parameter types
	ParamTypeForm      ParamType = "FORM"
	ParamTypeFormData  ParamType = "FORM_DATA"
	ParamTypeMultipart ParamType = "MULTIPART"

	// Header parameter types
	ParamTypeHeader ParamType = "HEADER"
	ParamTypeCookie ParamType = "COOKIE"
	ParamTypeAuth   ParamType = "AUTH"

	// Body parameter types
	ParamTypeJSON ParamType = "JSON"
	ParamTypeXML  ParamType = "XML"
	ParamTypeText ParamType = "TEXT"

	// DOM parameter types
	ParamTypeDOM       ParamType = "DOM"
	ParamTypeAttribute ParamType = "ATTRIBUTE"
	ParamTypeInnerHTML ParamType = "INNER_HTML"
	ParamTypeInnerText ParamType = "INNER_TEXT"

	// JavaScript context types
	ParamTypeJSVar      ParamType = "JS_VAR"
	ParamTypeJSFunction ParamType = "JS_FUNCTION"
	ParamTypeJSString   ParamType = "JS_STRING"
	ParamTypeJSObject   ParamType = "JS_OBJECT"

	// Special types
	ParamTypeFile      ParamType = "FILE"
	ParamTypeWebSocket ParamType = "WEBSOCKET"
	ParamTypeUnknown   ParamType = "UNKNOWN"
)

// Param is type of Parameters (Parameter analysis output)
type Param struct {
	Type    ParamType `json:"type"`
	Key     string    `json:"key"`
	Value   string    `json:"value"`
	Reflect bool      `json:"reflect"`
	SMap    string    `json:"smap"`
	// Additional fields for enhanced parameter analysis
	Context     string   `json:"context,omitempty"`     // HTML, JS, CSS, etc.
	Encoding    string   `json:"encoding,omitempty"`    // URL, HTML, Base64, etc.
	Validation  string   `json:"validation,omitempty"`  // Client-side validation info
	Constraints []string `json:"constraints,omitempty"` // Length, format constraints
	Sensitive   bool     `json:"sensitive,omitempty"`   // Contains sensitive data
}
