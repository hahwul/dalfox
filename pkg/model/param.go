package model

// Parameter type constants
const (
	ParamTypePath     = "PATH"
	ParamTypeQuery    = "QUERY"
	ParamTypeFragment = "FRAGMENT"
	ParamTypeHeader   = "HEADER"
	ParamTypeCookie   = "COOKIE"
	ParamTypeBodyForm = "BODY_FORM"
	ParamTypeBodyJSON = "BODY_JSON"
	ParamTypeBodyXML  = "BODY_XML"
	ParamTypeUnknown  = "UNKNOWN"
)

// Param is type of Parameters (Parameter analysis output)
// This struct seems to be used in older or different contexts than ParamResult.
// For the new standardized parameter types, ensure ParamResult.Type is used.
type Param struct {
	Type    string
	Key     string
	Value   string
	Reflect bool
	SMap    string
}
