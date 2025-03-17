package payload

// InterfaceGetGfXSS is exported interface
func InterfaceGetGfXSS() ([]string, int) {
	return getListAndLength(GetGfXSS)
}

// InterfaceGetEventHandlers is exported interface
func InterfaceGetEventHandlers() ([]string, int) {
	return getListAndLength(GetEventHandlers)
}

// InterfaceGetTags is exported interface
func InterfaceGetTags() ([]string, int) {
	return getListAndLength(GetTags)
}

// InterfaceGetSpecialChar is exported interface
func InterfaceGetSpecialChar() ([]string, int) {
	return getListAndLength(GetSpecialChar)
}

// InterfaceGetUsefulCode is exported interface
func InterfaceGetUsefulCode() ([]string, int) {
	return getListAndLength(GetUsefulCode)
}

// getListAndLength is a helper function to get list and its length
func getListAndLength(f func() []string) ([]string, int) {
	lst := f()
	return lst, len(lst)
}

// GetGfXSS is get cool parameter name from Gf-Patterns
func GetGfXSS() []string {
	return gfXSSParams
}

// GetEventHandlers is return event handlers (array type)
// level: 1(none trigger) / 2(user interaction) / 3(direct trigger)
func GetEventHandlers() []string {
	return eventHandlers
}

// GetTags is return tag list (array type)
func GetTags() []string {
	return tags
}

// GetSpecialChar is return chars (array type)
func GetSpecialChar() []string {
	return specialChars
}

// GetUsefulCode is return code list (array type)
func GetUsefulCode() []string {
	return usefulCodes
}

var gfXSSParams = []string{
	"q", "s", "search", "lang", "keyword", "query", "page", "keywords", "year", "view", "email", "type", "cat", "name",
	"p", "callback", "jsonp", "api_key", "api", "password", "email", "emailto", "token", "username", "csrf_token",
	"unsubscribe_token", "id", "item", "page_id", "month", "immagine", "list_type", "url", "terms", "categoryid", "key",
	"l", "begindate", "enddate", "go", "goto", "host", "html", "image_url", "img_url", "data", "domain", "dir", "feed",
	"file", "file_name", "file_url", "rurl", "show", "window", "return",
}

var eventHandlers = []string{
	"onabort", "onactivate", "onafterprint", "onafterscriptexecute", "onafterupdate", "onanimationcancel", "onanimationstart",
	"onauxclick", "onbeforeactivate", "onbeforecopy", "onbeforecut", "onbeforedeactivate", "onbeforeeditfocus", "onbeforepaste",
	"onbeforeprint", "onbeforescriptexecute", "onbeforeunload", "onbeforeupdate", "onbegin", "onblur", "onbounce", "oncanplay",
	"oncanplaythrough", "oncellchange", "onchange", "onclick", "oncontextmenu", "oncontrolselect", "oncopy", "oncut", "oncuechange",
	"ondataavailable", "ondatasetchanged", "ondatasetcomplete", "ondurationchange", "ondblclick", "ondeactivate", "ondrag",
	"ondragdrop", "ondragend", "ondragenter", "ondragleave", "ondragover", "ondragstart", "ondrop", "onend", "onerror",
	"onerrorupdate", "onfilterchange", "onfinish", "onfocus", "onfocusin", "onfocusout", "onhashchange", "onhelp", "oninput",
	"oninvalid", "onkeydown", "onkeypress", "onkeyup", "onlayoutcomplete", "onload", "onloadend", "onloadstart", "onloadstart",
	"onlosecapture", "onmediacomplete", "onmediaerror", "onmessage", "onmousedown", "onmouseenter", "onmouseleave", "onmousemove",
	"onmouseout", "onmouseover", "onmouseup", "onmousewheel", "onmove", "onmoveend", "onmovestart", "onoffline", "ononline",
	"onoutofsync", "onpageshow", "onpaste", "onpause", "onplay", "onplaying", "onpointerdown", "onpointerenter", "onpointerleave",
	"onpointermove", "onpointerout", "onpointerover", "onpointerup", "onpopstate", "onprogress", "onpropertychange", "onreadystatechange",
	"onredo", "onrepeat", "onreset", "onresize", "onresizeend", "onresizestart", "onresume", "onreverse", "onrowdelete", "onrowexit",
	"onrowinserted", "onrowsenter", "onrowsdelete", "onrowsinserted", "onscroll", "onsearch", "onseek", "onselect", "onselectionchange",
	"onselectstart", "onshow", "onstart", "onstop", "onstorage", "onsubmit", "onsyncrestored", "ontimeerror", "ontimeupdate", "ontoggle",
	"ontouchend", "ontouchmove", "ontouchstart", "ontrackchange", "ontransitionstart", "ontransitioncancel", "ontransitionend",
	"ontransitionrun", "onundo", "onunhandledrejection", "onunload", "onurlflip", "onvolumechange", "onwaiting", "onwebkitanimationiteration",
	"onwheel", "whatthe=\"'onload", "onpointerrawupdate", "onpagehide", "onanimationend", "onanimationiteration", "oncancel", "onclose",
	"oncontentvisibilityautostatechange", "ondragexit", "onended", "onformdata", "onfullscreenchange", "onloadeddata", "onloadedmetadata",
	"onmozfullscreenchange", "onpointercancel", "onratechange", "onscrollend", "onscrollsnapchange", "onscrollsnapchanging", "onseeked",
	"onseeking", "onsuspend", "ontouchcancel", "onwebkitanimationend", "onwebkitanimationstart", "onwebkitfullscreenchange",
	"onwebkitmouseforcechanged", "onwebkitmouseforcedown", "onwebkitmouseforceup", "onwebkitmouseforcewillbegin",
	"onwebkitplaybacktargetavailabilitychanged", "onwebkitpresentationmodechanged", "onwebkittransitionend", "onwebkitwillrevealbottom",
}

var tags = []string{
	"script", "iframe", "svg", "img", "video", "audio", "meta", "object", "embed", "style", "frame", "frameset", "applet",
}

var specialChars = []string{
	">", "<", "\"", "'", "`", ";", "|", "(", ")", "{", "}", "[", "]", ":", ".", ",", "+", "-", "=", "$", "\\",
}

var usefulCodes = []string{
	"javascript:", "JaVasCriPt:", "jaVas%0dcRipt:", "jaVas%0acRipt:", "jaVas%09cRipt:", "data:", "alert(", "alert`", "prompt(",
	"prompt`", "confirm(", "confirm`", "document.location", "document.cookie", "window.location",
}
