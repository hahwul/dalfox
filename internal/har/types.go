package har

import (
	"encoding/json"
	"time"
)

// copied from https://github.com/vvakame/go-harlog/blob/master/types.go

// from https://w3c.github.io/web-performance/specs/HAR/Overview.html

var _ json.Marshaler = Time{}
var _ json.Unmarshaler = (*Time)(nil)
var _ json.Marshaler = Duration(0)
var _ json.Unmarshaler = (*Duration)(nil)

// Time provides ISO 8601 format JSON data.
type Time time.Time

// MarshalJSON to ISO 8601 format from time.Time.
func (t Time) MarshalJSON() ([]byte, error) {
	if time.Time(t).IsZero() {
		return []byte(`null`), nil
	}

	v := time.Time(t).Format(time.RFC3339)
	return json.Marshal(v)
}

// UnmarshalJSON from ISO 8601 format to time.Time.
func (t *Time) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}

	v, err := time.Parse(`"`+time.RFC3339+`"`, string(data))
	if err != nil {
		return err
	}
	vt := Time(v)
	*t = vt
	return nil
}

// Duration provides milliseconds order JSON format.
type Duration time.Duration

// MarshalJSON to milliseconds order number format from time.Duration.
func (d Duration) MarshalJSON() ([]byte, error) {
	if d == -1 {
		return []byte("-1"), nil
	}
	v := float64(d) / float64(time.Millisecond)
	return json.Marshal(v)
}

// UnmarshalJSON from milliseconds order number format to time.Duration.
func (d *Duration) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}

	var v float64
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}

	*d = Duration(v * float64(time.Millisecond))

	return nil
}

// File represents the top-level JSON object in a HAR file
// The HAR format is based on JSON, as described in RFC 4627.
type File struct {
	Log *Log `json:"log"`
}

// Log represents the root of the exported data. This object MUST
// be present and its name MUST be "log". The object contains the
// following name/value pairs:
type Log struct {
	// Required. Version number of the format.
	Version string `json:"version"`
	// Required. An object of type creator that contains the name and version information of the log creator application.
	Creator *Creator `json:"creator"`
	// Optional. An object of type browser that contains the name and version information of the user agent.
	Browser *Browser `json:"browser,omitempty"`
	// Optional. An array of objects of type page, each representing one exported (tracked) page. Leave out this field if the application does not support grouping by pages.
	Pages []*Page `json:"pages,omitempty"`
	// Required. An array of objects of type entry, each representing one exported (tracked) HTTP request.
	Entries []*Entry `json:"entries"`
	// Optional. A comment provided by the user or the application.
	Comment string `json:"comment,omitempty"`
}

// Creator is ...
// This object contains information about the log creator application and contains the following name/value pairs:
type Creator struct {
	// Required. The name of the application that created the log.
	Name string `json:"name"`
	// Required. The version number of the application that created the log.
	Version string `json:"version"`
	// Optional. A comment provided by the user or the application.
	Comment string `json:"comment,omitempty"`
}

// Browser is ...
// This object contains information about the browser that created the log and contains the following name/value pairs:
type Browser struct {
	// Required. The name of the browser that created the log.
	Name string `json:"name"`
	// Required. The version number of the browser that created the log.
	Version string `json:"version"`
	// Optional. A comment provided by the user or the browser.
	Comment string `json:"comment,omitempty"`
}

// Page is ...
// This object represents list of exported pages.
type Page struct {
	// Date and time stamp for the beginning of the page load (ISO 8601 - YYYY-MM-DDThh:mm:ss.sTZD, e.g. 2009-07-24T19:20:30.45+01:00).
	StartedDateTime Time `json:"startedDateTime"`
	// Unique identifier of a page within the . Entries use it to refer the parent page.
	ID string `json:"id"`
	// Page title.
	Title string `json:"title"`
	// Detailed timing info about page load.
	PageTiming *PageTiming `json:"pageTimings,omitempty"`
	// A comment provided by the user or the application.
	Comment string `json:"comment,omitempty"`
}

// PageTiming is ...
// This object describes timings for various events (states) fired during the page load. All times are specified in milliseconds. If a time info is not available appropriate field is set to -1.
type PageTiming struct {
	// Content of the page loaded. Number of milliseconds since page load started (page.startedDateTime). Use -1 if the timing does not apply to the current request.
	OnContentLoad Duration `json:"onContentLoad,omitempty"`
	// Page is loaded (onLoad event fired). Number of milliseconds since page load started (page.startedDateTime). Use -1 if the timing does not apply to the current request.
	OnLoad Duration `json:"onLoad,omitempty"`
	// A comment provided by the user or the application.
	Comment string `json:"comment,omitempty"`
}

// Entry is ...
// This object represents an array with all exported HTTP requests. Sorting entries by startedDateTime (starting from the oldest) is preferred way how to export data since it can make importing faster. However the reader application should always make sure the array is sorted (if required for the import).
type Entry struct {
	// Reference to the parent page. Leave out this field if the application does not support grouping by pages.
	Pageref string `json:"pageref,omitempty"`
	// Date and time stamp of the request start (ISO 8601 - YYYY-MM-DDThh:mm:ss.sTZD).
	StartedDateTime Time `json:"startedDateTime"`
	// Total elapsed time of the request in milliseconds. This is the sum of all timings available in the timings object (i.e. not including -1 values) .
	Time Duration `json:"time"`
	// Detailed info about the request.
	Request *Request `json:"request"`
	// Detailed info about the response.
	Response *Response `json:"response"`
	// Info about cache usage.
	Cache *Cache `json:"cache"`
	// Detailed timing info about request/response round trip.
	Timings *Timings `json:"timings"`
	// IP address of the server that was connected (result of DNS resolution).
	ServerIPAddress string `json:"serverIPAddress,omitempty"`
	// Unique ID of the parent TCP/IP connection, can be the client port number. Note that a port number doesn't have to be unique identifier in cases where the port is shared for more connections. If the port isn't available for the application, any other unique connection ID can be used instead (e.g. connection index). Leave out this field if the application doesn't support this info.
	Connection string `json:"connection,omitempty"`
	// A comment provided by the user or the application.
	Comment string `json:"comment,omitempty"`
}

// Request is ...
// This object contains detailed info about performed request.
type Request struct {
	// Request method (GET, POST, ...).
	Method string `json:"method"`
	// Absolute URL of the request (fragments are not included).
	URL string `json:"url"`
	// Request HTTP Version.
	HTTPVersion string `json:"httpVersion"`
	// List of cookie objects.
	Cookies []*Cookie `json:"cookies"`
	// List of header objects.
	Headers []*NVP `json:"headers"`
	// List of query parameter objects.
	QueryString []*NVP `json:"queryString"`
	// Posted data info.
	PostData *PostData `json:"postData,omitempty"`
	// Total number of bytes from the start of the HTTP request message until (and including) the double CRLF before the body. Set to -1 if the info is not available.
	HeadersSize int `json:"headersSize"`
	// Size of the request body (POST data payload) in bytes. Set to -1 if the info is not available.
	BodySize int `json:"bodySize"`
	// A comment provided by the user or the application.
	Comment string `json:"comment,omitempty"`
}

// Response is ...
// This object contains detailed info about the response.
type Response struct {
	// Response status.
	Status int `json:"status"`
	// Response status description.
	StatusText string `json:"statusText"`
	// Response HTTP Version.
	HTTPVersion string `json:"httpVersion"`
	// List of cookie objects.
	Cookies []*Cookie `json:"cookies"`
	// List of header objects.
	Headers []*NVP `json:"headers"`
	// Details about the response body.
	Content *Content `json:"content"`
	// Redirection target URL from the Location response header.
	RedirectURL string `json:"redirectURL"`
	// Total number of bytes from the start of the HTTP response message until (and including) the double CRLF before the body. Set to -1 if the info is not available.
	HeadersSize int `json:"headersSize"`
	// Size of the received response body in bytes. Set to zero in case of responses coming from the cache (304). Set to -1 if the info is not available.
	BodySize int64 `json:"bodySize"`
	// A comment provided by the user or the application.
	Comment string `json:"comment,omitempty"`
}

// Cookie is ...
// This object contains list of all cookies (used in <request> and <response> objects).
type Cookie struct {
	// The name of the cookie.
	Name string `json:"name"`
	// The cookie value.
	Value string `json:"value"`
	// The path pertaining to the cookie.
	Path string `json:"path,omitempty"`
	// The host of the cookie.
	Domain string `json:"domain,omitempty"`
	// Cookie expiration time. (ISO 8601 - YYYY-MM-DDThh:mm:ss.sTZD, e.g. 2009-07-24T19:20:30.123+02:00).
	Expires Time `json:"expires,omitempty"`
	// Set to true if the cookie is HTTP only, false otherwise.
	HTTPOnly bool `json:"httpOnly,omitempty"`
	// True if the cookie was transmitted over ssl, false otherwise.
	Secure bool `json:"secure,omitempty"`
	// A comment provided by the user or the application.
	Comment string `json:"comment,omitempty"`
}

// NVP is name-value pairs.
type NVP struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Comment string `json:"comment,omitempty"`
}

// PostData is ...
// This object describes posted data, if any (embedded in <request> object).
type PostData struct {
	// Mime type of posted data.
	MimeType string `json:"mimeType"`
	// List of posted parameters (in case of URL encoded parameters).
	Params []*Param `json:"params"`
	// Plain text posted data
	Text string `json:"text"`
	// A comment provided by the user or the application.
	Comment string `json:"comment,omitempty"`
}

// Param is ...
// List of posted parameters, if any (embedded in <postData> object).
type Param struct {
	// name of a posted parameter.
	Name string `json:"name"`
	// value of a posted parameter or content of a posted file.
	Value string `json:"value,omitempty"`
	// name of a posted file.
	FileName string `json:"fileName,omitempty"`
	// content type of a posted file.
	ContentType string `json:"contentType,omitempty"`
	// A comment provided by the user or the application.
	Comment string `json:"comment,omitempty"`
}

// Content is ...
// This object describes details about response content (embedded in <response> object).
type Content struct {
	// Length of the returned content in bytes. Should be equal to response.bodySize if there is no compression and bigger when the content has been compressed.
	Size int64 `json:"size"`
	// Number of bytes saved. Leave out this field if the information is not available.
	Compression int64 `json:"compression,omitempty"`
	// MIME type of the response text (value of the Content-Type response header). The charset attribute of the MIME type is included (if available).
	MimeType string `json:"mimeType"`
	// Response body sent from the server or loaded from the browser cache. This field is populated with textual content only. The text field is either HTTP decoded text or a encoded (e.g. "base64") representation of the response body. Leave out this field if the information is not available.
	Text string `json:"text,omitempty"`
	// Encoding used for response text field e.g "base64". Leave out this field if the text field is HTTP decoded (decompressed & unchunked), than trans-coded from its original character set into UTF-8.
	Encoding string `json:"encoding,omitempty"`
	// A comment provided by the user or the application.
	Comment string `json:"comment,omitempty"`
}

// Cache is ...
// This objects contains info about a request coming from browser cache.
type Cache struct {
	// State of a cache entry before the request. Leave out this field if the information is not available.
	BeforeRequest *CacheInfo `json:"beforeRequest,omitempty"`
	// State of a cache entry after the request. Leave out this field if the information is not available.
	AfterRequest *CacheInfo `json:"afterRequest,omitempty"`
	// A comment provided by the user or the application.
	Comment string `json:"comment,omitempty"`
}

// CacheInfo is ...
// Both beforeRequest and afterRequest object share the following structure.
type CacheInfo struct {
	// Expiration time of the cache entry.
	Expires string `json:"expires,omitempty"`
	// The last time the cache entry was opened.
	LastAccess string `json:"lastAccess"`
	// Etag
	ETag string `json:"etag"`
	// The number of times the cache entry has been opened.
	HitCount int `json:"hitCount"`
	// A comment provided by the user or the application.
	Comment string `json:"comment,omitempty"`
}

// Timings is ...
// This object describes various phases within request-response round trip. All times are specified in milliseconds.
type Timings struct {
	// Time spent in a queue waiting for a network connection. Use -1 if the timing does not apply to the current request.
	Blocked Duration `json:"blocked,omitempty"`
	// DNS resolution time. The time required to resolve a host name. Use -1 if the timing does not apply to the current request.
	DNS Duration `json:"dns,omitempty"`
	// Time required to create TCP connection. Use -1 if the timing does not apply to the current request.
	Connect Duration `json:"connect,omitempty"`
	// Time required to send HTTP request to the server.
	Send Duration `json:"send"`
	// Waiting for a response from the server.
	Wait Duration `json:"wait"`
	// Time required to read entire response from the server (or cache).
	Receive Duration `json:"receive"`
	// Time required for SSL/TLS negotiation. If this field is defined then the time is also included in the connect field (to ensure backward compatibility with HAR 1.1). Use -1 if the timing does not apply to the current request.
	SSL Duration `json:"ssl,omitempty"`
	// A comment provided by the user or the application.
	Comment string `json:"comment,omitempty"`
}
