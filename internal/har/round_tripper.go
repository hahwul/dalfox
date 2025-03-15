// Package har implements HAR file output support for Dalfox
package har

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/httptrace"
	"strings"
	"time"
)

var _ http.RoundTripper = (*RoundTripper)(nil)

// forked from from https://github.com/vvakame/go-harlog/blob/master/types.go

// RoundTripper implements the http.RoundTripper interface. Requests and
// responses are written to HAR archives.
type RoundTripper struct {
	inner   http.RoundTripper
	writer  *Writer
	rewrite func(request *http.Request, response *http.Response, entry json.RawMessage) json.RawMessage
}

// NewRoundTripper creates a new RoundTripper. A RoundTripper is
// safe for concurrent use by multiple goroutines.
func NewRoundTripper(roundTripper http.RoundTripper, writer *Writer, rewrite func(request *http.Request, response *http.Response, entry json.RawMessage) json.RawMessage) *RoundTripper {
	if roundTripper == nil {
		roundTripper = http.DefaultTransport
	}

	if rewrite == nil {
		rewrite = func(request *http.Request, response *http.Response, entry json.RawMessage) json.RawMessage {
			return entry
		}
	}

	return &RoundTripper{
		inner:   roundTripper,
		writer:  writer,
		rewrite: rewrite,
	}
}

// RoundTrip satisfies the http.RoundTripper interface
func (rt *RoundTripper) RoundTrip(request *http.Request) (response *http.Response, err error) {
	entry := &Entry{}
	err = rt.preRoundTrip(request, entry)
	if err != nil {
		return
	}

	trace, clientTrace := newClientTracer()
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), clientTrace))

	response, err = rt.inner.RoundTrip(request)
	if err != nil {
		return
	}

	err = rt.postRoundTrip(response, entry, trace)
	if err != nil {
		return
	}

	err = rt.writeEntry(request, response, entry)
	if err != nil {
		return
	}

	return
}

func (rt *RoundTripper) writeEntry(request *http.Request, response *http.Response, entry *Entry) error {
	entryJSON, _ := json.Marshal(entry)

	entryJSON = rt.rewrite(request, response, entryJSON)
	if entryJSON == nil {
		return nil
	}

	return rt.writer.writeEntry(entryJSON)
}

func (rt *RoundTripper) preRoundTrip(r *http.Request, entry *Entry) error {
	bodySize := -1
	var postData *PostData
	if r.Body != nil {
		reqBody, err := r.GetBody()
		if err != nil {
			return fmt.Errorf("getting body: %w", err)
		}

		reqBodyBytes, err := io.ReadAll(reqBody)
		if err != nil {
			return fmt.Errorf("reading request body: %w", err)
		}

		bodySize = len(reqBodyBytes)

		mimeType := r.Header.Get("Content-Type")
		postData = &PostData{
			MimeType: mimeType,
			Params:   []*Param{},
			Text:     string(reqBodyBytes),
		}

		mediaType, _, err := mime.ParseMediaType(mimeType)
		if err != nil {
			return fmt.Errorf("parsing request Content-Type: %w", err)
		}

		switch mediaType {
		case "application/x-www-form-urlencoded":
			err = r.ParseForm()
			if err != nil {
				return fmt.Errorf("parsing urlencoded form in request body: %w", err)
			}
			r.Body = io.NopCloser(bytes.NewBuffer(reqBodyBytes))

			for k, v := range r.PostForm {
				for _, s := range v {
					postData.Params = append(postData.Params, &Param{
						Name:  k,
						Value: s,
					})
				}
			}

		case "multipart/form-data":
			err = r.ParseMultipartForm(10 * 1024 * 1024)
			if err != nil {
				return fmt.Errorf("parsing multipart form in request body: %w", err)
			}
			r.Body = io.NopCloser(bytes.NewBuffer(reqBodyBytes))

			for k, v := range r.MultipartForm.Value {
				for _, s := range v {
					postData.Params = append(postData.Params, &Param{
						Name:  k,
						Value: s,
					})
				}
			}
			for k, v := range r.MultipartForm.File {
				for _, s := range v {
					postData.Params = append(postData.Params, &Param{
						Name:        k,
						FileName:    s.Filename,
						ContentType: s.Header.Get("Content-Type"),
					})
				}
			}
		}
	}

	entry.Request = &Request{
		Method:      r.Method,
		URL:         r.URL.String(),
		HTTPVersion: r.Proto,
		Cookies:     toHARCookies(r.Cookies()),
		Headers:     toHARNVP(r.Header),
		QueryString: toHARNVP(r.URL.Query()),
		PostData:    postData,
		HeadersSize: -1, // TODO
		BodySize:    bodySize,
	}

	return nil
}

func (rt *RoundTripper) postRoundTrip(resp *http.Response, entry *Entry, trace *clientTracer) error {
	defer resp.Body.Close()
	respBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	resp.Body = io.NopCloser(bytes.NewBuffer(respBodyBytes))

	mimeType := resp.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(mimeType)
	if err != nil {
		return fmt.Errorf("parsing response Content-Type: %w", err)
	}

	var text string
	var encoding string
	switch {
	case strings.HasPrefix(mediaType, "text/"):
		text = string(respBodyBytes)
	default:
		text = base64.StdEncoding.EncodeToString(respBodyBytes)
		encoding = "base64"
	}

	entry.Response = &Response{
		Status:      resp.StatusCode,
		StatusText:  resp.Status,
		HTTPVersion: resp.Proto,
		Cookies:     toHARCookies(resp.Cookies()),
		Headers:     toHARNVP(resp.Header),
		RedirectURL: resp.Header.Get("Location"),
		HeadersSize: -1,
		BodySize:    resp.ContentLength,
		Content: &Content{
			Size:        resp.ContentLength, // TODO 圧縮されている場合のフォロー
			Compression: 0,
			MimeType:    mimeType,
			Text:        text,
			Encoding:    encoding,
		},
	}

	// TODO: these timings are suspect. the `connect` timing includes the TLS negotiation time (it shouldn't)
	trace.endAt = time.Now()
	entry.StartedDateTime = Time(trace.startAt)
	entry.Time = Duration(trace.endAt.Sub(trace.startAt))
	entry.Timings = &Timings{
		Blocked: Duration(trace.connStart.Sub(trace.startAt)),
		DNS:     -1,
		Connect: -1,
		Send:    Duration(trace.writeRequest.Sub(trace.connObtained)),
		Wait:    Duration(trace.firstResponseByte.Sub(trace.writeRequest)),
		Receive: Duration(trace.endAt.Sub(trace.firstResponseByte)),
		SSL:     -1,
	}
	if !trace.dnsStart.IsZero() {
		entry.Timings.DNS = Duration(trace.dnsEnd.Sub(trace.dnsStart))
	}
	if !trace.connStart.IsZero() {
		entry.Timings.Connect = Duration(trace.connObtained.Sub(trace.connStart))
	}
	if !trace.tlsHandshakeStart.IsZero() {
		entry.Timings.SSL = Duration(trace.tlsHandshakeEnd.Sub(trace.tlsHandshakeStart))
	}

	return nil
}

func toHARCookies(cookies []*http.Cookie) []*Cookie {
	harCookies := make([]*Cookie, 0, len(cookies))

	for _, cookie := range cookies {
		harCookies = append(harCookies, &Cookie{
			Name:     cookie.Name,
			Value:    cookie.Value,
			Path:     cookie.Path,
			Domain:   cookie.Domain,
			Expires:  Time(cookie.Expires),
			HTTPOnly: cookie.HttpOnly,
			Secure:   cookie.Secure,
		})
	}

	return harCookies
}

func toHARNVP(vs map[string][]string) []*NVP {
	nvps := make([]*NVP, 0, len(vs))

	for k, v := range vs {
		for _, s := range v {
			nvps = append(nvps, &NVP{
				Name:  k,
				Value: s,
			})
		}
	}

	return nvps
}
