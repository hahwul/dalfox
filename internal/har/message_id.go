package har

import (
	"context"
	"net/http"
	"sync/atomic"
)

var nextMessageID int64

// NewMessageID returns an incrementing message ID. It is used for
// correlating Dalfox PoCs with entries in a HAR file.
func NewMessageID() int64 {
	return atomic.AddInt64(&nextMessageID, 1)
}

type ctxkeyType int

const ctxkey ctxkeyType = iota

// MessageIDFromRequest returns the message ID associated with a *http.Request
func MessageIDFromRequest(req *http.Request) int64 {
	return req.Context().Value(ctxkey).(int64)
}

// AddMessageIDToRequest returns a new *http.Request with a message ID associated to it
func AddMessageIDToRequest(req *http.Request) *http.Request {
	messageID := NewMessageID()
	ctx := context.WithValue(req.Context(), ctxkey, messageID)
	return req.WithContext(ctx)
}
