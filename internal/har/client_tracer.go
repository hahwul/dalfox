package har

import (
	"crypto/tls"
	"net/http/httptrace"
	"time"
)

func newClientTracer() (*clientTracer, *httptrace.ClientTrace) {
	ct1 := &clientTracer{
		startAt: time.Now(),
	}

	ct2 := &httptrace.ClientTrace{
		GetConn:              ct1.GetConn,
		GotConn:              ct1.GotConn,
		PutIdleConn:          nil,
		GotFirstResponseByte: ct1.GotFirstResponseByte,
		Got100Continue:       nil,
		Got1xxResponse:       nil,
		DNSStart:             ct1.DNSStart,
		DNSDone:              ct1.DNSDone,
		ConnectStart:         nil,
		ConnectDone:          nil,
		TLSHandshakeStart:    ct1.TLSHandshakeStart,
		TLSHandshakeDone:     ct1.TLSHandshakeDone,
		WroteHeaderField:     nil,
		WroteHeaders:         nil,
		Wait100Continue:      nil,
		WroteRequest:         ct1.WroteRequest,
	}

	return ct1, ct2
}

type clientTracer struct {
	startAt           time.Time
	connStart         time.Time
	connObtained      time.Time
	firstResponseByte time.Time
	dnsStart          time.Time
	dnsEnd            time.Time
	tlsHandshakeStart time.Time
	tlsHandshakeEnd   time.Time
	writeRequest      time.Time
	endAt             time.Time
}

func (ct *clientTracer) GetConn(hostPort string) {
	ct.connStart = time.Now()
}

func (ct *clientTracer) GotConn(info httptrace.GotConnInfo) {
	ct.connObtained = time.Now()
}

func (ct *clientTracer) GotFirstResponseByte() {
	ct.firstResponseByte = time.Now()
}

func (ct *clientTracer) DNSStart(info httptrace.DNSStartInfo) {
	ct.dnsStart = time.Now()
}

func (ct *clientTracer) DNSDone(info httptrace.DNSDoneInfo) {
	ct.dnsEnd = time.Now()
}

func (ct *clientTracer) TLSHandshakeStart() {
	ct.tlsHandshakeStart = time.Now()
}

func (ct *clientTracer) TLSHandshakeDone(tls.ConnectionState, error) {
	ct.tlsHandshakeEnd = time.Now()
}

func (ct *clientTracer) WroteRequest(info httptrace.WroteRequestInfo) {
	ct.writeRequest = time.Now()
}
