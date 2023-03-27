package har

import (
	"crypto/tls"
	"net/http/httptrace"
	"testing"
	"time"
)

func Test_clientTracer_GetConn(t *testing.T) {
	type fields struct {
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
	type args struct {
		hostPort string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name:   "test",
			fields: fields{},
			args: args{
				hostPort: "",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct := &clientTracer{
				startAt:           tt.fields.startAt,
				connStart:         tt.fields.connStart,
				connObtained:      tt.fields.connObtained,
				firstResponseByte: tt.fields.firstResponseByte,
				dnsStart:          tt.fields.dnsStart,
				dnsEnd:            tt.fields.dnsEnd,
				tlsHandshakeStart: tt.fields.tlsHandshakeStart,
				tlsHandshakeEnd:   tt.fields.tlsHandshakeEnd,
				writeRequest:      tt.fields.writeRequest,
				endAt:             tt.fields.endAt,
			}
			ct.GetConn(tt.args.hostPort)
		})
	}
}

func Test_clientTracer_GotFirstResponseByte(t *testing.T) {
	type fields struct {
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
	tests := []struct {
		name   string
		fields fields
	}{
		{
			name:   "test",
			fields: fields{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct := &clientTracer{
				startAt:           tt.fields.startAt,
				connStart:         tt.fields.connStart,
				connObtained:      tt.fields.connObtained,
				firstResponseByte: tt.fields.firstResponseByte,
				dnsStart:          tt.fields.dnsStart,
				dnsEnd:            tt.fields.dnsEnd,
				tlsHandshakeStart: tt.fields.tlsHandshakeStart,
				tlsHandshakeEnd:   tt.fields.tlsHandshakeEnd,
				writeRequest:      tt.fields.writeRequest,
				endAt:             tt.fields.endAt,
			}
			ct.GotFirstResponseByte()
		})
	}
}

func Test_clientTracer_DNSStart(t *testing.T) {
	type fields struct {
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
	type args struct {
		info httptrace.DNSStartInfo
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name:   "test",
			fields: fields{},
			args: args{
				info: httptrace.DNSStartInfo{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct := &clientTracer{
				startAt:           tt.fields.startAt,
				connStart:         tt.fields.connStart,
				connObtained:      tt.fields.connObtained,
				firstResponseByte: tt.fields.firstResponseByte,
				dnsStart:          tt.fields.dnsStart,
				dnsEnd:            tt.fields.dnsEnd,
				tlsHandshakeStart: tt.fields.tlsHandshakeStart,
				tlsHandshakeEnd:   tt.fields.tlsHandshakeEnd,
				writeRequest:      tt.fields.writeRequest,
				endAt:             tt.fields.endAt,
			}
			ct.DNSStart(tt.args.info)
		})
	}
}

func Test_clientTracer_DNSDone(t *testing.T) {
	type fields struct {
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
	type args struct {
		info httptrace.DNSDoneInfo
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name:   "test",
			fields: fields{},
			args: args{
				info: httptrace.DNSDoneInfo{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct := &clientTracer{
				startAt:           tt.fields.startAt,
				connStart:         tt.fields.connStart,
				connObtained:      tt.fields.connObtained,
				firstResponseByte: tt.fields.firstResponseByte,
				dnsStart:          tt.fields.dnsStart,
				dnsEnd:            tt.fields.dnsEnd,
				tlsHandshakeStart: tt.fields.tlsHandshakeStart,
				tlsHandshakeEnd:   tt.fields.tlsHandshakeEnd,
				writeRequest:      tt.fields.writeRequest,
				endAt:             tt.fields.endAt,
			}
			ct.DNSDone(tt.args.info)
		})
	}
}

func Test_clientTracer_TLSHandshakeStart(t *testing.T) {
	type fields struct {
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
	tests := []struct {
		name   string
		fields fields
	}{
		{
			name:   "test",
			fields: fields{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct := &clientTracer{
				startAt:           tt.fields.startAt,
				connStart:         tt.fields.connStart,
				connObtained:      tt.fields.connObtained,
				firstResponseByte: tt.fields.firstResponseByte,
				dnsStart:          tt.fields.dnsStart,
				dnsEnd:            tt.fields.dnsEnd,
				tlsHandshakeStart: tt.fields.tlsHandshakeStart,
				tlsHandshakeEnd:   tt.fields.tlsHandshakeEnd,
				writeRequest:      tt.fields.writeRequest,
				endAt:             tt.fields.endAt,
			}
			ct.TLSHandshakeStart()
		})
	}
}

func Test_clientTracer_TLSHandshakeDone(t *testing.T) {
	type fields struct {
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
	type args struct {
		in0 tls.ConnectionState
		in1 error
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name:   "test",
			fields: fields{},
			args: args{
				in1: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct := &clientTracer{
				startAt:           tt.fields.startAt,
				connStart:         tt.fields.connStart,
				connObtained:      tt.fields.connObtained,
				firstResponseByte: tt.fields.firstResponseByte,
				dnsStart:          tt.fields.dnsStart,
				dnsEnd:            tt.fields.dnsEnd,
				tlsHandshakeStart: tt.fields.tlsHandshakeStart,
				tlsHandshakeEnd:   tt.fields.tlsHandshakeEnd,
				writeRequest:      tt.fields.writeRequest,
				endAt:             tt.fields.endAt,
			}
			ct.TLSHandshakeDone(tt.args.in0, tt.args.in1)
		})
	}
}

func Test_clientTracer_WroteRequest(t *testing.T) {
	type fields struct {
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
	type args struct {
		info httptrace.WroteRequestInfo
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name:   "test",
			fields: fields{},
			args: args{
				info: httptrace.WroteRequestInfo{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct := &clientTracer{
				startAt:           tt.fields.startAt,
				connStart:         tt.fields.connStart,
				connObtained:      tt.fields.connObtained,
				firstResponseByte: tt.fields.firstResponseByte,
				dnsStart:          tt.fields.dnsStart,
				dnsEnd:            tt.fields.dnsEnd,
				tlsHandshakeStart: tt.fields.tlsHandshakeStart,
				tlsHandshakeEnd:   tt.fields.tlsHandshakeEnd,
				writeRequest:      tt.fields.writeRequest,
				endAt:             tt.fields.endAt,
			}
			ct.WroteRequest(tt.args.info)
		})
	}
}
