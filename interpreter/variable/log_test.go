package variable

import (
	ghttp "net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/http"
	"github.com/ysugimoto/falco/interpreter/value"
)

// LogScopeVariables.Get must not panic when the response, backend request, or
// request body are nil (e.g. a test invokes vcl_log without a fully
// initialized context). Each guarded variable returns a zero value instead.
func TestLogScopeNilGuards(t *testing.T) {
	tests := []struct {
		name    string
		varName string
		expect  value.Value
	}{
		{
			name:    "resp.status with nil response",
			varName: RESP_STATUS,
			expect:  &value.Integer{Value: 0},
		},
		{
			name:    "resp.proto with nil response",
			varName: RESP_PROTO,
			expect:  &value.String{Value: ""},
		},
		{
			name:    "resp.response with nil response",
			varName: RESP_RESPONSE,
			expect:  &value.String{Value: ""},
		},
		{
			name:    "req.body_bytes_read with nil request body",
			varName: REQ_BODY_BYTES_READ,
			expect:  &value.Integer{Value: 0},
		},
		{
			name:    "bereq.body_bytes_written with nil backend request",
			varName: BEREQ_BODY_BYTES_WRITTEN,
			expect:  &value.Integer{Value: 0},
		},
		{
			name:    "bereq.header_bytes_written with nil backend request",
			varName: BEREQ_HEADER_BYTES_WRITTEN,
			expect:  &value.Integer{Value: 0},
		},
		{
			name:    "resp.http header with nil response",
			varName: "resp.http.X-Custom",
			expect:  &value.String{IsNotSet: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Request has no Body; Response and BackendRequest are nil.
			v := NewLogScopeVariables(&context.Context{
				Request:           http.WrapRequest(&ghttp.Request{Header: ghttp.Header{}}),
				OverrideVariables: map[string]value.Value{},
			})
			result, err := v.Get(context.LogScope, tt.varName)
			if err != nil {
				t.Fatalf("Unexpected error: %s", err)
			}
			if diff := cmp.Diff(result, tt.expect); diff != "" {
				t.Errorf("Return value unmatch, diff: %s", diff)
			}
		})
	}
}

// Add() routes response headers to the response and passes everything else to
// the base scope. A nil response must not panic.
func TestLogScopeAdd(t *testing.T) {
	t.Run("adds response header", func(t *testing.T) {
		resp := http.WrapResponse(&ghttp.Response{Header: ghttp.Header{}})
		v := NewLogScopeVariables(&context.Context{
			Request:           http.WrapRequest(&ghttp.Request{Header: ghttp.Header{}}),
			Response:          resp,
			OverrideVariables: map[string]value.Value{},
		})
		if err := v.Add(context.LogScope, "resp.http.X-Added", &value.String{Value: "yes"}); err != nil {
			t.Fatalf("Unexpected error: %s", err)
		}
		if got := resp.Header.Get("X-Added"); got != "yes" {
			t.Errorf("expected header X-Added=yes, got %q", got)
		}
	})

	t.Run("nil response does not panic", func(t *testing.T) {
		v := NewLogScopeVariables(&context.Context{
			Request:           http.WrapRequest(&ghttp.Request{Header: ghttp.Header{}}),
			OverrideVariables: map[string]value.Value{},
		})
		if err := v.Add(context.LogScope, "resp.http.X-Added", &value.String{Value: "yes"}); err != nil {
			t.Fatalf("Unexpected error: %s", err)
		}
	})
}
