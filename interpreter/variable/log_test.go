package variable

import (
	ghttp "net/http"
	"testing"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/http"
	"github.com/ysugimoto/falco/interpreter/value"
)

// LogScopeVariables.Add must add a matched response header to the response. The
// match condition was inverted, so a "resp.http.*" name was passed to the base
// scope instead of being handled here, and the header was never set.
func TestLogScopeAddResponseHeader(t *testing.T) {
	resp := http.WrapResponse(&ghttp.Response{Header: ghttp.Header{}})
	v := NewLogScopeVariables(&context.Context{
		Request:           http.WrapRequest(&ghttp.Request{Header: ghttp.Header{}}),
		Response:          resp,
		OverrideVariables: map[string]value.Value{},
	})

	if err := v.Add(context.LogScope, "resp.http.X-Custom", &value.String{Value: "value"}); err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
	if got := resp.Header.Get("X-Custom"); got != "value" {
		t.Errorf("expected response header X-Custom=value, got %q", got)
	}
}
