package interpreter

import (
	"testing"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

func TestSubroutine(t *testing.T) {
	tests := []struct {
		name       string
		vcl        string
		assertions map[string]value.Value
		isError    bool
	}{
		{
			// ref: https://github.com/ysugimoto/falco/issues/253
			name: "Local variable scope maintained after call statement",
			vcl: `sub func {}

			sub vcl_recv {
				declare local var.myint INTEGER;
				set var.myint = 2;
				call func();
				set req.http.X-Int-Value = var.myint;
			}`,
			assertions: map[string]value.Value{
				"req.http.X-Int-Value": &value.String{Value: "2"},
			},
		},
		{
			// ref: https://github.com/ysugimoto/falco/issues/253
			name: "Local variable from outer scope is not accessible",
			vcl: `sub func {
				log var.myint;
			}

			sub vcl_recv {
				declare local var.myint INTEGER;
				set var.myint = 2;
				call func();
				set req.http.X-Int-Value = var.myint;
			}`,
			isError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertInterpreter(t, tt.vcl, context.RecvScope, tt.assertions, tt.isError)
		})
	}
}

func TestFunctionSubroutine(t *testing.T) {
	tests := []struct {
		name       string
		vcl        string
		assertions map[string]value.Value
	}{
		{
			name: "Functional subroutine returns a value",
			vcl: `sub compute INTEGER {
				return 2;
			}

			sub vcl_recv {
				declare local var.myint INTEGER;
				set var.myint = compute();
				set req.http.X-Int-Value = var.myint;
			}
			`,
			assertions: map[string]value.Value{
				"req.http.X-Int-Value": &value.String{Value: "2"},
			},
		},
		{
			// ref: https://github.com/ysugimoto/falco/issues/241
			name: "Functional subroutine returns a value from if",
			vcl: `sub compute INTEGER {
				if (true) {
					return 2;
				}
				return 3;
			}

			sub vcl_recv {
				declare local var.myint INTEGER;
				set var.myint = compute();
				set req.http.X-Int-Value = var.myint;
			}
			`,
			assertions: map[string]value.Value{
				"req.http.X-Int-Value": &value.String{Value: "2"},
			},
		},
		{
			name: "Functional subroutine returns a value from switch",
			vcl: `sub compute INTEGER {
				switch (true) {
				default:
					return 2;
					break;
				}
				return 3;
			}

			sub vcl_recv {
				declare local var.myint INTEGER;
				set var.myint = compute();
				set req.http.X-Int-Value = var.myint;
			}
			`,
			assertions: map[string]value.Value{
				"req.http.X-Int-Value": &value.String{Value: "2"},
			},
		},
		{
			name: "Functional subroutine returns a value from bare block",
			vcl: `sub compute INTEGER {
				{
					return 2;
				}
			}

			sub vcl_recv {
				declare local var.myint INTEGER;
				set var.myint = compute();
				set req.http.X-Int-Value = var.myint;
			}
			`,
			assertions: map[string]value.Value{
				"req.http.X-Int-Value": &value.String{Value: "2"},
			},
		},
		{
			name: "Functional subroutine allows non-literals in return statement",
			vcl: `sub compute INTEGER {
				{
					return std.toupper("test");
				}
			}

			sub vcl_recv {
				declare local var.mystr STRING;
				set var.mystr = compute();
				set req.http.X-Str-Value = var.mystr;
			}
			`,
			assertions: map[string]value.Value{
				"req.http.X-Str-Value": &value.String{Value: "TEST"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertInterpreter(t, tt.vcl, context.RecvScope, tt.assertions, false)
		})
	}
}

// String literals passed as function arguments should not be treated as
// literals inside the function body.
func TestFunctionStringParameterLiteralFlag(t *testing.T) {
	// https://fiddle.fastly.dev/fiddle/40cdf7e5
	t.Run("Regex match operator accepts function STRING parameter", func(t *testing.T) {
		vcl := `sub is_numeric(STRING var.input) BOOL {
				if (var.input ~ "^[0-9]+$") {
					return true;
				}
				return false;
			}

			sub vcl_recv {
				set req.http.X-Result = is_numeric("1000");
			}
			`
		assertInterpreter(t, vcl, context.RecvScope, map[string]value.Value{
			"req.http.X-Result": &value.String{Value: "1"},
		}, false)
	})

	// https://fiddle.fastly.dev/fiddle/71193db1
	t.Run("regsub rejects function STRING parameter as pattern", func(t *testing.T) {
		vcl := `sub my_replace(STRING var.pattern, STRING var.replacement) STRING {
				return regsub("hello world", var.pattern, var.replacement);
			}

			sub vcl_recv {
				set req.http.X-Result = my_replace("world", "earth");
			}
			`
		assertInterpreter(t, vcl, context.RecvScope, nil, true)
	})
}

func TestMaxCallStackExceeded(t *testing.T) {
	tests := []struct {
		name string
		vcl  string
	}{
		{
			name: "process subroutine max call stack exceeded",
			vcl: `
sub s1 {
	set req.http.Foo = "1";
	call s2;
}
sub s2 {
	set req.http.Bar = "1";
	call s1;
}

sub vcl_recv {
	call s1;
}`,
		},
		{
			name: "functional subroutine max call stack exceeded",
			vcl: `
sub f1 STRING {
	declare local var.V STRING;
	set var.V = f2();
	return var.V;
}
sub f2 STRING {
	declare local var.V STRING;
	set var.V = f1();
	return var.V;
}

sub vcl_recv {
	set req.http.Foo = f1();
}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertInterpreter(t, tt.vcl, context.RecvScope, nil, true)
		})
	}
}
