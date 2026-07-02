package upstream

import (
	"reflect"
	"testing"
)

func TestParseAlternateCertLinks(t *testing.T) {
	base := "https://upstream.example/acme/cert/default"
	headers := []string{
		`<https://upstream.example/acme/cert/alt-r3>;rel="alternate", <https://upstream.example/acme/cert/default>;rel="index"`,
		`</acme/cert/alt-e1>; rel=alternate`,
		`<mailto:ops@example.com>;rel="alternate"`,
	}

	got := parseAlternateCertLinks(headers, base)
	want := []string{
		"https://upstream.example/acme/cert/alt-r3",
		"https://upstream.example/acme/cert/alt-e1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseAlternateCertLinks() = %#v, want %#v", got, want)
	}
}

func TestSplitLinkHeaderValues_RespectsQuotedCommas(t *testing.T) {
	in := `<https://upstream.example/alt>;rel="alternate", <https://upstream.example/meta>;title="a,b", <https://upstream.example/x>;rel="index"`
	got := splitLinkHeaderValues(in)
	want := []string{
		`<https://upstream.example/alt>;rel="alternate"`,
		`<https://upstream.example/meta>;title="a,b"`,
		`<https://upstream.example/x>;rel="index"`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("splitLinkHeaderValues() = %#v, want %#v", got, want)
	}
}

func TestParseAlternateLinkPart(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{name: "quoted rel", in: `<https://upstream.example/alt>; rel="alternate"`, want: "https://upstream.example/alt", ok: true},
		{name: "multi rel list", in: `<https://upstream.example/alt>; rel="up alternate"`, want: "https://upstream.example/alt", ok: true},
		{name: "non alternate", in: `<https://upstream.example/default>; rel="index"`, want: "", ok: false},
		{name: "invalid", in: `https://upstream.example/default; rel="alternate"`, want: "", ok: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseAlternateLinkPart(tc.in)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("parseAlternateLinkPart(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.ok)
			}
		})
	}
}
