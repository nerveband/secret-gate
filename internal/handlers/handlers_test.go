package handlers

import "testing"

func TestNormalizeRequesterIP(t *testing.T) {
	tests := map[string]string{
		"172.18.0.1:60562":          "172.18.0.1",
		"10.0.0.5":                  "10.0.0.5",
		"10.0.0.5, 192.168.1.10":    "10.0.0.5",
		"[2001:db8::1]:443":         "2001:db8::1",
		"2001:db8::1":               "2001:db8::1",
		" 10.0.0.5 , 192.168.1.10 ": "10.0.0.5",
	}

	for input, want := range tests {
		t.Run(input, func(t *testing.T) {
			if got := normalizeRequesterIP(input); got != want {
				t.Fatalf("normalizeRequesterIP(%q) = %q, want %q", input, got, want)
			}
		})
	}
}
