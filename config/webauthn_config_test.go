package config

import "testing"

func TestValidateSubdomainOrigin(t *testing.T) {
	tests := []struct {
		name   string
		origin string
		want   bool
	}{
		{name: "localhost dev origin", origin: "http://localhost:3000", want: true},
		{name: "loopback dev origin", origin: "http://127.0.0.1:5173", want: true},
		{name: "allowed production subdomain", origin: "https://adi.app.authsec.dev", want: true},
		{name: "allowed base domain", origin: "https://dev.authsec.dev", want: true},
		{name: "reject non https remote origin", origin: "http://adi.app.authsec.dev", want: false},
		{name: "reject unknown remote origin", origin: "https://evil.example.com", want: false},
		{name: "reject empty origin", origin: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateSubdomainOrigin(tt.origin); got != tt.want {
				t.Fatalf("ValidateSubdomainOrigin(%q) = %v, want %v", tt.origin, got, tt.want)
			}
		})
	}
}
