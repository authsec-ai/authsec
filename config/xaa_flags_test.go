package config

import "testing"

func TestValidateXAAFlags(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		ok   bool
	}{
		{"all off", Config{}, true},
		{"sealer only", Config{XAANativeSealer: true}, true},
		{"all issuance on", Config{XAANativeSealer: true, XAAm2m: true, XAARedemption: true, XAACiba: true, XAAIssuance: true}, true},
		{"m2m without sealer", Config{XAAm2m: true}, false},
		{"ciba without sealer", Config{XAACiba: true}, false},
		{"issuance without sealer", Config{XAAIssuance: true}, false},
		{"redemption without sealer", Config{XAARedemption: true}, false},
		{"dpop (unvalidated) refused", Config{XAANativeSealer: true, XAARedemption: true, XAADPOP: true}, false},
	}
	for _, tc := range cases {
		err := tc.cfg.ValidateXAAFlags()
		if (err == nil) != tc.ok {
			t.Errorf("%s: err=%v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}
