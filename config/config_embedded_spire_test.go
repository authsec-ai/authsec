package config

import "testing"

// AS-081: the embedded SPIRE control plane cannot be switched on where real
// tenants are.
func TestValidateEmbeddedSpire(t *testing.T) {
	for env, wantErr := range map[string]bool{"production": true, "Staging": true, "development": false, "": false} {
		c := &Config{Environment: env, EnableEmbeddedSpire: true}
		if err := c.ValidateEmbeddedSpire(); (err != nil) != wantErr {
			t.Errorf("ENVIRONMENT=%q: err = %v, want error %v", env, err, wantErr)
		}
	}
	if err := (&Config{Environment: "production"}).ValidateEmbeddedSpire(); err != nil {
		t.Errorf("flag off must pass: %v", err)
	}
}
