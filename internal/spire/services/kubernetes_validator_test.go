package services

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/sirupsen/logrus"
)

// AS-076: ENVIRONMENT never turns PSAT signature verification off, and
// without a Kubernetes API host the validator refuses instead of parsing the
// token unverified.

func unsignedPSAT() string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none"}`)) + "." +
		enc([]byte(`{"kubernetes.io/serviceaccount/namespace":"kube-system","kubernetes.io/serviceaccount/service-account.name":"admin"}`)) + "."
}

func TestKubernetesValidator_VerificationIsTheDefault(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	for _, env := range []string{"development", "dev", "", "production"} {
		t.Setenv("ENVIRONMENT", env)
		t.Setenv("SPIRE_K8S_INSECURE_SKIP_TOKEN_VERIFY", "")
		t.Setenv("KUBERNETES_SERVICE_HOST", "")
		v, err := NewKubernetesValidator(logger, &KubernetesValidatorConfig{UseTokenReview: false})
		if err != nil {
			t.Fatal(err)
		}
		if !v.useTokenReview {
			t.Errorf("ENVIRONMENT=%q: token review must be on", env)
		}
		if _, err := v.Validate(context.Background(), map[string]interface{}{"psat_token": unsignedPSAT()}); err == nil {
			t.Errorf("ENVIRONMENT=%q: an unsigned PSAT was accepted without an API host", env)
		}
	}
}

func TestKubernetesValidator_InsecureFlagRefusedInProduction(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	t.Setenv("SPIRE_K8S_INSECURE_SKIP_TOKEN_VERIFY", "true")
	for env, want := range map[string]bool{"production": false, "staging": false, "development": true} {
		t.Setenv("ENVIRONMENT", env)
		if got := insecureK8sTokensAllowed(logger); got != want {
			t.Errorf("ENVIRONMENT=%s: insecure allowed = %v, want %v", env, got, want)
		}
	}
}
