//go:build integration

// Package flagsoff is a sibling integration-test binary that boots the
// harness with all XAA feature flags disabled (XAA_NATIVE_SEALER, XAA_M2M,
// XAA_REDEMPTION, XAA_CIBA, XAA_ISSUANCE all set to "false").
//
// Flag-off approach
// -----------------
// testsupport.Boot accepts a WithXAAFlagsOff() option that causes
// setHarnessEnv (called inside Boot before config.LoadConfig) to write
// "false" for every XAA_* env var instead of "true". Because LoadConfig
// reads those vars via getEnvBool at startup, the resulting AppConfig has all
// XAA fields set to false for the lifetime of this binary. No post-Boot
// override is needed.
//
// Do NOT call Boot() without WithXAAFlagsOff() here — setHarnessEnv defaults
// all XAA flags to "true", which would defeat the purpose of this package.
package flagsoff

import (
	"log"
	"os"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/authsec-ai/authsec/internal/tokens"
)

func TestMain(m *testing.M) {
	// Reset all process-global singletons so this binary gets a clean slate.
	config.ResetForTest()
	tokens.ResetForTest()

	// Boot the harness with XAA flags OFF. WithXAAFlagsOff() causes
	// setHarnessEnv (invoked inside Boot before LoadConfig) to write "false"
	// for XAA_NATIVE_SEALER, XAA_M2M, XAA_REDEMPTION, XAA_CIBA, and
	// XAA_ISSUANCE, so AppConfig will have all XAA booleans = false.
	env, err := testsupport.Boot(testsupport.WithXAAFlagsOff())
	if err != nil {
		log.Fatalf("testsupport.Boot (flags-off): %v", err)
	}

	code := m.Run()

	env.Teardown()
	os.Exit(code)
}
