//go:build integration

package flows

import (
	"log"
	"os"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/authsec-ai/authsec/internal/tokens"
)

func TestMain(m *testing.M) {
	config.ResetForTest()
	tokens.ResetForTest()

	env, err := testsupport.Boot()
	if err != nil {
		log.Fatalf("testsupport.Boot: %v", err)
	}

	code := m.Run()

	env.Teardown()

	os.Exit(code)
}
