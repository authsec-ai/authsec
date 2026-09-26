package integration

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/directory/adldap"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestSambaADInventory runs the inventory reader against the local Samba AD
// fixture. It does not run unless AD_SAMBA_TESTS=1, and it never uses a real
// directory or a real credential. The bind password is the placeholder in
// tests/fixtures/samba/entrypoint.sh.
func TestSambaADInventory(t *testing.T) {
	if os.Getenv("AD_SAMBA_TESTS") != "1" {
		t.Skip("set AD_SAMBA_TESTS=1 to build and run the Samba AD DC fixture")
	}
	if _, err := os.Stat("/var/run/docker.sock"); err != nil {
		t.Fatal("AD_SAMBA_TESTS=1 but docker is not available")
	}

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("fixture path")
	}
	fixture := filepath.Join(filepath.Dir(file), "..", "fixtures", "samba")

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{
				Context:    fixture,
				Dockerfile: "Dockerfile",
			},
			ExposedPorts: []string{"389/tcp", "636/tcp"},
			Privileged:   true,
			Hostname:     "dc.authsec.test",
			WaitingFor:   wait.ForLog("AUTHSEC_AD_READY").WithStartupTimeout(5 * time.Minute),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("samba fixture: %v", err)
	}
	t.Cleanup(func() { _ = container.Terminate(context.Background()) })

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := container.MappedPort(ctx, "389/tcp")
	if err != nil {
		t.Fatal(err)
	}

	reader := &adldap.LDAPReader{Conn: adldap.Conn{
		Server:   host + ":" + port.Port(),
		Username: "Administrator@AUTHSEC.TEST",
		Password: "CANARY-SECRET-DO-NOT-LEAK-1",
		PageSize: 50,
	}}
	ident, err := reader.DirectoryIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ident.ForestID == "" {
		t.Fatal("rootDSE returned no forest id")
	}
	users, err := reader.ReadClass(ctx, ident.DomainDN, adldap.ClassUser, 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	if !users.Complete {
		t.Fatalf("user read incomplete: %s", users.Reason)
	}
	var sawNoMail, sawDisabled bool
	for _, obj := range users.Objects {
		if obj.SAMAccountName == "nomail" && obj.Mail == "" {
			sawNoMail = true
		}
		if obj.AccountFlags.AccountDisabled {
			sawDisabled = true
		}
		if obj.ObjectGUID == "" {
			t.Fatal("object without a canonical GUID")
		}
	}
	if !sawNoMail || !sawDisabled {
		t.Fatalf("seed incomplete: nomail=%v disabled=%v objects=%d", sawNoMail, sawDisabled, len(users.Objects))
	}
}
