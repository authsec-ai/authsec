package igagraph

import (
	"strings"
	"testing"
)

func TestRuntimeKeysCollideOnlyOnTheirComponents(t *testing.T) {
	host, err := HostKey("estate-a")
	if err != nil {
		t.Fatal(err)
	}
	other, err := HostKey("estate-b")
	if err != nil {
		t.Fatal(err)
	}
	if host == other {
		t.Fatal("two estates collapsed to one host")
	}
	if _, err := HostKey(""); err == nil {
		t.Fatal("empty estate must not key a host")
	}

	unit, err := SystemdWorkloadKey("estate-a", "invoice-worker.service")
	if err != nil {
		t.Fatal(err)
	}
	renamed, err := SystemdWorkloadKey("estate-a", "invoice-worker.service")
	if err != nil || renamed != unit {
		t.Fatalf("unit key changed: %s %s", unit, renamed)
	}

	proc, err := ProcessRuntimeKey("estate-a", "boot-a", "host", "824", "93401")
	if err != nil {
		t.Fatal(err)
	}
	reused, err := ProcessRuntimeKey("estate-a", "boot-a", "host", "824", "100")
	if err != nil || reused == proc {
		t.Fatal("PID reuse with different start ticks must be a different runtime")
	}

	uid, err := LocalIdentityKey("estate-a", "host", "995")
	if err != nil {
		t.Fatal(err)
	}
	same, err := LocalIdentityKey("estate-a", "host", "995")
	if err != nil || same != uid {
		t.Fatal("a renamed local account must keep its key")
	}
	otherHost, err := LocalIdentityKey("estate-b", "host", "995")
	if err != nil || otherHost == uid {
		t.Fatal("UID 995 on two estates must not be one identity")
	}

	wl, err := KubernetesWorkloadKey("c", "apps", "Deployment", "pay", "invoice", "0")
	if err != nil {
		t.Fatal(err)
	}
	recreated, err := KubernetesWorkloadKey("c", "apps", "Deployment", "pay", "invoice", "0")
	if err != nil || recreated != wl {
		t.Fatal("a new object UID must not change the workload key")
	}
	sa, err := KubernetesServiceAccountKey("c", "pay", "invoice")
	if err != nil {
		t.Fatal(err)
	}
	if sa == wl {
		t.Fatal("workload and service account keys collided")
	}

	path, err := FileResourceKey("estate-a", "mnt", "/var/lib/invoice/data")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(path, "/var") {
		t.Fatalf("path slash was not escaped: %q", path)
	}
	hostile, err := FileResourceKey("estate-a", "mnt", "a"+Sep+"b")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(hostile, Sep) != strings.Count(path, Sep) {
		t.Fatalf("separator in a path changed the segment count: %q", hostile)
	}

	pub, err := NetworkEndpointKey("ipv4", "1.1.1.1", "443", "tcp", "estate-a", false)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := NetworkEndpointKey("ipv4", "10.20.0.15", "5432", "tcp", "estate-a", true)
	if err != nil {
		t.Fatal(err)
	}
	if pub == priv {
		t.Fatal("public and private endpoints collided")
	}
	if _, err := NetworkEndpointKey("ipv4", "10.0.0.1", "1", "tcp", "", true); err == nil {
		t.Fatal("private endpoint without an estate")
	}
	if strings.Contains(pub, "estate-a") {
		t.Fatal("a public endpoint must not carry an estate")
	}

	secret, err := SecretRefKey("linux", "estate-a", "app", "db", "password")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(secret, "CANARY-SECRET-DO-NOT-LEAK") {
		t.Fatal("secret value entered a key")
	}
	again, err := SecretRefKey("linux", "estate-a", "app", "db", "password")
	if err != nil || again != secret {
		t.Fatal("secret ref key is not stable")
	}
}

func TestADIdentityKeyStillThreeSegments(t *testing.T) {
	key, err := ADIdentityKey("DC=authsec,DC=test", "aabbccdd-eeff-0011-2233-445566778899")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(key, Sep) != 2 {
		t.Fatalf("segments: %q", key)
	}
	hostile, err := ADIdentityKey("dc"+Sep+"x", "aabbccdd-eeff-0011-2233-445566778899")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(hostile, Sep) != 2 {
		t.Fatalf("hostile forest changed the segment count: %q", hostile)
	}
}
