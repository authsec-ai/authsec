package unit

import (
	"testing"

	"github.com/authsec-ai/authsec/utils"
)

func TestHashPassword_ProducesNonEmptyHash(t *testing.T) {
	hash, err := utils.HashPassword("SuperSecret1!")
	if err != nil {
		t.Fatalf("HashPassword error: %v", err)
	}
	if hash == "" {
		t.Error("HashPassword returned empty hash")
	}
}

func TestHashPassword_DifferentInputsDifferentHashes(t *testing.T) {
	h1, _ := utils.HashPassword("Password1!")
	h2, _ := utils.HashPassword("Password2!")
	if h1 == h2 {
		t.Error("different passwords should produce different hashes")
	}
}

func TestHashPassword_SameInputDifferentHashes(t *testing.T) {
	// bcrypt uses random salt — same input must not produce same hash
	h1, _ := utils.HashPassword("Password1!")
	h2, _ := utils.HashPassword("Password1!")
	if h1 == h2 {
		t.Error("bcrypt should produce different hashes for same input (random salt)")
	}
}

func TestCheckPassword_CorrectPassword(t *testing.T) {
	hash, err := utils.HashPassword("Correct1!")
	if err != nil {
		t.Fatalf("HashPassword error: %v", err)
	}
	if !utils.CheckPassword(hash, "Correct1!") {
		t.Error("CheckPassword: correct password should return true")
	}
}

func TestCheckPassword_WrongPassword(t *testing.T) {
	hash, _ := utils.HashPassword("Correct1!")
	if utils.CheckPassword(hash, "Wrong1!") {
		t.Error("CheckPassword: wrong password should return false")
	}
}

func TestCheckPassword_EmptyPassword(t *testing.T) {
	hash, _ := utils.HashPassword("Correct1!")
	if utils.CheckPassword(hash, "") {
		t.Error("CheckPassword: empty password should return false")
	}
}

func TestCheckPassword_InvalidHash(t *testing.T) {
	if utils.CheckPassword("not-a-bcrypt-hash", "anything") {
		t.Error("CheckPassword: invalid hash should return false")
	}
}
