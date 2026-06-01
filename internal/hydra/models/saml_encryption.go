package hydramodels

import (
	"encoding/base64"
	"fmt"

	"github.com/authsec-ai/authsec/config"
)

// encryptPrivateKeyWithVault encrypts a private key using Vault transit engine
func encryptPrivateKeyWithVault(workspaceID, privateKeyPEM string) (string, error) {
	if config.VaultClient == nil {
		return "", fmt.Errorf("Vault client not initialized")
	}

	encodedKey := base64.StdEncoding.EncodeToString([]byte(privateKeyPEM))

	data := map[string]interface{}{
		"plaintext": encodedKey,
		"context":   base64.StdEncoding.EncodeToString([]byte(workspaceID)),
	}

	secret, err := config.VaultClient.Logical().Write("transit/encrypt/saml-sp-keys", data)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt with Vault: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("Vault encryption returned nil")
	}

	ciphertext, ok := secret.Data["ciphertext"].(string)
	if !ok {
		return "", fmt.Errorf("ciphertext not found in Vault response")
	}

	return "vault:" + ciphertext, nil
}
