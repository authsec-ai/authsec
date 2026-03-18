#!/bin/sh
set -eu

echo "Waiting for Vault to become ready..."
until VAULT_ADDR="${VAULT_ADDR}" VAULT_TOKEN="${VAULT_TOKEN}" vault status >/dev/null 2>&1; do
  sleep 1
done

echo "Enabling kv-v2 at kv/ if needed..."
VAULT_ADDR="${VAULT_ADDR}" VAULT_TOKEN="${VAULT_TOKEN}" vault secrets enable -path=kv kv-v2 >/dev/null 2>&1 || true

echo "Writing a smoke secret to kv/data/secret/local-stack..."
VAULT_ADDR="${VAULT_ADDR}" VAULT_TOKEN="${VAULT_TOKEN}" vault kv put kv/secret/local-stack initialized=true >/dev/null

echo "Vault initialization complete."
