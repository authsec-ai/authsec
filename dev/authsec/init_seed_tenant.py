#!/usr/bin/env python3
import base64
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request


AUTHSEC_BASE_URL = os.environ.get("AUTHSEC_BASE_URL", "http://authsec:7468/authsec").rstrip("/")
JWT_SECRET = os.environ.get("JWT_SECRET", "authsecai")
SEED_TENANT_ID = os.environ.get("SEED_TENANT_ID", "11111111-1111-1111-1111-111111111111")
SEED_ADMIN_EMAIL = os.environ.get("SEED_ADMIN_EMAIL", "admin@test.com")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_jwt() -> str:
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": "local-seed-init",
        "tenant_id": SEED_TENANT_ID,
        "email": SEED_ADMIN_EMAIL,
        "roles": ["admin"],
        "permissions": ["admin:access"],
        "iss": "authsec-ai/auth-manager",
        "iat": now,
        "nbf": now,
        "exp": now + 3600,
    }
    signing_input = f"{b64url(json.dumps(header, separators=(',', ':')).encode())}.{b64url(json.dumps(payload, separators=(',', ':')).encode())}"
    signature = b64url(hmac.new(JWT_SECRET.encode(), signing_input.encode(), hashlib.sha256).digest())
    return f"{signing_input}.{signature}"


def request(method: str, path: str, body=None):
    headers = {"Authorization": f"Bearer {make_jwt()}"}
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()

    req = urllib.request.Request(f"{AUTHSEC_BASE_URL}{path}", data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=20) as resp:
        raw = resp.read().decode()
        return resp.status, json.loads(raw) if raw else {}


def wait_for_authsec():
    health_url = f"{AUTHSEC_BASE_URL}/uflow/health"
    for _ in range(60):
        try:
            with urllib.request.urlopen(health_url, timeout=5) as resp:
                if resp.status == 200:
                    print("authsec-init: AuthSec is healthy", flush=True)
                    return
        except Exception:
            pass
        time.sleep(2)
    raise RuntimeError("timed out waiting for AuthSec health")


def ensure_seed_tenant_db():
    status, response = request("POST", "/migration/tenants/create-db", {"tenant_id": SEED_TENANT_ID})
    if status not in (200, 201):
        raise RuntimeError(f"unexpected create-db status {status}: {response}")
    print(f"authsec-init: create-db responded with {status}: {response}", flush=True)

    status_path = f"/migration/tenants/{SEED_TENANT_ID}/migrations/status"
    for _ in range(90):
        status, response = request("GET", status_path)
        if status == 200 and response.get("migration_status") == "completed":
            print(f"authsec-init: tenant migration completed: {response}", flush=True)
            return
        print(f"authsec-init: waiting for tenant migration: {response}", flush=True)
        time.sleep(2)
    raise RuntimeError("timed out waiting for seed tenant migration completion")


def main():
    try:
        wait_for_authsec()
        ensure_seed_tenant_db()
    except urllib.error.HTTPError as err:
        body = err.read().decode()
        print(f"authsec-init: HTTP {err.code}: {body}", file=sys.stderr, flush=True)
        raise
    except Exception as err:
        print(f"authsec-init: {err}", file=sys.stderr, flush=True)
        raise


if __name__ == "__main__":
    main()
