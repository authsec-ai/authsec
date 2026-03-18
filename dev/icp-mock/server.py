import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer


PORT = int(os.environ.get("ICP_MOCK_PORT", "7001"))


def _json(handler, status, payload):
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("[icp-mock]", fmt % args)

    def do_GET(self):
        if self.path == "/health":
            _json(self, 200, {"status": "healthy", "service": "icp-mock"})
            return
        _json(self, 404, {"error": "not_found"})

    def do_POST(self):
        if self.path.startswith("/admin/pki/provision/"):
            tenant_id = self.path.rsplit("/", 1)[-1]
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
            payload = json.loads(raw or b"{}")
            response = {
                "tenant_id": tenant_id,
                "pki_mount": f"pki/{tenant_id}",
                "ca_cert": "-----BEGIN CERTIFICATE-----\nLOCAL-ICP-MOCK\n-----END CERTIFICATE-----",
                "role_created": f"{tenant_id}-role",
                "message": "mock PKI provisioned",
                "request": payload,
            }
            _json(self, 200, response)
            return
        _json(self, 404, {"error": "not_found"})

    def do_PATCH(self):
        if self.path.startswith("/admin/tenants/") and self.path.endswith("/status"):
            tenant_id = self.path.split("/")[3]
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
            payload = json.loads(raw or b"{}")
            _json(
                self,
                200,
                {
                    "tenant_id": tenant_id,
                    "status": payload.get("status", "unknown"),
                    "message": "mock tenant status updated",
                },
            )
            return
        _json(self, 404, {"error": "not_found"})


if __name__ == "__main__":
    print(f"Starting icp-mock on :{PORT}")
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
