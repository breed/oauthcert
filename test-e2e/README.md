# test-e2e

End-to-end test fixtures for the oauthcert project.

## WARNING: TEST KEYS ONLY

`ca.key` and `server.key` are **test-only** key material generated exclusively for local
integration tests. They are **not** production keys and must never be used to configure any
production or staging deployment.

| File | Purpose |
|------|---------|
| `ca.key` | EC private key for the test CA — **TEST USE ONLY** |
| `server.key` | WireGuard private key for the test server — **TEST USE ONLY** |
| `ca.crt` | Self-signed test CA certificate |

These files are intentionally committed as test fixtures. Treat them as fully public
information; assume any attacker has a copy.
