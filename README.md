# Leuffen RMM Agent

Windows agent source, packaging, and CI for the Leuffen RMM platform.

See `agent/` for the agent source, `packaging/windows/` for the MSI packaging,
and `.github/workflows/` for the build/release pipelines.

## Configuration

The agent reads its settings from environment variables first, then from
`rmm_config.json` in its data dir (`%ProgramData%\LeuffenRMM` on Windows). Env
vars win; the resolved config is persisted so it survives an MSI upgrade.

| Env var | Config key | Purpose |
|---|---|---|
| `RMM_SERVER_URL` | `server_url` | Server base URL (https assumed if no scheme). |
| `RMM_API_KEY` | `api_key` | One-time enrollment key (or org key) used on first connect. |
| `RMM_INSECURE_TLS` | `insecure_tls` | Accept the server's self-signed cert (default for the bundled setup). |
| `RMM_SERVER_FINGERPRINT` | `server_fingerprint` | SHA-256 of the server's TLS cert (hex, colons optional). When set, the agent **pins** that exact cert after connect — MITM-proof even with `insecure_tls`. |

### Secure connection

- **Cert pinning:** set `RMM_SERVER_FINGERPRINT` (or the `server_fingerprint`
  config key) to the server cert's SHA-256. The server exposes its own
  fingerprint at `GET /api/server-fingerprint` (admin) and logs it on startup.
- **Per-device secret:** the agent advertises `supports_secret` and stores a
  server-issued secret in `rmm_device_secret`, proving its identity on reconnect
  so a stolen `device_id` alone can't impersonate it. No setup required.
