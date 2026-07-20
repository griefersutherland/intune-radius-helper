# intune-radius-helper

A small FastAPI service that lets FreeRADIUS (or any EAP-TLS RADIUS server) gate
authentication on live Microsoft Intune device compliance and Entra ID account
status, keyed off identifiers embedded in the client certificate's SAN URIs.

It is designed to sit behind a RADIUS server's `verify { client = ... }` hook:
the RADIUS server does the certificate chain/EKU validation, then calls this
service's `POST /check` with the client cert (PEM) and RADIUS username; the
service extracts an Entra device ID / user UPN from the cert's SAN URIs,
checks Intune `managedDevices` compliance and Entra account status via
Microsoft Graph, and returns `200` (allow) or `403` (deny).

## Certificate identity convention

The client certificate must carry one or more SAN URIs of the form:

```
<URN_PREFIX>:entra-device-id:<entra device id>
<URN_PREFIX>:user-upn:<user principal name>
<URN_PREFIX>:entra-user-id:<entra object id>
```

`URN_PREFIX` is configurable (e.g. `urn:example.com`).

## Request / response contract

```
POST /check
{
  "cert_pem": "-----BEGIN CERTIFICATE-----...",
  "radius_username": "...",
  "calling_station_id": "..."
}
```

Returns `200` with `{"allow": true, "reason": "...", "checks": {...}}` when
allowed, `403` with the same shape (allow: false) when denied.

`GET /healthz` reports cache backend health and effective policy config.
`POST /refresh/devices` and `POST /refresh/users` force an immediate Graph
cache refresh.

## Configuration

See [`.env.example`](.env.example) for all supported environment variables,
including:

- Graph app registration (`TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET`)
- Policy (`REQUIRE_COMPLIANT`, `REQUIRE_DEVICE_FOR_USER_CERT`, `MAX_LAST_SYNC_HOURS`, ...)
- Cache backend: `sqlite` (single file, zero external dependencies) or
  `postgres_redis` (for multi-replica / higher-throughput deployments)

## Running

```
docker build -t intune-radius-helper .
docker run --env-file .env -p 8080:8080 intune-radius-helper
```

Pre-built images are published to `ghcr.io/griefersutherland/intune-radius-helper`.

This service has no opinion about how FreeRADIUS is configured — pair it with
your own RADIUS `clients.conf` / EAP TLS setup, calling `POST /check` from a
certificate verify script.

## License

GPLv3 or later. See [LICENSE](LICENSE).
