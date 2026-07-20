# intune-radius-helper

> **Note:** This project is written by Claude (Anthropic) and is still a work in progress. Review it accordingly before relying on it.

A small FastAPI service that lets FreeRADIUS (or any EAP-TLS RADIUS server) gate
authentication on live Microsoft Intune device compliance and Entra ID account
status, keyed off identifiers embedded in the client certificate's SAN URIs.

It is designed to sit behind a RADIUS server's `verify { client = ... }` hook:
the RADIUS server does the certificate chain/EKU validation, then calls this
service's `POST /check` with the client cert (PEM) and RADIUS username; the
service extracts an Entra device ID / user UPN from the cert's SAN URIs,
checks Intune `managedDevices` compliance and Entra account status via
Microsoft Graph, evaluates a declarative JSON policy against those facts to
pick a tier (`access` / `untrust` / `reject`), and returns `200` (access) or
`403` (untrust or reject) accordingly.

## Certificate identity convention

The client certificate must carry one or more SAN URIs of the form:

```
<URN_PREFIX>:entra-device-id:<entra device id>
<URN_PREFIX>:user-upn:<user principal name>
<URN_PREFIX>:entra-user-id:<entra object id>
<URN_PREFIX>:onprem-sid:<on-prem AD objectSid, e.g. via Intune SCEP's {{OnPremisesSecurityIdentifier}}>
```

`URN_PREFIX` is configurable (e.g. `urn:example.com`). The `onprem-sid` URI is
only consumed when `AD_LDAP_ENABLED=true` (see "Policy engine" and
"Configuration" below) - it's ignored otherwise.

## Request / response contract

```
POST /check
{
  "cert_pem": "-----BEGIN CERTIFICATE-----...",
  "radius_username": "...",
  "calling_station_id": "..."
}
```

Returns:

```
{
  "tier": "access",
  "allow": true,
  "reason": "device compliant",
  "matchedRule": "compliant-device-access",
  "checks": { "identity": {...}, "device": {...}, "user": {...}, "facts": {...} }
}
```

`allow` is `true` only when `tier` is `access`; `untrust` and `reject` both
return HTTP `403` today (`allow: false`) - see "Policy engine" below for what
distinguishes them and why "untrust" doesn't yet get separate treatment on
the wire.

`GET /healthz` reports cache backend health and effective policy config
(`policyRulesFile`, `policySource`, `policyLoadError`, `policyRuleCount`).
`POST /refresh/devices` and `POST /refresh/users` force an immediate Graph
cache refresh. `POST /debug/ad-device` (`{"onprem_sid": "S-1-5-21-..."}`)
runs a live AD/LDAPS lookup directly - bypassing the cache and `/check`'s
policy evaluation entirely - for testing connectivity/bind/base-DN/filter
against a real DC (only works when `AD_LDAP_ENABLED=true`).

## Policy engine

Whether a request lands in `access`, `untrust`, or `reject` is decided by a
declarative JSON ruleset, not hardcoded logic. Each request is first reduced
to a flat set of **facts**:

| Fact | Meaning |
|---|---|
| `cert_type` | `"device"` or `"user"` |
| `device_id_present_in_cert` / `user_upn_present_in_cert` | whether the cert's SAN URIs carried that identifier at all |
| `device_found` / `user_found` | whether Graph actually resolved the device/user |
| `compliance_state` | Intune `complianceState`, lowercased |
| `last_sync_age_hours` | hours since the device's last Intune sync, computed fresh per request |
| `device_account_enabled` / `user_account_enabled` | Entra `accountEnabled` |
| `onprem_sid_present_in_cert` | whether the cert's SAN URIs carried an `onprem-sid` |
| `ad_device_found` / `ad_device_enabled` | on-prem AD lookup result, only populated when `AD_LDAP_ENABLED=true` (see below) - otherwise `false`/`null` |

Rules are an ordered list, evaluated first-match-wins; falling off the end
uses `defaultTier` (fail-closed: `reject`). A rule's `when` is a condition
tree: `{"field": ..., "op": ..., "value": ...}` leaves (`op` one of `eq`,
`neq`, `gt`, `gte`, `lt`, `lte`, `in`, `exists`) combined with `{"all": [...]}`
/ `{"any": [...]}` / `{"not": ...}`.

[`policy.example.json`](policy.example.json) documents the format and
reproduces the built-in default ruleset (compliant device → `access`; known
but non-compliant device → `untrust`; disabled user/device, an unresolved
user identity, or a user cert missing its required device pairing → `reject`;
anything else → `reject` via `defaultTier`). Copy it, edit it, and mount it at
`POLICY_RULES_FILE` (default `/config/policy.json`) to override the default -
if that path doesn't exist, the built-in default ruleset above is used as-is,
and if it exists but fails to parse, **every request is rejected** (loud and
fail-closed, rather than silently falling back to a maybe-more-permissive
default) - check `policyLoadError` on `/healthz`.

Note that `untrust` and `reject` currently produce the same HTTP `403` from
`/check` - FreeRADIUS's `verify { client = ... }` hook (see
[intune-radius-stack](https://github.com/griefersutherland/intune-radius-stack))
hard-fails the TLS handshake on any non-200, so there's no way yet for a
denied client to land on a different VLAN instead of being rejected outright.
The `tier` field is there for that future integration; today it's informational
(visible in `/check` responses, `intune-auth.log`, and the `auth_events`
Postgres table when `CACHE_BACKEND=postgres_redis`).

### On-prem AD device lookup (optional)

Set `AD_LDAP_ENABLED=true` (plus `AD_LDAP_SERVER`, `AD_LDAP_BASE_DN`,
`AD_LDAP_BIND_USERNAME`/`AD_LDAP_BIND_PASSWORD`) to have `/check` also query
Active Directory over LDAPS for the device's `objectSid`, matched against the
cert's `onprem-sid` SAN URI. This is the strong-mapping identifier Intune SCEP
profiles can emit via the `{{OnPremisesSecurityIdentifier}}` variable - add a
SAN URI entry the same way the Intune SCEP profile setup already adds
`entra-device-id`:

| Type | Value |
|---|---|
| URI | `urn:example.com:onprem-sid:{{OnPremisesSecurityIdentifier}}` |

This populates `ad_device_found`/`ad_device_enabled` (from AD's
`userAccountControl` `ACCOUNTDISABLE` bit) but **does not change any
decision by itself** - the built-in default ruleset doesn't reference these
facts. To act on them, add a rule to your `policy.json`, e.g.:

```json
{
  "name": "ad-device-disabled-reject",
  "when": {"field": "ad_device_enabled", "op": "eq", "value": false},
  "tier": "reject",
  "reason": "AD computer account disabled"
}
```

`AD_LDAP_VERIFY_CERT=false` skips LDAPS certificate validation entirely (no
partial options like a custom CA bundle) - only use it against a DC you trust
on the network path, and prefer fixing the container's trust store instead
where possible. AD lookups are cached the same way as Graph device/user
lookups (subject to `LOCAL_CACHE_FIRST`, `ALLOW_STALE_CACHE_ON_GRAPH_ERROR` -
which, despite the name, also governs stale-cache fallback for AD lookup
failures - and `MAX_STALE_CACHE_HOURS`).

Test the bind/base-DN/filter against your real DC directly through the
running container, without needing a real cert or RADIUS auth attempt:

```bash
curl -X POST http://localhost:8080/debug/ad-device \
  -H "Content-Type: application/json" \
  -d '{"onprem_sid": "S-1-5-21-..."}'
```

This calls the live LDAP lookup directly (bypassing the cache), so a
connectivity, bind, or filter problem shows up immediately in the response's
`_ldapError` rather than being masked by a stale cache entry.

## Configuration

See [`.env.example`](.env.example) for all supported environment variables,
including:

- Graph app registration (`TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET`)
- Policy (`POLICY_RULES_FILE`, `TRUST_CHAIN_FALLBACK`) - see "Policy engine" above
- Optional AD/LDAP (`AD_LDAP_*`) - see "On-prem AD device lookup" above
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
