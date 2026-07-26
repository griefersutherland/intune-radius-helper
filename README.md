# intune-radius-helper

> **Note:** This project is written by Claude (Anthropic) and is still a work in progress. Review it accordingly before relying on it.

## Thanks

This service is a thin layer of glue on top of other people's real
engineering work. Special thanks to the maintainers of
[FastAPI](https://fastapi.tiangolo.com/), [httpx](https://www.python-httpx.org/),
[ldap3](https://github.com/cannatag/ldap3), [asyncpg](https://github.com/MagicStack/asyncpg),
and [redis-py](https://github.com/redis/redis-py), and to the
[PostgreSQL](https://www.postgresql.org/) and [Redis](https://redis.io/)
projects underneath the caching layer - none of this would work, or be
anywhere near this simple, without their efforts.

A small FastAPI service that lets FreeRADIUS (or any EAP-TLS RADIUS server) gate
authentication on live Microsoft Intune device compliance and Entra ID account
status, keyed off identifiers embedded in the client certificate's SAN URIs.

It's a plain HTTP service with no opinion about when it's called - the
RADIUS server does its own certificate chain/EKU validation, then calls this
service's `POST /check` with the client cert (PEM) and RADIUS username; the
service extracts an Entra device ID / user UPN from the cert's SAN URIs,
checks Intune `managedDevices` compliance and Entra account status via
Microsoft Graph, evaluates a declarative JSON policy against those facts to
pick a tier (`access` / `untrust` / `reject`), and returns `200` (access) or
`403` (untrust or reject) accordingly.
[mid-radius-stack](https://github.com/griefersutherland/mid-radius-stack)
calls it from RADIUS's `post-auth` phase rather than the EAP-TLS
`verify { client = ... }` hook specifically so a non-`access` tier can still
land on a different VLAN instead of only ever being able to reject outright.

## Certificate identity convention

The client certificate must carry one or more SAN URIs of the form:

```
<URN_PREFIX>:entra-device-id:<entra device id>
<URN_PREFIX>:user-upn:<user principal name>
<URN_PREFIX>:entra-user-id:<entra object id>
<URN_PREFIX>:onprem-sid:<on-prem AD objectSid, e.g. via Intune SCEP's {{OnPremisesSecurityIdentifier}}>
<URN_PREFIX>:jamf-serial:<device serial number, e.g. via a Jamf SCEP profile's $SERIALNUMBER>
```

`URN_PREFIX` is configurable (e.g. `urn:example.com`). The `onprem-sid` URI is
only consumed when `AD_LDAP_ENABLED=true`, and `jamf-serial` only when
`JAMF_ENABLED=true` (see "Policy engine" and "Configuration" below) - both are
ignored otherwise.

## Request / response contract

```
POST /check
{
  "cert_pem": "-----BEGIN CERTIFICATE-----...",
  "radius_username": "...",
  "calling_station_id": "...",
  "correlation_id": "..."
}
```

`correlation_id` is optional and just passed through into the response's
`checks.correlationId` and (when `CACHE_BACKEND=postgres_redis`) the
`auth_events` table's own `correlation_id` column - see "Correlating a
single auth attempt across logs" below. A caller that doesn't send one just
gets an event with no `correlationId`, same as before this existed.

Returns:

```
{
  "tier": "access",
  "allow": true,
  "reason": "device compliant",
  "matchedRule": "compliant-device-access",
  "checks": { "correlationId": "...", "identity": {...}, "device": {...}, "user": {...}, "facts": {...} }
}
```

`allow` is `true` only when `tier` is `access`; `untrust` and `reject` both
return HTTP `403` (`allow: false`) at this endpoint - the distinction between
them is carried in the `tier` field of the response body, not the status
code. See "Policy engine" below and
[mid-radius-stack](https://github.com/griefersutherland/mid-radius-stack)'s
README for how that consumes `tier` to land `untrust` on a different VLAN
than an outright `reject`.

`GET /healthz` reports cache backend health and effective policy config
(`policyRulesFile`, `policySource`, `policyLoadError`, `policyRuleCount`).
`POST /refresh/devices` and `POST /refresh/users` force an immediate Graph
cache refresh. `POST /debug/ad-device` (`{"onprem_sid": "S-1-5-21-..."}`)
runs a live AD/LDAPS lookup directly - bypassing the cache and `/check`'s
policy evaluation entirely - for testing connectivity/bind/base-DN/filter
against a real DC (only works when `AD_LDAP_ENABLED=true`). `POST
/debug/jamf-device` (`{"serial": "C02ZC2QYLVDL"}`) does the same for a live
Jamf Pro inventory lookup (only works when `JAMF_ENABLED=true`).

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
| `jamf_serial_present_in_cert` | whether the cert's SAN URIs carried a `jamf-serial` |
| `jamf_device_found` / `jamf_device_managed` / `jamf_compliant_group_member` / `jamf_last_contact_age_hours` | Jamf Pro lookup result, only populated when `JAMF_ENABLED=true` (see below) - otherwise `false`/`null` |

On top of those platform-specific facts, a second layer of **normalized**
facts collapses whichever platform actually resolved for a given cert into a
shared vocabulary, so one ruleset can express "compliant → access, known but
not → untrust, unknown → reject" without repeating it per platform:

| Fact | Meaning |
|---|---|
| `identity_platform` | `"intune"`, `"jamf"`, or `"unresolved"` - which check path populated data for this cert |
| `identity_found` | normalized `device_found`/`jamf_device_found`/`user_found`, whichever platform matched |
| `compliant` | `true`/`false`, or `null` if no compliance signal applies (e.g. a bare user cert, or nothing found) - Intune: `compliance_state == "compliant"`; Jamf: managed **and** a member of the compliant Smart Group |
| `last_checkin_age_hours` | normalized `last_sync_age_hours`/`jamf_last_contact_age_hours` |
| `account_enabled` | normalized `device_account_enabled`/`user_account_enabled`/Jamf `managed`, collapsed to `false` if *any* populated signal is `false` |

**AD/LDAP is deliberately excluded from `compliant`/`account_enabled`** - on-prem AD has no compliance concept, just enabled/disabled, which isn't the same axis as "out of compliance." It stays a separate, additive check (`ad_device_found`/`ad_device_enabled`) that a custom rule can still act on.

Rules are an ordered list, evaluated first-match-wins; falling off the end
uses `defaultTier` (fail-closed: `reject`). A rule's `when` is a condition
tree: `{"field": ..., "op": ..., "value": ...}` leaves (`op` one of `eq`,
`neq`, `gt`, `gte`, `lt`, `lte`, `in`, `exists`) combined with `{"all": [...]}`
/ `{"any": [...]}` / `{"not": ...}`.

[`policy.example.json`](policy.example.json) documents the format and
reproduces the built-in default ruleset, which is built on the normalized
facts above - compliant device (Intune **or** Jamf) → `access`; known but
non-compliant → `untrust`; disabled/unmanaged account, an unresolved user
identity, or a user cert missing its required device pairing → `reject`;
anything else → `reject` via `defaultTier`. This means a fresh deployment
with `JAMF_ENABLED=true` gets correct compliance-gated behavior for both
Intune and Jamf devices with **no custom `policy.json` needed at all**. Copy
`policy.example.json`, edit it, and mount it at `POLICY_RULES_FILE` (default
`/config/policy.json`) only once you need to diverge from the default - e.g.
different staleness thresholds per platform, or acting on the AD facts. If
`POLICY_RULES_FILE` doesn't exist, the built-in default ruleset above is used
as-is, and if it exists but fails to parse, **every request is rejected**
(loud and fail-closed, rather than silently falling back to a maybe-more-permissive
default) - check `policyLoadError` on `/healthz`.

`untrust` and `reject` both produce HTTP `403` from `/check` - a consumer
that only looks at the status code can't tell them apart. FreeRADIUS's
`verify { client = ... }` hook (see
[mid-radius-stack](https://github.com/griefersutherland/mid-radius-stack))
can't either, since a non-200 there hard-fails the TLS handshake before any
VLAN could ever be assigned - which is why that stack's actual compliance
check now happens later, in RADIUS's `post-auth` phase, where it can read
the `tier` field directly and land `untrust` on a different VLAN than a
`reject`. Every `tier` decision is also visible in `/check` responses,
`intune-auth.log`, and the `auth_events` Postgres table when
`CACHE_BACKEND=postgres_redis`.

### Correlating a single auth attempt across logs

A single auth attempt touches three separate, otherwise-unlinked places:
mid-radius-stack's `radius-verify.log` (the EAP-TLS cert verify step),
this service's `intune-auth.log`/`/check` response (the policy decision),
and - if `CACHE_BACKEND=postgres_redis` - the `auth_events` table. Matching
these up by MAC address and rough timestamp works until a device retries
several times in quick succession (routine during initial device setup,
profile misconfiguration, or a flaky NAS) and the timestamps stop being
unambiguous.

mid-radius-stack's `verify-client-cert.sh` generates a UUID once per attempt,
writes it into its own log line, and forwards it through `check-policy.sh`
into this service's `/check` request as `correlation_id`. From here it's
just carried through - into the response's `checks.correlationId`,
`intune-auth.log`'s JSON event, and (with `CACHE_BACKEND=postgres_redis`)
`auth_events.correlation_id`, which is indexed for direct lookup:

```sql
select * from auth_events where correlation_id = '...';
```

No configuration needed on this side - if `correlation_id` isn't sent (e.g.
a caller other than mid-radius-stack), `checks.correlationId` is just empty,
same as before this existed.

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

### Jamf Pro device lookup (optional)

For Jamf-managed devices (typically macOS, not enrolled in Intune) - set
`JAMF_ENABLED=true` (plus `JAMF_API_URL`, `JAMF_API_CLIENT_ID`,
`JAMF_API_CLIENT_SECRET`, `JAMF_COMPLIANT_GROUP_ID`) to have `/check` also
query Jamf Pro for the device's inventory record and Smart Group
memberships, matched against the cert's `jamf-serial` SAN URI:

| Type | Value |
|---|---|
| URI | `urn:example.com:jamf-serial:{{SERIALNUMBER}}` |

(If certs come from [pimptune-stack](https://github.com/griefersutherland/pimptune-stack)'s
Jamf SCEP provisioner, add this URI in the same SCEP profile's Subject
Alternative Name section documented in that repo's README.)

Jamf Pro has no single `complianceState` field the way Intune's
`managedDevices` does - "compliant" here means membership in a **Smart
Group you define yourself** in Jamf Pro (e.g. one built from Smart Group
criteria like FileVault status, OS version, or a compliance Extension
Attribute). `JAMF_COMPLIANT_GROUP_ID` is that group's numeric ID, visible in
the group's URL in the Jamf Pro console (`.../smartComputerGroups.html?id=42`
→ `42`).

The API Client (Jamf Pro → Settings → System → API roles and clients) needs
read access to computer inventory and group memberships; auth is OAuth
client-credentials against `{JAMF_API_URL}/api/oauth/token`.

This populates `jamf_device_found`, `jamf_device_managed` (Jamf's
"actively MDM-managed" flag), `jamf_compliant_group_member`, and
`jamf_last_contact_age_hours`. Unlike the AD facts, **these do change the
decision out of the box** - the built-in default ruleset (see "Policy
engine" above) normalizes them into the same `identity_found`/`compliant`/
`account_enabled` facts the Intune path uses, so `JAMF_ENABLED=true` alone
gets you correct compliant → `access` / non-compliant → `untrust` /
unmanaged or not-found → `reject` behavior with no `policy.json` needed at
all. Only write a custom `policy.json` if you need to diverge from that
(different staleness threshold than Intune's, Jamf capped at `untrust` even
when compliant, etc.).

Jamf lookups are cached the same way as Graph/AD lookups (subject to
`LOCAL_CACHE_FIRST`, `ALLOW_STALE_CACHE_ON_GRAPH_ERROR`, and
`MAX_STALE_CACHE_HOURS`).

Test connectivity/auth/group-ID against your real Jamf Pro instance directly
through the running container, without needing a real cert or RADIUS auth
attempt:

```bash
curl -X POST http://localhost:8080/debug/jamf-device \
  -H "Content-Type: application/json" \
  -d '{"serial": "C02ZC2QYLVDL"}'
```

This calls the live Jamf Pro lookup directly (bypassing the cache), so an
auth or filter problem shows up immediately in the response's `_jamfError`
rather than being masked by a stale cache entry.

### AD-only mode (no Graph app registration)

Set `GRAPH_ENABLED=false` to skip Microsoft Graph entirely - no token
requests, no `/deviceManagement/managedDevices` or `/users` calls, and the
background device/user cache refresh loops never start. Use this when
`AD_LDAP_ENABLED=true` and on-prem AD is meant to be the sole source of
truth, with no Intune/Entra app registration provisioned at all.

With `GRAPH_ENABLED=false`, a cert's `onprem-sid` SAN URI alone is enough to
pass identity extraction (normally at least one of `entra-device-id` /
`user-upn` is required) - see "Certificate identity convention" above.
`device_found`, `compliance_state`, and `user_found` are never populated in
this mode, so the built-in default ruleset (which keys off those facts) will
fail-closed to `reject` for every request. You must supply a custom
`policy.json` keyed off `ad_device_found`/`ad_device_enabled` instead - see
[`policy.ad-only.example.json`](policy.ad-only.example.json) for a ready-to-copy
ruleset. `TENANT_ID`/`CLIENT_ID`/`CLIENT_SECRET` can be left unset in this mode.

## Device blocking

An explicit denylist, independent of Intune/Entra compliance and the policy
engine above - for immediately cutting off a stolen/terminated device
regardless of what Graph or AD currently reports about it. Requires
`CACHE_BACKEND=postgres_redis` (backed by a `blocked_devices` table) and
`ADMIN_API_KEY` set - with no key configured, the endpoints below refuse
every request rather than accept unauthenticated writes.

A block is checked live (never cached) on every `/check` call, and short-circuits
*everything else* - including `TRUST_CHAIN_FALLBACK` and the declarative
policy engine - so it can't be bypassed by a custom `policy.json`. It's
checked once by MAC (`Calling-Station-Id`) before the certificate is even
parsed, and again by Entra device ID / AD SID / Jamf serial once the cert
identity is extracted, so a block still applies across a NIC swap if the
identity in the cert is what's blocked.

```bash
# block (identifier_type is one of: mac, entra_device_id, ad_sid, jamf_serial)
curl -X POST http://localhost:8080/block-device \
  -H "X-Admin-Api-Key: $ADMIN_API_KEY" -H "Content-Type: application/json" \
  -d '{"identifier_type": "mac", "identifier_value": "aa:bb:cc:dd:ee:ff", "reason": "reported stolen"}'

# unblock
curl -X POST http://localhost:8080/unblock-device \
  -H "X-Admin-Api-Key: $ADMIN_API_KEY" -H "Content-Type: application/json" \
  -d '{"identifier_type": "mac", "identifier_value": "aa:bb:cc:dd:ee:ff"}'

# list
curl -H "X-Admin-Api-Key: $ADMIN_API_KEY" http://localhost:8080/blocked-devices
```

MAC values are normalized (colons/dashes stripped, lowercased) before
storage and lookup, so any common `Calling-Station-Id` format matches.

## Configuration

See [`.env.example`](.env.example) for all supported environment variables,
including:

- Graph app registration (`TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET`), and
  `GRAPH_ENABLED` to disable Graph entirely - see "AD-only mode" above
- Policy (`POLICY_RULES_FILE`, `TRUST_CHAIN_FALLBACK`) - see "Policy engine" above
- Optional AD/LDAP (`AD_LDAP_*`) - see "On-prem AD device lookup" above
- Optional Jamf Pro (`JAMF_*`) - see "Jamf Pro device lookup" above
- Cache backend: `sqlite` (single file, zero external dependencies) or
  `postgres_redis` (for multi-replica / higher-throughput deployments)
- Device blocking (`ADMIN_API_KEY`) - see "Device blocking" above

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

## Support open source

If this project was useful to you, consider donating to an open-source
project you rely on — most of them run on volunteer time and small
donations. A few of my own favorites:

- [KDE](https://kde.org/donate/)
- [ReactOS](https://reactos.org/donate/)
- [Matrix.org](https://donorbox.org/keep-matrix-exciting) — a free-speech,
  end-to-end encrypted chat protocol
- [LLVM](https://github.com/sponsors/llvm) — the compiler infrastructure
  underneath a huge share of modern software

Both feel especially important to keep funded right now, in these
uncertain times of dark enlightenment.

And if you'd like to help cover this project's own Anthropic API usage, or
support a personal local-inference homelab, that's separate and entirely
optional: [GoFundMe](https://gofund.me/815bb9c26)
