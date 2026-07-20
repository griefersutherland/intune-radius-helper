# intune-radius-helper - Intune/Entra device compliance gate for FreeRADIUS EAP-TLS
# Copyright (C) 2026  griefersutherland
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import json
import os
import re
import sqlite3
import ssl
import subprocess
import tempfile
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Optional
from urllib.parse import quote

import asyncpg
import httpx
import ldap3
import redis.asyncio as redis
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


app = FastAPI(title="Intune RADIUS Helper")


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "y", "on")


def env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    return int(value)


TENANT_ID = os.getenv("TENANT_ID", "")
CLIENT_ID = os.getenv("CLIENT_ID", "")
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "")

URN_PREFIX = os.getenv("URN_PREFIX", "urn:t0.pac3.net").rstrip(":")

POLICY_RULES_FILE = os.getenv("POLICY_RULES_FILE", "/config/policy.json")

GRAPH_TIMEOUT_SECONDS = env_int("GRAPH_TIMEOUT_SECONDS", 20)
GRAPH_MAX_RETRIES = env_int("GRAPH_MAX_RETRIES", 1)

TRUST_CHAIN_FALLBACK = env_bool("TRUST_CHAIN_FALLBACK", False)

# Optional on-prem AD device lookup over LDAPS, keyed off the cert's
# onprem-sid SAN URI (Intune SCEP strong mapping via {{OnPremisesSecurityIdentifier}}).
AD_LDAP_ENABLED = env_bool("AD_LDAP_ENABLED", False)
AD_LDAP_SERVER = os.getenv("AD_LDAP_SERVER", "")
AD_LDAP_PORT = env_int("AD_LDAP_PORT", 636)
AD_LDAP_USE_SSL = env_bool("AD_LDAP_USE_SSL", True)
AD_LDAP_VERIFY_CERT = env_bool("AD_LDAP_VERIFY_CERT", True)
AD_LDAP_BIND_USERNAME = os.getenv("AD_LDAP_BIND_USERNAME", "")
AD_LDAP_BIND_PASSWORD = os.getenv("AD_LDAP_BIND_PASSWORD", "")
AD_LDAP_BASE_DN = os.getenv("AD_LDAP_BASE_DN", "")
AD_LDAP_TIMEOUT_SECONDS = env_int("AD_LDAP_TIMEOUT_SECONDS", 10)

CACHE_BACKEND = os.getenv("CACHE_BACKEND", "sqlite").strip().lower()
CACHE_DB_PATH = os.getenv("CACHE_DB_PATH", "/data/intune-radius-cache.sqlite3")

LOCAL_CACHE_FIRST = env_bool("LOCAL_CACHE_FIRST", False)
LOCAL_CACHE_MAX_AGE_SECONDS = env_int("LOCAL_CACHE_MAX_AGE_SECONDS", 900)
LIVE_LOOKUP_CACHE_SECONDS = env_int("LIVE_LOOKUP_CACHE_SECONDS", 300)

ALLOW_STALE_CACHE_ON_GRAPH_ERROR = env_bool("ALLOW_STALE_CACHE_ON_GRAPH_ERROR", True)
MAX_STALE_CACHE_HOURS = env_int("MAX_STALE_CACHE_HOURS", 24)

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = env_int("REDIS_PORT", 6379)
REDIS_DB = env_int("REDIS_DB", 0)
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")
REDIS_CACHE_TTL_SECONDS = env_int("REDIS_CACHE_TTL_SECONDS", 300)

POSTGRES_DB = os.getenv("POSTGRES_DB", "radius_cache")
POSTGRES_USER = os.getenv("POSTGRES_USER", "radius_app")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "")
POSTGRES_HOST = os.getenv("POSTGRES_HOST", "postgres")
POSTGRES_PORT = env_int("POSTGRES_PORT", 5432)

DEVICE_CACHE_REFRESH_SECONDS = env_int("DEVICE_CACHE_REFRESH_SECONDS", 900)
USER_CACHE_REFRESH_ENABLED = env_bool("USER_CACHE_REFRESH_ENABLED", True)
USER_CACHE_REFRESH_SECONDS = env_int("USER_CACHE_REFRESH_SECONDS", 1800)
USER_CACHE_SOURCE = os.getenv("USER_CACHE_SOURCE", "all").strip().lower()

INTUNE_AUTH_LOG = os.getenv("INTUNE_AUTH_LOG", "/logs/intune-auth.log")

redis_client: Optional[redis.Redis] = None
pg_pool: Optional[asyncpg.Pool] = None

memory_cache: dict[str, dict[str, Any]] = {}
token_cache: dict[str, Any] = {
    "access_token": None,
    "expires_at": 0,
}


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return now_utc().isoformat()


def parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def age_seconds(fetched_at: Optional[str]) -> Optional[float]:
    dt = parse_dt(fetched_at)
    if not dt:
        return None
    return (now_utc() - dt).total_seconds()


def age_hours(value: Optional[str]) -> Optional[float]:
    dt = parse_dt(value)
    if not dt:
        return None
    return (now_utc() - dt).total_seconds() / 3600


def is_fresh(fetched_at: Optional[str], max_age_seconds: int) -> bool:
    age = age_seconds(fetched_at)
    return age is not None and age <= max_age_seconds


def is_stale_usable(fetched_at: Optional[str]) -> bool:
    age = age_seconds(fetched_at)
    return age is not None and age <= MAX_STALE_CACHE_HOURS * 3600


def log_event(event: dict[str, Any]) -> None:
    event.setdefault("timestamp", iso_now())
    try:
        os.makedirs(os.path.dirname(INTUNE_AUTH_LOG), exist_ok=True)
        with open(INTUNE_AUTH_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, separators=(",", ":"), default=str) + "\n")
    except Exception:
        pass


def postgres_dsn() -> str:
    return (
        f"postgresql://{quote(POSTGRES_USER)}:{quote(POSTGRES_PASSWORD)}"
        f"@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
    )


def sqlite_init() -> None:
    os.makedirs(os.path.dirname(CACHE_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(CACHE_DB_PATH)
    try:
        conn.execute(
            """
            create table if not exists cache (
                cache_key text primary key,
                cache_type text not null,
                object_id text,
                data_json text not null,
                fetched_at text not null
            )
            """
        )
        conn.execute("create index if not exists idx_cache_type on cache(cache_type)")
        conn.commit()
    finally:
        conn.close()


async def postgres_init() -> None:
    global pg_pool
    pg_pool = await asyncpg.create_pool(
        dsn=postgres_dsn(),
        min_size=1,
        max_size=10,
        command_timeout=30,
    )
    async with pg_pool.acquire() as conn:
        await conn.execute(
            """
            create table if not exists cache (
                cache_key text primary key,
                cache_type text not null,
                object_id text,
                data_json jsonb not null,
                fetched_at timestamptz not null
            )
            """
        )
        await conn.execute(
            "create index if not exists idx_cache_type on cache(cache_type)"
        )
        await conn.execute(
            """
            create table if not exists auth_events (
                id bigserial primary key,
                created_at timestamptz not null default now(),
                allow boolean,
                reason text,
                device_id text,
                user_upn text,
                cert_type text,
                source_device text,
                source_user text,
                event_json jsonb not null
            )
            """
        )


async def redis_init() -> None:
    global redis_client
    redis_client = redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        db=REDIS_DB,
        password=REDIS_PASSWORD or None,
        decode_responses=True,
    )
    await redis_client.ping()


def memory_get(key: str) -> Optional[dict[str, Any]]:
    item = memory_cache.get(key)
    if not item:
        return None
    if item["expires_at"] < time.time():
        memory_cache.pop(key, None)
        return None
    data = dict(item["data"])
    data["_decisionSource"] = "live_memory_cache"
    return data


def memory_set(key: str, data: dict[str, Any]) -> None:
    memory_cache[key] = {
        "expires_at": time.time() + LIVE_LOOKUP_CACHE_SECONDS,
        "data": dict(data),
    }


async def cache_get_sqlite(cache_key: str) -> Optional[dict[str, Any]]:
    conn = sqlite3.connect(CACHE_DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "select cache_key, cache_type, object_id, data_json, fetched_at from cache where cache_key = ?",
            (cache_key,),
        ).fetchone()
        if not row:
            return None
        return {
            "cache_key": row["cache_key"],
            "cache_type": row["cache_type"],
            "object_id": row["object_id"],
            "data": json.loads(row["data_json"]),
            "fetched_at": row["fetched_at"],
        }
    finally:
        conn.close()


async def cache_set_sqlite(cache_key: str, cache_type: str, object_id: str, data: dict[str, Any]) -> None:
    fetched_at = data.get("fetched_at") or iso_now()
    conn = sqlite3.connect(CACHE_DB_PATH)
    try:
        conn.execute(
            """
            insert into cache(cache_key, cache_type, object_id, data_json, fetched_at)
            values (?, ?, ?, ?, ?)
            on conflict(cache_key) do update set
              cache_type=excluded.cache_type,
              object_id=excluded.object_id,
              data_json=excluded.data_json,
              fetched_at=excluded.fetched_at
            """,
            (cache_key, cache_type, object_id, json.dumps(data), fetched_at),
        )
        conn.commit()
    finally:
        conn.close()


async def cache_get_postgres(cache_key: str) -> Optional[dict[str, Any]]:
    if not pg_pool:
        return None
    async with pg_pool.acquire() as conn:
        row = await conn.fetchrow(
            "select cache_key, cache_type, object_id, data_json::text as data_json, fetched_at from cache where cache_key=$1",
            cache_key,
        )
    if not row:
        return None
    data = json.loads(row["data_json"])
    return {
        "cache_key": row["cache_key"],
        "cache_type": row["cache_type"],
        "object_id": row["object_id"],
        "data": data,
        "fetched_at": row["fetched_at"].astimezone(timezone.utc).isoformat(),
    }


async def cache_set_postgres(cache_key: str, cache_type: str, object_id: str, data: dict[str, Any]) -> None:
    if not pg_pool:
        return
    fetched_at = parse_dt(data.get("fetched_at")) or now_utc()
    async with pg_pool.acquire() as conn:
        await conn.execute(
            """
            insert into cache(cache_key, cache_type, object_id, data_json, fetched_at)
            values ($1, $2, $3, $4::jsonb, $5)
            on conflict(cache_key) do update set
              cache_type=excluded.cache_type,
              object_id=excluded.object_id,
              data_json=excluded.data_json,
              fetched_at=excluded.fetched_at
            """,
            cache_key,
            cache_type,
            object_id,
            json.dumps(data),
            fetched_at,
        )


async def cache_get(cache_key: str) -> Optional[dict[str, Any]]:
    if CACHE_BACKEND == "postgres_redis" and redis_client:
        raw = await redis_client.get(f"radius-cache:{cache_key}")
        if raw:
            try:
                value = json.loads(raw)
                return value
            except Exception:
                pass

    if CACHE_BACKEND == "postgres_redis":
        return await cache_get_postgres(cache_key)

    return await cache_get_sqlite(cache_key)


async def cache_set(cache_key: str, cache_type: str, object_id: str, data: dict[str, Any]) -> None:
    data = dict(data)
    data.setdefault("fetched_at", iso_now())

    if CACHE_BACKEND == "postgres_redis":
        await cache_set_postgres(cache_key, cache_type, object_id, data)
        if redis_client:
            value = {
                "cache_key": cache_key,
                "cache_type": cache_type,
                "object_id": object_id,
                "data": data,
                "fetched_at": data["fetched_at"],
            }
            await redis_client.set(
                f"radius-cache:{cache_key}",
                json.dumps(value, default=str),
                ex=REDIS_CACHE_TTL_SECONDS,
            )
        return

    await cache_set_sqlite(cache_key, cache_type, object_id, data)


async def postgres_log_auth_event(event: dict[str, Any]) -> None:
    if CACHE_BACKEND != "postgres_redis" or not pg_pool:
        return
    checks = event.get("checks", {})
    identity = checks.get("identity", {})
    device = checks.get("device", {})
    user = checks.get("user", {})
    async with pg_pool.acquire() as conn:
        await conn.execute(
            """
            insert into auth_events(
              allow, reason, device_id, user_upn, cert_type,
              source_device, source_user, event_json
            )
            values ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
            """,
            event.get("allow"),
            event.get("reason"),
            identity.get("entra_device_id"),
            identity.get("user_upn"),
            checks.get("certType"),
            device.get("_decisionSource"),
            user.get("_decisionSource"),
            json.dumps(event, default=str),
        )


async def graph_token() -> str:
    if token_cache["access_token"] and token_cache["expires_at"] > time.time() + 120:
        return token_cache["access_token"]

    url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials",
    }

    async with httpx.AsyncClient(timeout=GRAPH_TIMEOUT_SECONDS) as client:
        response = await client.post(url, data=data)
        response.raise_for_status()
        body = response.json()

    token_cache["access_token"] = body["access_token"]
    token_cache["expires_at"] = time.time() + int(body.get("expires_in", 3600))
    return token_cache["access_token"]


async def graph_get(path_or_url: str, params: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    token = await graph_token()

    if path_or_url.startswith("https://"):
        url = path_or_url
    else:
        url = "https://graph.microsoft.com/v1.0" + path_or_url

    last_error = None

    for attempt in range(GRAPH_MAX_RETRIES + 1):
        try:
            async with httpx.AsyncClient(timeout=GRAPH_TIMEOUT_SECONDS) as client:
                response = await client.get(
                    url,
                    params=params,
                    headers={"Authorization": f"Bearer {token}"},
                )

            if response.status_code in (429, 500, 502, 503, 504):
                last_error = {
                    "status_code": response.status_code,
                    "message": response.text[:500],
                }
                await asyncio.sleep(1 + attempt)
                continue

            response.raise_for_status()
            return response.json()

        except Exception as exc:
            last_error = {
                "status_code": None,
                "message": str(exc),
            }
            await asyncio.sleep(1 + attempt)

    raise RuntimeError(json.dumps(last_error))


def openssl_cert_text(cert_pem: str) -> str:
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write(cert_pem)
        cert_path = f.name

    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-noout", "-text"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            raise ValueError(result.stderr.strip())
        return result.stdout
    finally:
        try:
            os.unlink(cert_path)
        except Exception:
            pass


def extract_identity(cert_pem: str) -> dict[str, Any]:
    text = openssl_cert_text(cert_pem)

    uris = []
    emails = []

    for match in re.finditer(r"URI:([^,\s]+)", text):
        value = match.group(1).strip()
        if value.lower().startswith("uri:"):
            value = value[4:]
        uris.append(value)

    for match in re.finditer(r"email:([^,\s]+)", text, flags=re.IGNORECASE):
        emails.append(match.group(1).strip().lower())

    entra_device_id = None
    user_upn = None
    entra_user_id = None
    onprem_sid = None

    device_prefix = f"{URN_PREFIX}:entra-device-id:"
    upn_prefix = f"{URN_PREFIX}:user-upn:"
    user_id_prefix = f"{URN_PREFIX}:entra-user-id:"
    onprem_sid_prefix = f"{URN_PREFIX}:onprem-sid:"

    for uri in uris:
        if uri.startswith(device_prefix):
            entra_device_id = uri[len(device_prefix):].strip().lower()
        elif uri.startswith(upn_prefix):
            user_upn = uri[len(upn_prefix):].strip().lower()
        elif uri.startswith(user_id_prefix):
            entra_user_id = uri[len(user_id_prefix):].strip().lower()
        elif uri.startswith(onprem_sid_prefix):
            onprem_sid = uri[len(onprem_sid_prefix):].strip()

    return {
        "entra_device_id": entra_device_id,
        "user_upn": user_upn,
        "entra_user_id": entra_user_id,
        "onprem_sid": onprem_sid,
        "emails": emails,
        "uris": uris,
    }


def evaluate_managed_device(managed: dict[str, Any], entra_device: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Normalize a Graph managedDevice (+ optional Entra device) into cache-friendly fields.

    Carries no allow/deny opinion - that decision is made by the policy engine
    from the facts this produces, at request time (see build_facts/evaluate_policy).
    """
    device_id = (
        managed.get("azureADDeviceId")
        or managed.get("entraDeviceId")
        or managed.get("deviceId")
        or ""
    )

    return {
        "id": managed.get("id"),
        "deviceName": managed.get("deviceName") or managed.get("displayName"),
        "entraDeviceId": str(device_id).lower(),
        "complianceState": managed.get("complianceState"),
        "lastSyncDateTime": managed.get("lastSyncDateTime"),
        "userPrincipalName": managed.get("userPrincipalName"),
        "managementAgent": managed.get("managementAgent"),
        "operatingSystem": managed.get("operatingSystem"),
        "entraDevice": entra_device,
        "fetched_at": iso_now(),
    }


def evaluate_user(user: dict[str, Any]) -> dict[str, Any]:
    """Normalize a Graph user into cache-friendly fields - no allow/deny opinion, see evaluate_managed_device."""
    return {
        "id": user.get("id"),
        "userPrincipalName": (user.get("userPrincipalName") or "").lower(),
        "accountEnabled": user.get("accountEnabled"),
        "displayName": user.get("displayName"),
        "fetched_at": iso_now(),
    }


DEFAULT_POLICY: dict[str, Any] = {
    "version": 1,
    "defaultTier": "reject",
    "rules": [
        {
            "name": "user-cert-missing-device-pairing",
            "when": {"all": [
                {"field": "cert_type", "op": "eq", "value": "user"},
                {"field": "device_id_present_in_cert", "op": "eq", "value": False},
            ]},
            "tier": "reject",
            "reason": "user certificate missing required entra-device-id URN",
        },
        {
            "name": "user-cert-unresolved",
            "when": {"all": [
                {"field": "user_upn_present_in_cert", "op": "eq", "value": True},
                {"field": "user_found", "op": "eq", "value": False},
            ]},
            "tier": "reject",
            "reason": "user certificate identity could not be resolved against Entra",
        },
        {
            "name": "disabled-user-reject",
            "when": {"field": "user_account_enabled", "op": "eq", "value": False},
            "tier": "reject",
            "reason": "user account disabled",
        },
        {
            "name": "disabled-device-reject",
            "when": {"field": "device_account_enabled", "op": "eq", "value": False},
            "tier": "reject",
            "reason": "device account disabled",
        },
        {
            "name": "compliant-device-access",
            "when": {"all": [
                {"field": "device_found", "op": "eq", "value": True},
                {"field": "compliance_state", "op": "eq", "value": "compliant"},
                {"field": "last_sync_age_hours", "op": "lte", "value": 72},
            ]},
            "tier": "access",
            "reason": "device compliant",
        },
        {
            "name": "known-noncompliant-device-untrust",
            "when": {"field": "device_found", "op": "eq", "value": True},
            "tier": "untrust",
            "reason": "device enrolled but not compliant",
        },
    ],
}

_policy_load_error: Optional[str] = None


def load_policy() -> dict[str, Any]:
    global _policy_load_error

    if not POLICY_RULES_FILE or not os.path.isfile(POLICY_RULES_FILE):
        _policy_load_error = None
        return DEFAULT_POLICY

    try:
        with open(POLICY_RULES_FILE, "r", encoding="utf-8") as f:
            policy = json.load(f)
        _policy_load_error = None
        return policy
    except Exception as exc:
        # Fail closed: an unreadable/invalid policy file must not silently
        # fall back to the (potentially far more permissive) default ruleset.
        _policy_load_error = str(exc)
        return {"version": 1, "defaultTier": "reject", "rules": []}


def eval_condition(condition: dict[str, Any], facts: dict[str, Any]) -> bool:
    if "all" in condition:
        return all(eval_condition(c, facts) for c in condition["all"])
    if "any" in condition:
        return any(eval_condition(c, facts) for c in condition["any"])
    if "not" in condition:
        return not eval_condition(condition["not"], facts)

    field = condition["field"]
    op = condition["op"]
    actual = facts.get(field)

    if op == "exists":
        return actual is not None
    if op == "eq":
        return actual == condition.get("value")
    if op == "neq":
        return actual != condition.get("value")
    if op == "in":
        return actual in condition.get("value", [])
    if actual is None:
        return False
    if op == "gt":
        return actual > condition["value"]
    if op == "gte":
        return actual >= condition["value"]
    if op == "lt":
        return actual < condition["value"]
    if op == "lte":
        return actual <= condition["value"]

    raise ValueError(f"unknown policy condition operator: {op}")


def evaluate_policy(policy: dict[str, Any], facts: dict[str, Any]) -> dict[str, Any]:
    for rule in policy.get("rules", []):
        condition = rule.get("when")
        if condition is None or eval_condition(condition, facts):
            return {
                "tier": rule["tier"],
                "reason": rule.get("reason", rule.get("name", "matched")),
                "matchedRule": rule.get("name"),
            }

    return {
        "tier": policy.get("defaultTier", "reject"),
        "reason": "no policy rule matched",
        "matchedRule": None,
    }


def build_facts(
    identity: dict[str, Any],
    cert_type: str,
    device_result: Optional[dict[str, Any]],
    user_result: Optional[dict[str, Any]],
    ad_device_result: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    facts: dict[str, Any] = {
        "cert_type": cert_type,
        "device_id_present_in_cert": bool(identity.get("entra_device_id")),
        "user_upn_present_in_cert": bool(identity.get("user_upn")),
        "onprem_sid_present_in_cert": bool(identity.get("onprem_sid")),
        "device_found": False,
        "compliance_state": None,
        "last_sync_age_hours": None,
        "device_account_enabled": None,
        "user_found": False,
        "user_account_enabled": None,
        "ad_device_found": False,
        "ad_device_enabled": None,
    }

    if device_result is not None:
        facts["device_found"] = bool(device_result.get("id"))
        compliance_state = device_result.get("complianceState")
        facts["compliance_state"] = compliance_state.lower() if compliance_state else None
        facts["last_sync_age_hours"] = age_hours(device_result.get("lastSyncDateTime"))
        entra_device = device_result.get("entraDevice")
        if entra_device is not None:
            facts["device_account_enabled"] = entra_device.get("accountEnabled")

    if user_result is not None:
        facts["user_found"] = bool(user_result.get("id"))
        facts["user_account_enabled"] = user_result.get("accountEnabled")

    if ad_device_result is not None:
        facts["ad_device_found"] = bool(ad_device_result.get("found"))
        facts["ad_device_enabled"] = ad_device_result.get("accountEnabled")

    return facts


def reject_event(reason: str, checks: dict[str, Any]) -> dict[str, Any]:
    return {
        "tier": "reject",
        "allow": False,
        "reason": reason,
        "matchedRule": None,
        "checks": checks,
    }


async def live_graph_device_lookup(entra_device_id: str) -> dict[str, Any]:
    managed_response = await graph_get(
        "/deviceManagement/managedDevices",
        params={
            "$filter": f"azureADDeviceId eq '{entra_device_id}'",
            "$top": "1",
            "$select": "id,deviceName,azureADDeviceId,complianceState,lastSyncDateTime,userPrincipalName,managementAgent,operatingSystem",
        },
    )

    managed_values = managed_response.get("value", [])
    if not managed_values:
        return {
            "reason": "device not found in Intune managedDevices",
            "entraDeviceId": entra_device_id,
            "fetched_at": iso_now(),
        }

    managed = managed_values[0]

    entra_device = None
    try:
        entra_response = await graph_get(
            "/devices",
            params={
                "$filter": f"deviceId eq '{entra_device_id}'",
                "$top": "1",
                "$select": "id,deviceId,displayName,accountEnabled",
            },
        )
        values = entra_response.get("value", [])
        if values:
            entra_device = values[0]
    except Exception as exc:
        entra_device = {
            "_lookupError": str(exc),
        }

    result = evaluate_managed_device(managed, entra_device)
    result["_decisionSource"] = "live_graph"
    return result


async def live_graph_user_lookup(user_upn: str) -> dict[str, Any]:
    safe_upn = quote(user_upn)
    response = await graph_get(
        f"/users/{safe_upn}",
        params={
            "$select": "id,userPrincipalName,accountEnabled,displayName",
        },
    )
    result = evaluate_user(response)
    result["_decisionSource"] = "live_graph"
    return result


async def check_device(entra_device_id: str) -> dict[str, Any]:
    cache_key = f"device:{entra_device_id.lower()}"

    mem = memory_get(cache_key)
    if mem:
        return mem

    cached = await cache_get(cache_key)

    if LOCAL_CACHE_FIRST and cached and is_fresh(cached.get("fetched_at"), LOCAL_CACHE_MAX_AGE_SECONDS):
        data = dict(cached["data"])
        data["_decisionSource"] = "local_cache"
        memory_set(cache_key, data)
        return data

    try:
        result = await live_graph_device_lookup(entra_device_id)
        await cache_set(cache_key, "device", entra_device_id.lower(), result)
        memory_set(cache_key, result)
        return result
    except Exception as exc:
        graph_error = {
            "message": str(exc),
        }

        if ALLOW_STALE_CACHE_ON_GRAPH_ERROR and cached and is_stale_usable(cached.get("fetched_at")):
            data = dict(cached["data"])
            data["_decisionSource"] = "stale_persistent_cache"
            data["_graphError"] = graph_error
            memory_set(cache_key, data)
            return data

        return {
            "reason": "Graph device lookup failed and no usable cache exists",
            "entraDeviceId": entra_device_id.lower(),
            "_decisionSource": "graph_error_no_cache",
            "_graphError": graph_error,
            "fetched_at": iso_now(),
        }


async def check_user(user_upn: str) -> dict[str, Any]:
    cache_key = f"user:{user_upn.lower()}"

    mem = memory_get(cache_key)
    if mem:
        return mem

    cached = await cache_get(cache_key)

    if LOCAL_CACHE_FIRST and cached and is_fresh(cached.get("fetched_at"), LOCAL_CACHE_MAX_AGE_SECONDS):
        data = dict(cached["data"])
        data["_decisionSource"] = "local_cache"
        memory_set(cache_key, data)
        return data

    try:
        result = await live_graph_user_lookup(user_upn)
        await cache_set(cache_key, "user", user_upn.lower(), result)
        memory_set(cache_key, result)
        return result
    except Exception as exc:
        graph_error = {
            "message": str(exc),
        }

        if ALLOW_STALE_CACHE_ON_GRAPH_ERROR and cached and is_stale_usable(cached.get("fetched_at")):
            data = dict(cached["data"])
            data["_decisionSource"] = "stale_persistent_cache"
            data["_graphError"] = graph_error
            memory_set(cache_key, data)
            return data

        return {
            "reason": "Graph user lookup failed and no usable cache exists",
            "userPrincipalName": user_upn.lower(),
            "_decisionSource": "graph_error_no_cache",
            "_graphError": graph_error,
            "fetched_at": iso_now(),
        }


def sid_to_ldap_filter_value(sid: str) -> str:
    """Convert an SDDL SID string (S-1-5-21-...-RID) into the escaped byte
    sequence AD's binary objectSid attribute requires for LDAP filtering."""
    parts = sid.strip().split("-")
    if len(parts) < 3 or parts[0].upper() != "S":
        raise ValueError(f"not a valid SID string: {sid!r}")

    revision = int(parts[1])
    identifier_authority = int(parts[2])
    sub_authorities = [int(p) for p in parts[3:]]

    raw = bytearray()
    raw.append(revision)
    raw.append(len(sub_authorities))
    raw += identifier_authority.to_bytes(6, byteorder="big")
    for sub_authority in sub_authorities:
        raw += sub_authority.to_bytes(4, byteorder="little")

    return "".join(f"\\{b:02x}" for b in raw)


def _ldap_connection() -> ldap3.Connection:
    tls = ldap3.Tls(
        validate=ssl.CERT_REQUIRED if AD_LDAP_VERIFY_CERT else ssl.CERT_NONE,
    )
    server = ldap3.Server(
        AD_LDAP_SERVER,
        port=AD_LDAP_PORT,
        use_ssl=AD_LDAP_USE_SSL,
        tls=tls,
        connect_timeout=AD_LDAP_TIMEOUT_SECONDS,
    )
    return ldap3.Connection(
        server,
        user=AD_LDAP_BIND_USERNAME,
        password=AD_LDAP_BIND_PASSWORD,
        authentication=ldap3.SIMPLE,
        auto_bind=True,
        receive_timeout=AD_LDAP_TIMEOUT_SECONDS,
    )


ACCOUNTDISABLE = 0x2


def _ldap_search_device_by_sid(onprem_sid: str) -> dict[str, Any]:
    filter_value = sid_to_ldap_filter_value(onprem_sid)
    search_filter = f"(&(objectClass=computer)(objectSid={filter_value}))"

    conn = _ldap_connection()
    try:
        conn.search(
            search_base=AD_LDAP_BASE_DN,
            search_filter=search_filter,
            attributes=["distinguishedName", "sAMAccountName", "userAccountControl"],
        )
        if not conn.entries:
            return {"found": False}

        entry = conn.entries[0]
        uac = int(entry.userAccountControl.value) if entry.userAccountControl else 0

        return {
            "found": True,
            "distinguishedName": str(entry.distinguishedName) if entry.distinguishedName else None,
            "sAMAccountName": str(entry.sAMAccountName) if entry.sAMAccountName else None,
            "accountEnabled": not bool(uac & ACCOUNTDISABLE),
        }
    finally:
        conn.unbind()


async def live_ad_device_lookup(onprem_sid: str) -> dict[str, Any]:
    result = await asyncio.to_thread(_ldap_search_device_by_sid, onprem_sid)
    result["fetched_at"] = iso_now()
    result["_decisionSource"] = "live_ldap"
    return result


async def check_ad_device(onprem_sid: str) -> dict[str, Any]:
    cache_key = f"ad_device:{onprem_sid.lower()}"

    mem = memory_get(cache_key)
    if mem:
        return mem

    cached = await cache_get(cache_key)

    if LOCAL_CACHE_FIRST and cached and is_fresh(cached.get("fetched_at"), LOCAL_CACHE_MAX_AGE_SECONDS):
        data = dict(cached["data"])
        data["_decisionSource"] = "local_cache"
        memory_set(cache_key, data)
        return data

    try:
        result = await live_ad_device_lookup(onprem_sid)
        await cache_set(cache_key, "ad_device", onprem_sid.lower(), result)
        memory_set(cache_key, result)
        return result
    except Exception as exc:
        ldap_error = {
            "message": str(exc),
        }

        if ALLOW_STALE_CACHE_ON_GRAPH_ERROR and cached and is_stale_usable(cached.get("fetched_at")):
            data = dict(cached["data"])
            data["_decisionSource"] = "stale_persistent_cache"
            data["_ldapError"] = ldap_error
            memory_set(cache_key, data)
            return data

        return {
            "found": False,
            "_decisionSource": "ldap_error_no_cache",
            "_ldapError": ldap_error,
            "fetched_at": iso_now(),
        }


async def refresh_device_cache_once() -> dict[str, Any]:
    count = 0
    next_url = None

    params = {
        "$top": "999",
        "$select": "id,deviceName,azureADDeviceId,complianceState,lastSyncDateTime,userPrincipalName,managementAgent,operatingSystem",
    }

    while True:
        if next_url:
            response = await graph_get(next_url)
        else:
            response = await graph_get("/deviceManagement/managedDevices", params=params)

        for managed in response.get("value", []):
            entra_device_id = managed.get("azureADDeviceId") or managed.get("entraDeviceId")
            if not entra_device_id:
                continue
            result = evaluate_managed_device(managed, None)
            result["_decisionSource"] = "background_intune_cache"
            await cache_set(
                f"device:{str(entra_device_id).lower()}",
                "device",
                str(entra_device_id).lower(),
                result,
            )
            count += 1

        next_url = response.get("@odata.nextLink")
        if not next_url:
            break

    event = {
        "eventType": "device_cache_refresh",
        "refreshedDevices": count,
        "cacheBackend": CACHE_BACKEND,
    }
    log_event(event)
    return event


async def refresh_user_cache_once() -> dict[str, Any]:
    count = 0

    if USER_CACHE_SOURCE != "all":
        event = {
            "eventType": "user_cache_refresh",
            "skipped": True,
            "reason": f"unsupported USER_CACHE_SOURCE={USER_CACHE_SOURCE}; use all",
        }
        log_event(event)
        return event

    next_url = None
    params = {
        "$top": "999",
        "$select": "id,userPrincipalName,accountEnabled,displayName",
    }

    while True:
        if next_url:
            response = await graph_get(next_url)
        else:
            response = await graph_get("/users", params=params)

        for user in response.get("value", []):
            upn = (user.get("userPrincipalName") or "").lower()
            if not upn:
                continue
            result = evaluate_user(user)
            result["_decisionSource"] = "background_user_cache"
            await cache_set(f"user:{upn}", "user", upn, result)
            count += 1

        next_url = response.get("@odata.nextLink")
        if not next_url:
            break

    event = {
        "eventType": "user_cache_refresh",
        "refreshedUsers": count,
        "cacheBackend": CACHE_BACKEND,
        "userCacheSource": USER_CACHE_SOURCE,
    }
    log_event(event)
    return event


async def device_cache_loop() -> None:
    while True:
        try:
            await refresh_device_cache_once()
        except Exception as exc:
            log_event({
                "eventType": "device_cache_refresh",
                "error": str(exc),
                "cacheBackend": CACHE_BACKEND,
            })
        await asyncio.sleep(DEVICE_CACHE_REFRESH_SECONDS)


async def user_cache_loop() -> None:
    while True:
        try:
            await refresh_user_cache_once()
        except Exception as exc:
            log_event({
                "eventType": "user_cache_refresh",
                "error": str(exc),
                "cacheBackend": CACHE_BACKEND,
            })
        await asyncio.sleep(USER_CACHE_REFRESH_SECONDS)


@app.on_event("startup")
async def startup() -> None:
    if CACHE_BACKEND == "postgres_redis":
        await postgres_init()
        await redis_init()
    else:
        sqlite_init()

    asyncio.create_task(device_cache_loop())

    if USER_CACHE_REFRESH_ENABLED:
        asyncio.create_task(user_cache_loop())


@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    redis_ok = None
    postgres_ok = None

    if CACHE_BACKEND == "postgres_redis":
        try:
            if redis_client:
                await redis_client.ping()
            redis_ok = True
        except Exception as exc:
            redis_ok = str(exc)

        try:
            if pg_pool:
                async with pg_pool.acquire() as conn:
                    await conn.fetchval("select 1")
            postgres_ok = True
        except Exception as exc:
            postgres_ok = str(exc)

    policy = load_policy()

    return {
        "ok": True,
        "cacheBackend": CACHE_BACKEND,
        "localCacheFirst": LOCAL_CACHE_FIRST,
        "localCacheMaxAgeSeconds": LOCAL_CACHE_MAX_AGE_SECONDS,
        "redis": redis_ok,
        "postgres": postgres_ok,
        "policyRulesFile": POLICY_RULES_FILE,
        "policySource": "file" if os.path.isfile(POLICY_RULES_FILE) else "default",
        "policyLoadError": _policy_load_error,
        "policyRuleCount": len(policy.get("rules", [])),
        "policyDefaultTier": policy.get("defaultTier"),
        "allowStaleCacheOnGraphError": ALLOW_STALE_CACHE_ON_GRAPH_ERROR,
        "maxStaleCacheHours": MAX_STALE_CACHE_HOURS,
        "deviceCacheRefreshSeconds": DEVICE_CACHE_REFRESH_SECONDS,
        "userCacheRefreshEnabled": USER_CACHE_REFRESH_ENABLED,
        "userCacheRefreshSeconds": USER_CACHE_REFRESH_SECONDS,
        "userCacheSource": USER_CACHE_SOURCE,
        "trustChainFallback": TRUST_CHAIN_FALLBACK,
        "adLdapEnabled": AD_LDAP_ENABLED,
        "adLdapServer": AD_LDAP_SERVER if AD_LDAP_ENABLED else None,
        "adLdapVerifyCert": AD_LDAP_VERIFY_CERT,
    }


@app.post("/refresh/devices")
async def refresh_devices() -> JSONResponse:
    try:
        result = await refresh_device_cache_once()
        return JSONResponse(result, status_code=200)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@app.post("/refresh/users")
async def refresh_users() -> JSONResponse:
    try:
        result = await refresh_user_cache_once()
        return JSONResponse(result, status_code=200)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@app.post("/debug/ad-device")
async def debug_ad_device(request: Request) -> JSONResponse:
    """Bypasses the cache to test the live AD/LDAPS device lookup directly -
    for confirming connectivity/bind/base-DN/filter against a real DC without
    waiting for an actual RADIUS auth or going through /check's caching."""
    if not AD_LDAP_ENABLED:
        return JSONResponse({"ok": False, "error": "AD_LDAP_ENABLED is false"}, status_code=400)

    body = await request.json()
    onprem_sid = body.get("onprem_sid") or body.get("sid") or ""
    if not onprem_sid:
        return JSONResponse({"ok": False, "error": "missing onprem_sid"}, status_code=400)

    try:
        result = await live_ad_device_lookup(onprem_sid)
        return JSONResponse({"ok": True, "result": result}, status_code=200)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@app.post("/check")
async def check(request: Request) -> JSONResponse:
    body = await request.json()

    cert_pem = (
        body.get("cert_pem")
        or body.get("certPem")
        or body.get("certificate")
        or body.get("pem")
        or body.get("client_cert")
        or ""
    )

    radius_username = (
        body.get("radius_username")
        or body.get("radiusUsername")
        or body.get("username")
        or body.get("User-Name")
        or ""
    )

    calling_station_id = (
        body.get("calling_station_id")
        or body.get("callingStationId")
        or body.get("Calling-Station-Id")
        or ""
    )

    checks: dict[str, Any] = {
        "radiusUsername": radius_username,
        "callingStationId": calling_station_id,
    }

    if TRUST_CHAIN_FALLBACK:
        event = {
            "tier": "access",
            "allow": True,
            "reason": "TRUST_CHAIN_FALLBACK enabled; FreeRADIUS certificate validation already succeeded",
            "matchedRule": None,
            "checks": checks,
        }
        log_event(event)
        await postgres_log_auth_event(event)
        return JSONResponse(event, status_code=200)

    if not cert_pem:
        event = reject_event("missing cert_pem", checks)
        log_event(event)
        await postgres_log_auth_event(event)
        return JSONResponse(event, status_code=403)

    try:
        identity = extract_identity(cert_pem)
    except Exception as exc:
        event = reject_event(f"failed to parse certificate identity: {exc}", checks)
        log_event(event)
        await postgres_log_auth_event(event)
        return JSONResponse(event, status_code=403)

    checks["identity"] = identity

    entra_device_id = identity.get("entra_device_id")
    user_upn = identity.get("user_upn")
    cert_type = "user" if user_upn or identity.get("entra_user_id") else "device"
    checks["certType"] = cert_type

    if not entra_device_id and not user_upn:
        event = reject_event("certificate does not contain expected URN identity", checks)
        log_event(event)
        await postgres_log_auth_event(event)
        return JSONResponse(event, status_code=403)

    device_result = None
    user_result = None
    ad_device_result = None

    if entra_device_id:
        device_result = await check_device(entra_device_id)
        checks["device"] = device_result

    if user_upn:
        user_result = await check_user(user_upn)
        checks["user"] = user_result

    onprem_sid = identity.get("onprem_sid")
    if AD_LDAP_ENABLED and onprem_sid:
        ad_device_result = await check_ad_device(onprem_sid)
        checks["adDevice"] = ad_device_result

    facts = build_facts(identity, cert_type, device_result, user_result, ad_device_result)
    checks["facts"] = facts

    policy = load_policy()
    if _policy_load_error:
        decision = {"tier": "reject", "reason": f"invalid policy file: {_policy_load_error}", "matchedRule": None}
    else:
        decision = evaluate_policy(policy, facts)

    event = {
        "tier": decision["tier"],
        "allow": decision["tier"] == "access",
        "reason": decision["reason"],
        "matchedRule": decision["matchedRule"],
        "checks": checks,
    }

    log_event(event)
    await postgres_log_auth_event(event)

    return JSONResponse(event, status_code=200 if decision["tier"] == "access" else 403)
