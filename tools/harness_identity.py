# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Validated customer state and tenant-bound, silent Microsoft Graph access."""

import base64
import json
import re
import time
import uuid
from urllib.parse import urlparse

import requests


def require_guid(state, field):
    value = state.get(field)
    if not isinstance(value, str):
        raise RuntimeError(f"Configure a nonempty GUID for '{field}' in the ignored Entra state.")
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        raise RuntimeError(f"Configure a nonempty GUID for '{field}' in the ignored Entra state.") from None
    if not parsed.int or str(parsed) != value.lower():
        raise RuntimeError(f"Configure a nonempty GUID for '{field}' in the ignored Entra state.")
    return str(parsed)


def read_state(path):
    if not path.is_file():
        raise RuntimeError("Run infra\\Initialize-Entra.ps1 with explicit customer inputs first.")
    state = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(state, dict):
        raise RuntimeError("The customer configuration must be a JSON object.")
    for field in ("TenantId", "SubscriptionId", "AdministratorObjectId", "ClientId", "ServicePrincipalId"):
        state[field] = require_guid(state, field)
    domain = state.get("TenantDomain")
    if (
        not isinstance(domain, str)
        or len(domain) > 253
        or not re.fullmatch(
            r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
            r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?",
            domain,
        )
        or not domain.lower().endswith(".onmicrosoft.com")
    ):
        raise RuntimeError("Configure TenantDomain as the tenant's initial onmicrosoft.com domain.")
    state["TenantDomain"] = domain.lower()
    origin = state.get("PlannedHarnessUrl")
    try:
        url = urlparse(origin) if isinstance(origin, str) else None
        valid_origin = (
            url is not None
            and url.scheme == "https"
            and url.hostname
            and len(url.hostname) <= 253
            and re.fullmatch(
                r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
                r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?",
                url.hostname,
            )
            and url.port in (None, 443)
            and not url.username
            and not url.password
            and url.path in ("", "/")
            and not url.query
            and not url.fragment
            and not any(char.isspace() for char in origin)
        )
    except ValueError:
        valid_origin = False
    if not valid_origin:
        raise RuntimeError("Configure PlannedHarnessUrl as the HTTPS origin of the customer portal.")
    state["PlannedHarnessUrl"] = origin.rstrip("/")
    for field in ("ApprovedB2BGuestObjectIds", "ApprovedB2BGuestAdministratorObjectIds"):
        values = state.get(field, [])
        if not isinstance(values, list):
            raise RuntimeError(f"'{field}' must be an explicit list of guest object IDs.")
        state[field] = [require_guid({"id": value}, "id") for value in values]
    if not set(state["ApprovedB2BGuestAdministratorObjectIds"]).issubset(state["ApprovedB2BGuestObjectIds"]):
        raise RuntimeError("Approved guest administrators must also be explicitly approved harness guests.")
    return state


def _validate_graph_token(token, state):
    try:
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        valid = (
            str(claims.get("tid", "")).lower() == state["TenantId"]
            and str(claims.get("oid", "")).lower() == state["AdministratorObjectId"]
            and claims.get("aud") in (
                "00000003-0000-0000-c000-000000000000",
                "https://graph.microsoft.com",
                "https://graph.microsoft.com/",
            )
            and int(claims.get("exp", 0)) > time.time()
        )
    except (ValueError, TypeError, IndexError, AttributeError):
        valid = False
    if not valid:
        raise RuntimeError("The cached Graph token does not match the configured tenant, administrator, resource, or lifetime.")


def silent_session(state):
    from azure.cli.core import get_default_cli
    from azure.cli.core._profile import Profile

    profile = Profile(cli_ctx=get_default_cli())
    credential, subscription, tenant = profile.get_login_credentials(
        subscription_id=state["SubscriptionId"], sdk_credential=False
    )
    if str(tenant).lower() != state["TenantId"] or str(subscription).lower() != state["SubscriptionId"]:
        raise RuntimeError("The cached identity is outside the configured tenant/subscription.")
    options = {"force_refresh": True}
    claims = None
    try:
        from azure.cli.core.auth.agentic_session import (
            build_agentic_session_params,
            merge_access_token_claims,
        )

        session_id, session_claims = build_agentic_session_params()
        if session_id:
            options["data"] = {"client_session": session_id}
            options["params"] = {"client_session": session_id}
            if getattr(credential._msal_app, "_enable_broker", False):
                claims = merge_access_token_claims(None, session_claims)
    except ImportError:
        pass
    result = credential._msal_app.acquire_token_silent_with_error(
        ["https://graph.microsoft.com/.default"],
        credential._account,
        claims_challenge=claims,
        **options,
    )
    if not result or not result.get("access_token"):
        raise RuntimeError(
            "The existing Graph session cannot refresh silently. "
            "No interactive authentication was attempted."
        )
    session = None
    try:
        _validate_graph_token(result["access_token"], state)
        session = requests.Session()
        session.headers["Authorization"] = "Bearer " + result["access_token"]
    finally:
        result.clear()
    try:
        administrator = graph(session, "GET", "v1.0/me?$select=id")
        if str(administrator.get("id", "")).lower() != state["AdministratorObjectId"]:
            raise RuntimeError("The cached operator is not the configured administrator.")
        return session
    except Exception:
        session.headers.clear()
        session.close()
        raise


def graph(session, method, path, body=None):
    if not isinstance(path, str) or not path.startswith(("v1.0/", "beta/")):
        raise RuntimeError("Only relative Microsoft Graph API paths are allowed.")
    response = session.request(
        method,
        "https://graph.microsoft.com/" + path,
        json=body,
        timeout=45,
        allow_redirects=False,
    )
    if not 200 <= response.status_code < 300:
        try:
            code = response.json().get("error", {}).get("code", "unknown")
        except ValueError:
            code = "unknown"
        raise RuntimeError(f"Microsoft Graph {method} failed: HTTP {response.status_code} ({code}).")
    return response.json() if response.content else {}
