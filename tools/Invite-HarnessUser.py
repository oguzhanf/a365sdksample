# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Prepare, notify, and verify an explicitly approved harness B2B guest."""

import argparse
import json
import pathlib
import sys
import time
from urllib.parse import quote

import requests

import harness_identity as operations

ROOT = pathlib.Path(__file__).resolve().parent.parent
ROLE = "AgentHarnessUsers"


def user(session, object_id):
    return operations.graph(
        session, "GET",
        f"v1.0/users/{object_id}?$select=id,displayName,mail,userPrincipalName,userType,accountEnabled,externalUserState",
    )


def application(state, name):
    fields = {
        "harness": ("ServicePrincipalId", "ClientId"),
        "internal-api": ("InternalApiServicePrincipalId", "InternalApiClientId"),
        "gravitee": ("GraviteeServicePrincipalId", "GraviteeClientId"),
    }
    if name not in fields:
        raise RuntimeError("Only the configured harness, internal API, and gateway applications are allowed.")
    return tuple(operations.require_guid(state, field) for field in fields[name])


def assignments(session, state, object_id, target="harness"):
    principal_id, _ = application(state, target)
    response = operations.graph(
        session, "GET",
        f"v1.0/users/{object_id}/appRoleAssignments?$select=id,appRoleId,resourceId,principalId&$top=100",
    )
    if response.get("@odata.nextLink"):
        raise RuntimeError("Assignment pagination requires an explicit review.")
    return [
        item for item in response["value"]
        if item.get("resourceId") == principal_id
        and item.get("principalId") == object_id
    ]


def role(session, state, value=ROLE, target="harness"):
    principal_id, client_id = application(state, target)
    principal = operations.graph(
        session, "GET",
        f"v1.0/servicePrincipals/{principal_id}?$select=appId,appRoles",
    )
    if principal["appId"] != client_id:
        raise RuntimeError("The application is outside the saved harness identity boundary.")
    matches = [
        item for item in principal["appRoles"]
        if item.get("value") == value and item.get("isEnabled")
        and "User" in item.get("allowedMemberTypes", [])
    ]
    if len(matches) != 1:
        raise RuntimeError("The requested application role was not uniquely identified.")
    return matches[0]


def invitation(state, email, display_name, notify):
    redirect = state["PlannedHarnessUrl"] + "/auth/login"
    body = {
        "invitedUserEmailAddress": email,
        "invitedUserDisplayName": display_name,
        "invitedUserType": "Guest",
        "inviteRedirectUrl": redirect,
        "sendInvitationMessage": notify,
        "resetRedemption": False,
    }
    if notify:
        body["invitedUserMessageInfo"] = {
            "messageLanguage": "en-US",
            "customizedMessageBody": (
                "You have been invited to use AgentHarness. "
                "Accept this invitation using your own work account, then open "
                + redirect + ". Your approved application permissions are available after redemption."
            ),
        }
    return body


def write_state(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def application_bindings(state, requested):
    result = {}
    for assignment in requested:
        target = assignment["application"]
        principal_id, client_id = application(state, target)
        result[target] = {"clientId": client_id, "servicePrincipalId": principal_id}
    return result


def read_record(path, state, object_id):
    record = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(record, dict) or (
        record.get("tenantId") != state["TenantId"]
        or record.get("clientId") != state["ClientId"]
        or record.get("userObjectId") != object_id
    ):
        raise RuntimeError("The guest approval record is not bound to the configured tenant, application, and user.")
    requested = record.get("roleAssignments")
    if not isinstance(requested, list) or not requested:
        raise RuntimeError("The guest approval record has no explicit application roles.")
    allowed = {
        ("harness", ROLE),
        ("harness", "AgentHarnessAdministrators"),
        ("internal-api", "InternalApi.Reader"),
        ("internal-api", "InternalApi.Approver"),
        ("gravitee", "Gravitee.Administrator"),
    }
    for assignment in requested:
        if not isinstance(assignment, dict) or (assignment.get("application"), assignment.get("role")) not in allowed:
            raise RuntimeError("The guest approval record contains an unsupported application role.")
    if record.get("applicationBindings") != application_bindings(state, requested):
        raise RuntimeError("The guest approval record targets different application identities.")
    if any(not isinstance(record.get(field), bool) for field in ("administratorApproved", "gatewayApproved", "invitationEmailSent")):
        raise RuntimeError("The guest approval record has ambiguous approval or notification flags.")
    administrator = record["administratorApproved"]
    gateway = record["gatewayApproved"]
    if gateway and not administrator:
        raise RuntimeError("Gateway administration requires explicit administrator approval.")
    expected = {("harness", ROLE)}
    if administrator:
        expected.add(("harness", "AgentHarnessAdministrators"))
    if gateway:
        expected.update({
            ("internal-api", "InternalApi.Reader"),
            ("internal-api", "InternalApi.Approver"),
            ("gravitee", "Gravitee.Administrator"),
        })
    if {(item["application"], item["role"]) for item in requested} != expected:
        raise RuntimeError("The guest roles do not match the saved explicit approvals.")
    return record


def read_deployment(state):
    path = ROOT / "artifacts" / "deployment-state.json"
    if not path.is_file():
        raise RuntimeError("Deploy the configured customer portal before preparing guest access.")
    deployment = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(deployment, dict):
        raise RuntimeError("The deployment state must be a JSON object.")
    for field in ("TenantId", "SubscriptionId", "AdministratorObjectId", "ClientId", "ServicePrincipalId"):
        deployment_field = field[0].lower() + field[1:]
        if operations.require_guid(deployment, deployment_field) != state[field]:
            raise RuntimeError("The deployment state is outside the configured tenant/application boundary.")
    portal_url = deployment.get("plannedHarnessUrl")
    if not isinstance(portal_url, str) or portal_url.rstrip("/") != state["PlannedHarnessUrl"]:
        raise RuntimeError("The deployment state targets a different customer portal.")
    return deployment


def grant(session, state, object_id, target, value):
    definition = role(session, state, value, target)
    principal_id, _ = application(state, target)
    for attempt in range(5):
        current = assignments(session, state, object_id, target)
        if any(item["appRoleId"] == definition["id"] for item in current):
            return
        try:
            operations.graph(
                session, "POST",
                f"v1.0/servicePrincipals/{principal_id}/appRoleAssignedTo",
                {"principalId": object_id, "resourceId": principal_id, "appRoleId": definition["id"]},
            )
        except RuntimeError as error:
            if not any(status in str(error) for status in ("HTTP 400", "HTTP 404", "HTTP 409")) or attempt == 4:
                raise
        verified = assignments(session, state, object_id, target)
        if any(item["appRoleId"] == definition["id"] for item in verified):
            return
        if attempt < 4:
            time.sleep(2 ** attempt)
    raise RuntimeError("The direct application-role assignment has not been confirmed.")


def prepare(session, state, email, display_name, administrator, gateway):
    if not email or email.count("@") != 1 or any(char in email for char in "\r\n<>"):
        raise RuntimeError("Provide one valid external email address.")
    deployment = read_deployment(state)
    if gateway:
        application(state, "internal-api")
        application(state, "gravitee")
    escaped = email.replace("'", "''")
    guest_upn = email.replace("@", "_") + "#EXT#@" + state["TenantDomain"]
    predicate = quote(
        f"mail eq '{escaped}' or userPrincipalName eq '{guest_upn.replace(chr(39), chr(39) * 2)}'",
        safe="",
    )
    found = operations.graph(
        session, "GET",
        "v1.0/users?$filter=" + predicate +
        "&$select=id,displayName,mail,userPrincipalName,userType,accountEnabled,externalUserState",
    )
    if found.get("@odata.nextLink") or len(found["value"]) > 1:
        raise RuntimeError("Multiple matching directory users require an explicit review.")
    created = not found["value"]
    if created:
        if gateway and not administrator:
            raise RuntimeError("Gateway administration requires explicit administrator approval.")
        response = operations.graph(session, "POST", "v1.0/invitations", invitation(state, email, display_name, False))
        for attempt in range(5):
            try:
                account = user(session, operations.require_guid(response["invitedUser"], "id"))
                break
            except RuntimeError as error:
                if attempt == 4 or "HTTP 404" not in str(error):
                    raise
                time.sleep(2 ** attempt)
    else:
        account = found["value"][0]
    if account.get("userType") != "Guest" or account.get("accountEnabled") is not True:
        raise RuntimeError("The matched account is not an enabled B2B guest; no role was granted.")
    account["id"] = operations.require_guid(account, "id")
    record_path = ROOT / "artifacts" / "b2b-access" / (account["id"] + ".json")
    previous = read_record(record_path, state, account["id"]) if record_path.exists() else {}
    administrator = administrator or previous.get("administratorApproved", False)
    gateway = gateway or previous.get("gatewayApproved", False)
    if gateway and not administrator:
        raise RuntimeError("Gateway administration requires explicit administrator approval.")
    requested = [("harness", ROLE)]
    if administrator:
        requested.append(("harness", "AgentHarnessAdministrators"))
    if gateway:
        requested.extend([
            ("internal-api", "InternalApi.Reader"),
            ("internal-api", "InternalApi.Approver"),
            ("gravitee", "Gravitee.Administrator"),
        ])
    for target, value in requested:
        grant(session, state, account["id"], target, value)
    allowed = list(state.get("ApprovedB2BGuestObjectIds", []))
    if account["id"] not in allowed:
        allowed.append(account["id"])
    state["ApprovedB2BGuestObjectIds"] = allowed
    approved_administrators = list(state.get("ApprovedB2BGuestAdministratorObjectIds", []))
    if administrator and account["id"] not in approved_administrators:
        approved_administrators.append(account["id"])
    state["ApprovedB2BGuestAdministratorObjectIds"] = approved_administrators
    write_state(ROOT / "infra" / "entra-state.json", state)
    deployment_path = ROOT / "artifacts" / "deployment-state.json"
    deployment["approvedB2BGuestObjectIds"] = allowed
    deployment["approvedB2BGuestAdministratorObjectIds"] = approved_administrators
    write_state(deployment_path, deployment)
    record = {
        "tenantId": state["TenantId"],
        "clientId": state["ClientId"],
        "userObjectId": account["id"],
        "email": email,
        "displayName": display_name,
        "userType": "Guest",
        "externalUserState": account.get("externalUserState"),
        "role": ROLE,
        "roleAssignments": [{"application": target, "role": value} for target, value in requested],
        "applicationBindings": application_bindings(
            state, [{"application": target} for target, _ in requested]
        ),
        "administratorApproved": administrator,
        "gatewayApproved": gateway,
        "directRoleAssignmentVerified": True,
        "created": created,
        "invitationEmailSent": previous.get("invitationEmailSent", False),
    }
    write_state(record_path, record)
    return record


def notify_or_verify(session, state, object_id, notify):
    path = ROOT / "artifacts" / "b2b-access" / (object_id + ".json")
    record = read_record(path, state, object_id)
    if object_id not in state.get("ApprovedB2BGuestObjectIds", []):
        raise RuntimeError("The saved guest is not explicitly approved for this harness.")
    if record["administratorApproved"] and object_id not in state.get("ApprovedB2BGuestAdministratorObjectIds", []):
        raise RuntimeError("The saved guest is not explicitly approved as a harness administrator.")
    requested = record["roleAssignments"]
    for assignment in requested:
        definition = role(session, state, assignment["role"], assignment["application"])
        if not any(item["appRoleId"] == definition["id"] for item in assignments(session, state, object_id, assignment["application"])):
            raise RuntimeError("The approved guest no longer has one of the requested direct roles.")
    account = user(session, object_id)
    if account.get("userType") != "Guest" or account.get("accountEnabled") is not True:
        raise RuntimeError("The saved guest is no longer an enabled B2B account.")
    if notify and not record["invitationEmailSent"] and account.get("externalUserState") != "Accepted":
        readiness = requests.get(state["PlannedHarnessUrl"] + "/", timeout=30, allow_redirects=False)
        expected = (
            "Guest administrator and gateway roles require separate explicit approval"
            if record.get("administratorApproved")
            else "accepted, explicitly approved B2B guest account"
        )
        if readiness.status_code != 200 or expected not in readiness.text:
            raise RuntimeError("The deployed guest policy is not ready; the invitation email was not sent.")
        response = operations.graph(
            session, "POST", "v1.0/invitations",
            invitation(state, record["email"], record["displayName"], True),
        )
        if response["invitedUser"]["id"] != object_id:
            raise RuntimeError("The invitation resolved to a different account; review before continuing.")
        record["invitationEmailSent"] = response.get("sendInvitationMessage") is True
        record["invitationStatus"] = response.get("status")
        if not record["invitationEmailSent"]:
            raise RuntimeError("Microsoft Graph did not confirm the invitation email request.")
    record["externalUserState"] = account.get("externalUserState")
    record["directRoleAssignmentVerified"] = True
    write_state(path, record)
    return record


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=("prepare", "send", "verify"), required=True)
    parser.add_argument("--email")
    parser.add_argument("--display-name")
    parser.add_argument("--user-id")
    parser.add_argument("--administrator", action="store_true")
    parser.add_argument("--gateway", action="store_true")
    args = parser.parse_args()
    state = operations.read_state(ROOT / "infra" / "entra-state.json")
    if args.phase == "prepare":
        if not args.display_name:
            raise RuntimeError("--display-name is required.")
        read_deployment(state)
    elif not args.user_id:
        raise RuntimeError("--user-id is required.")
    session = operations.silent_session(state)
    try:
        if args.phase == "prepare":
            result = prepare(session, state, args.email, args.display_name, args.administrator, args.gateway)
        else:
            object_id = operations.require_guid({"id": args.user_id}, "id")
            result = notify_or_verify(session, state, object_id, args.phase == "send")
        print(json.dumps({**result, "interactiveAuthenticationAttempted": False}))
    finally:
        session.headers.clear()
        session.close()


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError, TypeError, OSError, requests.RequestException) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
