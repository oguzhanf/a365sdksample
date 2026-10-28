# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Offline tests: no Azure sign-in, invitation, or policy operations."""

import base64
import copy
import importlib.util
import json
import pathlib
import sys
import time
import types
import unittest
import uuid
from unittest.mock import Mock, patch
from urllib.parse import unquote

sys.dont_write_bytecode = True
TOOLS = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import harness_identity as identity

spec = importlib.util.spec_from_file_location("invite_harness_user", TOOLS / "Invite-HarnessUser.py")
invite = importlib.util.module_from_spec(spec)
spec.loader.exec_module(invite)


def configuration():
    state = {
        field: str(uuid.uuid4())
        for field in ("TenantId", "SubscriptionId", "AdministratorObjectId", "ClientId", "ServicePrincipalId")
    }
    state.update(TenantDomain="sample.onmicrosoft.com", PlannedHarnessUrl="https://portal.example.test")
    return state


def state_path(state):
    return Mock(is_file=Mock(return_value=True), read_text=Mock(return_value=json.dumps(state)))


def token(claims):
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return "header." + payload + ".signature"


class CustomerIdentityTests(unittest.TestCase):
    def test_customer_configuration_is_required_and_invalid_ids_fail_closed(self):
        with self.assertRaises(RuntimeError):
            identity.read_state(Mock(is_file=Mock(return_value=False)))
        for invalid in ("", "replace-me", str(uuid.UUID(int=0)), None):
            state = configuration()
            state["TenantId"] = invalid
            with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                identity.read_state(state_path(state))
        state = configuration()
        self.assertEqual(identity.read_state(state_path(state))["TenantId"], state["TenantId"])

    def test_only_explicit_https_portal_origins_and_initial_tenant_domains_are_accepted(self):
        state = configuration()
        for origin in (
            None, "http://portal.example.test", "https://user@portal.example.test",
            "https://portal.example.test/path", "https://portal.example.test?next=elsewhere",
            "https://portal.example.test:8443", "https://portal.example.test\\path",
        ):
            with self.subTest(origin=origin), self.assertRaises(RuntimeError):
                identity.read_state(state_path({**state, "PlannedHarnessUrl": origin}))
        with self.assertRaises(RuntimeError):
            identity.read_state(state_path({**state, "TenantDomain": "other.example.test"}))
        loaded = identity.read_state(state_path({**state, "PlannedHarnessUrl": state["PlannedHarnessUrl"] + "/"}))
        self.assertEqual(loaded["PlannedHarnessUrl"], state["PlannedHarnessUrl"])

    def test_cached_credentials_cannot_cross_the_configured_tenant_or_subscription(self):
        state = configuration()
        profile = Mock()
        credential = Mock()
        core = types.ModuleType("azure.cli.core")
        core.get_default_cli = Mock(return_value=object())
        profile_module = types.ModuleType("azure.cli.core._profile")
        profile_module.Profile = Mock(return_value=profile)
        modules = {"azure.cli.core": core, "azure.cli.core._profile": profile_module}
        for subscription, tenant in (
            (state["SubscriptionId"], str(uuid.uuid4())),
            (str(uuid.uuid4()), state["TenantId"]),
        ):
            profile.get_login_credentials.return_value = (credential, subscription, tenant)
            with patch.dict(sys.modules, modules), patch.object(identity.requests, "Session") as session:
                with self.assertRaises(RuntimeError):
                    identity.silent_session(state)
                session.assert_not_called()
                credential._msal_app.acquire_token_silent_with_error.assert_not_called()
            profile.get_login_credentials.assert_called_with(
                subscription_id=state["SubscriptionId"], sdk_credential=False
            )

    def test_graph_tokens_must_match_configured_operator_tenant_audience_and_lifetime(self):
        state = configuration()
        claims = {
            "tid": state["TenantId"], "oid": state["AdministratorObjectId"],
            "aud": "https://graph.microsoft.com/", "exp": int(time.time()) + 600,
        }
        identity._validate_graph_token(token(claims), state)
        for changed in (
            {"tid": str(uuid.uuid4())}, {"oid": str(uuid.uuid4())},
            {"aud": "https://other.example.test/"}, {"exp": 0},
        ):
            with self.subTest(changed=changed), self.assertRaises(RuntimeError):
                identity._validate_graph_token(token({**claims, **changed}), state)

    def test_invitation_uses_only_configured_portal_and_guest_domain(self):
        state = configuration()
        guest_id = str(uuid.uuid4())
        guest = {"id": guest_id, "userType": "Guest", "accountEnabled": True}
        graph = Mock(return_value={"value": [guest]})
        with (
            patch.object(invite, "read_deployment", return_value={}),
            patch.object(invite.operations, "graph", graph),
            patch.object(invite, "grant"),
            patch.object(invite, "write_state"),
            patch.object(pathlib.Path, "exists", return_value=False),
        ):
            result = invite.prepare(None, state, "guest@example.test", "Sample guest", False, False)
        self.assertIn("#EXT#@" + state["TenantDomain"], unquote(graph.call_args.args[2]))
        body = invite.invitation(state, "guest@example.test", "Sample guest", True)
        self.assertEqual(body["inviteRedirectUrl"], state["PlannedHarnessUrl"] + "/auth/login")
        self.assertFalse(body["resetRedemption"])
        self.assertEqual(result["tenantId"], state["TenantId"])
        self.assertEqual(result["applicationBindings"]["harness"]["clientId"], state["ClientId"])

    def test_approval_records_cannot_be_reused_after_application_identity_changes(self):
        state = configuration()
        object_id = str(uuid.uuid4())
        roles = [{"application": "harness", "role": invite.ROLE}]
        record = {
            "tenantId": state["TenantId"], "clientId": state["ClientId"], "userObjectId": object_id,
            "roleAssignments": roles, "applicationBindings": invite.application_bindings(state, roles),
            "administratorApproved": False, "gatewayApproved": False, "invitationEmailSent": False,
        }
        self.assertEqual(invite.read_record(state_path(record), state, object_id), record)
        for changed in (
            {"tenantId": str(uuid.uuid4())},
            {"clientId": str(uuid.uuid4())},
            {"applicationBindings": {}},
            {"gatewayApproved": True},
        ):
            with self.subTest(changed=changed), self.assertRaises(RuntimeError):
                invite.read_record(state_path({**copy.deepcopy(record), **changed}), state, object_id)
        with self.assertRaises(RuntimeError):
            invite.application(state, "gravitee")


if __name__ == "__main__":
    unittest.main()
