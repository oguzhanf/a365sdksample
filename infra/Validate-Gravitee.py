"""Offline provisioning regressions; no Docker, Azure access, or signed-token fabrication."""

import copy
import http.server
import importlib.util
import json
import pathlib
import sys
import threading
import unittest
import urllib.parse
from unittest import mock

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("agentharness_provision", pathlib.Path(__file__).parent / "gravitee" / "provision.py")
provision = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provision)
CONFIG = {
    "tenantId": "11111111-1111-4111-8111-111111111111",
    "harnessClientId": "22222222-2222-4222-8222-222222222222",
    "internalApiClientId": "33333333-3333-4333-8333-333333333333",
    "graviteeUrl": "https://gateway.example.invalid",
    "consoleAuthMode": "password",
}
OIDC_CONFIG = {
    **CONFIG,
    "graviteeClientId": "44444444-4444-4444-8444-444444444444",
    "consoleAuthMode": "entra-oidc",
}


class ContractDouble:
    """In-memory official v1 REST shapes, including server-added defaults."""

    def __init__(self):
        self.apis = {}
        self.plans = {}
        self.applications = {}
        self.subscriptions = {}
        self.providers = {}
        self.activations = [{"identityProvider": "existing-provider"}]
        self.actions = []
        self.lifecycles = []
        self.tamper_readback = False

    def save(self, store, body, prefix):
        item = copy.deepcopy(body)
        item["id"] = prefix + str(len(store) + 1)
        store[item["id"]] = item
        return copy.deepcopy(item)

    def call(self, method, uri, body=None):
        parsed = urllib.parse.urlsplit(uri)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        self.actions.append((method, path, copy.deepcopy(body)))
        org = provision.ORG_PATH
        env = provision.ENV_PATH
        if path == org + "/identities":
            if method == "PUT":
                self.activations = copy.deepcopy(body)
            return copy.deepcopy(self.activations)
        if path == org + "/configuration/identities":
            if method == "GET":
                return copy.deepcopy(list(self.providers.values()))
            return self.save(self.providers, body, "provider")
        if path.startswith(org + "/configuration/identities/"):
            key = path.rsplit("/", 1)[1]
            if method == "PUT":
                self.providers[key] = {**copy.deepcopy(body), "id": key}
            return copy.deepcopy(self.providers[key])
        if path == env + "/apis":
            if method == "GET":
                return copy.deepcopy(list(self.apis.values()))
            result = self.save(self.apis, body, "api")
            self.apis[result["id"]].update({"proxy": {}, "plans": [], "state": "STOPPED"})
            return result
        if path == env + "/applications":
            if method == "GET":
                return copy.deepcopy(list(self.applications.values()))
            return self.save(self.applications, body, "application")
        if path.startswith(env + "/applications/"):
            key = path.rsplit("/", 1)[1]
            if method == "PUT":
                self.applications[key] = {**copy.deepcopy(body), "id": key}
            return copy.deepcopy(self.applications[key])
        if not path.startswith(env + "/apis/"):
            raise AssertionError("Unexpected request path: " + path)
        tail = path[len(env + "/apis/"):].split("/")
        api_id = tail[0]
        if len(tail) == 1:
            api = self.apis[api_id]
            if method == "POST":
                api["state"] = "STARTED" if query["action"] == ["START"] else "STOPPED"
                self.lifecycles.append(api["state"])
                return None
            if method == "PUT":
                self.apis[api_id] = {**api, **copy.deepcopy(body)}
                for flow in self.apis[api_id]["flows"]:
                    flow["consumers"] = []
                    flow["condition"] = None
                    for step in flow["pre"]:
                        step["description"] = None
            result = copy.deepcopy(self.apis[api_id])
            if self.tamper_readback and result.get("flows"):
                result["flows"][0]["pre"] = result["flows"][0]["pre"][:1]
            return result
        if tail[1] == "deploy":
            return None
        if tail[1] == "plans":
            if len(tail) == 2:
                if method == "GET":
                    return copy.deepcopy(list(self.plans.values()))
                return self.save(self.plans, body, "plan")
            plan = self.plans[tail[2]]
            if len(tail) == 4:
                plan["status"] = "PUBLISHED" if tail[3] == "_publish" else "CLOSED"
            elif method == "PUT":
                self.plans[tail[2]] = {**plan, **copy.deepcopy(body)}
            return copy.deepcopy(self.plans[tail[2]])
        if tail[1] == "subscriptions":
            if method == "GET":
                return {"data": copy.deepcopy(list(self.subscriptions.values()))}
            return self.save(self.subscriptions, {"status": "ACCEPTED", "api": api_id, "application": query["application"][0],
                                                 "plan": query["plan"][0]}, "subscription")
        raise AssertionError("Unexpected request path: " + path)


class ProvisioningRegressions(unittest.TestCase):
    def test_elasticsearch_password_uses_image_owner_and_strict_mode(self):
        with mock.patch.object(provision, "write_private") as write_private:
            provision.write_elasticsearch_password("noncredential-contract-fixture")
        write_private.assert_called_once_with(
            "elasticsearch-password",
            "noncredential-contract-fixture",
            mode=0o400,
            owner_uid=1000,
            owner_gid=0,
        )

    def test_request_validation_plugin_is_pinned_verified_and_single_file_mounted(self):
        version = "1.15.1"
        filename = "gravitee-policy-request-validation-" + version + ".zip"
        sha256 = "61b5bfe74c99ab91aa36f9c1d8b45bb4c94a11856ec605af5f75f68e27485f67"
        gravitee_dir = pathlib.Path(__file__).parent / "gravitee"
        bootstrap = (gravitee_dir / "bootstrap.sh").read_text(encoding="utf-8-sig")
        self.assertIn("plugin_version=" + version, bootstrap)
        self.assertIn("plugin_sha256=" + sha256, bootstrap)
        self.assertIn(
            "https://download.gravitee.io/graviteeio-apim/plugins/policies/"
            "gravitee-policy-request-validation/${plugin_name}",
            bootstrap,
        )
        self.assertIn("sha256sum --check --status", bootstrap)
        self.assertLess(
            bootstrap.index("plugin_sha256=" + sha256),
            bootstrap.index("docker compose --file compose.runtime.json config --quiet"),
        )
        self.assertIn(
            "ExecStartPre=/usr/bin/sha256sum --check --status ${deployment_root}/plugins/"
            + filename
            + ".sha256",
            bootstrap,
        )

        compose = json.loads((gravitee_dir / "compose.json").read_text(encoding="utf-8-sig"))
        targets = {
            "management-api": "/opt/graviteeio-management-api/plugins/" + filename,
            "gateway": "/opt/graviteeio-gateway/plugins/" + filename,
        }
        for service, target in targets.items():
            volumes = compose["services"][service]["volumes"]
            self.assertIn("./plugins/" + filename + ":" + target + ":ro", volumes)
            self.assertFalse(any(volume.startswith("./plugins:") for volume in volumes))

    def test_management_replays_server_csrf_header_and_session_cookie(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header("X-Xsrf-Token", "noncredential-csrf-fixture")
                self.send_header("Set-Cookie", "GRAVITEESESSID=noncredential-session-fixture; Path=/")
                self.end_headers()
                self.wfile.write(b"[]")

            def do_POST(self):
                valid = (
                    self.headers.get("X-Xsrf-Token") == "noncredential-csrf-fixture"
                    and "GRAVITEESESSID=noncredential-session-fixture" in self.headers.get("Cookie", "")
                )
                self.send_response(200 if valid else 403)
                self.end_headers()
                self.wfile.write(b"{}")

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            client = provision.Management("127.0.0.1", "noncredential-contract-fixture")
            client.base = "http://127.0.0.1:" + str(server.server_port)
            client.call("GET", provision.ENV_PATH + "/apis")
            self.assertEqual(client.call("POST", provision.ENV_PATH + "/apis", {}), {})
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_second_apply_reuses_api_plan_application_subscription(self):
        client = ContractDouble()
        first = provision.provision_api(client, CONFIG)
        second = provision.provision_api(client, CONFIG)
        self.assertEqual(first, second)
        self.assertEqual([len(client.apis), len(client.plans), len(client.applications),
                          len(client.subscriptions)], [1, 1, 1, 1])
        self.assertEqual(client.apis[first[0]]["state"], "STARTED")
        self.assertEqual(client.lifecycles, ["STARTED", "STOPPED", "STARTED"])

    def test_brand_migration_adopts_only_recorded_owned_ids_without_changing_security(self):
        client = ContractDouble()
        first = provision.provision_resources(client, CONFIG, {})
        ids = {key: first[key] for key in provision.OWNED_ID_KEYS}
        marker = "[previous-deployment-owned]"
        for entity in (client.apis[first["apiId"]], client.plans[first["planId"]],
                       client.applications[first["applicationId"]]):
            entity["description"] = entity["description"].replace(provision.OWNER, marker)
            entity["name"] = "Previous " + entity["name"]
        client.apis[first["apiId"]]["labels"] = [marker[1:-1]]
        before = copy.deepcopy(client)
        config = {**CONFIG, "managedResourceIds": ids}

        client.applications[first["applicationId"]]["description"] = "not owned"
        client.actions.clear()
        with self.assertRaisesRegex(RuntimeError, "not owned"):
            provision.rebrand_owned_resources(client, config, first, marker)
        self.assertTrue(all(method == "GET" for method, _, _ in client.actions))
        client.applications[first["applicationId"]] = copy.deepcopy(before.applications[first["applicationId"]])
        self.assertEqual(provision.rebrand_owned_resources(client, config, first, marker), ids)
        self.assertEqual([len(client.apis), len(client.plans), len(client.applications),
                          len(client.subscriptions)], [1, 1, 1, 1])
        self.assertEqual(client.apis[first["apiId"]]["flows"], before.apis[first["apiId"]]["flows"])
        self.assertEqual(client.apis[first["apiId"]]["proxy"], before.apis[first["apiId"]]["proxy"])
        self.assertEqual(client.plans[first["planId"]]["securityDefinition"],
                         before.plans[first["planId"]]["securityDefinition"])
        self.assertEqual(client.subscriptions, before.subscriptions)
        client.actions.clear()
        provision.rebrand_owned_resources(client, config, first, marker)
        self.assertTrue(all(method == "GET" for method, _, _ in client.actions))
        self.assertEqual(provision.provision_resources(client, config, {}), first)
        self.assertEqual([len(client.apis), len(client.plans), len(client.applications),
                          len(client.subscriptions)], [1, 1, 1, 1])

    def test_existing_runtime_uses_external_data_aliases_and_the_existing_backend_image(self):
        template = json.loads((pathlib.Path(__file__).parent / "gravitee" / "compose.json").read_text(
            encoding="utf-8-sig"
        ))
        aliases = {key: "existing_" + key for key in template["volumes"]}
        config = {**CONFIG, "runtime": {
            "projectName": "existing",
            "networks": {key: "existing-" + key for key in template["networks"]},
            "volumes": aliases,
            "dataRoot": "/var/lib/existing-docker",
            "backendDataPath": "/var/lib/existing-docker/backend",
            "internalApiImage": "existing-internal-api:deployment",
        }}
        runtime = provision.compose_for_runtime(template, config)
        self.assertEqual(runtime["name"], "existing")
        self.assertEqual(runtime["volumes"],
                         {key: {"name": name, "external": True} for key, name in aliases.items()})
        self.assertEqual(runtime["services"]["internal-api"]["image"], "existing-internal-api:deployment")
        self.assertEqual(runtime["services"]["internal-api"]["volumes"],
                         ["/var/lib/existing-docker/backend:/app/data"])
        self.assertEqual(template["name"], "agentharness")
        config["runtime"]["volumes"] = {key: value for key, value in aliases.items() if key != "mongo-data"}
        with self.assertRaisesRegex(RuntimeError, "explicit external alias"):
            provision.compose_for_runtime(template, config)
        config["runtime"]["volumes"] = aliases
        config["runtime"]["backendDataPath"] = "/var/lib/new-empty-disk/backend"
        with self.assertRaisesRegex(RuntimeError, "persistent disk"):
            provision.compose_for_runtime(template, config)

    def test_migration_allows_expired_command_messages_but_rejects_durable_data_loss(self):
        before = {"commands": 15, "apis": 1, "users": 2, "subscriptions": 1}
        after = {**before, "commands": 0}
        provision.verify_persistent_collections(before, after)
        for collection in ("apis", "users", "subscriptions"):
            with self.subTest(collection=collection), self.assertRaisesRegex(RuntimeError, collection):
                provision.verify_persistent_collections(before, {**after, collection: before[collection] - 1})

    def test_foreign_name_collision_does_not_mutate(self):
        client = ContractDouble()
        client.apis["foreign"] = {"id": "foreign", "name": provision.API_NAME, "description": "not owned", "state": "STARTED"}
        with self.assertRaisesRegex(RuntimeError, "not owned"):
            provision.provision_api(client, CONFIG)
        self.assertTrue(all(method == "GET" for method, _, _ in client.actions))
        self.assertEqual(client.apis["foreign"]["state"], "STARTED")

    def test_policy_readback_loss_keeps_owned_api_stopped(self):
        client = ContractDouble()
        first = provision.provision_api(client, CONFIG)
        client.tamper_readback = True
        with self.assertRaisesRegex(RuntimeError, "deny-by-default"):
            provision.provision_api(client, CONFIG)
        self.assertEqual(client.apis[first[0]]["state"], "STOPPED")

    def test_keyless_alternative_is_closed_before_start(self):
        client = ContractDouble()
        provision.provision_api(client, CONFIG)
        client.plans["unsafe"] = {"id": "unsafe", "name": "Manually added keyless", "security": "KEY_LESS", "status": "PUBLISHED"}
        provision.provision_api(client, CONFIG)
        self.assertEqual(client.plans["unsafe"]["status"], "CLOSED")

    def test_password_mode_skips_oidc_and_license_but_keeps_entra_jwt_policy(self):
        client = ContractDouble()
        default_password_config = {key: value for key, value in CONFIG.items() if key != "consoleAuthMode"}
        provisioned = provision.provision_resources(client, default_password_config, {})

        self.assertEqual(provisioned["consoleAuthMode"], "password")
        self.assertEqual(provisioned["consoleUsername"], "demo-admin")
        self.assertEqual(provisioned["consoleOidcStatus"], "not-accessed")
        self.assertIsNone(provisioned["identityProviderId"])
        self.assertFalse(any("/identities" in path for _, path, _ in client.actions))
        self.assertNotIn("gravitee-oidc-client-secret", provision.required_secret_names(default_password_config))
        self.assertNotIn("gravitee-license", provision.required_secret_names(default_password_config))

        compose_path = pathlib.Path(__file__).parent / "gravitee" / "compose.json"
        compose = provision.compose_for_mode(
            json.loads(compose_path.read_text(encoding="utf-8-sig")),
            provision.console_auth_mode(default_password_config),
        )
        self.assertNotIn("gravitee-license.key", json.dumps(compose))

        management = provision.management_configuration(
            default_password_config,
            {"gravitee-jwt-secret": "noncredential-contract-fixture"},
            "mongodb://private-contract-fixture",
            {},
            "$2a$12$noncredentialcontractfixture",
        )
        provider = management["security"]["providers"][0]
        administrator = provider["users"][0]
        self.assertEqual(provider["password-encoding-algo"], "bcrypt")
        self.assertIsNone(administrator["user"])
        self.assertEqual(administrator["username"], "demo-admin")
        self.assertEqual(administrator["password"], "$2a$12$noncredentialcontractfixture")
        self.assertEqual(administrator["roles"], "ORGANIZATION:ADMIN,ENVIRONMENT:ADMIN")

        plan = client.plans[provisioned["planId"]]
        definition = json.loads(plan["securityDefinition"])
        self.assertEqual(plan["security"], "JWT")
        self.assertEqual(definition["signature"], "RSA_RS256")
        self.assertEqual(definition["publicKeyResolver"], "JWKS_URL")
        self.assertEqual(
            definition["resolverParameter"],
            "https://login.microsoftonline.com/"
            + default_password_config["tenantId"]
            + "/discovery/v2.0/keys",
        )
        self.assertTrue(definition["extractClaims"])
        self.assertEqual(definition["clientIdClaim"], "azp")
        self.assertFalse(definition["propagateAuthHeader"])
        flows = client.apis[provisioned["apiId"]]["flows"]
        self.assertEqual(
            [step["policy"] for step in flows[0]["pre"]],
            ["policy-request-validation", "policy-request-validation"],
        )
        policy = json.dumps(flows)
        for required in (
            "https://login.microsoftonline.com/"
            + default_password_config["tenantId"]
            + "/v2.0",
            default_password_config["tenantId"],
            default_password_config["internalApiClientId"],
            default_password_config["harnessClientId"],
            "access_as_user",
            "['exp']",
            "InternalApi.Reader",
            "InternalApi.Approver",
        ):
            self.assertIn(required, policy)

    def test_oidc_apply_reuses_provider_and_preserves_other_activations(self):
        client = ContractDouble()
        secrets = {"gravitee-oidc-client-secret": "noncredential-contract-fixture"}
        first = provision.provision_identity_provider(client, OIDC_CONFIG, secrets)
        second = provision.provision_identity_provider(client, OIDC_CONFIG, secrets)
        self.assertEqual(first, second)
        self.assertEqual(len(client.providers), 1)
        self.assertEqual({item["identityProvider"] for item in client.activations}, {"existing-provider", first})
        self.assertEqual(len(client.providers[first]["roleMappings"]), 2)
        self.assertIn("gravitee-oidc-client-secret", provision.required_secret_names(OIDC_CONFIG))
        self.assertIn("gravitee-license", provision.required_secret_names(OIDC_CONFIG))
        compose_path = pathlib.Path(__file__).parent / "gravitee" / "compose.json"
        compose = provision.compose_for_mode(
            json.loads(compose_path.read_text(encoding="utf-8-sig")),
            provision.console_auth_mode(OIDC_CONFIG),
        )
        self.assertEqual(json.dumps(compose).count("gravitee-license.key"), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
