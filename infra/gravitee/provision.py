#!/usr/bin/env python3
"""Run on the VM; never print request bodies, credentials, or access tokens."""

import base64
import copy
import http.cookiejar
import ipaddress
import json
import os
import pathlib
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

OWNER = "[agentharness-agent-harness-owned]"
API_NAME = "AgentHarness synthetic purchase orders"
PLAN_NAME = "AgentHarness delegated JWT"
APPLICATION_NAME = "AgentHarness"
IDP_NAME = "AgentHarness Microsoft Entra ID"
ORG_PATH = "/management/organizations/DEFAULT"
ENV_PATH = ORG_PATH + "/environments/DEFAULT"
COMPOSE_FILE = "compose.runtime.json"
CONSOLE_AUTH_PASSWORD = "password"
CONSOLE_AUTH_ENTRA_OIDC = "entra-oidc"
BASE_SECRET_NAMES = (
    "gravitee-demo-admin-password",
    "gravitee-jwt-secret",
    "gravitee-mongodb-password",
    "gravitee-elasticsearch-password",
)
ENTRA_OIDC_SECRET_NAMES = (
    "gravitee-oidc-client-secret",
    "gravitee-license",
)
OWNED_ID_KEYS = ("apiId", "planId", "applicationId", "subscriptionId")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def fail(message):
    raise RuntimeError(message)


def console_auth_mode(config):
    mode = config.get("consoleAuthMode", CONSOLE_AUTH_PASSWORD)
    if mode not in (CONSOLE_AUTH_PASSWORD, CONSOLE_AUTH_ENTRA_OIDC):
        fail("Invalid console authentication mode.")
    return mode


def required_secret_names(config):
    names = BASE_SECRET_NAMES
    if console_auth_mode(config) == CONSOLE_AUTH_ENTRA_OIDC:
        names += ENTRA_OIDC_SECRET_NAMES
    return names


def read_config():
    config = json.loads(pathlib.Path("public.json").read_text(encoding="utf-8-sig"))
    config["consoleAuthMode"] = console_auth_mode(config)
    identity_keys = ["tenantId", "harnessClientId", "internalApiClientId"]
    if config["consoleAuthMode"] == CONSOLE_AUTH_ENTRA_OIDC:
        identity_keys.append("graviteeClientId")
    for key in identity_keys:
        if not re.fullmatch(r"[0-9a-fA-F-]{36}", config.get(key, "")):
            fail("Invalid deployment identity configuration.")
    uri = urllib.parse.urlparse(config["keyVaultUri"])
    if uri.scheme != "https" or not re.fullmatch(r"[a-z0-9-]+\.vault\.azure\.net", uri.hostname or ""):
        fail("Refusing an unexpected Key Vault endpoint.")
    public = urllib.parse.urlparse(config["graviteeUrl"])
    if public.scheme != "https" or not re.fullmatch(
        r"[a-z0-9-]+\.[a-z0-9]+\.cloudapp\.azure\.com", public.hostname or ""
    ):
        fail("Refusing an unexpected public Gravitee endpoint.")
    return config


def fetch_secrets(config):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    metadata = "http://169.254.169.254/metadata/identity/oauth2/token?" + urllib.parse.urlencode(
        {"api-version": "2018-02-01", "resource": "https://vault.azure.net"}
    )
    token_request = urllib.request.Request(metadata, headers={"Metadata": "true"})
    with opener.open(token_request, timeout=30) as response:
        token = json.load(response)["access_token"]
    result = {}
    for name in required_secret_names(config):
        request = urllib.request.Request(
            config["keyVaultUri"].rstrip("/") + "/secrets/" + name + "?api-version=7.4",
            headers={"Authorization": "Bearer " + token},
        )
        for attempt in range(30):
            try:
                with opener.open(request, timeout=30) as response:
                    result[name] = json.load(response)["value"]
                break
            except urllib.error.HTTPError as error:
                if error.code not in (403, 429, 500, 502, 503, 504) or attempt == 29:
                    fail("Key Vault secret retrieval failed; check VM identity RBAC and stored secrets.")
                time.sleep(5)
    return result


def write_private(name, value, *, mode=0o444, owner_uid=None, owner_gid=None):
    private = pathlib.Path("private")
    private.mkdir(mode=0o700, exist_ok=True)
    private.chmod(0o700)
    path = private / name
    # The parent remains root-only while a bind-mounted file can be owned by
    # the unprivileged UID required by its container image.
    path.write_text(value, encoding="utf-8")
    if (owner_uid is None) != (owner_gid is None):
        fail("Private-file ownership must specify both UID and GID.")
    if owner_uid is not None:
        os.chown(path, owner_uid, owner_gid)
    path.chmod(mode)


def write_elasticsearch_password(value):
    write_private(
        "elasticsearch-password",
        value,
        mode=0o400,
        owner_uid=1000,
        owner_gid=0,
    )


def management_configuration(config, secrets, mongo_uri, elastic, password_hash):
    return {
        "management": {"type": "mongodb", "mongodb": {"uri": mongo_uri}},
        "analytics": {"type": "elasticsearch", "elasticsearch": elastic},
        "security": {
            "providers": [{
                "type": "memory",
                "password-encoding-algo": "bcrypt",
                "users": [{
                    "user": None,
                    "username": "demo-admin",
                    "password": password_hash,
                    "roles": "ORGANIZATION:ADMIN,ENVIRONMENT:ADMIN",
                }],
            }],
        },
        "jwt": {
            "secret": secrets["gravitee-jwt-secret"],
            "expire-after": 3600,
            "cookie-secure": True,
            "cookie-path": "/",
        },
        "http": {
            "api": {"portal": {"enabled": False}},
            "secureHeaders": {
                "csrf": {"enabled": True},
                "hsts": {"enabled": True, "max-age": 31536000},
            },
        },
        "services": {"core": {"http": {"enabled": False}}},
        "email": {"enabled": False},
        "installation": {"standalone": {
            "console": {"url": config["graviteeUrl"]},
            "api": {"url": config["graviteeUrl"] + "/management"},
        }},
    }


def compose_for_mode(template, mode):
    if mode not in (CONSOLE_AUTH_PASSWORD, CONSOLE_AUTH_ENTRA_OIDC):
        fail("Invalid console authentication mode.")
    runtime = copy.deepcopy(template)
    mounts = {
        "management-api": (
            "./private/gravitee-license.key:"
            "/opt/graviteeio-management-api/license/license.key:ro"
        ),
        "gateway": (
            "./private/gravitee-license.key:"
            "/opt/graviteeio-gateway/license/license.key:ro"
        ),
    }
    for service, mount in mounts.items():
        volumes = runtime["services"][service].setdefault("volumes", [])
        if any("gravitee-license.key" in str(volume) for volume in volumes):
            fail("The base Compose file must not mount a Gravitee license.")
        if mode == CONSOLE_AUTH_ENTRA_OIDC:
            volumes.append(mount)
    return runtime


def runtime_settings(config):
    settings = {
        "projectName": "agentharness",
        "networks": {key: "agentharness-" + key for key in ("control", "storage", "backend")},
        "volumes": {},
        "backendDataPath": "/var/lib/agentharness-docker/backend",
        "internalApiImage": "agentharness-internal-api:deployment",
        "workingDirectory": "/opt/agentharness",
        "dataRoot": "/var/lib/agentharness-docker",
        "systemdService": "agentharness-gravitee.service",
    }
    overrides = config.get("runtime", {})
    if not isinstance(overrides, dict) or set(overrides) - set(settings):
        fail("Invalid persistent-runtime configuration.")
    for key, value in overrides.items():
        if key in ("networks", "volumes"):
            if not isinstance(value, dict):
                fail("Invalid persistent-runtime aliases.")
            settings[key] = {**settings[key], **value}
        else:
            settings[key] = value
    identifier = r"[a-z0-9][a-z0-9_.-]{0,127}"
    if not isinstance(settings["projectName"], str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9_-]{0,63}", settings["projectName"]
    ):
        fail("Invalid persistent Compose project name.")
    if set(settings["networks"]) != {"control", "storage", "backend"} or any(
        not isinstance(value, str) or not re.fullmatch(identifier, value)
        for value in (*settings["networks"].values(), *settings["volumes"].values())
    ):
        fail("Invalid persistent Docker network or volume name.")
    for key, prefix in (("workingDirectory", "/opt/"), ("dataRoot", "/var/lib/"),
                        ("backendDataPath", "/var/lib/")):
        value = settings[key]
        if not isinstance(value, str) or not value.startswith(prefix) or not re.fullmatch(
            r"/[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_.-]+)+", value
        ) or any(part in (".", "..") for part in pathlib.PurePosixPath(value).parts):
            fail("Invalid persistent-runtime filesystem path.")
    if not settings["backendDataPath"].startswith(settings["dataRoot"] + "/"):
        fail("The backend data bind must remain on the configured persistent disk.")
    if not isinstance(settings["systemdService"], str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9-]{0,63}\.service", settings["systemdService"]
    ):
        fail("Invalid persistent service name.")
    if not isinstance(settings["internalApiImage"], str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9./:_@-]{0,255}", settings["internalApiImage"]
    ):
        fail("Invalid persistent backend image reference.")
    return settings


def compose_for_runtime(template, config):
    runtime = compose_for_mode(template, console_auth_mode(config))
    settings = runtime_settings(config)
    runtime["name"] = settings["projectName"]
    for key, name in settings["networks"].items():
        runtime["networks"][key]["name"] = name
    if set(settings["volumes"]) - set(runtime["volumes"]):
        fail("Unexpected persistent volume alias.")
    if config.get("runtime") and set(settings["volumes"]) != set(runtime["volumes"]):
        fail("Every existing persistent volume requires an explicit external alias.")
    for key, name in settings["volumes"].items():
        # External aliases fail closed if an existing data volume is missing.
        runtime["volumes"][key] = {"name": name, "external": True}
    backend = runtime["services"]["internal-api"]
    backend["image"] = settings["internalApiImage"]
    backend["volumes"] = [settings["backendDataPath"] + ":/app/data"]
    return runtime


def write_runtime_compose(config):
    template = json.loads(pathlib.Path("compose.json").read_text(encoding="utf-8-sig"))
    runtime = compose_for_runtime(template, config)
    path = pathlib.Path(COMPOSE_FILE)
    path.write_text(json.dumps(runtime, indent=2), encoding="utf-8")
    path.chmod(0o600)


def render(config, secrets):
    import bcrypt

    mongo_password = urllib.parse.quote(secrets["gravitee-mongodb-password"], safe="")
    mongo_uri = (
        "mongodb://gravitee:" + mongo_password
        + "@mongodb:27017/gravitee?authSource=admin&serverSelectionTimeoutMS=5000"
    )
    elastic = {
        "endpoints": ["http://elasticsearch:9200"],
        "security": {"username": "elastic", "password": secrets["gravitee-elasticsearch-password"]},
    }
    password_hash = bcrypt.hashpw(
        secrets["gravitee-demo-admin-password"].encode(), bcrypt.gensalt(rounds=12, prefix=b"2a")
    ).decode()
    management = management_configuration(config, secrets, mongo_uri, elastic, password_hash)
    gateway = {
        "management": {"type": "mongodb", "mongodb": {"uri": mongo_uri}},
        "ratelimit": {"type": "mongodb", "mongodb": {"uri": mongo_uri}},
        "reporters": {"elasticsearch": {"enabled": True, **elastic}},
        "services": {"core": {"http": {"enabled": False}}},
        "http": {"port": 8082},
    }
    write_private("management.yml", json.dumps(management))
    write_private("gateway.yml", json.dumps(gateway))
    write_private("mongodb-password", secrets["gravitee-mongodb-password"])
    write_elasticsearch_password(secrets["gravitee-elasticsearch-password"])
    elastic_health_password = secrets["gravitee-elasticsearch-password"].replace("\\", "\\\\").replace('"', '\\"')
    if "\r" in elastic_health_password or "\n" in elastic_health_password:
        fail("The stored Elasticsearch password must be a single-line secret.")
    write_private("elasticsearch-health.conf", 'user = "elastic:' + elastic_health_password + '"\n')
    license_path = pathlib.Path("private") / "gravitee-license.key"
    if console_auth_mode(config) == CONSOLE_AUTH_ENTRA_OIDC:
        write_private("gravitee-license.key", secrets["gravitee-license"])
    elif license_path.exists():
        license_path.unlink()
    public = urllib.parse.urlparse(config["graviteeUrl"])
    email = config["acmeEmail"]
    if not re.fullmatch(r"[A-Za-z0-9_.+@-]+", email) or "@" not in email:
        fail("Invalid ACME contact email.")
    pathlib.Path(".env").write_text(
        f"PUBLIC_HOST={public.hostname}\nPUBLIC_URL={config['graviteeUrl']}\nACME_EMAIL={email}\n",
        encoding="utf-8",
    )
    pathlib.Path(".env").chmod(0o600)
    write_runtime_compose(config)


def container_address(service, network):
    container = subprocess.check_output(
        ["docker", "compose", "--file", COMPOSE_FILE, "ps", "-q", service], text=True
    ).strip()
    if not container:
        fail("Required container is not running: " + service)
    inspected = json.loads(subprocess.check_output(["docker", "inspect", container], text=True))[0]
    address = inspected["NetworkSettings"]["Networks"][network]["IPAddress"]
    if not ipaddress.ip_address(address).is_private:
        fail("Refusing to send management credentials to a non-private container address.")
    if inspected["HostConfig"].get("PortBindings"):
        fail("A non-proxy service unexpectedly has host port bindings: " + service)
    return address


class Management:
    def __init__(self, address, password):
        self.base = "http://" + address + ":8083"
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(self.cookies), NoRedirect()
        )
        self.authorization = "Basic " + base64.b64encode(("demo-admin:" + password).encode()).decode()
        self.xsrf_token = None

    def call(self, method, path, body=None):
        if not path.startswith(ORG_PATH + "/"):
            fail("Refusing an out-of-scope management request.")
        headers = {
            "Authorization": self.authorization,
            "Accept": "application/json",
            "X-Requested-With": "XMLHttpRequest",
        }
        for cookie in self.cookies:
            if "xsrf" in cookie.name.lower() or "csrf" in cookie.name.lower():
                headers["X-Xsrf-Token"] = urllib.parse.unquote(cookie.value)
        if self.xsrf_token:
            headers["X-Xsrf-Token"] = self.xsrf_token
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base + path, method=method, headers=headers, data=data)
        try:
            with self.opener.open(request, timeout=60) as response:
                self.xsrf_token = response.headers.get("X-Xsrf-Token", self.xsrf_token)
                payload = response.read()
                return json.loads(payload) if payload else None
        except urllib.error.HTTPError as error:
            self.xsrf_token = error.headers.get("X-Xsrf-Token", self.xsrf_token)
            if error.code == 403 and "/configuration/identities" in path:
                fail("Console OIDC was refused. A valid license including apim-openid-connect-sso is required.")
            # Error payloads can contain echoed identity-provider configuration.
            fail(f"Gravitee management {method} failed (HTTP {error.code}); response content suppressed.")

    def wait(self):
        for attempt in range(120):
            try:
                self.call("GET", ENV_PATH + "/apis")
                return
            except (RuntimeError, urllib.error.URLError, TimeoutError):
                if attempt == 119:
                    fail("Management API did not become ready; inspect VM-local service logs.")
                time.sleep(5)


def entities(response):
    if isinstance(response, list):
        return response
    if isinstance(response, dict):
        for key in ("data", "content"):
            if isinstance(response.get(key), list):
                return response[key]
    fail("Unexpected Gravitee collection response.")


def find_named(response, name):
    matches = [item for item in entities(response) if item.get("name") == name]
    if len(matches) > 1:
        fail("Duplicate managed entities; refusing ambiguous mutation: " + name)
    return matches[0] if matches else None


def find_managed(response, name, config, id_key):
    items = entities(response)
    named = find_named(items, name)
    known_id = config.get("managedResourceIds", {}).get(id_key)
    if not known_id:
        return named
    matches = [item for item in items if item.get("id") == known_id]
    if len(matches) != 1 or (named and named["id"] != known_id):
        fail("The recorded managed entity is missing or has a foreign name collision.")
    return matches[0]


def verify_persistent_collections(before, after):
    for name, count in before.items():
        # Gravitee expires command-bus messages independently of deployment.
        if name != "commands" and after.get(name, -1) < count:
            fail("A persisted MongoDB collection lost documents: " + name)


def validation_step(name, status, rules):
    return {
        "name": name, "enabled": True, "policy": "policy-request-validation",
        "configuration": {"status": str(status), "rules": rules},
    }


def required_rule(expression, constraint, parameters=None):
    rule = {"input": expression, "isRequired": True, "constraint": {"type": constraint}}
    if parameters is not None:
        rule["constraint"]["parameters"] = parameters
    return rule


def contains_shape(actual, expected):
    if isinstance(expected, dict):
        if isinstance(actual, str):
            try:
                actual = json.loads(actual)
            except ValueError:
                return False
        return isinstance(actual, dict) and all(
            (key not in actual and value in (None, [], {}))
            or (key in actual and contains_shape(actual[key], value))
            for key, value in expected.items()
        )
    if isinstance(expected, list):
        if not expected and actual is None:
            return True
        return isinstance(actual, list) and len(actual) == len(expected) and all(
            contains_shape(value, wanted) for value, wanted in zip(actual, expected)
        )
    return actual == expected


def api_flows(config):
    claims = "#context.attributes['jwt.claims']"
    identity_rules = [
        required_rule("{" + claims + "['iss']}", "ENUM",
                      ["https://login.microsoftonline.com/" + config["tenantId"] + "/v2.0"]),
        required_rule("{" + claims + "['tid']}", "ENUM", [config["tenantId"]]),
        required_rule("{" + claims + "['aud']}", "ENUM", [config["internalApiClientId"]]),
        required_rule("{" + claims + "['azp']}", "ENUM", [config["harnessClientId"]]),
        required_rule("{" + claims + "['scp']}", "PATTERN", [r"(^|\S+\s+)*access_as_user(\s+\S+)*$"]),
        # JWT validates expiration; requiring exp also rejects non-expiring JWTs.
        required_rule("{" + claims + "['exp']}", "MIN", ["1"]),
    ]
    roles = claims + "['roles']"
    allowed = (
        "{" + roles + " != null && ("
        "(#request.method == 'GET' && #request.pathInfo matches '^/purchaseorders/?$' && ("
        + roles + ".contains('InternalApi.Reader') || " + roles + ".contains('InternalApi.Approver'))) || "
        "(#request.method == 'POST' && #request.pathInfo matches '^/purchaseorders/PO-[0-9]+/approve/?$' && "
        + roles + ".contains('InternalApi.Approver')))}"
    )
    return [{
        "name": "Tenant, audience, delegated scope, and fail-closed purchase-order authorization",
        "enabled": True,
        "path-operator": {"path": "/", "operator": "STARTS_WITH"},
        "methods": [],
        "pre": [
            validation_step("Validate configured-tenant delegated identity", 401, identity_rules),
            validation_step("Enforce roles and deny every unlisted method/path", 403,
                            [required_rule(allowed, "PATTERN", ["true"])]),
        ],
        "post": [],
    }]


def provision_identity_provider(client, config, secrets):
    path = ORG_PATH + "/configuration/identities"
    existing = find_named(client.call("GET", path), IDP_NAME)
    tenant_endpoint = "https://login.microsoftonline.com/" + config["tenantId"]
    body = {
        "name": IDP_NAME,
        "description": OWNER + " Tenant-specific Entra authentication; roles come from the ID token.",
        "type": "OIDC",
        "enabled": False,
        "emailRequired": False,
        "syncMappings": True,
        "configuration": {
            "clientId": config["graviteeClientId"],
            "clientSecret": secrets["gravitee-oidc-client-secret"],
            "tokenEndpoint": tenant_endpoint + "/oauth2/v2.0/token",
            "authorizeEndpoint": tenant_endpoint + "/oauth2/v2.0/authorize",
            "userInfoEndpoint": "https://graph.microsoft.com/oidc/userinfo",
            "userLogoutEndpoint": tenant_endpoint + "/oauth2/v2.0/logout",
            "scopes": ["openid", "profile", "email"],
            "color": "#0078d4",
        },
        "userProfileMapping": {"id": "sub", "firstname": "given_name", "lastname": "family_name", "email": "email"},
    }
    if existing:
        existing = client.call("GET", path + "/" + existing["id"])
        if OWNER not in existing.get("description", ""):
            fail("The matching identity provider is not owned by this automation.")
        provider_id = existing["id"]
    else:
        provider_id = client.call("POST", path, body)["id"]
    base_condition = (
        "#idToken != null && #jsonPath(#idToken, '$.tid') == '" + config["tenantId"]
        + "' && #jsonPath(#idToken, '$.aud') == '" + config["graviteeClientId"] + "'"
    )
    body["roleMappings"] = [{
        "condition": "{" + base_condition + " && #jsonPath(#idToken, '$.roles').contains('Gravitee.Administrator')}",
        "organizations": ["ADMIN"],
        "environments": {"DEFAULT": ["ADMIN"]},
    }, {
        "condition": "{" + base_condition + " && #jsonPath(#idToken, '$.roles').contains('Gravitee.User')}",
        "organizations": ["USER"],
        "environments": {"DEFAULT": ["USER"]},
    }]
    body["groupMappings"] = []
    client.call("PUT", path + "/" + provider_id, body)
    activations = client.call("GET", ORG_PATH + "/identities")
    activations = [entry for entry in entities(activations) if entry.get("identityProvider") != provider_id]
    activations.append({"identityProvider": provider_id})
    client.call("PUT", ORG_PATH + "/identities", activations)
    verified = client.call("GET", path + "/" + provider_id)
    mappings = {item["condition"]: item for item in verified.get("roleMappings", [])}
    if not verified.get("syncMappings") or len(mappings) != 2 or not all(
        contains_shape(mappings.get(item["condition"]), item) for item in body["roleMappings"]
    ):
        fail("Identity-provider role mappings were not persisted exactly.")
    activated = client.call("GET", ORG_PATH + "/identities")
    if not any(item.get("identityProvider") == provider_id for item in entities(activated)):
        fail("The OIDC identity provider was not activated for the console.")
    return provider_id


def provision_api(client, config):
    if config.get("ownershipMigration"):
        fail("Complete the recorded ownership migration before provisioning.")
    apis_path = ENV_PATH + "/apis"
    existing = find_managed(client.call("GET", apis_path), API_NAME, config, "apiId")
    description = OWNER + " Private synthetic orders. Authorization is performed only by Gravitee."
    if existing:
        api = client.call("GET", apis_path + "/" + existing["id"])
        if OWNER not in api.get("description", ""):
            fail("The matching API is not owned by this automation.")
        if api.get("state") == "STARTED":
            client.call("POST", apis_path + "/" + api["id"] + "?action=STOP")
    else:
        api = client.call("POST", apis_path, {
            "name": API_NAME, "version": "1.0", "description": description,
            "contextPath": "/gateway/internal", "endpoint": "http://internal-api:8080",
            "gravitee": "2.0.0", "visibility": "PRIVATE", "flows": [],
        })
    api_path = apis_path + "/" + api["id"]
    api = client.call("GET", api_path)
    proxy = api["proxy"]
    proxy["virtual_hosts"] = [{"path": "/gateway/internal"}]
    proxy["strip_context_path"] = True
    proxy["groups"] = [{
        "name": "default-group",
        "endpoints": [{"name": "private-synthetic-orders", "target": "http://internal-api:8080", "weight": 1}],
        "load_balancing": {"type": "ROUND_ROBIN"},
    }]
    update = {
        "name": API_NAME, "version": "1.0", "description": description, "visibility": "PRIVATE",
        "gravitee": "2.0.0", "proxy": proxy, "flows": api_flows(config),
        "flow_mode": "DEFAULT", "execution_mode": "v3", "labels": ["agentharness-agent-harness-owned"],
        "plans": api.get("plans", []),
    }
    client.call("PUT", api_path, update)
    plan_path = api_path + "/plans"
    plans = entities(client.call("GET", plan_path + "?status=STAGING,PUBLISHED,DEPRECATED,CLOSED"))
    plan = find_managed(plans, PLAN_NAME, config, "planId")
    jwt = {
        "signature": "RSA_RS256",
        "publicKeyResolver": "JWKS_URL",
        "resolverParameter": "https://login.microsoftonline.com/" + config["tenantId"] + "/discovery/v2.0/keys",
        "extractClaims": True,
        "clientIdClaim": "azp",
        "propagateAuthHeader": False,
    }
    plan_body = {
        "name": PLAN_NAME, "description": OWNER + " Signed Entra JWT; azp-bound harness subscription.",
        "security": "JWT", "securityDefinition": json.dumps(jwt),
        "validation": "AUTO", "type": "API", "status": "STAGING", "flows": [],
    }
    if plan:
        if OWNER not in plan.get("description", "") or plan.get("security") != "JWT":
            fail("Unexpected existing plan; refusing to weaken security.")
        if plan["status"] == "CLOSED":
            fail("The managed plan was closed; a deliberate plan migration is required.")
        plan_body["status"] = plan["status"]
        client.call("PUT", plan_path + "/" + plan["id"], plan_body)
    else:
        plan = client.call("POST", plan_path, plan_body)
    for other in plans:
        if other["id"] != plan["id"] and other["status"] in ("PUBLISHED", "DEPRECATED"):
            client.call("POST", plan_path + "/" + other["id"] + "/_close")
    if plan["status"] == "STAGING":
        client.call("POST", plan_path + "/" + plan["id"] + "/_publish")
    persisted_plan = client.call("GET", plan_path + "/" + plan["id"])
    if (
        persisted_plan.get("security") != "JWT"
        or persisted_plan.get("status") != "PUBLISHED"
        or not contains_shape(persisted_plan.get("securityDefinition"), jwt)
    ):
        fail("The signed, claim-extracting, azp-bound JWT plan was not persisted.")
    active_plans = [
        item for item in entities(client.call("GET", plan_path + "?status=PUBLISHED,DEPRECATED"))
        if item["status"] in ("PUBLISHED", "DEPRECATED")
    ]
    if len(active_plans) != 1 or active_plans[0]["id"] != plan["id"]:
        fail("An alternative active plan could bypass the managed JWT plan.")

    applications_path = ENV_PATH + "/applications"
    application = find_managed(
        client.call("GET", applications_path), APPLICATION_NAME, config, "applicationId"
    )
    application_body = {
        "name": APPLICATION_NAME, "description": OWNER + " Only this client's azp can subscribe.",
        "type": "SIMPLE", "settings": {"app": {"type": "WEB", "client_id": config["harnessClientId"]}},
    }
    if application:
        application = client.call("GET", applications_path + "/" + application["id"])
        if OWNER not in application.get("description", ""):
            fail("The matching application is not owned by this automation.")
        client.call("PUT", applications_path + "/" + application["id"], application_body)
    else:
        application = client.call("POST", applications_path, application_body)
    persisted_application = client.call("GET", applications_path + "/" + application["id"])
    if not contains_shape(persisted_application.get("settings"), application_body["settings"]):
        fail("The application's harness client ID was not persisted.")
    query = urllib.parse.urlencode({"application": application["id"], "plan": plan["id"]})
    subscriptions = entities(client.call("GET", api_path + "/subscriptions?" + query))
    accepted = [item for item in subscriptions if item.get("status") == "ACCEPTED"]
    if len(accepted) > 1:
        fail("Duplicate accepted harness subscriptions.")
    known_subscription = config.get("managedResourceIds", {}).get("subscriptionId")
    if known_subscription and (
        len(accepted) != 1 or accepted[0].get("id") != known_subscription
    ):
        fail("The recorded harness subscription is missing; refusing to replace it.")
    subscription = accepted[0] if accepted else client.call("POST", api_path + "/subscriptions?" + query, {})
    if subscription.get("status") != "ACCEPTED":
        fail("The harness JWT subscription was not accepted.")
    verified = client.call("GET", api_path)
    if not contains_shape(verified.get("flows"), update["flows"]) or not verified["proxy"].get("strip_context_path"):
        fail("The API's deny-by-default policies or context-path stripping were not persisted.")
    client.call("POST", api_path + "/deploy", {"deploymentLabel": "AgentHarness reproducible deployment"})
    client.call("POST", api_path + "?action=START")
    return api["id"], plan["id"], application["id"], subscription["id"]


def rebrand_owned_resources(client, config, owned, previous_marker, *, dry_run=False):
    """Adopt only recorded IDs; never discover ownership by a legacy display name."""
    if not isinstance(previous_marker, str) or not re.fullmatch(r"\[[a-z0-9-]+\]", previous_marker):
        fail("A valid recorded ownership marker is required.")
    ids = {key: owned.get(key) for key in OWNED_ID_KEYS}
    if any(not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9-]{1,128}", value)
           for value in ids.values()) or len(set(ids.values())) != len(ids):
        fail("All four distinct recorded managed IDs are required for migration.")
    recorded = config.get("managedResourceIds")
    if recorded is not None and recorded != ids:
        fail("The migration IDs do not match the recorded deployment.")
    scoped = {**config, "managedResourceIds": ids}
    api_path = ENV_PATH + "/apis/" + ids["apiId"]
    find_managed(client.call("GET", ENV_PATH + "/apis"), API_NAME, scoped, "apiId")
    api = client.call("GET", api_path)
    plans_path = api_path + "/plans"
    find_managed(client.call("GET", plans_path + "?status=STAGING,PUBLISHED,DEPRECATED,CLOSED"),
                 PLAN_NAME, scoped, "planId")
    plan = client.call("GET", plans_path + "/" + ids["planId"])
    applications_path = ENV_PATH + "/applications"
    find_managed(client.call("GET", applications_path), APPLICATION_NAME, scoped, "applicationId")
    application = client.call("GET", applications_path + "/" + ids["applicationId"])
    for entity in (api, plan, application):
        if not any(entity.get("description", "").startswith(marker + " ")
                   for marker in (previous_marker, OWNER)):
            fail("A recorded migration entity is not owned by this automation.")
    expected_jwt = {
        "signature": "RSA_RS256", "publicKeyResolver": "JWKS_URL",
        "resolverParameter": "https://login.microsoftonline.com/" + config["tenantId"] + "/discovery/v2.0/keys",
        "extractClaims": True, "clientIdClaim": "azp", "propagateAuthHeader": False,
    }
    if (plan.get("security") != "JWT" or plan.get("status") != "PUBLISHED"
            or not contains_shape(plan.get("securityDefinition"), expected_jwt)
            or not contains_shape(api.get("flows"), api_flows(config))
            or application.get("settings", {}).get("app", {}).get("client_id") != config["harnessClientId"]):
        fail("The recorded migration entities do not match the secured deployment.")
    query = urllib.parse.urlencode({"application": ids["applicationId"], "plan": ids["planId"]})
    subscriptions = entities(client.call("GET", api_path + "/subscriptions?" + query))
    accepted = [item for item in subscriptions if item.get("status") == "ACCEPTED"]
    if len(accepted) != 1 or accepted[0].get("id") != ids["subscriptionId"]:
        fail("The recorded accepted subscription was not found unambiguously.")
    subscription = accepted[0]
    for key, id_key in (("api", "apiId"), ("application", "applicationId"), ("plan", "planId")):
        value = subscription.get(key)
        if isinstance(value, dict):
            value = value.get("id")
        if value != ids[id_key]:
            fail("The recorded subscription does not belong to the recorded API, plan, and application.")
    if dry_run:
        return ids
    updates = []
    for entity, name, path in (
        (api, API_NAME, api_path), (plan, PLAN_NAME, plans_path + "/" + ids["planId"]),
        (application, APPLICATION_NAME, applications_path + "/" + ids["applicationId"]),
    ):
        body = copy.deepcopy(entity)
        body["name"] = name
        body["description"] = OWNER + entity["description"][len(
            OWNER if entity["description"].startswith(OWNER + " ") else previous_marker
        ):]
        if entity is api:
            labels = [label for label in entity.get("labels", [])
                      if label not in (previous_marker[1:-1], OWNER[1:-1])]
            body["labels"] = labels + [OWNER[1:-1]]
        if any(body.get(key) != entity.get(key) for key in ("name", "description", "labels")):
            for key in ("id", "owner", "created_at", "updated_at", "deployed_at", "state",
                        "context_path", "environmentId", "entrypoints", "originContext"):
                body.pop(key, None)
            updates.append((path, body))
    if not updates:
        return ids
    started = api.get("state") == "STARTED"
    if started:
        client.call("POST", api_path + "?action=STOP")
    for path, body in updates:
        client.call("PUT", path, body)
    verified_api = client.call("GET", api_path)
    verified_plan = client.call("GET", plans_path + "/" + ids["planId"])
    verified_application = client.call("GET", applications_path + "/" + ids["applicationId"])
    for before, after, keys in (
        (api, verified_api, ("proxy", "flows", "gravitee", "flow_mode", "execution_mode", "visibility")),
        (plan, verified_plan, ("security", "securityDefinition", "status", "validation", "flows")),
        (application, verified_application, ("settings", "type", "api_key_mode", "status")),
    ):
        if any(after.get(key) != before.get(key) for key in keys):
            fail("Brand migration changed persisted security settings; the owned API remains stopped.")
    for entity, name in ((verified_api, API_NAME), (verified_plan, PLAN_NAME),
                         (verified_application, APPLICATION_NAME)):
        if entity.get("name") != name or not entity.get("description", "").startswith(OWNER + " "):
            fail("The owned display name and ownership marker were not persisted.")
    verified_subscriptions = entities(client.call("GET", api_path + "/subscriptions?" + query))
    if not any(item.get("id") == ids["subscriptionId"] and item.get("status") == "ACCEPTED"
               for item in verified_subscriptions):
        fail("Brand migration did not preserve the accepted subscription.")
    client.call("POST", api_path + "/deploy", {"deploymentLabel": "AgentHarness brand migration"})
    if started:
        client.call("POST", api_path + "?action=START")
    return ids


def provision_resources(client, config, secrets):
    mode = console_auth_mode(config)
    provider_id = None
    oidc_status = "not-accessed"
    if mode == CONSOLE_AUTH_ENTRA_OIDC:
        provider_id = provision_identity_provider(client, config, secrets)
        oidc_status = "configured"
    # Community password mode intentionally leaves every existing identity
    # provider and activation untouched instead of calling licensed endpoints.
    api_id, plan_id, application_id, subscription_id = provision_api(client, config)
    return {
        "consoleAuthMode": mode,
        "consoleUsername": "demo-admin",
        "consoleOidcStatus": oidc_status,
        "identityProviderId": provider_id,
        "apiId": api_id,
        "planId": plan_id,
        "applicationId": application_id,
        "subscriptionId": subscription_id,
        "gatewayUrl": config["graviteeUrl"] + "/gateway/internal",
    }


def private_smoke(config):
    networks = runtime_settings(config)["networks"]
    backend = container_address("internal-api", networks["backend"])
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open("http://" + backend + ":8080/healthz", timeout=20) as response:
        if response.status != 200:
            fail("The private backend is unhealthy.")
    with opener.open("http://" + backend + ":8080/purchaseorders", timeout=20) as response:
        orders = json.load(response).get("orders", [])
        if not {"PO-1001", "PO-1002"}.issubset({order.get("id") for order in orders}):
            fail("The private backend could not read the persisted synthetic purchase orders.")
    gateway = container_address("gateway", networks["control"])
    for service, network in (("mongodb", networks["storage"]), ("elasticsearch", networks["storage"])):
        container_address(service, network)
    target = "http://" + gateway + ":8082/gateway/internal/purchaseorders"
    for headers in ({}, {"Authorization": "Bearer deliberately.invalid.token"}):
        for attempt in range(60):
            try:
                request = urllib.request.Request(target, headers=headers)
                with opener.open(request, timeout=15):
                    fail("The gateway accepted an unauthenticated or invalidly signed request.")
            except urllib.error.HTTPError as error:
                if error.code in (401, 403):
                    break
                if error.code != 404 or attempt == 59:
                    fail("The configured gateway did not produce an authentication denial.")
                time.sleep(3)
            except (urllib.error.URLError, TimeoutError):
                if attempt == 59:
                    fail("The gateway did not become responsive.")
                time.sleep(3)


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("render", "provision", "rebrand", "smoke"):
        fail("Usage: provision.py render|provision|rebrand|smoke")
    config = read_config()
    if sys.argv[1] == "smoke":
        private_smoke(config)
        return
    secrets = fetch_secrets(config)
    if sys.argv[1] == "render":
        render(config, secrets)
        return
    client = Management(
        container_address("management-api", runtime_settings(config)["networks"]["control"]),
        secrets["gravitee-demo-admin-password"],
    )
    client.wait()
    if sys.argv[1] == "rebrand":
        migration = config.get("ownershipMigration", {})
        provisioned = json.loads(pathlib.Path("provisioned.json").read_text(encoding="utf-8-sig"))
        ids = rebrand_owned_resources(client, config, provisioned, migration.get("previousMarker", OWNER))
        private_smoke(config)
        config["managedResourceIds"] = ids
        config.pop("ownershipMigration", None)
        provisioned["gatewayUrl"] = config["graviteeUrl"] + "/gateway/internal"
        pathlib.Path("public.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
        pathlib.Path("provisioned.json").write_text(json.dumps(provisioned, indent=2), encoding="utf-8")
        print("Verified owned IDs, unchanged security, persisted subscription, and AgentHarness display names.")
        return
    provisioned = provision_resources(client, config, secrets)
    private_smoke(config)
    pathlib.Path("provisioned.json").write_text(json.dumps(provisioned, indent=2), encoding="utf-8")
    if provisioned["consoleAuthMode"] == CONSOLE_AUTH_ENTRA_OIDC:
        console_status = "owned OIDC provider and bcrypt-backed demo administrator"
    else:
        console_status = (
            "bcrypt-backed demo administrator; licensed console OIDC configuration was left untouched"
        )
    print(
        "Verified " + console_status
        + ", azp-bound JWT subscription, private backend, and fail-closed gateway."
    )


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
    except Exception:
        # Even dependency or HTTP exceptions must not echo credential-bearing values.
        print("Gravitee bootstrap failed. Inspect root-only VM logs and identity/license/RBAC prerequisites.", file=sys.stderr)
        sys.exit(1)
