# Customer deployment and operations

Use this guide to configure and deploy the sample in your own environment.
Supply your own tenant, administrator, subscription, names, certificate contact, and URLs.
Replace every `<placeholder>` below before running a command.

Run commands from the sample checkout with PowerShell 7.2+. The deployment
scripts use an already authorized Azure CLI user session. They never call
`az login`, select a default subscription, or change the CLI's active account.

## Prerequisites and authorization boundary

* The .NET SDK selected by `global.json`, restored application dependencies,
  Azure CLI with Bicep, Python, Bash, and `ssh-keygen` are needed for the
  corresponding build and validation steps. Existing Azure CLI Python and
  Git for Windows Bash installations are reused where available.
* Choose an enabled subscription in the configured tenant. The cached user must
  match the explicitly configured administrator object ID and UPN. Token requests
  include that subscription and tenant; cached or explicitly supplied Graph
  tokens must match the configured tenant, administrator, audience, and expiry.
  Graph `/me` must verify the administrator before other requests are allowed.
* Initialization requires permission to create or update the sample's three
  single-tenant app registrations, create service principals, grant the requested
  Graph permissions and delegated API consent, and assign application roles.
  Deployment requires subscription deployment, resource creation, role assignment,
  provider registration, and Defender AI pricing permissions.
* Authentication, directory/application roles, and explicit guest allowlists
  remain enforced. Configuring a display name, email, or URL does not grant access.
  Purview inline protection remains required; incomplete prerequisites must fail
  closed rather than bypass policy evaluation.
* Confirm regional capacity, model availability/quota, registry access, ACME
  reachability, and any Gravitee license entitlement in your own environment.

## Initialize customer identity

Both planned URLs must be distinct HTTPS origins without a path, query, fragment,
or embedded credentials. For the supplied Azure deployment, use your planned
App Service hostname and Azure gateway public DNS hostname.
`TenantDomain` is the tenant's initial `*.onmicrosoft.com` domain, not an email
alias or an arbitrary custom domain.

```powershell
$identity = @{
    TenantId = '<tenant-guid>'
    SubscriptionId = '<subscription-guid>'
    TenantDomain = '<initial-tenant-domain>.onmicrosoft.com'
    AdministratorObjectId = '<administrator-object-guid>'
    AdministratorUpn = '<administrator-upn>'
    TenantName = 'Your organization'
    HarnessUrl = 'https://<unique-webapp-name>.azurewebsites.net'
    GraviteeUrl = 'https://<unique-gateway-label>.<azure-region>.cloudapp.azure.com'
}
.\infra\Initialize-Entra.ps1 @identity
```

`-ApplicationName` optionally changes the app-registration display-name prefix;
its default is `AgentHarness`. Internal API and Gravitee registrations use that
prefix. Duplicate names, an existing multi-tenant registration, or missing expected
application roles are refused. Existing redirect URIs are preserved. Initial roles
are assigned only to the verified administrator, never to a fixed email address.

Initialization writes `infra\entra-state.json`, which is ignored by Git.
An optional `-OutputPath` must also be ignored and inside the checkout. An existing
file belonging to another tenant, subscription, administrator, or app prefix is
not overwritten. No client secret is written to this state file.

### Local state contract

Identity state uses these case-preserving property names:

| Properties | Meaning |
| --- | --- |
| `TenantId`, `TenantName`, `TenantDomain`, `SubscriptionId` | Customer tenant and explicitly selected subscription |
| `AdministratorObjectId`, `AdministratorUpn`, `ApplicationName` | Verified bootstrap administrator and application prefix |
| `ClientId`, `ApplicationObjectId`, `ServicePrincipalId` | Harness application and enterprise application |
| `InternalApiClientId`, `InternalApiApplicationObjectId`, `InternalApiServicePrincipalId` | Internal API identities |
| `GraviteeClientId`, `GraviteeApplicationObjectId`, `GraviteeServicePrincipalId` | Gravitee identities |
| `PlannedHarnessUrl`, `PlannedGraviteeUrl` | Customer-selected HTTPS origins |
| `HarnessUrl`, `GraviteeUrl` | Compatibility aliases for the planned origins |

Granted/unavailable Graph permissions and a configuration timestamp are also
recorded locally. Treat all generated identity, deployment, guest-approval,
diagnostic, and policy evidence as customer-specific operational data. Keep it
outside source control and published sample archives.

Deployment state defaults to `artifacts\deployment-state.json`. It uses camelCase
ARM properties, including `tenantId`, `subscriptionId`, `administratorObjectId`,
`clientId`, `servicePrincipalId`, the corresponding internal API/Gravitee IDs,
`plannedHarnessUrl`, `plannedGraviteeUrl`, `resourceGroup`, actual URLs/resource IDs,
and component readiness. A saved state must match the selected tenant,
subscription, and application before it can be used.

## Offline validation and packaging

```powershell
.\infra\Validate.ps1
# Equivalent entry point:
.\infra\Deploy.ps1 -Mode Validate

# Local publish/package only; no Azure writes:
.\infra\Package.ps1
```

Validation parses PowerShell/Python/Bash, compiles Bicep, checks digest pins and
private container networking, runs mocked customer-configuration and Gravitee
provisioning regressions, and checks public-only SSH-key encoding. Its local
report is `artifacts\infra-validation\validation.json`; this is not evidence of
deployment, TLS issuance, successful user sign-in, or policy readiness.

**Packages contain no agent catalog seed by default.** They do not automatically
read an operator's ignored catalog or SQLite data. To intentionally distribute a
reviewed metadata seed, pass the same explicit option to Package or Deploy:

```powershell
.\infra\Package.ps1 -HarnessOnly `
    -AgentCatalogPath '.\private-inputs\reviewed-sample-agents.json'
```

The selected file must exist and parse as JSON. Review it for customer identifiers,
resource URLs, and sensitive metadata before opting in. It becomes
`seed\agents.json` in the ZIP. Local configuration/state, `.env`, raw SQLite
databases, and WAL/SHM files are refused in publish output.

## Select models and preview new infrastructure

```powershell
$subscriptionId = $identity.SubscriptionId
.\infra\Deploy.ps1 -Mode Models -SubscriptionId $subscriptionId -Location eastus

$selection = @{
    SubscriptionId = $subscriptionId
    ResourceGroupName = 'rg-agentharness-demo'
    Location = 'eastus'
    ModelName = '<name-from-current-regional-catalog>'
    ModelVersion = '<exact-version-from-current-regional-catalog>'
    ModelSku = 'GlobalStandard'
    ModelCapacity = 10
    AcmeEmail = '<certificate-contact-email>'
    CreateNewInfrastructure = $true
}
.\infra\Deploy.ps1 @selection -Mode Plan
```

`Validate`, `Models`, `Plan`, and `Apply` are the implemented deployment modes.
Modes other than Validate require `-SubscriptionId` matching identity state.
`-EntraStatePath` selects another initialized identity file.

For new infrastructure, `-HarnessName` and `-GraviteeDnsLabel` can be supplied
explicitly or inferred from the initialized Azure hostnames.
Explicit names and the gateway region must still match those initialized origins;
reinitialize the customer configuration before changing them.
`-ResourceGroupName` defaults to the generic `rg-agentharness-demo`;
`-VmName` defaults to `agentharness-gravitee`. None selects an existing customer's
resource implicitly. `-AppServiceLocation` and `-GatewayLocation` independently
override hosting regions; the gateway region can also be inferred from its planned
hostname. No fixed model/version is assumed available.

Plan performs subscription what-if and writes only local generated parameters
and compiled templates under `artifacts`. It does not create resources, secrets,
consent, or pricing changes. The selected model's exact version, SKU, retirement,
and chat capability are checked against the regional catalog.

## Apply a new environment

Choose **one** initial deployment shape. Full deployment includes the private
Gravitee/backend stack:

```powershell
.\infra\Deploy.ps1 @selection -Mode Apply `
    -ConsoleAuthMode password -AcknowledgeSubscriptionDefenderAI
```

Alternatively, create only the persistent harness and its vault/AI/telemetry
dependencies:

```powershell
.\infra\Deploy.ps1 -SubscriptionId $subscriptionId -Mode Apply `
    -CreateNewInfrastructure -HarnessOnly -ResourceGroupName 'rg-agentharness-demo' `
    -AcknowledgeSubscriptionDefenderAI
```

HarnessOnly does not require gateway compute, a certificate contact, or a
Gravitee license. It attempts to publish and verify the sign-in shell before
provisioning a model. A model without verified capacity remains Pending, and
the gateway remains Pending. Purview is not bypassed to make model calls succeed.

New infrastructure requires `-CreateNewInfrastructure`; Apply additionally requires
`-AcknowledgeSubscriptionDefenderAI`. Billable resources can include B1 App Service,
VM/disks/public IP, private endpoints/DNS/peering, storage, Key Vault, telemetry,
Azure OpenAI capacity/usage, and Defender AI. The Defender `AI` plan and the
harness managed identity's Security Reader assignment have **subscription scope**.
Enabling that plan can affect other AI resources in the selected subscription.
The log ingestion cap is not a guaranteed spending limit.

The default `-ConsoleAuthMode password` uses the strong random Key Vault-backed
`demo-admin` credential and does not require a Gravitee license. API authentication
still uses Entra JWTs, with authorization enforced by Gravitee. Optional
`-ConsoleAuthMode entra-oidc` requires a valid license including
`apim-openid-connect-sso` and either `-GraviteeLicensePath` pointing to an existing
private license file or `-UseStoredGraviteeLicense` for a vault secret already
provisioned by the customer. Console OIDC uses the public console root callback.

`-AdminSshPublicKeyPath` optionally supplies an RSA public key. Otherwise only a
public key is generated; its private key is discarded. Neither option opens SSH
to the Internet. VM bootstrap uses ARM Run Command.

### Publishing a saved harness

Saved-state operation only republishes the existing harness and preserves its
models, vault, networks, and other shared infrastructure:

```powershell
.\infra\Deploy.ps1 -SubscriptionId $subscriptionId -Mode Plan -HarnessOnly
.\infra\Deploy.ps1 -SubscriptionId $subscriptionId -Mode Apply -HarnessOnly
```

Do not pass `-CreateNewInfrastructure` for saved state. Explicit model changes,
site renames, gateway expansion/reprovisioning, and migrations are not implemented
by this saved-state path; it refuses them rather than creating replacements.
`-SkipHarnessPublish` checks the saved target without publishing.
Use `-OutputPath` to select another ignored deployment-state file.

## Security and persistence

* Key Vault public networking stays disabled. App Service uses VNet integration,
  a private endpoint, and private DNS; the gateway VNet is peered and linked when
  deployed. The verified administrator writes secrets through the scoped ARM
  API; managed identities retrieve their values over the private vault path.
* OIDC secrets and strong cryptographic random passwords go directly to Key
  Vault. App Service receives a Key Vault reference, not a plaintext secret.
  New Entra secrets expire after 180 days and are renewed when fewer than 30 days
  remain. Failed secret storage removes the newly created credential.
* Azure OpenAI local API-key authentication is disabled. Managed identity and
  scoped roles authorize model access. Microsoft platform application/role GUIDs,
  official image digests, and the request-validation plugin checksum are public
  constants, not customer identity values.
* Only Caddy publishes ports 80/443. HTTPS is required externally; Caddy persists
  trusted TLS certificates and advertises HTTP/1.1. The NSG denies every other
  inbound port. MongoDB/Elasticsearch have passwords and no host bindings.
  The intentionally unauthenticated synthetic backend is attached only to the
  gateway's isolated internal network.
* Entra authenticates and Gravitee authorizes. JWT validation requires the
  configured tenant issuer/JWKS, signature, expiry, internal API audience,
  harness `azp`, delegated `access_as_user` scope, and application roles.
  Reader or Approver permits GET purchase orders; only Approver permits synthetic
  approvals. Every other method/path is denied. Alternative active plans are
  closed, and bearer tokens are not forwarded to the backend.
* Optional console SSO maps only `Gravitee.Administrator` and `Gravitee.User`
  ID-token roles with tenant/audience guards. The memory-provider administrator
  has a BCrypt-backed random credential; default `admin/admin` is not configured.
* Ownership markers, recorded IDs, collision checks, and read-back verification
  prevent ambiguous Gravitee mutation. The owned API stays stopped on failed
  provisioning. Do not run overlapping Apply operations.
* App Service stores SQLite and DataProtection data persistently. The VM's
  attached disk persists container data, synthetic orders, and certificates.
  A systemd unit restarts the stack when the VM boots. This single-instance
  sample is not HA and does not configure a backup/DR or spending-control service.

## Verification and operations

```powershell
.\infra\Smoke.ps1 -SubscriptionId $subscriptionId
# For a HarnessOnly deployment:
.\infra\Smoke.ps1 -SubscriptionId $subscriptionId -HarnessOnly
```

Smoke uses the initialized identity file and saved deployment, verifies HTTPS,
anonymous denials, tenant/client/callback redirects, Key Vault references,
private-vault/VNet configuration, managed identity roles, and Defender read-back.
`-StatePath`, `-EntraStatePath`, and `-EvidencePath` select alternate local paths.
Evidence defaults to ignored `artifacts\smoke-results.json`. A redirect is not
proof that a real user completed sign-in.

For delegated authorization tests, acquire real tokens through the authorized
interactive sign-in flow and pass SecureString variables, never literal tokens:

```powershell
.\infra\Smoke.ps1 -SubscriptionId $subscriptionId `
    -ReaderAccessToken $readerSecureToken `
    -ApproverAccessToken $approverSecureToken `
    -NoRoleAccessToken $noRoleSecureToken
```

Optional negative cases are `-ExpiredAccessToken`, `-WrongAudienceAccessToken`,
`-WrongTenantAccessToken`, and `-OtherClientAccessToken`. Missing inputs remain
not tested. The Approver case intentionally approves synthetic `PO-1001`.
Never invent tokens, weaken TLS, enable ROPC, or add unapproved redirects.

Retrieve the Gravitee password privately through the authenticated harness
administrator UI. Do not print it, save it in source, or put it in command-line
arguments. Do not print secret-bearing Compose configuration or private render
files, or enable token/request-body logging. Managed Run Command output is
suppressed by the deployment orchestration.

If a customer-approved operation stops a VM, its boot service cannot keep the
site available while deallocated. Resolve availability policy with the resource
owner; target only the resource IDs in that customer's saved state. Back up
SQLite consistently rather than copying a live WAL database, and use an approved
VM data-disk backup process. Remove superseded credentials only after successful
Key Vault refresh and sign-in verification. Channels and the Agent365 exporter
remain disabled until their actual registration and credential prerequisites
are configured.
