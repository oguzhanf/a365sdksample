# AgentHarness sample

A reusable .NET sample for integrating a custom agent runtime with **Microsoft Agent 365**. It combines an authenticated web workbench, Microsoft Entra application roles, Azure OpenAI, a Gravitee API authorization lab, and Microsoft Purview policy evaluation.

This is a **sample project**, not a production reference architecture. Configure your own tenant, applications, resources, permissions, and policies, then validate each integration against its documented prerequisites.

The workbench adapts four pinned Microsoft .NET samples: Agent Framework, Semantic Kernel, an autonomous GitHub digest, and Windows 365 computer use. The adapters share one administrative shell; they do not deploy the upstream web applications unchanged.

## Four integration capabilities

| Capability | Sample integration | Customer prerequisites |
| --- | --- | --- |
| **Identity** | Entra agent identity blueprints, agent identities, and custom-owned Agent 365 registry records | Tenant support, appropriate Graph consent, and authorized registration |
| **Observability** | Microsoft OpenTelemetry, Azure Monitor, and optional Agent 365 export | Exporter configuration and independently observed destination telemetry |
| **Tooling** | Governed Work IQ MCP registration for Agent Framework and Semantic Kernel | An authenticated agent channel, permitted servers, and delegated consent |
| **Notifications** | Agent 365 email and document-comment handlers | A provisioned agent user/mailbox, published endpoint, and supported tenant features |

Observability uses the separate **Microsoft OpenTelemetry** distribution, not the deprecated Agent 365 observability SDK. Agent user and notification availability can depend on preview access and licensing.

## Register → Extend → Validate → Operate

1. **Register:** create and read back the blueprint, agent identity, and registry relationship.
2. **Extend:** select capabilities and configure hosting identity, consent, channels, and policy prerequisites.
3. **Validate:** check identity relationships, run a protected turn, and inspect actual tool, policy, telemetry, and notification evidence separately.
4. **Operate:** review runtime evidence, manage opt-in autonomous schedules, and explicitly enable or disable registered identities.

The UI reports per-agent configuration, observations, and blockers from the backend. A portal link or local trace ID is not proof of downstream service operation.

## Prerequisites

- The .NET SDK selected by `global.json`, PowerShell 7.2 or later, and Git. The frontend is vanilla JavaScript; npm is not required.
- A customer Microsoft Entra tenant, application registrations, approved Graph permissions, and users assigned `AgentHarnessUsers` or `AgentHarnessAdministrators`.
- For model execution: an Azure OpenAI deployment and the managed identity/RBAC configuration required by the runtime. No model API-key fallback is provided.
- For deployment: Azure CLI, an explicitly selected subscription, resource permissions, quota, and cost approval.
- Capability-specific prerequisites: Work IQ consent/channel configuration; notification user/mailbox provisioning; or Windows 365 for Agents access, a compatible computer-use model, and an approved demonstration desktop.
- For protected execution: applicable Purview licensing, consent, and an individual-app inline policy. See [the customer governance runbook](docs/GOVERNANCE.md).

## Customer configuration

Keep environment values in ignored `src\AgentHarness\appsettings.Local.json`, environment variables, or an approved secret store. Bootstrap/deployment state belongs in ignored `infra\entra-state.json`; it is not a secret store. Do not commit credentials, tenant/subscription/application identifiers, resource addresses, or runtime evidence.

| Configuration | Supply for your environment |
| --- | --- |
| `AzureAd` | Tenant ID, harness client ID, and a securely supplied OIDC credential; register the chosen host's `/signin-oidc` callback |
| `Harness` | The same tenant/client IDs, enterprise application object IDs, tenant display name, and optional Azure/gateway resource settings |
| `Bootstrap` | The authorized bootstrap administrator object ID |
| `AzureOpenAI` | Resource endpoint, model deployment, and optional computer-use deployment |
| `Purview` | Keep `Enabled=true` and `RequireInlinePolicy=true`; configure actual app-scoped policies |
| `Agent365`, `AgentChannels`, `TokenValidation` | Approved exporter/channel settings and explicit registered audiences; enable only after prerequisites exist |
| `Data` | A writable persistent `Path` for runtime SQLite state |

For example, replace these placeholders before use:

```powershell
$env:AzureAd__TenantId = '<customer-tenant-id>'
$env:AzureAd__ClientId = '<harness-client-id>'
$env:Harness__TenantId = $env:AzureAd__TenantId
$env:Harness__ClientId = $env:AzureAd__ClientId
```

The application is single-tenant. Administrator access comes from application-role assignments, not an email address. B2B guests additionally require explicit object-ID approval and direct assignments; privileged guest access has a separate approval list. Do not relax tenant validation or Conditional Access to make a demonstration work.

## Restore, build, test, and run

Run from the repository root:

```powershell
.\tools\Get-MicrosoftSamples.ps1
dotnet restore .\AgentHarness.sln
dotnet build .\AgentHarness.sln --no-restore
dotnet test .\AgentHarness.sln --no-build

$env:Data__Path = Join-Path (Get-Location) 'data'
dotnet run --project .\src\AgentHarness --no-build --no-launch-profile -- --urls http://127.0.0.1:5178
```

Without customer identity configuration, the local app presents setup/sign-in guidance; it does not bypass authentication. Interactive sign-in needs a matching registered redirect URI and a credential. Model, policy, channel, and gateway operations require their external services even when the local host responds.

## Azure, Gravitee, and Purview

- Follow [the deployment guide](infra/OPERATIONS.md) for customer bootstrap and explicit-subscription model discovery, planning, and application. Start with `.\infra\Deploy.ps1 -Mode Validate`; review changes and costs before any cloud write.
- The infrastructure is a single-instance demonstration topology: App Service, managed identities, Key Vault, Azure OpenAI, monitoring, and a persistent Gravitee VM. Add production availability, network, backup, lifecycle, and security controls before adapting it for production.
- Gravitee is the API ingress. Keep the synthetic purchase-order backend and its database/search dependencies private. Gateway users authenticate with Entra JWTs; console password authentication is separate. Optional console Entra SSO requires the appropriate Gravitee license.
- Purview setup and runtime enforcement are separate from Azure deployment. Keep inline evaluation fail-closed, use only approved synthetic content, and validate an actual policy block before claiming protection. Audit, collection, billing, and downstream compliance policies each require their own authorization and evidence.
- Windows 365 screenshot image bytes are outside this sample's text-only DLP classification. Use an approved desktop and separately assess image/device governance. A registered agent does not substitute for delegated workload authorization.

## Official sources and licensing

`external\sources.json` pins [Microsoft Agent365-Samples](https://github.com/microsoft/Agent365-Samples) to commit `44eeeea2572a6600f69c4cd996cbf3a025637743`. The downloaded source retains its MIT license at `external\Agent365-Samples\LICENSE.md`; package versions are recorded in the project and lock file.

- [Microsoft Agent 365 SDK overview](https://learn.microsoft.com/en-us/microsoft-agent-365/developer/agent-365-sdk) and [.NET SDK](https://github.com/microsoft/Agent365-dotnet)
- [Microsoft 365 Agents SDK for .NET](https://github.com/microsoft/Agents-for-net) and [Agent 365 developer tools](https://github.com/microsoft/Agent365-devTools)
- [Microsoft Agent Framework](https://github.com/microsoft/agent-framework) and [Semantic Kernel](https://github.com/microsoft/semantic-kernel)
- [Microsoft Purview API integration](https://learn.microsoft.com/en-us/purview/developer/use-the-api)
