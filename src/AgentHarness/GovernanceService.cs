// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

extern alias ObservabilityIdentity;

using System.Net.Http.Headers;
using System.Text.Json.Nodes;
using Azure.Core;
using Microsoft.Extensions.Options;
using AzureCliCredential = ObservabilityIdentity::Azure.Identity.AzureCliCredential;
using AzureCliCredentialOptions = ObservabilityIdentity::Azure.Identity.AzureCliCredentialOptions;
using ManagedIdentityCredential = ObservabilityIdentity::Azure.Identity.ManagedIdentityCredential;

namespace AgentHarness;

public sealed record PortalLink(string Name, string Url, string Description, string Category);

public sealed class GovernanceService(
    IGraphClient graph, IOptions<HarnessOptions> options, IConfiguration configuration,
    HarnessStore store, IHttpClientFactory factory)
{
    private readonly HarnessOptions _settings = options.Value;

    public PortalLink[] Portals()
    {
        var tenant = _settings.TenantId;
        var resourceGroup = string.IsNullOrWhiteSpace(_settings.SubscriptionId) ? "https://portal.azure.com/" :
            $"https://portal.azure.com/#@{tenant}/resource/subscriptions/{_settings.SubscriptionId}/resourceGroups/{_settings.ResourceGroup}/overview";
        var entries = new List<PortalLink>
        {
            new("Agent 365 inventory", "https://admin.microsoft.com/", "Agents > All agents > Registry. Inspect catalog visibility, ownership, instances, deployment, and access.", "Agent 365"),
            new("Agent 365 tools and governance", "https://admin.microsoft.com/", "Agents > Tools and tenant settings. Govern Work IQ MCP servers and tool access.", "Agent 365"),
            new("Harness enterprise application", $"https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/{_settings.ServicePrincipalId}/appId/{_settings.ClientId}", "Users and groups, application roles, sign-in logs, consent, and assignment requirements.", "Identity"),
            new("Entra agent identities", "https://entra.microsoft.com/", "Entra ID > Agents > Agent identities and Agent blueprints. Inspect sponsors and lifecycle controls.", "Identity"),
            new("Entra Conditional Access", "https://entra.microsoft.com/", "Protection > Conditional Access. Apply tenant-approved user and agent access policies.", "Identity"),
            new("Defender XDR incidents", "https://security.microsoft.com/incidents", "Investigate correlated AI, identity, and endpoint incidents. Portal access does not prove incident ingestion.", "Security"),
            new("Defender AI assets", "https://security.microsoft.com/", "Assets > Cloud > AI. Inspect discovered AI services, agents, posture, and alerts.", "Security"),
            new("Defender for Cloud", "https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/overview", "Environment settings > AI services; Data & AI security and runtime threat protection.", "Security"),
            new("Purview DSPM for AI", "https://purview.microsoft.com/", "Data Security Posture Management > AI: onboarding, collection policies, interaction activity, and risk.", "Data governance"),
            new("Purview Data Loss Prevention", "https://purview.microsoft.com/", "Solutions > Data Loss Prevention. This custom Entra app requires an app-scoped policy; use the supplied PowerShell setup rather than assuming a generic M365 DLP rule applies.", "Data governance"),
            new("Purview Audit", "https://purview.microsoft.com/", "Solutions > Audit. Correlate actual protected interactions with the demo's trace and audit identifiers.", "Data governance"),
            new("Purview eDiscovery and compliance", "https://purview.microsoft.com/", "Solutions > eDiscovery, Insider Risk Management, Communication Compliance, and Data Lifecycle Management. Each needs appropriate roles, licensing, and onboarding.", "Data governance"),
            new("Azure demo resource group", resourceGroup, "Persistent hosting, managed identities, Key Vault, Azure OpenAI, and monitoring.", "Azure"),
            new("Azure OpenAI / Microsoft Foundry", "https://ai.azure.com/", "Inspect the Azure OpenAI model deployment, content filters, and model access.", "Azure"),
            new("Application Insights", resourceGroup, "Open the Application Insights resource and search the trace ID returned by a real agent run.", "Observability"),
            new("Intune", "https://intune.microsoft.com/", "Inspect device and Windows 365 compliance. The harness does not claim that a portal link onboards a device.", "Operations"),
            new("Windows 365", "https://intune.microsoft.com/", "Devices > Windows 365. Verify Cloud PC and Windows 365 for Agents availability before running computer use.", "Operations"),
            new("Power Platform administration", "https://admin.powerplatform.microsoft.com/", "Inspect the tenant environment, available connectors, and applicable environment controls.", "Operations")
        };
        if (Uri.TryCreate(_settings.GraviteeUrl, UriKind.Absolute, out var gateway) && gateway.Scheme == "https")
            entries.Insert(0, new("Gravitee management console", gateway.AbsoluteUri,
                _settings.GraviteeConsoleAuthMode == "entra-oidc"
                    ? "Use Entra console SSO or the protected demo-admin credential. Manage JWT plans, subscriptions, authorization policies, analytics, and the private sample API."
                    : "Use the protected demo-admin username/password. API users authenticate with Entra JWTs independently; licensed Entra console SSO is not active.",
                "API authorization"));
        return entries.ToArray();
    }

    public async Task<IReadOnlyList<IntegrationCheck>> CheckAsync(string userId, CancellationToken ct)
    {
        var checks = new List<IntegrationCheck>();
        try
        {
            var principal = await graph.SendAsync(HttpMethod.Get, $"v1.0/servicePrincipals/{_settings.ServicePrincipalId}?$select=appRoles,appRoleAssignmentRequired", cancellationToken: ct);
            var roles = principal["appRoles"]!.AsArray().Where(x => x?["isEnabled"]?.GetValue<bool>() == true).Select(x => x!["value"]!.GetValue<string>()).ToArray();
            var matches = HarnessRoles.Harness.All(roles.Contains) && principal["appRoleAssignmentRequired"]?.GetValue<bool>() == true;
            checks.Add(new("Entra harness roles", matches ? "Verified" : "Blocked",
                matches ? "Microsoft Graph confirmed the two requested app roles and required user assignment on the real enterprise application." : "The enterprise application role configuration does not match the required boundary.", "https://entra.microsoft.com/"));
        }
        catch (IntegrationException ex) { checks.Add(new("Entra harness roles", "Pending", ex.Message, "https://entra.microsoft.com/")); }
        checks.Add(new("Agent 365 registry", store.GetAgents().Any(x => x.RegistryId is not null) ? "Configured" : "Pending",
            "The per-agent builder records the real registry registration response. Use Validate to re-read each registry record; separate portal propagation and workload coverage still require verification.", "https://admin.microsoft.com/"));
        checks.Add(new("Microsoft OpenTelemetry", configuration.GetValue("Agent365:EnableExporter", false) ? "Configured" : "Pending",
            "The Microsoft.OpenTelemetry distro is compiled and instrumented. Agent 365 S2S export is independent of business tokens; configured exporters are not proof of telemetry arriving at the destination.", "https://admin.microsoft.com/"));
        checks.Add(new("Azure OpenAI", string.IsNullOrWhiteSpace(configuration["AzureOpenAI:Endpoint"]) ? "Pending" : "Configured",
            "All model adapters require an Azure OpenAI HTTPS endpoint and use Entra workload identity. No OpenAI public API fallback or model API key is used.", "https://ai.azure.com/"));
        try
        {
            if (!configuration.GetValue("Purview:Enabled", true) || !configuration.GetValue("Purview:RequireInlinePolicy", true))
                checks.Add(new("Purview DLP", "Blocked",
                    "Purview evaluation and the required inline-policy gate must both be enabled. Protection is not verified from configuration alone.", "https://purview.microsoft.com/"));
            else
            {
                var scopes = await graph.SendAsync(HttpMethod.Post, $"v1.0/users/{userId}/dataSecurityAndGovernance/protectionScopes/compute", new JsonObject
                {
                    ["activities"] = "uploadText,downloadText",
                    ["locations"] = new JsonArray(new JsonObject { ["@odata.type"] = "microsoft.graph.policyLocationApplication", ["value"] = _settings.ClientId })
                }, ct);
                var inline = PurviewService.HasInlineScope(scopes, "uploadText");
                checks.Add(new("Purview DLP", inline ? "Verified" : "Blocked",
                    inline
                        ? "Microsoft Graph confirmed an applicable inline input policy for your signed-in account and this Entra application. Every run still evaluates input and output; scope verification is not proof of downstream Audit, collection, or compliance delivery."
                        : "Microsoft Graph returned no applicable inline input policy for your signed-in account and this Entra application. Protected inference remains blocked.",
                    "https://purview.microsoft.com/"));
            }
        }
        catch (IntegrationException ex) { checks.Add(new("Purview DLP", "Pending", ex.Message, "https://purview.microsoft.com/")); }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            checks.Add(new("Purview DLP", "Pending",
                "The live policy-scope check could not complete. Protected inference still requires a successful Purview evaluation; no policy bypass is available.", "https://purview.microsoft.com/"));
        }
        checks.Add(new("Work IQ tools", "Validation required",
            "The Agent 365 SDK registers tools on authenticated agentic channel turns. A delegated token, Microsoft 365 Copilot entitlement, and governed servers are required; model S2S access alone does not enable Work IQ.", "https://admin.microsoft.com/"));
        checks.Add(new("Notifications / Windows 365", "Validation required",
            "SDK notification routing and Microsoft's Windows 365 orchestrator are compiled. Confirm the published endpoint, agent user/mailbox, Frontier availability, Cloud PC access, and computer-use model independently.", "https://intune.microsoft.com/"));
        checks.Add(new("Gravitee", string.IsNullOrWhiteSpace(_settings.GraviteeUrl) ? "Pending" : "Configured",
            "Use the authorization lab for real signed-token allow/deny results. Entra authenticates API users; Gravitee authorizes them, and the backend remains private. " +
            (_settings.GraviteeConsoleAuthMode == "entra-oidc"
                ? "Console Entra OIDC is selected and requires its separate licensed entitlement."
                : "Console administration uses the strong demo-admin password. Entra application roles on the Gravitee console registration apply only when console SSO is activated."),
            _settings.GraviteeUrl));
        if (Guid.TryParse(_settings.SubscriptionId, out _))
        {
            try
            {
                var resourceId = configuration["Harness:DefenderPricingResourceId"] ??
                    $"/subscriptions/{_settings.SubscriptionId}/providers/Microsoft.Security/pricings/AI";
                var response = await ArmAsync(resourceId, "2024-01-01", ct);
                var tier = response["properties"]?["pricingTier"]?.GetValue<string>();
                checks.Add(new("Defender for AI Services", tier == "Standard" ? "Verified" : "Blocked",
                    $"Azure Resource Manager returned AI pricingTier={tier ?? "unknown"} at {resourceId}. This verifies plan enablement, not an individual alert or XDR ingestion.", "https://security.microsoft.com/"));
            }
            catch (IntegrationException ex) { checks.Add(new("Defender for AI Services", "Pending", ex.Message, "https://security.microsoft.com/")); }
        }
        else checks.Add(new("Defender for AI Services", "Pending", "No Azure subscription has been confirmed for this deployment. No protection claim is inferred from another subscription.", "https://security.microsoft.com/"));
        return checks;
    }

    private async Task<JsonObject> ArmAsync(string resourceId, string apiVersion, CancellationToken ct)
    {
        if (!resourceId.StartsWith($"/subscriptions/{_settings.SubscriptionId}/", StringComparison.OrdinalIgnoreCase))
            throw new IntegrationException("The Azure evidence resource is outside the configured subscription.", 400);
        TokenCredential credential = Environment.GetEnvironmentVariable("WEBSITE_INSTANCE_ID") is null
            ? new AzureCliCredential(new AzureCliCredentialOptions { TenantId = _settings.TenantId })
            : new ManagedIdentityCredential();
        var token = await credential.GetTokenAsync(new TokenRequestContext(["https://management.azure.com/.default"]), ct);
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://management.azure.com" + resourceId + "?api-version=" + apiVersion);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);
        using var response = await factory.CreateClient("azure").SendAsync(request, ct);
        if (!response.IsSuccessStatusCode) throw new IntegrationException($"Azure evidence lookup returned {(int)response.StatusCode}. The hosting identity needs read access to the selected Defender pricing resource.");
        return await response.Content.ReadFromJsonAsync<JsonObject>(ct) ?? throw new IntegrationException("Azure returned no evidence document.");
    }
}
