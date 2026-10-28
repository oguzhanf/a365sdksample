// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Extensions.Options;

namespace AgentHarness;

public sealed record DemoOverview(DateTimeOffset ObservedAt, DemoHosting Hosting, DemoAgent[] Agents);
public sealed record DemoHosting(string State, string Detail, string HealthUrl, bool AzureHosted);
public sealed record DemoIdentity(string? BlueprintClientId, string? AgentClientId, string? RegistryId);
public sealed record DemoCapability(
    string Id, string Title, string State, string Detail, string? Blocker,
    string SourcePath, string ActionRoute, string? TraceId);
public sealed record DemoStage(string Id, string Title, string State, string Detail, string ActionRoute);
public sealed record DemoAgent(
    string Id, string Name, string Framework, string Status, DemoIdentity Identity,
    DemoCapability[] Capabilities, DemoStage[] Stages);

public sealed class DemoOverviewService(
    HarnessStore store, IConfiguration configuration, IOptions<HarnessOptions> options)
{
    public DemoOverview GetOverview()
    {
        var azureHosted = !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("WEBSITE_INSTANCE_ID"));
        return new DemoOverview(DateTimeOffset.UtcNow,
            new DemoHosting("Responding",
                "This authenticated AgentHarness server is responding. " +
                (azureHosted ? "An Azure App Service instance is detected. " : "No Azure App Service instance is detected. ") +
                "Host availability does not verify model inference, agent telemetry delivery, or workload governance.",
                "/healthz", azureHosted),
            store.GetAgents().Select(DescribeAgent).ToArray());
    }

    private DemoAgent DescribeAgent(AgentRecord agent)
    {
        var evidence = store.GetEvidence(agent.Id);
        // Legacy Verified records include identity checks and cannot establish runtime or delivery proof.
        Evidence? Proof(string checkId) => evidence.FirstOrDefault(x => x.CheckId == checkId && x.State == "Verified");
        var runtime = Proof("runtime-turn");
        var mcp = Proof("mcp-discovery");
        var notification = Proof("notification-received");
        var selected = agent.Capabilities ?? [];
        var channels = configuration.GetValue("AgentChannels:Enabled", false);
        var exporter = configuration.GetValue("Agent365:EnableExporter", false);
        var azureMonitor = !string.IsNullOrWhiteSpace(configuration["APPLICATIONINSIGHTS_CONNECTION_STRING"]);
        var disabled = agent.Status == "Disabled";
        var missingIds = new List<string>();
        if (string.IsNullOrWhiteSpace(agent.BlueprintClientId)) missingIds.Add("blueprint client ID");
        if (string.IsNullOrWhiteSpace(agent.AgentClientId)) missingIds.Add("agent client ID");
        if (string.IsNullOrWhiteSpace(agent.RegistryId)) missingIds.Add("Agent 365 registry ID");
        var registered = missingIds.Count == 0;
        var identity = new DemoCapability("identity", "Identity", registered ? "Registered" : "Not registered",
            registered
                ? "Saved blueprint, agent identity, and Agent 365 registry IDs are present. " +
                  (Proof("identity-validation") is not null && Proof("registry-validation") is not null
                      ? "Stored identity and registry read-back evidence is available. "
                      : "The catalog may contain registration metadata without read-back evidence. ") +
                  "This is not a fresh tenant recheck; Validate can re-read the IDs in Entra and Agent 365."
                : "Registration is incomplete. Missing: " + string.Join(", ", missingIds) + ".",
            registered ? null : "Use Register to create or recover the missing " + string.Join(", ", missingIds) + ".",
            "Harness/AgentProvisioningService.cs", registered ? "builder-validate" : "builder-register", null);

        var observability = new DemoCapability("observability", "Observability",
            !exporter ? "Agent 365 exporter off" : runtime is null ? "Not validated" : "Trace observed",
            "Microsoft.OpenTelemetry is wired to the host pipeline. Azure Monitor connection is " +
            (azureMonitor ? "configured" : "not configured") + "; the Agent 365 exporter is " +
            (exporter ? "enabled" : "off") + ". " +
            (runtime is null
                ? "No completed agent turn has been observed."
                : $"A completed runtime turn was recorded at {runtime.ObservedAt:O}. A generated trace is not destination delivery."),
            (!selected.Contains("observability") ? "Select Observability in Extend. " : "") +
            (!exporter ? "Enable the Agent 365 exporter. " : "") +
            (!azureMonitor ? "Configure the Azure Monitor connection before checking Application Insights. " : "") +
            (runtime is null ? "Run a governed agent turn, then " : "") +
            "Verify its trace in Application Insights and Agent 365; configuration and local trace IDs do not prove delivery.",
            "Harness/Program.cs", !selected.Contains("observability") ? "builder-extend" : "builder-validate",
            runtime?.CorrelationId);

        var tooling = new DemoCapability("tooling", "Tooling",
            !selected.Contains("workiq") ? "Not enabled" : !channels ? "Channel not connected" :
            mcp is null ? "Not validated" : "Tools discovered",
            !selected.Contains("workiq")
                ? "Work IQ tooling is not selected for this agent. Local date/time and model tools are not governed MCP discovery."
                : !channels
                    ? "Work IQ is selected, but the authenticated Agent 365 messaging channel is disabled."
                    : mcp is null
                        ? "The channel is enabled, but no successful governed MCP tool registration has been observed for this agent."
                        : $"Governed MCP tool registration was observed at {mcp.ObservedAt:O}. Discovery does not prove a tool was invoked.",
            !selected.Contains("workiq")
                ? "Select Work IQ in Extend, obtain agentic delegated consent, and enable the tenant's governed MCP servers."
                : !channels
                    ? "Connect and publish the authenticated Agent 365 channel with agentic delegated consent and governed MCP server access; web preview cannot impersonate an agent user."
                    : mcp is null
                        ? "Run an authenticated channel turn with agentic delegated consent and enabled governed MCP servers to discover real tools."
                        : "Execute a governed MCP tool call and verify its result and policy coverage; discovery alone is not execution proof.",
            "Harness/AgentRuntime.cs", !selected.Contains("workiq") ? "builder-extend" : "builder-validate",
            mcp?.CorrelationId);

        var notifications = new DemoCapability("notifications", "Notifications",
            string.IsNullOrWhiteSpace(agent.AgentUserId) ? "Needs agent user" :
            !selected.Contains("notifications") ? "Not enabled" : !channels ? "Channel not connected" :
            notification is null ? "Not validated" : "Notification received",
            string.IsNullOrWhiteSpace(agent.AgentUserId)
                ? "The SDK notification handlers are implemented, but no provisioned agent user/mailbox is recorded."
                : !selected.Contains("notifications")
                    ? "An agent user ID is recorded, but Notifications is not selected."
                    : !channels
                        ? "An agent user ID is recorded, but the authenticated notification channel is disabled."
                        : notification is null
                            ? "An agent user ID and enabled channel are recorded; mailbox readiness and actual notification receipt remain unverified."
                            : $"An authenticated SDK notification was received at {notification.ObservedAt:O}. Receipt does not prove a successful reply or mailbox policy coverage.",
            string.IsNullOrWhiteSpace(agent.AgentUserId)
                ? "Provision an agent user and mailbox, select Notifications in Extend, and publish the authenticated messaging endpoint before testing delivery."
                : !selected.Contains("notifications")
                    ? "Select Notifications in Extend and verify the agent mailbox, delegated consent, and published channel."
                    : !channels
                        ? "Publish and enable the authenticated Agent 365 messaging endpoint, then verify mailbox access and send a real notification."
                        : notification is null
                            ? "Verify the agent mailbox and delegated consent, then send a real email or document-comment notification through the authenticated channel."
                            : "Verify the governed response and downstream workload audit records; notification receipt does not establish all notification scenarios.",
            "Harness/HarnessChannelAgent.cs",
            string.IsNullOrWhiteSpace(agent.AgentUserId) || !selected.Contains("notifications") ? "builder-extend" : "builder-validate",
            notification?.CorrelationId);

        var purview = configuration.GetValue("Purview:Enabled", true);
        var inline = configuration.GetValue("Purview:RequireInlinePolicy", true);
        var validationDetail = !purview
            ? "Purview evaluation is disabled. Protected inference is unavailable; no simulated or local policy fallback is permitted. Enable evaluation and verify the app-scoped inline policy."
            : !inline
                ? "Purview inline policy is not required by the current configuration. Require and verify an applicable user/app-scoped inline DLP policy before claiming protected validation."
                : runtime is null
                    ? "No completed agent turn has been observed. Identity validation alone does not validate inference, tools, notifications, or Purview coverage. A real turn requires an applicable user/app-scoped inline Purview policy; verify that policy, then run a turn and follow its trace."
                    : $"A completed runtime turn was recorded at {runtime.ObservedAt:O}, including input/output Purview evaluation. Current app-scoped inline policy coverage, governed tool behavior, notifications, and destination trace delivery still need independent validation.";
        var stages = new[]
        {
            new DemoStage("register", "Register", identity.State, identity.Detail, "builder-register"),
            new DemoStage("extend", "Extend", selected.Length == 0 ? "Not extended" : "Capabilities selected",
                selected.Length == 0
                    ? "No extensions are selected. Choose Observability, Work IQ tooling, Notifications, and the required Purview integration; selection does not validate delivery."
                    : "Selected extensions: " + string.Join(", ", selected) + ". Selection is configuration, not proof of channel consent, tool execution, notification delivery, or policy coverage.",
                "builder-extend"),
            new DemoStage("validate", "Validate", !purview ? "Blocked" : !inline ? "Validation required" :
                runtime is null ? "Not validated" : "Turn observed", validationDetail, "builder-validate"),
            new DemoStage("operate", "Operate", "Controls available",
                $"{options.Value.TenantName} harness lifecycle, schedule opt-in, local audit, and governance portal controls are available. " +
                (registered ? "Entra enable/disable actions require read-back confirmation. " : "Complete registration before using Entra lifecycle controls. ") +
                "Use Agent 365, Defender XDR, and Purview portals to verify actual onboarding, licensing, policy coverage, and downstream activity; available controls are not verification.",
                "builder-operate")
        };
        var capabilities = new[] { identity, observability, tooling, notifications };
        if (disabled)
        {
            const string pause = "Stored status is Disabled; new harness turns and schedules are blocked. Re-enable explicitly with Entra read-back confirmation before validation. This is not a fresh directory check.";
            capabilities = capabilities.Select(x => x with
            {
                State = "Disabled",
                Detail = pause + " " + x.Detail,
                Blocker = pause + (x.Blocker is null ? "" : " " + x.Blocker)
            }).ToArray();
            stages = stages.Select(x => x with { State = "Disabled", Detail = pause + " " + x.Detail }).ToArray();
        }
        return new DemoAgent(agent.Id, agent.Name, agent.Framework, agent.Status,
            new DemoIdentity(agent.BlueprintClientId, agent.AgentClientId, agent.RegistryId), capabilities, stages);
    }
}
