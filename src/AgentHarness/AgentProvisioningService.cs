// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Concurrent;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Options;

namespace AgentHarness;

public sealed class AgentProvisioningService(IGraphClient graph, HarnessStore store, IOptions<HarnessOptions> options)
{
    private readonly HarnessOptions _settings = options.Value;
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _locks = new();

    public async Task<AgentRecord> RegisterAsync(string id, string actorId, CancellationToken ct)
    {
        var gate = _locks.GetOrAdd(id, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(ct);
        try
        {
            var agent = store.GetAgent(id) ?? throw new IntegrationException("Agent not found.", 404);
            var name = $"{agent.Name} ({agent.Id[..8]})";
            if (agent.BlueprintClientId is null)
            {
                var filter = Uri.EscapeDataString($"displayName eq '{name.Replace("'", "''", StringComparison.Ordinal)} Blueprint'");
                var existing = await graph.SendAsync(HttpMethod.Get, $"v1.0/applications/microsoft.graph.agentIdentityBlueprint?$filter={filter}", cancellationToken: ct);
                var blueprint = existing["value"]!.AsArray().SingleOrDefault();
                blueprint ??= await graph.SendAsync(HttpMethod.Post, "v1.0/applications/microsoft.graph.agentIdentityBlueprint", new JsonObject
                {
                    ["displayName"] = name + " Blueprint",
                    ["sponsors@odata.bind"] = new JsonArray($"https://graph.microsoft.com/v1.0/users/{actorId}"),
                    ["owners@odata.bind"] = new JsonArray($"https://graph.microsoft.com/v1.0/servicePrincipals/{_settings.ServicePrincipalId}")
                }, ct);
                agent = agent with { BlueprintObjectId = blueprint["id"]!.GetValue<string>(), BlueprintClientId = blueprint["appId"]!.GetValue<string>(), Status = "Blueprint created" };
                store.SaveAgent(agent);
                store.AddEvidence(id, "Register", "Verified", $"Typed Entra agent identity blueprint created: {agent.BlueprintClientId}.");
            }

            await CreateWithPropagationAsync(
                async () =>
                {
                    var principals = await graph.SendAsync(HttpMethod.Get, $"v1.0/servicePrincipals?$filter=appId eq '{agent.BlueprintClientId}'", cancellationToken: ct);
                    return principals["value"]!.AsArray().SingleOrDefault()?.AsObject();
                },
                () => graph.SendAsync(HttpMethod.Post, "v1.0/servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal",
                    new JsonObject { ["appId"] = agent.BlueprintClientId }, ct), ct);

            if (agent.AgentClientId is null)
            {
                var filter = Uri.EscapeDataString($"displayName eq '{name.Replace("'", "''", StringComparison.Ordinal)}'");
                var identity = await CreateWithPropagationAsync(
                    async () =>
                    {
                        var existing = await graph.SendAsync(HttpMethod.Get, $"beta/servicePrincipals/microsoft.graph.agentIdentity?$filter={filter}&$select=id,appId,agentIdentityBlueprintId,accountEnabled", cancellationToken: ct);
                        var found = existing["value"]!.AsArray().SingleOrDefault()?.AsObject();
                        if (found is not null && found["agentIdentityBlueprintId"]?.GetValue<string>() != agent.BlueprintClientId)
                            throw new IntegrationException("The recovered agent identity belongs to a different blueprint.", 409);
                        return found;
                    },
                    () => graph.SendAsync(HttpMethod.Post, "beta/servicePrincipals/microsoft.graph.agentIdentity", new JsonObject
                    {
                        ["displayName"] = name,
                        ["agentIdentityBlueprintId"] = agent.BlueprintClientId,
                        ["sponsors@odata.bind"] = new JsonArray($"https://graph.microsoft.com/v1.0/users/{actorId}")
                    }, ct), ct);
                agent = agent with { AgentObjectId = identity["id"]!.GetValue<string>(), AgentClientId = identity["appId"]!.GetValue<string>(), Status = "Identity created; registry pending" };
                store.SaveAgent(agent);
                store.AddEvidence(id, "Register", "Verified", $"Entra agent identity created: client {agent.AgentClientId}; object {agent.AgentObjectId}.");
            }

            if (agent.RegistryId is null)
            {
                var now = DateTimeOffset.UtcNow.ToString("O");
                JsonObject registration;
                try
                {
                    registration = await graph.SendAsync(HttpMethod.Post, "beta/copilot/agentRegistrations", new JsonObject
                    {
                        ["id"] = agent.Id,
                        ["displayName"] = agent.Name,
                        ["description"] = agent.Description,
                        ["ownerIds"] = new JsonArray(actorId),
                        ["createdBy"] = actorId,
                        ["sourceCreatedDateTime"] = agent.CreatedAt.ToString("O"),
                        ["sourceLastModifiedDateTime"] = now,
                        ["agentIdentityBlueprintId"] = agent.BlueprintClientId,
                        ["agentIdentityId"] = agent.AgentClientId,
                        ["sourceAgentId"] = agent.AgentClientId,
                        ["managedByAppId"] = _settings.ClientId
                    }, ct);
                }
                catch (IntegrationException ex) when (ex.StatusCode == 409)
                {
                    registration = await graph.SendAsync(HttpMethod.Get, $"beta/copilot/agentRegistrations/{agent.Id}", cancellationToken: ct);
                    if (registration["sourceAgentId"]?.GetValue<string>() != agent.AgentClientId)
                        throw new IntegrationException("The existing registry record does not match this agent identity.", 409);
                }
                agent = agent with { RegistryId = registration["id"]!.GetValue<string>(), Status = "Registered" };
                store.SaveAgent(agent);
                store.AddEvidence(id, "Register", "Verified", $"Agent 365 registry accepted registration {agent.RegistryId}. Portal propagation and workload policy coverage still require independent validation.");
            }
            store.Audit(actorId, "AgentRegistered", id, "Succeeded");
            return agent;
        }
        catch (Exception ex) when (ex is IntegrationException or HttpRequestException)
        {
            store.AddEvidence(id, "Register", "Blocked", ex is IntegrationException ? ex.Message : "The Microsoft service could not be reached. Saved identity checkpoints are retained for retry.");
            store.Audit(actorId, "AgentRegistered", id, "Blocked");
            throw;
        }
        finally { gate.Release(); }
    }

    private static async Task<JsonObject> CreateWithPropagationAsync(Func<Task<JsonObject?>> recover, Func<Task<JsonObject>> create, CancellationToken ct)
    {
        for (var attempt = 0; ; attempt++)
        {
            if (await recover() is { } existing) return existing;
            try { return await create(); }
            catch (IntegrationException ex) when (attempt < 4 && ex.StatusCode is 400 or 404 or 409 &&
                (ex.ServiceMessage?.Contains("exist", StringComparison.OrdinalIgnoreCase) == true ||
                 ex.ServiceMessage?.Contains("found", StringComparison.OrdinalIgnoreCase) == true ||
                 ex.ServiceMessage?.Contains("replicat", StringComparison.OrdinalIgnoreCase) == true ||
                 ex.ServiceMessage?.Contains("referenc", StringComparison.OrdinalIgnoreCase) == true))
            {
                await Task.Delay(TimeSpan.FromSeconds(2 << attempt), ct);
            }
        }
    }

    public async Task<AgentRecord> ExtendAsync(string id, string[] capabilities, string actor, CancellationToken ct)
    {
        var allowed = new[] { "observability", "workiq", "notifications", "purview" };
        if (capabilities.Except(allowed, StringComparer.Ordinal).Any())
            throw new IntegrationException("Unsupported agent capability.", 400);
        var gate = _locks.GetOrAdd(id, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(ct);
        try
        {
            var agent = store.GetAgent(id) ?? throw new IntegrationException("Agent not found.", 404);
            if (agent.BlueprintObjectId is null || agent.AgentClientId is null)
                throw new IntegrationException("Register the real Entra identity before extending it.", 409);
            if (agent.Status == "Disabled")
                throw new IntegrationException("Re-enable the agent explicitly before extending its capabilities.", 409);
            if (Guid.TryParse(_settings.ManagedIdentityPrincipalId, out _))
            {
                var credentials = await graph.SendAsync(HttpMethod.Get, $"v1.0/applications/{agent.BlueprintObjectId}/federatedIdentityCredentials", cancellationToken: ct);
                if (!credentials["value"]!.AsArray().Any(x => x?["name"]?.GetValue<string>() == "agentharness-harness-managed-identity"))
                    await graph.SendAsync(HttpMethod.Post, $"v1.0/applications/{agent.BlueprintObjectId}/federatedIdentityCredentials", new JsonObject
                    {
                        ["name"] = "agentharness-harness-managed-identity",
                        ["issuer"] = $"https://login.microsoftonline.com/{_settings.TenantId}/v2.0",
                        ["subject"] = _settings.ManagedIdentityPrincipalId,
                        ["audiences"] = new JsonArray("api://AzureADTokenExchange")
                    }, ct);
                store.AddEvidence(id, "Extend", "Verified", "The Azure hosting managed identity is federated to this blueprint. No blueprint secret is stored in the harness.");
            }
            else store.AddEvidence(id, "Extend", "Pending", "Host managed identity is not configured. Federated blueprint authentication cannot be validated.");
            agent = agent with { Capabilities = capabilities.Distinct().ToArray(), Status = "Extended; validation required" };
            store.SaveAgent(agent);
            foreach (var capability in capabilities.Distinct())
                store.AddEvidence(id, "Extend", "Configured", capability switch
                {
                    "observability" => "Microsoft OpenTelemetry is wired to the hosting pipeline. The Agent 365 exporter uses a separate blueprint-to-agent S2S token; validate delivery before claiming coverage.",
                    "workiq" => "Agent 365 MCP registration is wired on authenticated channel turns. Work IQ requires delegated consent and the tenant's enabled MCP servers; S2S model access is not Work IQ authorization.",
                    "notifications" => "Agent 365 notification handlers are implemented. A provisioned agent user, mailbox, published messaging endpoint, and Frontier availability are still required.",
                    _ => "Microsoft Graph protectionScopes/compute and processContent run before inference, with response evaluation before release. Policy coverage must be verified in Purview."
                });
            store.Audit(actor, "AgentExtended", id, "Succeeded");
            return agent;
        }
        finally { gate.Release(); }
    }

    public async Task<IReadOnlyList<Evidence>> ValidateAsync(string id, string actor, CancellationToken ct)
    {
        var agent = store.GetAgent(id) ?? throw new IntegrationException("Agent not found.", 404);
        if (agent.AgentObjectId is null || agent.BlueprintObjectId is null)
            throw new IntegrationException("Register an agent identity before validation.", 409);
        var blueprint = await graph.SendAsync(HttpMethod.Get, $"v1.0/applications/{agent.BlueprintObjectId}/microsoft.graph.agentIdentityBlueprint?$select=id,appId", cancellationToken: ct);
        var identity = await graph.SendAsync(HttpMethod.Get, $"beta/servicePrincipals/{agent.AgentObjectId}/microsoft.graph.agentIdentity?$select=id,appId,agentIdentityBlueprintId,accountEnabled", cancellationToken: ct);
        var identityMatches = blueprint["appId"]?.GetValue<string>() == agent.BlueprintClientId &&
            identity["appId"]?.GetValue<string>() == agent.AgentClientId &&
            identity["agentIdentityBlueprintId"]?.GetValue<string>() == agent.BlueprintClientId;
        if (!identityMatches) throw new IntegrationException("The persisted identity does not match the real Entra blueprint and agent.", 409);
        store.AddEvidence(id, "Validate", "Verified", "Microsoft Graph confirmed the typed blueprint, typed agent identity, and their parent relationship.", "identity-validation");
        if (agent.RegistryId is not null)
        {
            var registration = await graph.SendAsync(HttpMethod.Get, $"beta/copilot/agentRegistrations/{agent.RegistryId}", cancellationToken: ct);
            if (registration["sourceAgentId"]?.GetValue<string>() != agent.AgentClientId)
                throw new IntegrationException("The Agent 365 registry identity does not match this agent.", 409);
            store.AddEvidence(id, "Validate", "Verified", "The Agent 365 registry record is readable and points to this registered identity.", "registry-validation");
        }
        else store.AddEvidence(id, "Validate", "Blocked", "Agent 365 registry registration is incomplete; Entra identity creation alone is not catalog visibility.");
        store.AddEvidence(id, "Validate", "Pending", "Run a real turn, follow its trace ID in Application Insights and Agent 365, and verify tool and notification delivery. This check does not fabricate workload evidence.");
        var disabled = agent.Status == "Disabled" || identity["accountEnabled"]?.GetValue<bool>() == false;
        store.SaveAgent(agent with { Status = disabled ? "Disabled" : "Identity validated; runtime checks pending", ScheduleEnabled = !disabled && agent.ScheduleEnabled });
        if (disabled) store.AddEvidence(id, "Validate", "Blocked", "The identity exists but is disabled. Validation does not re-enable it.");
        store.Audit(actor, "AgentValidated", id, "Identity verified");
        return store.GetEvidence(id);
    }

    public Task DisableAsync(string id, string actor, CancellationToken ct) => SetEnabledAsync(id, false, actor, ct);

    public Task EnableAsync(string id, string actor, CancellationToken ct) => SetEnabledAsync(id, true, actor, ct);

    private async Task SetEnabledAsync(string id, bool enabled, string actor, CancellationToken ct)
    {
        var gate = _locks.GetOrAdd(id, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(ct);
        try
        {
            var agent = store.GetAgent(id) ?? throw new IntegrationException("Agent not found.", 404);
            if (agent.AgentObjectId is null) throw new IntegrationException("The agent has no registered identity.", 409);
            await graph.SendAsync(HttpMethod.Patch, $"beta/servicePrincipals/{agent.AgentObjectId}/microsoft.graph.agentIdentity", new JsonObject { ["accountEnabled"] = enabled }, ct);
            store.SaveAgent(agent with { Status = "Disabled", ScheduleEnabled = false });
            for (var attempt = 0; ; attempt++)
            {
                var observed = await graph.SendAsync(HttpMethod.Get,
                    $"beta/servicePrincipals/{agent.AgentObjectId}/microsoft.graph.agentIdentity?$select=id,accountEnabled", cancellationToken: ct);
                if (observed["accountEnabled"]?.GetValue<bool>() == enabled) break;
                if (attempt == 5)
                {
                    store.AddEvidence(id, "Operate", "Pending", "Entra accepted the state change, but read-back has not converged. The harness remains paused; retry after propagation.");
                    store.Audit(actor, enabled ? "AgentEnablePending" : "AgentDisablePending", id, "Awaiting Entra propagation");
                    throw new IntegrationException("Entra has not confirmed the requested state yet. The harness remains paused; retry after directory propagation.", 503);
                }
                await Task.Delay(TimeSpan.FromSeconds(Math.Min(1 << attempt, 8)), ct);
            }
            var status = enabled ? (agent.RegistryId is not null ? "Registered" : "Identity created; registry pending") : "Disabled";
            store.SaveAgent(agent with { Status = status, ScheduleEnabled = false });
            store.AddEvidence(id, "Operate", "Verified", enabled
                ? "Entra read-back confirmed accountEnabled=true. Scheduled runs remain off until explicitly enabled."
                : "Entra read-back confirmed accountEnabled=false. New harness turns and scheduled runs are blocked.");
            store.Audit(actor, enabled ? "AgentEnabled" : "AgentDisabled", id, "Succeeded");
        }
        finally { gate.Release(); }
    }
}
