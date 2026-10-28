// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Concurrent;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Options;

namespace AgentHarness;

public interface IPurviewService
{
    Task<string> EvaluateAsync(string userId, string content, string activity, string correlationId, CancellationToken ct);
}

public sealed class PurviewService(IGraphClient graph, IOptions<HarnessOptions> options, IConfiguration configuration, HarnessStore store) : IPurviewService
{
    private sealed record ScopeCache(JsonObject Response, string? Etag, DateTimeOffset Timestamp);
    private readonly ConcurrentDictionary<string, ScopeCache> _scopes = new();

    public async Task<string> EvaluateAsync(string userId, string content, string activity, string correlationId, CancellationToken ct)
    {
        if (!configuration.GetValue("Purview:Enabled", true))
            throw new IntegrationException("Purview evaluation is disabled. Protected inference is unavailable; the harness will not substitute a simulated DLP decision.", 503);
        if (!Guid.TryParse(userId, out _) || activity is not ("uploadText" or "downloadText"))
            throw new IntegrationException("A validated user and supported DLP activity are required.", 400);
        try
        {
            var scope = await GetScopesAsync(userId, ct);
            if (activity == "uploadText" && configuration.GetValue("Purview:RequireInlinePolicy", true) && !HasInlineScope(scope.Response, activity))
                throw new IntegrationException("No applicable Purview inline DLP policy was returned for this user and Entra application. Configure the app-scoped policy before protected inference.", 503);
            var message = new JsonObject
            {
                ["contentToProcess"] = new JsonObject
                {
                    ["contentEntries"] = new JsonArray(new JsonObject
                    {
                        ["@odata.type"] = "microsoft.graph.processConversationMetadata",
                        ["identifier"] = Guid.NewGuid().ToString(),
                        ["content"] = new JsonObject { ["@odata.type"] = "microsoft.graph.textContent", ["data"] = content },
                        ["name"] = "AgentHarness protected interaction",
                        ["correlationId"] = correlationId,
                        ["sequenceNumber"] = activity == "uploadText" ? 0 : 1,
                        ["isTruncated"] = false,
                        ["createdDateTime"] = DateTimeOffset.UtcNow.ToString("O"),
                        ["modifiedDateTime"] = DateTimeOffset.UtcNow.ToString("O")
                    }),
                    ["activityMetadata"] = new JsonObject { ["activity"] = activity },
                    ["protectedAppMetadata"] = new JsonObject
                    {
                        ["name"] = "AgentHarness", ["version"] = "1.0",
                        ["applicationLocation"] = new JsonObject
                        {
                            ["@odata.type"] = "microsoft.graph.policyLocationApplication", ["value"] = options.Value.ClientId
                        }
                    },
                    ["integratedAppMetadata"] = new JsonObject { ["name"] = "AgentHarness", ["version"] = "1.0" }
                }
            };
            var decision = await graph.SendAsync(HttpMethod.Post, $"v1.0/users/{userId}/dataSecurityAndGovernance/processContent", message, ct, scope.Etag);
            if (decision["protectionScopeState"]?.GetValue<string>() == "modified")
            {
                _scopes.TryRemove(userId, out _);
                scope = await GetScopesAsync(userId, ct);
                if (activity == "uploadText" && configuration.GetValue("Purview:RequireInlinePolicy", true) && !HasInlineScope(scope.Response, activity))
                    throw new IntegrationException("The updated Purview scope no longer includes the required inline protection. The interaction is blocked.", 503);
            }
            EnforceDecision(decision);
            store.Audit(userId, "Purview." + activity, correlationId, "Evaluated");
            return HasInlineScope(scope.Response, activity) ? "Purview evaluated an applicable inline policy." :
                "Purview evaluated the content; no applicable inline-blocking scope was verified. This is not proof that a blocking DLP policy is configured.";
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            store.Audit(userId, "Purview." + activity, correlationId, "Unavailable; blocked");
            throw new IntegrationException("Purview could not complete evaluation. The interaction is blocked rather than bypassing the policy check.");
        }
    }

    internal static bool HasInlineScope(JsonObject response, string activity) =>
        response["value"] is JsonArray scopes && scopes.Any(x =>
            (x?["activities"]?.GetValue<string>() ?? "").Split(',').Any(a => a.Trim() == activity) &&
            x?["executionMode"]?.GetValue<string>() == "evaluateInline");

    private async Task<ScopeCache> GetScopesAsync(string userId, CancellationToken ct)
    {
        if (_scopes.TryGetValue(userId, out var cached) && DateTimeOffset.UtcNow - cached.Timestamp < TimeSpan.FromMinutes(15)) return cached;
        var response = await graph.SendAsync(HttpMethod.Post, $"v1.0/users/{userId}/dataSecurityAndGovernance/protectionScopes/compute", new JsonObject
        {
            ["activities"] = "uploadText,downloadText",
            ["locations"] = new JsonArray(new JsonObject { ["@odata.type"] = "microsoft.graph.policyLocationApplication", ["value"] = options.Value.ClientId })
        }, ct);
        if (response["value"] is not JsonArray) throw new IntegrationException("Purview returned an invalid protection scope response.");
        var result = new ScopeCache(response, response["_etag"]?.GetValue<string>(), DateTimeOffset.UtcNow);
        _scopes[userId] = result;
        return result;
    }

    public static void EnforceDecision(JsonObject decision)
    {
        if (decision["processingErrors"] is not JsonArray errors || errors.Count != 0)
            throw new IntegrationException("Purview could not evaluate all submitted content. The interaction is blocked.", 503);
        if (decision["policyActions"] is not JsonArray actions)
            throw new IntegrationException("Purview returned an invalid policy decision. The interaction is blocked.", 503);
        foreach (var action in actions)
        {
            if (action?["action"]?.GetValue<string>() == "restrictAccess" &&
                action["restrictionAction"]?.GetValue<string>() is not "allow")
                throw new IntegrationException("Microsoft Purview DLP blocked this interaction. No blocked input is sent to Azure OpenAI and no blocked output is released.", 403);
            if (action?["action"]?.GetValue<string>() is not ("restrictAccess" or "audit" or "notify"))
                throw new IntegrationException("Purview returned an unsupported policy action. The interaction is withheld for administrator review.", 503);
        }
    }
}
