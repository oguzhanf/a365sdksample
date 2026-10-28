// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Concurrent;
using Agent365.Samples.Observability;

namespace AgentHarness;

public sealed class AgentExporterRegistry(IConfiguration configuration, HarnessOptions settings) : IDisposable
{
    private readonly ConcurrentDictionary<string, ObservabilityAppTokenProvider> _providers = new();
    private HarnessStore? _store;

    public void AttachStore(HarnessStore store) => _store = store;

    public async Task<string?> ResolveAsync(string agentId, string tenantId)
    {
        if (tenantId != settings.TenantId || !Guid.TryParse(agentId, out _))
            throw new InvalidOperationException("An exporter token must match the registered agent identity in the configured tenant.");
        var agent = _store?.GetAgents().SingleOrDefault(x => x.AgentClientId == agentId && x.RegistryId is not null && x.Status != "Disabled")
            ?? throw new InvalidOperationException("The Agent 365 exporter requires a successfully registered, enabled agent.");
        var provider = _providers.GetOrAdd(agentId, _ =>
        {
            var config = new ConfigurationBuilder().AddConfiguration(configuration).AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["EnableAgent365Exporter"] = "true",
                ["Agent365Observability:TenantId"] = settings.TenantId,
                ["Agent365Observability:AgentId"] = agent.AgentClientId,
                ["Agent365Observability:BlueprintClientId"] = agent.BlueprintClientId,
                ["Agent365Observability:UseManagedIdentity"] = "true"
            }).Build();
            return ObservabilityAppTokenFactory.Create(config);
        });
        return await provider.ResolveAsync(agentId, tenantId)
            ?? throw new InvalidOperationException("The registered agent's S2S telemetry token is unavailable.");
    }

    public void Dispose()
    {
        foreach (var provider in _providers.Values) provider.Dispose();
        _providers.Clear();
    }
}
