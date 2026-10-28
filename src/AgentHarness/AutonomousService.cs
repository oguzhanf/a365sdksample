// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace AgentHarness;

public sealed class AutonomousService(
    IServiceScopeFactory scopeFactory, HarnessStore store, IConfiguration configuration,
    ILogger<AutonomousService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var interval = Math.Clamp(configuration.GetValue("Autonomous:IntervalSeconds", 300), 60, 86400);
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(interval));
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            foreach (var agent in store.GetAgents().Where(x => x.Framework == "autonomous" && x.ScheduleEnabled && x.Status != "Disabled"))
            {
                try
                {
                    using var scope = scopeFactory.CreateScope();
                    var roles = await scope.ServiceProvider.GetRequiredService<IDirectoryService>().GetCurrentRolesAsync(agent.CreatedBy, stoppingToken);
                    if (roles is null || !roles.Contains(HarnessRoles.Administrator))
                    {
                        store.SaveAgent(agent with { ScheduleEnabled = false });
                        store.Audit(agent.CreatedBy, "AutonomousScheduleDisabled", agent.Id, "Owner no longer has the harness administrator role");
                        continue;
                    }
                    await scope.ServiceProvider.GetRequiredService<IAgentRuntime>()
                        .RunAsync(agent, SampleCatalog.Find("autonomous").Prompt, agent.CreatedBy, stoppingToken);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
                catch (Exception ex)
                {
                    logger.LogWarning("Autonomous cycle for {AgentId} failed with {ErrorType}; no fallback result was generated.", agent.Id, ex.GetType().Name);
                    store.AddEvidence(agent.Id, "Validate", "Blocked", "The autonomous cycle did not complete. Inspect its audit correlation and service prerequisites.");
                }
            }
        }
    }
}
