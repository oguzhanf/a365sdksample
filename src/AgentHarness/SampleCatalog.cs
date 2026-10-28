// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Reflection;

namespace AgentHarness;

public sealed record SampleDefinition(string Id, string Name, string Framework, string Description, string SourcePath, string[] Capabilities, string[] Prerequisites, string Prompt);

public static class SampleCatalog
{
    public const string Commit = "44eeeea2572a6600f69c4cd996cbf3a025637743";
    public const string Repository = "https://github.com/microsoft/Agent365-Samples";
    public static readonly SampleDefinition[] All =
    [
        new("agent-framework", "Agent Framework", "Microsoft Agent Framework",
            "A conversational agent with real function invocation, date/time and optional weather tools, governed Work IQ tool registration, and Microsoft OpenTelemetry.",
            "dotnet/agent-framework/sample-agent", ["Identity", "MCP tooling", "Notifications", "Tracing"],
            ["Azure OpenAI chat deployment", "Work IQ delegated consent for Microsoft 365 tools", "Optional OpenWeather API key for upstream weather tools"],
            "Use your date/time tool, then explain the Agent 365 integration boundaries in this harness."),
        new("semantic-kernel", "Semantic Kernel", "Microsoft Semantic Kernel",
            "A .NET Kernel with automatic function invocation, a native tool plugin, Azure OpenAI, and the Agent 365 Semantic Kernel MCP registration extension.",
            "dotnet/semantic-kernel/sample-agent", ["Kernel plugins", "Agent 365 MCP", "Notifications", "Tracing"],
            ["Azure OpenAI chat deployment", "Work IQ delegated consent for live Microsoft 365 tools"],
            "Use the GetCurrentDateTime plugin and summarize how Entra, Gravitee, and Purview protect a request."),
        new("autonomous", "Autonomous GitHub digest", "BackgroundService + Microsoft.Extensions.AI",
            "A hosted background agent and run-once action that query the public GitHub Search API and summarize actual trending repositories using Azure OpenAI.",
            "dotnet/autonomous/github-trending/sample-agent", ["BackgroundService", "Function invocation", "GitHub tool", "Nested spans"],
            ["Azure OpenAI chat deployment", "Outbound access to api.github.com", "Administrator opt-in before enabling the persistent schedule"],
            "Find trending C# repositories created in the past seven days using GetTrendingRepositories. Summarize the actual results, and state if the tool is rate-limited."),
        new("w365", "Windows 365 computer use", "Microsoft's CUA orchestrator + Responses API",
            "The unmodified Microsoft computer-use orchestrator, Azure OpenAI Responses provider, action normalization, MCP session lifecycle, and telemetry are compiled into this harness.",
            "dotnet/w365-computer-use/sample-agent", ["Computer-use loop", "W365 MCP", "Session isolation", "Responses API"],
            ["Provisioned Windows 365 for Agents access and an agent user", "Azure OpenAI computer-use model deployment", "Governed MCP discovery and an agentic delegated token"],
            "Describe the current desktop before taking any action.")
    ];

    public static SampleDefinition Find(string id) => All.SingleOrDefault(x => x.Id == id)
        ?? throw new IntegrationException("Unknown Microsoft .NET sample.", 400);
}

public sealed class SourceCatalog
{
    private readonly Assembly _assembly = typeof(SourceCatalog).Assembly;
    private readonly Dictionary<string, string> _resources;

    public SourceCatalog()
    {
        _resources = _assembly.GetManifestResourceNames()
            .Where(x => x.StartsWith("Upstream/", StringComparison.Ordinal) || x.StartsWith("Harness/", StringComparison.Ordinal))
            .ToDictionary(x => x.Replace('\\', '/'), x => x, StringComparer.Ordinal);
    }

    public string[] Paths => _resources.Keys.Order(StringComparer.Ordinal).ToArray();

    public string Read(string path)
    {
        if (!_resources.TryGetValue(path, out var name)) throw new IntegrationException("Source file is not in the embedded allowlist.", 404);
        using var stream = _assembly.GetManifestResourceStream(name)!;
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}
