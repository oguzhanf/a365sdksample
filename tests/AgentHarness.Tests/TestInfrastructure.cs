// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using AgentHarness;

namespace AgentHarness.Tests;

internal static class TestIdentity
{
    public const string TenantId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    public const string HarnessClientId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    public const string HarnessServicePrincipalId = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
    public const string InternalApiServicePrincipalId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
    public const string GraviteeServicePrincipalId = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
    public const string OtherTenantId = "11111111-1111-4111-8111-111111111111";
    public const string MemberObjectId = "22222222-2222-4222-8222-222222222222";
    public const string AdministratorObjectId = "33333333-3333-4333-8333-333333333333";
    public const string ApprovedGuestObjectId = "44444444-4444-4444-8444-444444444444";
    public const string UnapprovedGuestObjectId = "55555555-5555-4555-8555-555555555555";
}

internal static class TestHeaders
{
    public const string ObjectId = "X-Test-Oid";
    public const string TenantId = "X-Test-Tid";
    public const string AccountType = "X-Test-Acct";
    public const string Roles = "X-Test-Roles";
}

internal sealed class TestDataDirectory : IDisposable
{
    public TestDataDirectory()
    {
        DirectoryPath = Path.Combine(AppContext.BaseDirectory, "test-data", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(DirectoryPath);
    }

    public string DirectoryPath { get; }

    public void Dispose()
    {
        for (var attempt = 0; attempt < 10; attempt++)
        {
            try
            {
                if (Directory.Exists(DirectoryPath))
                    Directory.Delete(DirectoryPath, recursive: true);
                return;
            }
            catch (IOException) when (attempt < 9)
            {
                Thread.Sleep(50);
            }
            catch (UnauthorizedAccessException) when (attempt < 9)
            {
                Thread.Sleep(50);
            }
        }
    }
}

internal sealed record GraphCall(HttpMethod Method, string Path, JsonNode? Body, string? Etag);

internal sealed class RecordingGraphClient(Func<GraphCall, JsonObject>? responder = null) : IGraphClient
{
    private readonly ConcurrentQueue<GraphCall> calls = new();
    private readonly Func<GraphCall, JsonObject> responder = responder ??
        (call => throw new InvalidOperationException($"Unexpected Microsoft Graph call: {call.Method} {call.Path}"));

    public IReadOnlyList<GraphCall> Calls => calls.ToArray();

    public Task<JsonObject> SendAsync(
        HttpMethod method,
        string path,
        JsonNode? body = null,
        CancellationToken cancellationToken = default,
        string? etag = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var call = new GraphCall(method, path, body?.DeepClone(), etag);
        calls.Enqueue(call);
        return Task.FromResult(responder(call));
    }
}

internal sealed class StubDirectoryService : IDirectoryService
{
    public Task<IReadOnlyList<DirectoryUser>> SearchAsync(string query, CancellationToken ct) =>
        Task.FromResult<IReadOnlyList<DirectoryUser>>([]);

    public Task<IReadOnlyList<RoleAssignment>> GetAssignmentsAsync(string application, CancellationToken ct) =>
        Task.FromResult<IReadOnlyList<RoleAssignment>>([]);

    public Task AssignAsync(AssignmentRequest request, string actor, CancellationToken ct) =>
        throw new InvalidOperationException("The directory test double was not configured for assignment.");

    public Task RemoveAsync(string application, string assignmentId, string actor, CancellationToken ct) =>
        throw new InvalidOperationException("The directory test double was not configured for removal.");

    public Task<string[]?> GetCurrentRolesAsync(string objectId, CancellationToken ct) =>
        Task.FromResult<string[]?>([HarnessRoles.User]);
}

internal sealed record RuntimeCall(AgentRecord Agent, string Prompt, string UserId);

internal sealed class RecordingAgentRuntime : IAgentRuntime
{
    private readonly ConcurrentQueue<RuntimeCall> calls = new();

    public RunResult Result { get; set; } =
        new("Synthetic test result", "test-trace", "agent-framework", ["Test runtime invoked."], true);

    public IReadOnlyList<RuntimeCall> Calls => calls.ToArray();

    public Task<RunResult> RunAsync(
        AgentRecord agent,
        string prompt,
        string userId,
        CancellationToken ct,
        IList<AITool>? channelTools = null)
    {
        ct.ThrowIfCancellationRequested();
        calls.Enqueue(new RuntimeCall(agent, prompt, userId));
        return Task.FromResult(Result);
    }
}

internal sealed class HarnessWebApplicationFactory(
    string dataPath,
    RecordingAgentRuntime? runtime = null,
    RecordingGraphClient? graph = null,
    IDirectoryService? directory = null,
    IReadOnlyList<string>? allowedGuestIds = null,
    IReadOnlyList<string>? allowedGuestAdministratorIds = null,
    string tenantId = TestIdentity.TenantId) : WebApplicationFactory<Program>
{
    public RecordingAgentRuntime Runtime { get; } = runtime ?? new RecordingAgentRuntime();
    public RecordingGraphClient Graph { get; } = graph ?? new RecordingGraphClient();
    public IDirectoryService Directory { get; } = directory ?? new StubDirectoryService();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("Harness:TenantId", tenantId);
        builder.UseSetting("Harness:ClientId", TestIdentity.HarnessClientId);
        builder.UseSetting("Harness:ServicePrincipalId", TestIdentity.HarnessServicePrincipalId);
        builder.UseSetting("AzureAd:TenantId", tenantId);
        builder.UseSetting("AzureAd:ClientId", TestIdentity.HarnessClientId);
        builder.UseSetting("Bootstrap:AdministratorObjectId", TestIdentity.AdministratorObjectId);
        builder.UseSetting("Data:Path", dataPath);
        builder.UseSetting("Autonomous:IntervalSeconds", "86400");
        for (var index = 0; index < (allowedGuestIds?.Count ?? 0); index++)
            builder.UseSetting($"Harness:AllowedB2BGuestObjectIds:{index}", allowedGuestIds![index]);
        for (var index = 0; index < (allowedGuestAdministratorIds?.Count ?? 0); index++)
            builder.UseSetting(
                $"Harness:AllowedB2BGuestAdministratorObjectIds:{index}",
                allowedGuestAdministratorIds![index]);
        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IGraphClient>();
            services.RemoveAll<IDirectoryService>();
            services.RemoveAll<IAgentRuntime>();
            services.AddSingleton<IGraphClient>(Graph);
            services.AddSingleton(Directory);
            services.AddSingleton<IAgentRuntime>(Runtime);

            services.AddAuthentication()
                .AddScheme<AuthenticationSchemeOptions, HeaderAuthenticationHandler>(
                    HeaderAuthenticationHandler.SchemeName,
                    _ => { });
            services.PostConfigure<AuthenticationOptions>(options =>
            {
                options.DefaultAuthenticateScheme = HeaderAuthenticationHandler.SchemeName;
                options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultForbidScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            });
        });
    }
}

internal sealed class HeaderAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "AgentHarnessTestHeaders";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var objectId = Request.Headers[TestHeaders.ObjectId].ToString();
        if (string.IsNullOrWhiteSpace(objectId))
            return Task.FromResult(AuthenticateResult.NoResult());

        var tenantId = Request.Headers[TestHeaders.TenantId].ToString();
        if (string.IsNullOrWhiteSpace(tenantId))
            tenantId = TestIdentity.TenantId;
        var accountType = Request.Headers[TestHeaders.AccountType].ToString();

        var claims = new List<Claim>
        {
            new("oid", objectId),
            new("tid", tenantId),
            new("name", "Harness test principal")
        };
        if (!string.IsNullOrWhiteSpace(accountType))
            claims.Add(new Claim("acct", accountType));
        foreach (var role in Request.Headers[TestHeaders.Roles].ToString()
                     .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            claims.Add(new Claim("roles", role));
        }

        var identity = new ClaimsIdentity(claims, SchemeName, "name", "roles");
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName);
        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}

internal static class HarnessHttp
{
    public static HttpClient CreateClient(
        HarnessWebApplicationFactory factory,
        string? role = null,
        string tenantId = TestIdentity.TenantId,
        string? accountType = "0",
        string objectId = TestIdentity.MemberObjectId)
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = new Uri("https://localhost"),
            HandleCookies = true
        });
        if (!string.IsNullOrWhiteSpace(objectId))
        {
            client.DefaultRequestHeaders.Add(TestHeaders.ObjectId, objectId);
            client.DefaultRequestHeaders.Add(TestHeaders.TenantId, tenantId);
            if (accountType is not null)
                client.DefaultRequestHeaders.Add(TestHeaders.AccountType, accountType);
            if (!string.IsNullOrWhiteSpace(role))
                client.DefaultRequestHeaders.Add(TestHeaders.Roles, role);
        }
        return client;
    }

    public static async Task<string> GetCsrfTokenAsync(HttpClient client)
    {
        using var response = await client.GetAsync("/api/csrf");
        response.EnsureSuccessStatusCode();
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return document.RootElement.GetProperty("token").GetString()
            ?? throw new InvalidOperationException("The antiforgery endpoint did not return a token.");
    }

    public static async Task<HttpResponseMessage> PostJsonWithCsrfAsync<T>(
        HttpClient client,
        string path,
        T body,
        string token)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = JsonContent.Create(body)
        };
        request.Headers.Add("X-AgentHarness-CSRF", token);
        return await client.SendAsync(request);
    }
}
