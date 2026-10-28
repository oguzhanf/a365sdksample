// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics;
using System.Security.Claims;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Web;
using Microsoft.OpenTelemetry;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using AgentHarness;
using Microsoft.Agents.A365.Tooling.Services;
using Microsoft.Agents.Hosting.AspNetCore;
using Microsoft.Agents.Builder;
using Microsoft.Agents.Storage;
using Microsoft.Agents.Core;
using AfToolRegistration = Microsoft.Agents.A365.Tooling.Extensions.AgentFramework.Services;
using SkToolRegistration = Microsoft.Agents.A365.Tooling.Extensions.SemanticKernel.Services;

var registerSamples = args.Contains("--register-samples", StringComparer.Ordinal);
var validateSamples = args.Contains("--validate-samples", StringComparer.Ordinal);
var builder = WebApplication.CreateBuilder(args.Where(x => x is not ("--register-samples" or "--validate-samples")).ToArray());
builder.Configuration.AddJsonFile("appsettings.Local.json", optional: true, reloadOnChange: false);
var settings = builder.Configuration.GetSection("Harness").Get<HarnessOptions>() ?? new HarnessOptions();
if (!string.IsNullOrWhiteSpace(settings.TenantId) &&
    (!Guid.TryParse(settings.TenantId, out var configuredTenant) || configuredTenant == Guid.Empty))
    throw new InvalidOperationException("Harness:TenantId must identify the tenant that owns this deployment.");
builder.Services.Configure<HarnessOptions>(builder.Configuration.GetSection("Harness"));
builder.Services.AddSingleton<HarnessStore>();
builder.Services.AddScoped<DemoOverviewService>();
builder.Services.AddSingleton<SourceCatalog>();
builder.Services.AddSingleton<IGraphClient, GraphClient>();
builder.Services.AddSingleton<IDirectoryService, DirectoryService>();
builder.Services.AddSingleton<AgentProvisioningService>();
builder.Services.AddSingleton<IPurviewService, PurviewService>();
builder.Services.AddSingleton<GovernanceService>();
builder.Services.AddSingleton<GraviteeService>();
builder.Services.AddScoped<AgentRuntime>();
builder.Services.AddScoped<IAgentRuntime>(sp => sp.GetRequiredService<AgentRuntime>());
builder.Services.AddHostedService<AutonomousService>();
builder.Services.AddHttpClient("graph", client => client.Timeout = TimeSpan.FromSeconds(45));
builder.Services.AddHttpClient("tools", client => client.Timeout = TimeSpan.FromSeconds(20));
builder.Services.AddHttpClient("model", client => client.Timeout = TimeSpan.FromMinutes(2));
builder.Services.AddHttpClient("WebClient", client => client.Timeout = TimeSpan.FromMinutes(2));
builder.Services.AddHttpClient("gateway", client => client.Timeout = TimeSpan.FromSeconds(30));
builder.Services.AddHttpClient("azure", client => client.Timeout = TimeSpan.FromSeconds(30));
builder.Services.AddHttpContextAccessor();
builder.Services.AddSingleton<IMcpToolServerConfigurationService, McpToolServerConfigurationService>();
builder.Services.AddSingleton<AfToolRegistration.IMcpToolRegistrationService, AfToolRegistration.McpToolRegistrationService>();
builder.Services.AddSingleton<SkToolRegistration.IMcpToolRegistrationService, SkToolRegistration.McpToolRegistrationService>();
builder.Services.AddAntiforgery(o =>
{
    o.HeaderName = "X-AgentHarness-CSRF";
    o.Cookie.Name = "__Host-AgentHarnessCsrf";
    o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    o.Cookie.SameSite = SameSiteMode.Strict;
});
builder.Services.AddDataProtection();

var authentication = builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme);
if (settings.IsIdentityConfigured)
{
    if (!string.Equals(builder.Configuration["AzureAd:TenantId"], settings.TenantId, StringComparison.OrdinalIgnoreCase) ||
        !string.Equals(builder.Configuration["AzureAd:ClientId"], settings.ClientId, StringComparison.OrdinalIgnoreCase))
        throw new InvalidOperationException("AzureAd and Harness must use the same configured tenant and application client IDs.");
    authentication.AddMicrosoftIdentityWebApp(builder.Configuration.GetSection("AzureAd"))
        .EnableTokenAcquisitionToCallDownstreamApi()
        .AddInMemoryTokenCaches();
    builder.Services.Configure<MicrosoftIdentityOptions>(OpenIdConnectDefaults.AuthenticationScheme,
        o => o.MapInboundClaims = false);
    builder.Services.Configure<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme, o =>
    {
        o.MapInboundClaims = false;
        o.TokenValidationParameters.NameClaimType = "name";
        o.TokenValidationParameters.RoleClaimType = "roles";
        o.TokenValidationParameters.ValidateIssuer = true;
        var previous = o.Events.OnTokenValidated;
        o.Events.OnTokenValidated = async context =>
        {
            if (previous is not null) await previous(context);
            if (context.Principal is null || !SecurityBoundary.IsAllowedTenantPrincipal(context.Principal, settings))
            {
                context.Fail("Only members of the configured tenant and explicitly approved B2B guests are accepted.");
                return;
            }
            try
            {
                var roles = await context.HttpContext.RequestServices.GetRequiredService<IDirectoryService>()
                    .GetCurrentRolesAsync(context.Principal.ObjectId(), context.HttpContext.RequestAborted);
                if (roles is null || !roles.Intersect(HarnessRoles.Harness).Any())
                {
                    context.Fail("A harness application role must be assigned in Entra.");
                    return;
                }
                var identity = (ClaimsIdentity)context.Principal.Identity!;
                foreach (var claim in identity.FindAll("roles").ToArray()) identity.RemoveClaim(claim);
                foreach (var role in roles) identity.AddClaim(new Claim("roles", role));
                identity.AddClaim(new Claim("agentharness_roles_checked", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()));
            }
            catch (IntegrationException) { context.Fail("The directory role assignment could not be verified."); }
        };
        var redirect = o.Events.OnRedirectToIdentityProvider;
        o.Events.OnRedirectToIdentityProvider = async context =>
        {
            if (redirect is not null) await redirect(context);
            if (Uri.TryCreate(settings.PublicUrl, UriKind.Absolute, out var publicUrl) && publicUrl.Scheme == "https")
                context.ProtocolMessage.RedirectUri = settings.PublicUrl.TrimEnd('/') + "/signin-oidc";
        };
        var remoteFailure = o.Events.OnRemoteFailure;
        o.Events.OnRemoteFailure = async context =>
        {
            if (remoteFailure is not null) await remoteFailure(context);
            if (context.Result?.Handled == true || context.Result?.Skipped == true) return;
            await SignInFailureHandling.OnRemoteFailureAsync(context);
        };
    });
}
else authentication.AddCookie();

builder.Services.Configure<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme, o =>
{
    o.Cookie.Name = "__Host-AgentHarness";
    o.Cookie.HttpOnly = true;
    o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    o.Cookie.SameSite = SameSiteMode.Lax;
    o.ExpireTimeSpan = TimeSpan.FromHours(1);
    o.SlidingExpiration = false;
    o.Events.OnRedirectToLogin = context =>
    {
        if (context.Request.Path.StartsWithSegments("/api")) context.Response.StatusCode = 401;
        else context.Response.Redirect("/auth/login");
        return Task.CompletedTask;
    };
    o.Events.OnRedirectToAccessDenied = context => { context.Response.StatusCode = 403; return Task.CompletedTask; };
    o.Events.OnValidatePrincipal = async context =>
    {
        if (context.Principal is null || !SecurityBoundary.IsAllowedTenantPrincipal(context.Principal, settings))
        {
            context.RejectPrincipal();
            return;
        }
        if (long.TryParse(context.Principal.FindFirstValue("agentharness_roles_checked"), out var checkedAt) &&
            DateTimeOffset.UtcNow - DateTimeOffset.FromUnixTimeSeconds(checkedAt) < TimeSpan.FromMinutes(5)) return;
        try
        {
            var roles = await context.HttpContext.RequestServices.GetRequiredService<IDirectoryService>()
                .GetCurrentRolesAsync(context.Principal.ObjectId(), context.HttpContext.RequestAborted);
            if (roles is null || !roles.Intersect(HarnessRoles.Harness).Any()) { context.RejectPrincipal(); return; }
            var identity = (ClaimsIdentity)context.Principal.Identity!;
            foreach (var claim in identity.FindAll("roles").Concat(identity.FindAll("agentharness_roles_checked")).ToArray()) identity.RemoveClaim(claim);
            foreach (var role in roles) identity.AddClaim(new Claim("roles", role));
            identity.AddClaim(new Claim("agentharness_roles_checked", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()));
            context.ShouldRenew = true;
        }
        catch (Exception ex) when (ex is IntegrationException or HttpRequestException or TaskCanceledException) { context.RejectPrincipal(); }
    };
});

var channelsEnabled = builder.Configuration.GetValue("AgentChannels:Enabled", false);
if (channelsEnabled)
{
    if (!(builder.Configuration.GetSection("TokenValidation:Audiences").Get<string[]>() ?? []).Any(x => Guid.TryParse(x, out _)))
        throw new InvalidOperationException("Agent channel authentication requires registered agent audiences.");
    Agent365AgentFrameworkSampleAgent.AspNetExtensions.AddAgentAspNetAuthentication(builder.Services,
        new Agent365AgentFrameworkSampleAgent.AspNetExtensions.TokenValidationOptions
        {
            Audiences = builder.Configuration.GetSection("TokenValidation:Audiences").Get<string[]>()!,
            TenantId = settings.TenantId
        });
    builder.AddAgentApplicationOptions();
    builder.AddAgent<HarnessChannelAgent>();
    builder.Services.AddSingleton<IStorage, SqliteAgentStorage>();
}
builder.Services.Configure<AuthenticationOptions>(o =>
{
    o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    o.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    o.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
});
builder.Services.AddAuthorization(o =>
{
    o.AddPolicy("HarnessUser", p => p.RequireAuthenticatedUser()
        .RequireAssertion(c => SecurityBoundary.IsAllowedHarnessPrincipal(c.User, settings))
        .RequireRole(HarnessRoles.Administrator, HarnessRoles.User));
    o.AddPolicy("HarnessAdmin", p => p.RequireAuthenticatedUser()
        .RequireAssertion(c => SecurityBoundary.IsAllowedAdministratorPrincipal(c.User, settings))
        .RequireRole(HarnessRoles.Administrator));
    if (channelsEnabled) o.AddPolicy("AgentTransport", p => p.AddAuthenticationSchemes("Bearer").RequireAuthenticatedUser());
});
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = 429;
    o.AddPolicy("agent-runs", context => RateLimitPartition.GetFixedWindowLimiter(
        context.User.FindFirstValue("oid") ?? "anonymous",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 10, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
});
var exporterRegistry = new AgentExporterRegistry(builder.Configuration, settings);
builder.Services.AddSingleton(exporterRegistry);
builder.UseMicrosoftOpenTelemetry(o =>
{
    o.Exporters = ExportTarget.None;
    var connection = builder.Configuration["APPLICATIONINSIGHTS_CONNECTION_STRING"];
    if (!string.IsNullOrWhiteSpace(connection))
    {
        o.Exporters |= ExportTarget.AzureMonitor;
        o.AzureMonitor.ConnectionString = connection;
    }
    if (builder.Configuration.GetValue("Agent365:EnableExporter", false))
    {
        o.Exporters |= ExportTarget.Agent365;
        o.Agent365.UseS2SEndpoint = true;
        o.Agent365.TokenResolver = exporterRegistry.ResolveAsync;
    }
    o.Instrumentation.EnableAspNetCoreInstrumentation = true;
    o.Instrumentation.EnableHttpClientInstrumentation = true;
    o.Instrumentation.EnableAzureSdkInstrumentation = true;
});
builder.Services.AddOpenTelemetry().WithTracing(t => t.AddSource("AgentHarness", "AgentHarness.Model")
    .SetResourceBuilder(ResourceBuilder.CreateDefault().AddService("AgentHarness")));

var app = builder.Build();
exporterRegistry.AttachStore(app.Services.GetRequiredService<HarnessStore>());
var store = app.Services.GetRequiredService<HarnessStore>();
var seedFile = Path.Combine(app.Environment.ContentRootPath, "seed", "agents.json");
if (File.Exists(seedFile))
{
    var seeded = System.Text.Json.JsonSerializer.Deserialize<AgentRecord[]>(File.ReadAllText(seedFile), new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web)) ?? [];
    foreach (var seed in seeded)
    {
        if (!Guid.TryParse(seed.Id, out _) || !Guid.TryParse(seed.CreatedBy, out _))
            throw new InvalidOperationException("The deployment catalog contains an invalid identity identifier.");
        SampleCatalog.Find(seed.Framework);
        if (store.GetAgent(seed.Id) is null) store.SaveAgent(seed);
    }
}
for (var i = 0; i < SampleCatalog.All.Length; i++)
{
    var id = $"a3650000-0000-4000-8000-{(i + 1):000000000000}";
    var sample = SampleCatalog.All[i];
    if (store.GetAgent(id) is null)
        store.SaveAgent(new AgentRecord(id, sample.Name, sample.Id, sample.Description,
            builder.Configuration["Bootstrap:AdministratorObjectId"] ?? "", DateTimeOffset.UtcNow));
}
if (registerSamples || validateSamples)
{
    var actor = builder.Configuration["Bootstrap:AdministratorObjectId"] ?? "";
    var roles = await app.Services.GetRequiredService<IDirectoryService>().GetCurrentRolesAsync(actor, CancellationToken.None);
    if (roles?.Contains(HarnessRoles.Administrator) != true) throw new InvalidOperationException("The bootstrap sponsor must have the real harness administrator role.");
    foreach (var agent in store.GetAgents())
    {
        try
        {
            var provisioning = app.Services.GetRequiredService<AgentProvisioningService>();
            var registered = registerSamples ? await provisioning.RegisterAsync(agent.Id, actor, CancellationToken.None) : agent;
            if (validateSamples)
            {
                await provisioning.ValidateAsync(agent.Id, actor, CancellationToken.None);
                registered = store.GetAgent(agent.Id)!;
            }
            Console.WriteLine($"{registered.Name}: {registered.Status}; identity {registered.AgentClientId}; registry {registered.RegistryId}");
        }
        catch (IntegrationException ex)
        {
            Console.Error.WriteLine($"{agent.Name}: blocked: {ex.Message}");
            if (ex.ServiceMessage is not null) Console.Error.WriteLine($"Service diagnostic: {ex.ServiceMessage}");
            Environment.ExitCode = 1;
        }
    }
    store.ExportCatalog();
    await app.DisposeAsync();
    return;
}

app.UseExceptionHandler(error => error.Run(async context =>
{
    var exception = context.Features.Get<IExceptionHandlerFeature>()?.Error;
    var status = exception is IntegrationException integration ? integration.StatusCode : 500;
    if (status is < 400 or > 599) status = 500;
    context.Response.StatusCode = status;
    var message = exception is IntegrationException ? exception.Message : "The operation could not complete. Check its trace and integration prerequisites.";
    await Results.Problem(message, statusCode: status, extensions: new Dictionary<string, object?>
    {
        ["traceId"] = Activity.Current?.TraceId.ToString()
    }).ExecuteAsync(context);
}));
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["Referrer-Policy"] = "same-origin";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self' https://login.microsoftonline.com";
    if (context.Request.Path.StartsWithSegments("/api")) context.Response.Headers.CacheControl = "no-store";
    await next(context);
});
if (!app.Environment.IsDevelopment()) app.UseHsts();
app.UseDefaultFiles();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();
app.Use(async (context, next) =>
{
    var isMutation = HttpMethods.IsPost(context.Request.Method) || HttpMethods.IsPut(context.Request.Method) || HttpMethods.IsPatch(context.Request.Method) || HttpMethods.IsDelete(context.Request.Method);
    if (isMutation && context.Request.Path.StartsWithSegments("/api") && context.Request.Path != "/api/messages")
    {
        try { await context.RequestServices.GetRequiredService<IAntiforgery>().ValidateRequestAsync(context); }
        catch (AntiforgeryValidationException)
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsJsonAsync(new { error = "A valid same-origin antiforgery token is required." });
            return;
        }
    }
    await next(context);
});
app.MapGet("/healthz", () => Results.Ok(new { status = "healthy", application = "AgentHarness" })).AllowAnonymous();
app.MapGet("/api/session", (HttpContext context) => Results.Ok(new
{
    authenticated = SecurityBoundary.IsAllowedHarnessPrincipal(context.User, settings) &&
        (context.User.IsInRole(HarnessRoles.User) || context.User.IsInRole(HarnessRoles.Administrator)),
    name = context.User.Identity?.IsAuthenticated == true ? context.User.Identity.Name : null,
    administrator = SecurityBoundary.IsAllowedAdministratorPrincipal(context.User, settings) && context.User.IsInRole(HarnessRoles.Administrator),
    tenant = settings.TenantName,
    tenantId = settings.TenantId,
    identityConfigured = settings.IsIdentityConfigured,
    graviteeConsoleAuthMode = settings.GraviteeConsoleAuthMode,
    signInReady = !string.IsNullOrWhiteSpace(builder.Configuration["AzureAd:ClientSecret"]),
    hostingConfigured = !string.IsNullOrWhiteSpace(settings.SubscriptionId)
})).AllowAnonymous();
app.MapGet("/auth/login", () =>
    settings.IsIdentityConfigured && !string.IsNullOrWhiteSpace(builder.Configuration["AzureAd:ClientSecret"])
        ? Results.Challenge(new AuthenticationProperties { RedirectUri = "/" }, [OpenIdConnectDefaults.AuthenticationScheme])
        : Results.Problem("Configure the Entra application IDs and hosting credential before signing in. No local authentication bypass is provided.", statusCode: 503)).AllowAnonymous();
app.MapGet(SignInFailureHandling.ExpiredPath, SignInFailureHandling.ExpiredPage).AllowAnonymous();
app.MapPost("/api/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Ok(new { signedOut = true });
}).RequireAuthorization("HarnessUser");

var api = app.MapGroup("/api").RequireAuthorization("HarnessUser");
api.MapGet("/csrf", (HttpContext context, IAntiforgery antiforgery) =>
    Results.Ok(new { token = antiforgery.GetAndStoreTokens(context).RequestToken }));
api.MapGet("/samples", () => new { samples = SampleCatalog.All, SampleCatalog.Commit, SampleCatalog.Repository });
api.MapGet("/agents", () => store.GetAgents());
api.MapGet("/demo", (DemoOverviewService overview) => overview.GetOverview());
api.MapGet("/agents/{id:guid}/evidence", (string id) => store.GetEvidence(id));
api.MapGet("/sources", (SourceCatalog sources) => sources.Paths);
api.MapGet("/source", (string path, SourceCatalog sources) => Results.Text(sources.Read(path), "text/plain"));
api.MapGet("/portals", (GovernanceService governance) => governance.Portals());
api.MapGet("/integrations", (ClaimsPrincipal user, GovernanceService governance, CancellationToken ct) => governance.CheckAsync(user.ObjectId(), ct));
api.MapPost("/agents/{id:guid}/run", async (string id, RunRequest request, ClaimsPrincipal user, IAgentRuntime runtime, CancellationToken ct) =>
{
    var agent = store.GetAgent(id) ?? throw new IntegrationException("Agent not found.", 404);
    return await runtime.RunAsync(agent, request.Prompt, user.ObjectId(), ct);
}).RequireRateLimiting("agent-runs");
api.MapPost("/gateway/invoke", (GatewayRequest request, ClaimsPrincipal user, GraviteeService gateway, CancellationToken ct) => gateway.InvokeAsync(request.Operation, user, ct))
    .RequireRateLimiting("agent-runs");

var admin = api.MapGroup("/admin").RequireAuthorization("HarnessAdmin");
admin.MapGet("/users", (string query, IDirectoryService directory, CancellationToken ct) => directory.SearchAsync(query, ct));
admin.MapGet("/assignments", (string application, IDirectoryService directory, CancellationToken ct) => directory.GetAssignmentsAsync(application, ct));
admin.MapPost("/assignments", async (AssignmentRequest request, ClaimsPrincipal user, IDirectoryService directory, CancellationToken ct) =>
{
    await directory.AssignAsync(request, user.ObjectId(), ct);
    return Results.Ok(new { assigned = true });
});
admin.MapDelete("/assignments/{application}/{id}", async (string application, string id, ClaimsPrincipal user, IDirectoryService directory, CancellationToken ct) =>
{
    await directory.RemoveAsync(application, id, user.ObjectId(), ct);
    return Results.NoContent();
});
admin.MapGet("/audit", () => store.GetAudit());
admin.MapPost("/agents", (NewAgentRequest request, ClaimsPrincipal user) =>
{
    if (string.IsNullOrWhiteSpace(request.Name) || request.Name.Length is < 3 or > 80 ||
        request.Name.Any(char.IsControl) || request.Description is null || request.Description.Length > 1000)
        throw new IntegrationException("Agent names must be 3-80 characters and descriptions at most 1,000 characters.", 400);
    SampleCatalog.Find(request.Framework);
    var agent = new AgentRecord(Guid.NewGuid().ToString(), request.Name.Trim(), request.Framework, request.Description.Trim(), user.ObjectId(), DateTimeOffset.UtcNow);
    store.SaveAgent(agent);
    store.Audit(user.ObjectId(), "AgentDraftCreated", agent.Id, "Succeeded");
    return Results.Created("/api/agents/" + agent.Id, agent);
});
admin.MapPost("/agents/{id:guid}/register", (string id, ClaimsPrincipal user, AgentProvisioningService provisioning, CancellationToken ct) => provisioning.RegisterAsync(id, user.ObjectId(), ct));
admin.MapPost("/agents/{id:guid}/extend", (string id, CapabilitiesRequest request, ClaimsPrincipal user, AgentProvisioningService provisioning, CancellationToken ct) =>
    provisioning.ExtendAsync(id, request.Capabilities ?? [], user.ObjectId(), ct));
admin.MapPost("/agents/{id:guid}/validate", (string id, ClaimsPrincipal user, AgentProvisioningService provisioning, CancellationToken ct) => provisioning.ValidateAsync(id, user.ObjectId(), ct));
admin.MapPost("/agents/{id:guid}/disable", async (string id, ClaimsPrincipal user, AgentProvisioningService provisioning, CancellationToken ct) =>
{
    await provisioning.DisableAsync(id, user.ObjectId(), ct);
    return Results.Ok(new { disabled = true });
});
admin.MapPost("/agents/{id:guid}/enable", async (string id, ClaimsPrincipal user, AgentProvisioningService provisioning, CancellationToken ct) =>
{
    await provisioning.EnableAsync(id, user.ObjectId(), ct);
    return Results.Ok(new { enabled = true });
});
admin.MapPost("/agents/{id:guid}/schedule", (string id, ScheduleRequest request, ClaimsPrincipal user) =>
{
    var agent = store.GetAgent(id) ?? throw new IntegrationException("Agent not found.", 404);
    if (agent.Framework != "autonomous" || (request.Enabled && (agent.Status == "Disabled" || agent.RegistryId is null)))
        throw new IntegrationException("Only a registered, enabled autonomous agent can be scheduled.", 409);
    store.SaveAgent(agent with { ScheduleEnabled = request.Enabled, CreatedBy = user.ObjectId() });
    store.Audit(user.ObjectId(), "AutonomousScheduleChanged", id, request.Enabled ? "Enabled" : "Disabled");
    return Results.Ok(new { enabled = request.Enabled });
});
admin.MapPost("/gravitee/credentials", (ClaimsPrincipal user, GraviteeService gateway, CancellationToken ct) => gateway.CredentialsAsync(user.ObjectId(), ct));
if (channelsEnabled)
{
    app.MapPost("/api/messages", async (HttpRequest request, HttpResponse response, IAgentHttpAdapter adapter, IAgent agent, CancellationToken ct) =>
        await adapter.ProcessAsync(request, response, agent, ct)).RequireAuthorization("AgentTransport");
}
await app.RunAsync();

public partial class Program;
