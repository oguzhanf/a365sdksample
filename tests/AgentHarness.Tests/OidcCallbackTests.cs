// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using AgentHarness;

namespace AgentHarness.Tests;

public sealed class OidcCallbackTests
{
    [Fact]
    public async Task Missing_correlation_cookie_redirects_to_expired_page_and_remains_anonymous()
    {
        using var data = new TestDataDirectory();
        using var factory = new OidcWebApplicationFactory(data.DirectoryPath);
        using var client = CreateClient(factory);
        var attempt = await BeginSignInAsync(client);

        using var callbackResponse = await PostCallbackAsync(client, attempt.State);

        AssertExpiredRedirect(callbackResponse);
        AssertNoHarnessAuthenticationCookie(callbackResponse);
        Assert.Empty(factory.Graph.Calls);
        Assert.Equal(0, factory.BackchannelHandler.CallCount);

        using var sessionResponse = await client.GetAsync("/api/session");
        Assert.Equal(HttpStatusCode.OK, sessionResponse.StatusCode);
        var session = await sessionResponse.Content.ReadFromJsonAsync<JsonElement>();
        Assert.False(session.GetProperty("authenticated").GetBoolean());

        using var adminResponse = await client.GetAsync("/api/admin/audit");
        Assert.Equal(HttpStatusCode.Unauthorized, adminResponse.StatusCode);
        Assert.Null(adminResponse.Headers.Location);
    }

    [Fact]
    public async Task Wrong_correlation_cookie_redirects_without_redeeming_the_code()
    {
        using var data = new TestDataDirectory();
        using var factory = new OidcWebApplicationFactory(data.DirectoryPath);
        using var client = CreateClient(factory);
        var attempt = await BeginSignInAsync(client);

        using var callbackResponse = await PostCallbackAsync(
            client,
            attempt.State,
            $"{attempt.CorrelationCookieName}=wrong");

        AssertExpiredRedirect(callbackResponse);
        AssertNoHarnessAuthenticationCookie(callbackResponse);
        Assert.Empty(factory.Graph.Calls);
        Assert.Equal(0, factory.BackchannelHandler.CallCount);
    }

    [Fact]
    public async Task Expired_sign_in_page_is_anonymous_non_cacheable_and_has_local_retry_link()
    {
        using var data = new TestDataDirectory();
        using var factory = new OidcWebApplicationFactory(data.DirectoryPath);
        using var client = CreateClient(factory);

        using var response = await client.GetAsync(SignInFailureHandling.ExpiredPath);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);
        var html = await response.Content.ReadAsStringAsync();
        Assert.Contains("Sign-in session expired", html, StringComparison.Ordinal);
        Assert.Contains("href=\"/auth/login\"", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Oidc_handler_validates_signed_tokens_with_raw_tenant_boundary_claims()
    {
        using var data = new TestDataDirectory();
        using var factory = new OidcWebApplicationFactory(data.DirectoryPath);
        var options = factory.Services
            .GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>()
            .Get(OpenIdConnectDefaults.AuthenticationScheme);
        var tokenHandler = Assert.IsType<JsonWebTokenHandler>(options.TokenHandler);
        const string issuer = "https://login.microsoftonline.com/test/v2.0";
        const string audience = "oidc-regression-test";
        var signingKey = new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32));
        var validationParameters = options.TokenValidationParameters.Clone();
        validationParameters.ValidIssuer = issuer;
        validationParameters.ValidAudience = audience;
        validationParameters.IssuerSigningKey = signingKey;
        validationParameters.ValidateIssuer = true;
        validationParameters.ValidateAudience = true;
        validationParameters.ValidateIssuerSigningKey = true;
        validationParameters.ValidateLifetime = true;
        validationParameters.ClockSkew = TimeSpan.Zero;

        var member = await ValidatePrincipalAsync(
            tokenHandler,
            validationParameters,
            signingKey,
            issuer,
            audience,
            TestIdentity.TenantId,
            "0");
        var foreignTenant = await ValidatePrincipalAsync(
            tokenHandler,
            validationParameters,
            signingKey,
            issuer,
            audience,
            TestIdentity.OtherTenantId,
            "0");
        var guest = await ValidatePrincipalAsync(
            tokenHandler,
            validationParameters,
            signingKey,
            issuer,
            audience,
            TestIdentity.TenantId,
            "1");

        Assert.False(options.MapInboundClaims);
        Assert.False(tokenHandler.MapInboundClaims);
        Assert.Equal("name", options.TokenValidationParameters.NameClaimType);
        Assert.Equal("roles", options.TokenValidationParameters.RoleClaimType);
        Assert.NotNull(member.FindFirst("tid"));
        Assert.NotNull(member.FindFirst("oid"));
        Assert.True(SecurityBoundary.IsTenantMember(member, TestIdentity.TenantId));
        Assert.Equal(TestIdentity.MemberObjectId, member.ObjectId());
        Assert.False(SecurityBoundary.IsTenantMember(foreignTenant, TestIdentity.TenantId));
        Assert.False(SecurityBoundary.IsTenantMember(guest, TestIdentity.TenantId));
    }

    [Fact]
    public async Task Nested_exact_correlation_failure_is_handled()
    {
        using var services = new ServiceCollection().AddLogging().BuildServiceProvider();
        var context = CreateFailureContext(
            services,
            new InvalidOperationException(
                "Remote authentication failed.",
                new AuthenticationFailureException("Correlation failed.")));

        await SignInFailureHandling.OnRemoteFailureAsync(context);

        Assert.True(context.Result?.Handled);
        Assert.Equal(StatusCodes.Status303SeeOther, context.Response.StatusCode);
        Assert.Equal(SignInFailureHandling.ExpiredPath, context.Response.Headers.Location.ToString());
        Assert.Equal("no-store", context.Response.Headers.CacheControl.ToString());
    }

    [Fact]
    public async Task Non_correlation_failures_are_left_untouched()
    {
        using var services = new ServiceCollection().AddLogging().BuildServiceProvider();
        var failures = new Exception[]
        {
            new InvalidOperationException("Correlation failed."),
            new AuthenticationFailureException("correlation failed."),
            new AuthenticationFailureException("Correlation failed. ")
        };

        foreach (var failure in failures)
        {
            var context = CreateFailureContext(services, failure);

            await SignInFailureHandling.OnRemoteFailureAsync(context);

            Assert.False(context.Result?.Handled ?? false);
            Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
            Assert.False(context.Response.Headers.ContainsKey("Location"));
            Assert.False(context.Response.Headers.ContainsKey("Cache-Control"));
        }
    }

    private static HttpClient CreateClient(WebApplicationFactory<Program> factory) =>
        factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = new Uri("https://localhost"),
            HandleCookies = false
        });

    private static async Task<LoginAttempt> BeginSignInAsync(HttpClient client)
    {
        using var response = await client.GetAsync("/auth/login");
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location
            ?? throw new InvalidOperationException("The OIDC challenge did not return a redirect.");
        var query = QueryHelpers.ParseQuery(location.Query);
        var state = query["state"].ToString();
        if (string.IsNullOrWhiteSpace(state))
            throw new InvalidOperationException("The OIDC challenge did not return protected state.");

        if (!response.Headers.TryGetValues("Set-Cookie", out var setCookieHeaders))
            throw new InvalidOperationException("The OIDC challenge did not set a correlation cookie.");
        var correlationHeader = setCookieHeaders.FirstOrDefault(
            value => value.StartsWith(".AspNetCore.Correlation.", StringComparison.Ordinal));
        if (correlationHeader is null)
            throw new InvalidOperationException("The OIDC challenge did not set a correlation cookie.");
        var separator = correlationHeader.IndexOf('=', StringComparison.Ordinal);
        if (separator <= 0)
            throw new InvalidOperationException("The OIDC correlation cookie was malformed.");

        return new LoginAttempt(state, correlationHeader[..separator]);
    }

    private static async Task<HttpResponseMessage> PostCallbackAsync(
        HttpClient client,
        string state,
        string? cookie = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/signin-oidc")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["state"] = state,
                ["code"] = "dummy-code"
            })
        };
        if (cookie is not null)
            request.Headers.TryAddWithoutValidation("Cookie", cookie);
        return await client.SendAsync(request);
    }

    private static void AssertExpiredRedirect(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
        Assert.Equal(SignInFailureHandling.ExpiredPath, response.Headers.Location?.OriginalString);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
    }

    private static void AssertNoHarnessAuthenticationCookie(HttpResponseMessage response)
    {
        var hasAuthenticationCookie = response.Headers.TryGetValues("Set-Cookie", out var values) &&
            values.Any(value => value.StartsWith("__Host-AgentHarness=", StringComparison.Ordinal));
        Assert.False(hasAuthenticationCookie);
    }

    private static RemoteFailureContext CreateFailureContext(IServiceProvider services, Exception failure)
    {
        var httpContext = new DefaultHttpContext { RequestServices = services };
        var scheme = new AuthenticationScheme(
            OpenIdConnectDefaults.AuthenticationScheme,
            OpenIdConnectDefaults.AuthenticationScheme,
            typeof(OpenIdConnectHandler));
        return new RemoteFailureContext(httpContext, scheme, new OpenIdConnectOptions(), failure);
    }

    private static async Task<System.Security.Claims.ClaimsPrincipal> ValidatePrincipalAsync(
        JsonWebTokenHandler tokenHandler,
        TokenValidationParameters validationParameters,
        SecurityKey signingKey,
        string issuer,
        string audience,
        string tenantId,
        string accountType)
    {
        var token = tokenHandler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            NotBefore = DateTime.UtcNow.AddMinutes(-1),
            Expires = DateTime.UtcNow.AddMinutes(5),
            SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256),
            Claims = new Dictionary<string, object>
            {
                ["tid"] = tenantId,
                ["oid"] = TestIdentity.MemberObjectId,
                ["acct"] = accountType,
                ["name"] = "OIDC regression test principal",
                ["roles"] = new[] { HarnessRoles.User }
            }
        });
        var result = await tokenHandler.ValidateTokenAsync(token, validationParameters);
        Assert.True(result.IsValid, result.Exception?.GetType().Name);
        var identity = Assert.IsAssignableFrom<System.Security.Claims.ClaimsIdentity>(result.ClaimsIdentity);
        return new System.Security.Claims.ClaimsPrincipal(identity);
    }

    private sealed record LoginAttempt(string State, string CorrelationCookieName);
}

internal sealed class OidcWebApplicationFactory(string dataPath) : WebApplicationFactory<Program>
{
    public RecordingGraphClient Graph { get; } = new();
    public RejectingOidcBackchannelHandler BackchannelHandler { get; } = new();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("Harness:TenantId", TestIdentity.TenantId);
        builder.UseSetting("Harness:ClientId", TestIdentity.HarnessClientId);
        builder.UseSetting("Harness:ServicePrincipalId", TestIdentity.HarnessServicePrincipalId);
        builder.UseSetting("AzureAd:TenantId", TestIdentity.TenantId);
        builder.UseSetting("AzureAd:ClientId", TestIdentity.HarnessClientId);
        builder.UseSetting("AzureAd:ClientSecret", "dummy-test-only-value");
        builder.UseSetting("Data:Path", dataPath);
        builder.UseSetting("Autonomous:IntervalSeconds", "86400");
        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IGraphClient>();
            services.AddSingleton<IGraphClient>(Graph);
            services.PostConfigure<OpenIdConnectOptions>(
                OpenIdConnectDefaults.AuthenticationScheme,
                options =>
                {
                    var authority = $"https://login.microsoftonline.com/{TestIdentity.TenantId}";
                    options.ConfigurationManager =
                        new StaticConfigurationManager<OpenIdConnectConfiguration>(
                            new OpenIdConnectConfiguration
                            {
                                Issuer = $"{authority}/v2.0",
                                AuthorizationEndpoint = $"{authority}/oauth2/v2.0/authorize",
                                TokenEndpoint = $"{authority}/oauth2/v2.0/token"
                            });
                    options.BackchannelHttpHandler = BackchannelHandler;
                    options.Backchannel = new HttpClient(BackchannelHandler, disposeHandler: false);
                });
        });
    }
}

internal sealed class RejectingOidcBackchannelHandler : HttpMessageHandler
{
    private int callCount;

    public int CallCount => Volatile.Read(ref callCount);

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref callCount);
        throw new InvalidOperationException("OIDC backchannel network access is not allowed in this test.");
    }
}
