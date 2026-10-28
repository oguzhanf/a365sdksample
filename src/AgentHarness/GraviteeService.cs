// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

extern alias ObservabilityIdentity;

using System.Diagnostics;
using System.Net.Http.Headers;
using System.Security.Claims;
using Azure.Core;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Web;
using Microsoft.IdentityModel.JsonWebTokens;
using AzureCliCredential = ObservabilityIdentity::Azure.Identity.AzureCliCredential;
using AzureCliCredentialOptions = ObservabilityIdentity::Azure.Identity.AzureCliCredentialOptions;
using ManagedIdentityCredential = ObservabilityIdentity::Azure.Identity.ManagedIdentityCredential;
using ClientSecretCredential = ObservabilityIdentity::Azure.Identity.ClientSecretCredential;

namespace AgentHarness;

public sealed class GraviteeService(
    IHttpClientFactory factory, IOptions<HarnessOptions> options, IConfiguration configuration,
    IServiceProvider services, HarnessStore store)
{
    private readonly HarnessOptions _settings = options.Value;

    public async Task<object> InvokeAsync(string operation, ClaimsPrincipal user, CancellationToken ct)
    {
        if (operation is not ("read" or "approve" or "anonymous" or "wrong-audience"))
            throw new IntegrationException("Unsupported authorization lab operation.", 400);
        if (!Uri.TryCreate(_settings.GraviteeUrl, UriKind.Absolute, out var origin) || origin.Scheme != "https" ||
            origin.UserInfo.Length != 0 || origin.Query.Length != 0 || origin.Fragment.Length != 0)
            throw new IntegrationException("The Gravitee HTTPS endpoint is not deployed or configured.");
        var path = operation == "approve" ? "gateway/internal/purchaseorders/PO-1001/approve" : "gateway/internal/purchaseorders";
        using var request = new HttpRequestMessage(operation == "approve" ? HttpMethod.Post : HttpMethod.Get, new Uri(origin.AbsoluteUri.TrimEnd('/') + "/" + path));
        string? token = null;
        if (operation == "wrong-audience")
        {
            var secret = configuration["AzureAd:ClientSecret"];
            if (string.IsNullOrWhiteSpace(secret)) throw new IntegrationException("The harness workload credential is not configured.");
            var credential = new ClientSecretCredential(_settings.TenantId, _settings.ClientId, secret);
            token = (await credential.GetTokenAsync(new TokenRequestContext(["https://graph.microsoft.com/.default"]), ct)).Token;
        }
        else if (operation != "anonymous")
        {
            try
            {
                var acquisition = services.GetRequiredService<ITokenAcquisition>();
                token = await acquisition.GetAccessTokenForUserAsync([$"api://{_settings.InternalApiClientId}/access_as_user"], user: user);
            }
            catch (Exception ex) when (ex is MicrosoftIdentityWebChallengeUserException or Microsoft.Identity.Client.MsalUiRequiredException)
            {
                throw new IntegrationException("The internal API scope could not be acquired silently. Sign out and sign in after administrator consent or a role-assignment change.", 409);
            }
        }
        if (token is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await factory.CreateClient("gateway").SendAsync(request, ct);
        var body = await response.Content.ReadAsStringAsync(ct);
        if (body.Length > 20000) body = body[..20000];
        if (token is not null) body = body.Replace(token, "[redacted]", StringComparison.Ordinal);
        var jwt = token is not null ? new JsonWebToken(token) : null;
        var claims = jwt?.Claims.Where(c => c.Type is "iss" or "aud" or "tid" or "azp" or "scp" or "roles")
            .GroupBy(c => c.Type).ToDictionary(g => g.Key, g => g.Select(c => c.Value).ToArray());
        var status = (int)response.StatusCode;
        store.Audit(user.ObjectId(), "Gravitee." + operation, "PrivatePurchaseOrderApi", "HTTP " + status);
        return new
        {
            statusCode = status, body,
            decision = status is >= 200 and < 300 ? "Allowed by the deployed gateway" :
                status is 401 or 403 ? "Denied by the deployed gateway" : "Gateway/backend failure; not an authorization verdict",
            traceId = Activity.Current?.TraceId.ToString(),
            claims
        };
    }

    public async Task<object> CredentialsAsync(string actor, CancellationToken ct)
    {
        if (!Uri.TryCreate(_settings.KeyVaultUri, UriKind.Absolute, out var vault) || vault.Scheme != "https" ||
            !vault.Host.EndsWith(".vault.azure.net", StringComparison.OrdinalIgnoreCase))
            throw new IntegrationException("The deployment's Key Vault is not configured. No default password is supplied.");
        TokenCredential credential = Environment.GetEnvironmentVariable("WEBSITE_INSTANCE_ID") is null
            ? new AzureCliCredential(new AzureCliCredentialOptions { TenantId = _settings.TenantId })
            : new ManagedIdentityCredential();
        var secret = await new SecretClient(vault, credential).GetSecretAsync("gravitee-demo-admin-password", cancellationToken: ct);
        store.Audit(actor, "GraviteeCredentialViewed", "Gravitee", "Succeeded");
        return new { username = "demo-admin", password = secret.Value.Value, url = _settings.GraviteeUrl, consoleAuthMode = _settings.GraviteeConsoleAuthMode };
    }
}
