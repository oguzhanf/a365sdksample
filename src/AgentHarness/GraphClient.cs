// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

extern alias ObservabilityIdentity;

using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Azure.Core;
using Microsoft.Extensions.Options;
using ClientSecretCredential = ObservabilityIdentity::Azure.Identity.ClientSecretCredential;
using ManagedIdentityCredential = ObservabilityIdentity::Azure.Identity.ManagedIdentityCredential;
using CredentialUnavailableException = ObservabilityIdentity::Azure.Identity.CredentialUnavailableException;
using AuthenticationFailedException = ObservabilityIdentity::Azure.Identity.AuthenticationFailedException;

namespace AgentHarness;

public interface IGraphClient
{
    Task<JsonObject> SendAsync(HttpMethod method, string path, JsonNode? body = null,
        CancellationToken cancellationToken = default, string? etag = null);
}

public sealed class GraphClient(IHttpClientFactory factory, IConfiguration configuration, IOptions<HarnessOptions> options) : IGraphClient
{
    private readonly TokenCredential credential = CreateCredential(configuration, options.Value);

    private static TokenCredential CreateCredential(IConfiguration config, HarnessOptions options)
    {
        var secret = config["AzureAd:ClientSecret"];
        return !string.IsNullOrWhiteSpace(secret) && Guid.TryParse(options.ClientId, out _)
            ? new ClientSecretCredential(options.TenantId, options.ClientId, secret)
            : new ManagedIdentityCredential();
    }

    public async Task<JsonObject> SendAsync(HttpMethod method, string path, JsonNode? body = null,
        CancellationToken cancellationToken = default, string? etag = null)
    {
        if (!path.StartsWith("v1.0/", StringComparison.Ordinal) && !path.StartsWith("beta/", StringComparison.Ordinal))
            throw new ArgumentException("Only relative Microsoft Graph API paths are supported.", nameof(path));
        var uri = new Uri("https://graph.microsoft.com/" + path);
        if (uri.Host != "graph.microsoft.com" || uri.Scheme != "https")
            throw new ArgumentException("Invalid Microsoft Graph endpoint.", nameof(path));
        AccessToken token;
        try
        {
            token = await credential.GetTokenAsync(new TokenRequestContext(["https://graph.microsoft.com/.default"]), cancellationToken);
        }
        catch (Exception ex) when (ex is CredentialUnavailableException or AuthenticationFailedException)
        {
            throw new IntegrationException("The harness workload identity cannot obtain a Microsoft Graph application token. Complete Entra provisioning and admin consent.");
        }
        using var request = new HttpRequestMessage(method, uri);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);
        request.Headers.Add("OData-Version", "4.0");
        if (method == HttpMethod.Get && path.Contains("$count=true", StringComparison.Ordinal))
            request.Headers.Add("ConsistencyLevel", "eventual");
        if (etag is not null) request.Headers.TryAddWithoutValidation("If-None-Match", etag);
        if (body is not null) request.Content = JsonContent.Create(body);
        using var response = await factory.CreateClient("graph").SendAsync(request, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            var code = "";
            string? serviceMessage = null;
            try
            {
                var error = await response.Content.ReadFromJsonAsync<JsonObject>(cancellationToken);
                code = error?["error"]?["code"]?.GetValue<string>() ?? "";
                serviceMessage = error?["error"]?["message"]?.GetValue<string>()?.Replace(token.Token, "[redacted]", StringComparison.Ordinal);
                if (serviceMessage?.Length > 2000) serviceMessage = serviceMessage[..2000];
            }
            catch (System.Text.Json.JsonException) { }
            throw new IntegrationException($"Microsoft Graph returned {(int)response.StatusCode} ({code}). Check the recorded Entra permissions, tenant feature availability, and consent.", (int)response.StatusCode)
            {
                ServiceCode = code,
                ServiceMessage = serviceMessage
            };
        }
        if (response.StatusCode == System.Net.HttpStatusCode.NoContent) return [];
        var result = await response.Content.ReadFromJsonAsync<JsonObject>(cancellationToken) ?? [];
        if (response.Headers.ETag is not null) result["_etag"] = response.Headers.ETag.ToString();
        return result;
    }
}
