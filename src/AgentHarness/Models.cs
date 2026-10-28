// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace AgentHarness;

public sealed class HarnessOptions
{
    public string TenantId { get; set; } = "";
    public string TenantName { get; set; } = "Your organization";
    public string ClientId { get; set; } = "";
    public string ServicePrincipalId { get; set; } = "";
    public string InternalApiClientId { get; set; } = "";
    public string InternalApiServicePrincipalId { get; set; } = "";
    public string GraviteeClientId { get; set; } = "";
    public string GraviteeServicePrincipalId { get; set; } = "";
    public string GraviteeUrl { get; set; } = "";
    public string GraviteeConsoleAuthMode { get; set; } = "password";
    public string KeyVaultUri { get; set; } = "";
    public string SubscriptionId { get; set; } = "";
    public string ResourceGroup { get; set; } = "rg-agentharness-demo";
    public string OpenAiResourceId { get; set; } = "";
    public string ManagedIdentityPrincipalId { get; set; } = "";
    public string PublicUrl { get; set; } = "";
    public string[] AllowedB2BGuestObjectIds { get; set; } = [];
    public string[] AllowedB2BGuestAdministratorObjectIds { get; set; } = [];
    public bool IsIdentityConfigured =>
        Guid.TryParse(TenantId, out var tenant) && tenant != Guid.Empty &&
        Guid.TryParse(ClientId, out var client) && client != Guid.Empty &&
        Guid.TryParse(ServicePrincipalId, out var principal) && principal != Guid.Empty;
}

public static class HarnessRoles
{
    public const string Administrator = "AgentHarnessAdministrators";
    public const string User = "AgentHarnessUsers";
    public const string Reader = "InternalApi.Reader";
    public const string Approver = "InternalApi.Approver";
    public const string GraviteeAdministrator = "Gravitee.Administrator";
    public const string GraviteeUser = "Gravitee.User";
    public static readonly string[] Harness = [Administrator, User];
    public static readonly string[] InternalApi = [Reader, Approver];
    public static readonly string[] Gravitee = [GraviteeAdministrator, GraviteeUser];
}

public sealed record AgentRecord(
    string Id, string Name, string Framework, string Description, string CreatedBy,
    DateTimeOffset CreatedAt, string? BlueprintObjectId = null, string? BlueprintClientId = null,
    string? AgentObjectId = null, string? AgentClientId = null, string? RegistryId = null,
    string[]? Capabilities = null, bool ScheduleEnabled = false,
    string Status = "Draft", string? AgentUserId = null);

public sealed record Evidence(
    string Id, string AgentId, string Stage, string State, string Summary,
    DateTimeOffset ObservedAt, string? CorrelationId = null, string? CheckId = null);

public sealed record AuditEvent(
    string Id, string ActorId, string Action, string Target, string Outcome,
    DateTimeOffset Timestamp, string? TraceId = null);

public sealed record RunResult(string Text, string TraceId, string Framework, string[] Steps, bool Live);
public sealed record NewAgentRequest(string Name, string Framework, string Description);
public sealed record RunRequest(string Prompt);
public sealed record AssignmentRequest(string UserId, string Application, string Role);
public sealed record CapabilitiesRequest(string[] Capabilities);
public sealed record ScheduleRequest(bool Enabled);
public sealed record DirectoryUser(
    string Id, string DisplayName, string UserPrincipalName, string UserType, bool AccountEnabled,
    string? ExternalUserState = null, bool PrivilegedGuestApproved = false);
public sealed record RoleDefinition(string Id, string Value, string DisplayName);
public sealed record RoleAssignment(string Id, string PrincipalId, string PrincipalDisplayName, string AppRoleId, string Role, string Application);
public sealed record GatewayRequest(string Operation);
public sealed record IntegrationCheck(string Name, string State, string Detail, string? Portal = null);

public sealed class IntegrationException(string message, int statusCode = 503) : Exception(message)
{
    public int StatusCode { get; } = statusCode;
    public string? ServiceCode { get; init; }
    public string? ServiceMessage { get; init; }
}
