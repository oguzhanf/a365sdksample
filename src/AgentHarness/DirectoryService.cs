// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Claims;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Options;

namespace AgentHarness;

public interface IDirectoryService
{
    Task<IReadOnlyList<DirectoryUser>> SearchAsync(string query, CancellationToken ct);
    Task<IReadOnlyList<RoleAssignment>> GetAssignmentsAsync(string application, CancellationToken ct);
    Task AssignAsync(AssignmentRequest request, string actor, CancellationToken ct);
    Task RemoveAsync(string application, string assignmentId, string actor, CancellationToken ct);
    Task<string[]?> GetCurrentRolesAsync(string objectId, CancellationToken ct);
}

public sealed class DirectoryService(IGraphClient graph, IOptions<HarnessOptions> options, HarnessStore store) : IDirectoryService
{
    private readonly HarnessOptions settings = options.Value;
    private readonly SemaphoreSlim assignmentLock = new(1, 1);

    private (string Id, string[] Roles) Target(string application) => application switch
    {
        "harness" when Guid.TryParse(settings.ServicePrincipalId, out _) => (settings.ServicePrincipalId, HarnessRoles.Harness),
        "internal-api" when Guid.TryParse(settings.InternalApiServicePrincipalId, out _) => (settings.InternalApiServicePrincipalId, HarnessRoles.InternalApi),
        "gravitee" when Guid.TryParse(settings.GraviteeServicePrincipalId, out _) => (settings.GraviteeServicePrincipalId, HarnessRoles.Gravitee),
        _ => throw new IntegrationException("This application is not provisioned or is outside the harness permission boundary.", 400)
    };

    public async Task<IReadOnlyList<DirectoryUser>> SearchAsync(string query, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(query) || query.Length > 80)
            throw new IntegrationException("Enter a directory search between 1 and 80 characters.", 400);
        var escaped = query.Trim().Replace("'", "''", StringComparison.Ordinal);
        var approvedIds = (settings.AllowedB2BGuestObjectIds ?? [])
            .Where(x => Guid.TryParse(x, out _)).Select(x => Guid.Parse(x).ToString()).Distinct().ToArray();
        var users = "userType eq 'Member'";
        if (approvedIds.Length > 0)
            users += " or (userType eq 'Guest' and (" + string.Join(" or ", approvedIds.Select(id => $"id eq '{id}'")) + "))";
        var filter = Uri.EscapeDataString($"({users}) and accountEnabled eq true and (startswith(displayName,'{escaped}') or startswith(userPrincipalName,'{escaped}'))");
        var response = await graph.SendAsync(HttpMethod.Get, $"v1.0/users?$filter={filter}&$select=id,displayName,userPrincipalName,userType,accountEnabled,externalUserState&$top=20", cancellationToken: ct);
        return response["value"]!.AsArray().Select(x => User(x!)).ToArray();
    }

    private DirectoryUser User(JsonNode node) => new(
        node["id"]!.GetValue<string>(), node["displayName"]?.GetValue<string>() ?? "",
        node["userPrincipalName"]?.GetValue<string>() ?? "", node["userType"]?.GetValue<string>() ?? "",
        node["accountEnabled"]?.GetValue<bool>() ?? false, node["externalUserState"]?.GetValue<string>(),
        SecurityBoundary.IsApprovedB2BGuestAdministrator(node["id"]!.GetValue<string>(), settings));

    private async Task<IReadOnlyList<JsonNode>> AllAsync(string path, CancellationToken ct)
    {
        var result = new List<JsonNode>();
        for (var page = 0; page < 100; page++)
        {
            var response = await graph.SendAsync(HttpMethod.Get, path, cancellationToken: ct);
            result.AddRange(response["value"]!.AsArray().Select(x => x!));
            var next = response["@odata.nextLink"]?.GetValue<string>();
            if (next is null) return result;
            if (!Uri.TryCreate(next, UriKind.Absolute, out var uri) || uri.Scheme != "https" || uri.Host != "graph.microsoft.com")
                throw new IntegrationException("Microsoft Graph returned an invalid pagination URL.");
            path = uri.PathAndQuery.TrimStart('/');
        }
        throw new IntegrationException("Directory pagination limit reached. Narrow the directory scope.");
    }

    private async Task<RoleDefinition[]> DefinitionsAsync(string targetId, CancellationToken ct)
    {
        var app = await graph.SendAsync(HttpMethod.Get, $"v1.0/servicePrincipals/{targetId}?$select=appRoles", cancellationToken: ct);
        return app["appRoles"]!.AsArray()
            .Where(x => x?["isEnabled"]?.GetValue<bool>() == true)
            .Select(x => new RoleDefinition(x!["id"]!.GetValue<string>(), x["value"]!.GetValue<string>(), x["displayName"]!.GetValue<string>())).ToArray();
    }

    public async Task<IReadOnlyList<RoleAssignment>> GetAssignmentsAsync(string application, CancellationToken ct)
    {
        var (targetId, allowed) = Target(application);
        var definitions = await DefinitionsAsync(targetId, ct);
        var roles = definitions.Where(x => allowed.Contains(x.Value)).ToDictionary(x => x.Id, x => x.Value);
        var assignments = await AllAsync($"v1.0/servicePrincipals/{targetId}/appRoleAssignedTo?$select=id,principalId,principalDisplayName,appRoleId&$top=100", ct);
        return assignments.Where(x => roles.ContainsKey(x["appRoleId"]!.GetValue<string>()))
            .Select(x => new RoleAssignment(x["id"]!.GetValue<string>(), x["principalId"]!.GetValue<string>(),
                x["principalDisplayName"]?.GetValue<string>() ?? "", x["appRoleId"]!.GetValue<string>(),
                roles[x["appRoleId"]!.GetValue<string>()], application)).ToArray();
    }

    public async Task AssignAsync(AssignmentRequest request, string actor, CancellationToken ct)
    {
        var (targetId, allowed) = Target(request.Application);
        if (!Guid.TryParse(request.UserId, out _) || !allowed.Contains(request.Role))
            throw new IntegrationException("Only approved roles on the harness-owned applications can be assigned.", 400);
        var user = User(await graph.SendAsync(HttpMethod.Get, $"v1.0/users/{request.UserId}?$select=id,displayName,userPrincipalName,userType,accountEnabled,externalUserState", cancellationToken: ct));
        var approvedGuest = SecurityBoundary.IsApprovedB2BGuest(user.Id, settings);
        if (!user.AccountEnabled || user.UserType is not ("Member" or "Guest") ||
            (user.UserType == "Guest" && !approvedGuest))
            throw new IntegrationException("Only enabled tenant members or explicitly approved B2B guests may be added.", 400);
        if (approvedGuest && !SecurityBoundary.IsApprovedB2BGuestAdministrator(user.Id, settings) &&
            (request.Application != "harness" || request.Role != HarnessRoles.User))
            throw new IntegrationException("Approved B2B guests may receive AgentHarnessUsers only.", 403);
        await assignmentLock.WaitAsync(ct);
        try
        {
            if ((await GetAssignmentsAsync(request.Application, ct)).Any(x => x.PrincipalId == request.UserId && x.Role == request.Role)) return;
            var role = (await DefinitionsAsync(targetId, ct)).Single(x => x.Value == request.Role);
            await graph.SendAsync(HttpMethod.Post, $"v1.0/servicePrincipals/{targetId}/appRoleAssignedTo", new JsonObject
            {
                ["principalId"] = request.UserId, ["resourceId"] = targetId, ["appRoleId"] = role.Id
            }, ct);
            store.Audit(actor, "RoleAssigned", $"{request.Application}/{request.UserId}/{request.Role}", "Succeeded");
        }
        finally { assignmentLock.Release(); }
    }

    public async Task RemoveAsync(string application, string assignmentId, string actor, CancellationToken ct)
    {
        var (targetId, _) = Target(application);
        if (string.IsNullOrWhiteSpace(assignmentId) || assignmentId.Length > 120 || assignmentId.Any(c => !char.IsLetterOrDigit(c) && c != '_' && c != '-'))
            throw new IntegrationException("Invalid assignment identifier.", 400);
        await assignmentLock.WaitAsync(ct);
        try
        {
            var assignments = await GetAssignmentsAsync(application, ct);
            var assignment = assignments.SingleOrDefault(x => x.Id == assignmentId)
                ?? throw new IntegrationException("Assignment not found in the selected application.", 404);
            if (application == "harness" && assignment.Role == HarnessRoles.Administrator &&
                assignments.Count(x => x.Role == HarnessRoles.Administrator) <= 1)
                throw new IntegrationException("The last harness administrator cannot be removed.", 409);
            await graph.SendAsync(HttpMethod.Delete, $"v1.0/servicePrincipals/{targetId}/appRoleAssignedTo/{assignmentId}", cancellationToken: ct);
            store.Audit(actor, "RoleRemoved", $"{application}/{assignment.PrincipalId}/{assignment.Role}", "Succeeded");
        }
        finally { assignmentLock.Release(); }
    }

    public async Task<string[]?> GetCurrentRolesAsync(string objectId, CancellationToken ct)
    {
        if (!Guid.TryParse(objectId, out _)) return null;
        var user = User(await graph.SendAsync(HttpMethod.Get, $"v1.0/users/{objectId}?$select=id,displayName,userPrincipalName,userType,accountEnabled,externalUserState", cancellationToken: ct));
        var approvedGuest = SecurityBoundary.IsApprovedB2BGuest(user.Id, settings);
        var approvedGuestAdministrator = SecurityBoundary.IsApprovedB2BGuestAdministrator(user.Id, settings);
        if (!user.AccountEnabled || user.UserType is not ("Member" or "Guest")) return null;
        if (user.UserType == "Guest" && (!approvedGuest || user.ExternalUserState != "Accepted")) return null;
        var (targetId, allowed) = Target("harness");
        var definitions = (await DefinitionsAsync(targetId, ct)).Where(x => allowed.Contains(x.Value)).ToDictionary(x => x.Id, x => x.Value);
        var assignments = await AllAsync($"v1.0/users/{objectId}/appRoleAssignments?$select=appRoleId,resourceId,principalId&$count=true&$top=100", ct);
        return assignments.Where(x => x["resourceId"]?.GetValue<string>() == targetId &&
                x["appRoleId"] is not null && definitions.ContainsKey(x["appRoleId"]!.GetValue<string>()) &&
                (!approvedGuest || ((definitions[x["appRoleId"]!.GetValue<string>()] == HarnessRoles.User ||
                    (approvedGuestAdministrator && definitions[x["appRoleId"]!.GetValue<string>()] == HarnessRoles.Administrator)) &&
                    string.Equals(x["principalId"]?.GetValue<string>(), objectId, StringComparison.OrdinalIgnoreCase))))
            .Select(x => definitions[x["appRoleId"]!.GetValue<string>()]).Distinct().ToArray();
    }
}

public static class SecurityBoundary
{
    private static bool IsTenantPrincipal(ClaimsPrincipal user, string tenantId) =>
        user.Identity?.IsAuthenticated == true &&
        Guid.TryParse(tenantId, out var configuredTenant) && configuredTenant != Guid.Empty &&
        Guid.TryParse(user.FindFirstValue("tid"), out var tokenTenant) && tokenTenant == configuredTenant &&
        Guid.TryParse(user.FindFirstValue("oid"), out var objectId) && objectId != Guid.Empty;

    public static bool IsTenantMember(ClaimsPrincipal user, string tenantId) =>
        IsTenantPrincipal(user, tenantId) && user.FindFirstValue("acct") != "1";

    public static bool IsApprovedB2BGuest(string objectId, HarnessOptions settings) =>
        Guid.TryParse(objectId, out var id) &&
        (settings.AllowedB2BGuestObjectIds ?? []).Any(value => Guid.TryParse(value, out var approved) && approved == id);

    public static bool IsApprovedB2BGuestAdministrator(string objectId, HarnessOptions settings) =>
        IsApprovedB2BGuest(objectId, settings) && Guid.TryParse(objectId, out var id) &&
        (settings.AllowedB2BGuestAdministratorObjectIds ?? []).Any(value => Guid.TryParse(value, out var approved) && approved == id);

    public static bool IsAllowedTenantPrincipal(ClaimsPrincipal user, HarnessOptions settings) =>
        IsTenantPrincipal(user, settings.TenantId) &&
        (user.FindFirstValue("acct") != "1" || IsApprovedB2BGuest(user.ObjectId(), settings));

    public static bool IsAllowedHarnessPrincipal(ClaimsPrincipal user, HarnessOptions settings) =>
        IsAllowedTenantPrincipal(user, settings) &&
        (!IsApprovedB2BGuest(user.ObjectId(), settings) || user.IsInRole(HarnessRoles.User) ||
            (IsApprovedB2BGuestAdministrator(user.ObjectId(), settings) && user.IsInRole(HarnessRoles.Administrator)));

    public static bool IsAllowedAdministratorPrincipal(ClaimsPrincipal user, HarnessOptions settings) =>
        IsAllowedTenantPrincipal(user, settings) &&
        (IsApprovedB2BGuest(user.ObjectId(), settings)
            ? IsApprovedB2BGuestAdministrator(user.ObjectId(), settings)
            : IsTenantMember(user, settings.TenantId));

    public static string ObjectId(this ClaimsPrincipal user) =>
        user.FindFirstValue("oid") ?? throw new IntegrationException("A validated Entra object ID is required.", 401);
}
