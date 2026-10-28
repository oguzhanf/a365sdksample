// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json.Nodes;
using System.Reflection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using AgentHarness;
using AfRegistration = Microsoft.Agents.A365.Tooling.Extensions.AgentFramework.Services.IMcpToolRegistrationService;
using SkRegistration = Microsoft.Agents.A365.Tooling.Extensions.SemanticKernel.Services.IMcpToolRegistrationService;

namespace AgentHarness.Tests;

public sealed class HarnessServiceTests
{
    private const string HarnessClientId = TestIdentity.HarnessClientId;
    private const string HarnessServicePrincipalId = TestIdentity.HarnessServicePrincipalId;
    private const string InternalApiServicePrincipalId = TestIdentity.InternalApiServicePrincipalId;
    private const string GraviteeServicePrincipalId = TestIdentity.GraviteeServicePrincipalId;

    [Fact]
    public async Task Directory_current_roles_for_approved_accepted_guest_returns_only_direct_harness_user()
    {
        using var data = new TestDataDirectory();
        const string administratorRoleId = "66666666-6666-4666-8666-666666666666";
        const string userRoleId = "77777777-7777-4777-8777-777777777777";
        const string groupObjectId = "88888888-8888-4888-8888-888888888888";
        var graph = new RecordingGraphClient(call =>
        {
            if (call.Method == HttpMethod.Get &&
                call.Path == $"v1.0/users/{TestIdentity.ApprovedGuestObjectId}?$select=id,displayName,userPrincipalName,userType,accountEnabled,externalUserState")
            {
                return DirectoryUserResponse(
                    "Guest",
                    accountEnabled: true,
                    TestIdentity.ApprovedGuestObjectId,
                    "Accepted");
            }
            if (call.Method == HttpMethod.Get &&
                call.Path == $"v1.0/servicePrincipals/{HarnessServicePrincipalId}?$select=appRoles")
            {
                return new JsonObject
                {
                    ["appRoles"] = new JsonArray(
                        RoleDefinition(administratorRoleId, HarnessRoles.Administrator),
                        RoleDefinition(userRoleId, HarnessRoles.User))
                };
            }
            if (call.Method == HttpMethod.Get &&
                call.Path == $"v1.0/users/{TestIdentity.ApprovedGuestObjectId}/appRoleAssignments?$select=appRoleId,resourceId,principalId&$count=true&$top=100")
            {
                return Collection(
                    RoleAssignment(userRoleId, HarnessServicePrincipalId, TestIdentity.ApprovedGuestObjectId),
                    RoleAssignment(administratorRoleId, HarnessServicePrincipalId, TestIdentity.ApprovedGuestObjectId),
                    RoleAssignment(userRoleId, HarnessServicePrincipalId, groupObjectId),
                    RoleAssignment(userRoleId, InternalApiServicePrincipalId, TestIdentity.ApprovedGuestObjectId));
            }
            throw new InvalidOperationException($"Unexpected Microsoft Graph call: {call.Method} {call.Path}");
        });
        var service = new DirectoryService(
            graph,
            Options.Create(Settings(TestIdentity.ApprovedGuestObjectId)),
            CreateStore(data.DirectoryPath));

        var roles = await service.GetCurrentRolesAsync(TestIdentity.ApprovedGuestObjectId, CancellationToken.None);

        Assert.NotNull(roles);
        Assert.Equal([HarnessRoles.User], roles);
        Assert.Equal(3, graph.Calls.Count);
    }

    [Fact]
    public async Task Directory_privileged_guest_gets_only_direct_roles_and_is_marked_for_role_options()
    {
        using var data = new TestDataDirectory();
        const string administratorRoleId = "66666666-6666-4666-8666-666666666666";
        const string userRoleId = "77777777-7777-4777-8777-777777777777";
        const string groupObjectId = "88888888-8888-4888-8888-888888888888";
        var graph = new RecordingGraphClient(call =>
        {
            if (call.Method == HttpMethod.Get &&
                call.Path == $"v1.0/users/{TestIdentity.ApprovedGuestObjectId}?$select=id,displayName,userPrincipalName,userType,accountEnabled,externalUserState")
            {
                return DirectoryUserResponse(
                    "Guest",
                    accountEnabled: true,
                    TestIdentity.ApprovedGuestObjectId,
                    "Accepted");
            }
            if (call.Method == HttpMethod.Get &&
                call.Path == $"v1.0/servicePrincipals/{HarnessServicePrincipalId}?$select=appRoles")
            {
                return new JsonObject
                {
                    ["appRoles"] = new JsonArray(
                        RoleDefinition(administratorRoleId, HarnessRoles.Administrator),
                        RoleDefinition(userRoleId, HarnessRoles.User))
                };
            }
            if (call.Method == HttpMethod.Get &&
                call.Path == $"v1.0/users/{TestIdentity.ApprovedGuestObjectId}/appRoleAssignments?$select=appRoleId,resourceId,principalId&$count=true&$top=100")
            {
                return Collection(
                    RoleAssignment(administratorRoleId, HarnessServicePrincipalId, TestIdentity.ApprovedGuestObjectId),
                    RoleAssignment(userRoleId, HarnessServicePrincipalId, TestIdentity.ApprovedGuestObjectId),
                    RoleAssignment(administratorRoleId, HarnessServicePrincipalId, groupObjectId),
                    RoleAssignment(userRoleId, HarnessServicePrincipalId, groupObjectId),
                    RoleAssignment(administratorRoleId, InternalApiServicePrincipalId, TestIdentity.ApprovedGuestObjectId));
            }
            if (call.Method == HttpMethod.Get &&
                call.Path.StartsWith("v1.0/users?$filter=", StringComparison.Ordinal))
            {
                return Collection(DirectoryUserResponse(
                    "Guest",
                    accountEnabled: true,
                    TestIdentity.ApprovedGuestObjectId,
                    "Accepted"));
            }
            throw new InvalidOperationException($"Unexpected Microsoft Graph call: {call.Method} {call.Path}");
        });
        var service = new DirectoryService(
            graph,
            Options.Create(Settings(
                [TestIdentity.ApprovedGuestObjectId],
                [TestIdentity.ApprovedGuestObjectId])),
            CreateStore(data.DirectoryPath));

        var roles = await service.GetCurrentRolesAsync(TestIdentity.ApprovedGuestObjectId, CancellationToken.None);
        var users = await service.SearchAsync("Target", CancellationToken.None);

        Assert.NotNull(roles);
        Assert.Equal(2, roles.Length);
        Assert.Contains(HarnessRoles.User, roles);
        Assert.Contains(HarnessRoles.Administrator, roles);
        Assert.True(Assert.Single(users).PrivilegedGuestApproved);
        Assert.Equal(4, graph.Calls.Count);
    }

    [Fact]
    public async Task Directory_current_roles_rejects_unredeemed_disabled_missing_state_and_unapproved_guests()
    {
        using var data = new TestDataDirectory();
        var scenarios = new (string ObjectId, string? ExternalUserState, bool AccountEnabled)[]
        {
            (TestIdentity.ApprovedGuestObjectId, "PendingAcceptance", true),
            (TestIdentity.ApprovedGuestObjectId, "Accepted", false),
            (TestIdentity.ApprovedGuestObjectId, null, true),
            (TestIdentity.UnapprovedGuestObjectId, "Accepted", true)
        };

        foreach (var scenario in scenarios)
        {
            var graph = new RecordingGraphClient(call =>
            {
                if (call.Method == HttpMethod.Get &&
                    call.Path.StartsWith($"v1.0/users/{scenario.ObjectId}?$select=", StringComparison.Ordinal))
                {
                    return DirectoryUserResponse(
                        "Guest",
                        scenario.AccountEnabled,
                        scenario.ObjectId,
                        scenario.ExternalUserState);
                }
                throw new InvalidOperationException($"Unexpected Microsoft Graph call: {call.Method} {call.Path}");
            });
            var service = new DirectoryService(
                graph,
                Options.Create(Settings(TestIdentity.ApprovedGuestObjectId)),
                CreateStore(data.DirectoryPath));

            var roles = await service.GetCurrentRolesAsync(scenario.ObjectId, CancellationToken.None);

            Assert.Null(roles);
            Assert.DoesNotContain(graph.Calls, call =>
                call.Path.Contains("/appRoleAssignments", StringComparison.Ordinal) ||
                call.Path.StartsWith("v1.0/servicePrincipals/", StringComparison.Ordinal));
        }
    }

    [Fact]
    public async Task Directory_assignment_allows_approved_guest_user_before_invitation_redemption()
    {
        using var data = new TestDataDirectory();
        const string userRoleId = "77777777-7777-4777-8777-777777777777";
        var graph = new RecordingGraphClient(call =>
        {
            if (call.Method == HttpMethod.Get &&
                call.Path.StartsWith($"v1.0/users/{TestIdentity.ApprovedGuestObjectId}?$select=", StringComparison.Ordinal))
            {
                return DirectoryUserResponse(
                    "Guest",
                    accountEnabled: true,
                    TestIdentity.ApprovedGuestObjectId,
                    "PendingAcceptance");
            }
            if (call.Method == HttpMethod.Get &&
                call.Path == $"v1.0/servicePrincipals/{HarnessServicePrincipalId}?$select=appRoles")
            {
                return new JsonObject
                {
                    ["appRoles"] = new JsonArray(RoleDefinition(userRoleId, HarnessRoles.User))
                };
            }
            if (call.Method == HttpMethod.Get &&
                call.Path == $"v1.0/servicePrincipals/{HarnessServicePrincipalId}/appRoleAssignedTo?$select=id,principalId,principalDisplayName,appRoleId&$top=100")
            {
                return Collection();
            }
            if (call.Method == HttpMethod.Post &&
                call.Path == $"v1.0/servicePrincipals/{HarnessServicePrincipalId}/appRoleAssignedTo")
            {
                return new JsonObject();
            }
            throw new InvalidOperationException($"Unexpected Microsoft Graph call: {call.Method} {call.Path}");
        });
        var service = new DirectoryService(
            graph,
            Options.Create(Settings(TestIdentity.ApprovedGuestObjectId)),
            CreateStore(data.DirectoryPath));

        await service.AssignAsync(
            new AssignmentRequest(TestIdentity.ApprovedGuestObjectId, "harness", HarnessRoles.User),
            TestIdentity.AdministratorObjectId,
            CancellationToken.None);

        var post = Assert.Single(graph.Calls, call => call.Method == HttpMethod.Post);
        Assert.Equal($"v1.0/servicePrincipals/{HarnessServicePrincipalId}/appRoleAssignedTo", post.Path);
        Assert.Equal(TestIdentity.ApprovedGuestObjectId, post.Body?["principalId"]?.GetValue<string>());
        Assert.Equal(HarnessServicePrincipalId, post.Body?["resourceId"]?.GetValue<string>());
        Assert.Equal(userRoleId, post.Body?["appRoleId"]?.GetValue<string>());
    }

    [Fact]
    public async Task Directory_assignment_allows_privileged_guest_roles_on_harness_api_and_gateway_apps()
    {
        using var data = new TestDataDirectory();
        var requests = new[]
        {
            new AssignmentRequest(TestIdentity.ApprovedGuestObjectId, "harness", HarnessRoles.User),
            new AssignmentRequest(TestIdentity.ApprovedGuestObjectId, "harness", HarnessRoles.Administrator),
            new AssignmentRequest(TestIdentity.ApprovedGuestObjectId, "internal-api", HarnessRoles.Reader),
            new AssignmentRequest(TestIdentity.ApprovedGuestObjectId, "internal-api", HarnessRoles.Approver),
            new AssignmentRequest(TestIdentity.ApprovedGuestObjectId, "gravitee", HarnessRoles.GraviteeAdministrator),
            new AssignmentRequest(TestIdentity.ApprovedGuestObjectId, "gravitee", HarnessRoles.GraviteeUser)
        };

        foreach (var request in requests)
        {
            const string roleId = "99999999-9999-4999-8999-999999999999";
            var targetId = request.Application switch
            {
                "harness" => HarnessServicePrincipalId,
                "internal-api" => InternalApiServicePrincipalId,
                "gravitee" => GraviteeServicePrincipalId,
                _ => throw new InvalidOperationException($"Unexpected application {request.Application}.")
            };
            var graph = new RecordingGraphClient(call =>
            {
                if (call.Method == HttpMethod.Get &&
                    call.Path.StartsWith($"v1.0/users/{TestIdentity.ApprovedGuestObjectId}?$select=", StringComparison.Ordinal))
                {
                    return DirectoryUserResponse(
                        "Guest",
                        accountEnabled: true,
                        TestIdentity.ApprovedGuestObjectId,
                        "PendingAcceptance");
                }
                if (call.Method == HttpMethod.Get &&
                    call.Path == $"v1.0/servicePrincipals/{targetId}?$select=appRoles")
                {
                    return new JsonObject
                    {
                        ["appRoles"] = new JsonArray(RoleDefinition(roleId, request.Role))
                    };
                }
                if (call.Method == HttpMethod.Get &&
                    call.Path == $"v1.0/servicePrincipals/{targetId}/appRoleAssignedTo?$select=id,principalId,principalDisplayName,appRoleId&$top=100")
                {
                    return Collection();
                }
                if (call.Method == HttpMethod.Post &&
                    call.Path == $"v1.0/servicePrincipals/{targetId}/appRoleAssignedTo")
                {
                    return new JsonObject();
                }
                throw new InvalidOperationException($"Unexpected Microsoft Graph call: {call.Method} {call.Path}");
            });
            var service = new DirectoryService(
                graph,
                Options.Create(Settings(
                    [TestIdentity.ApprovedGuestObjectId],
                    [TestIdentity.ApprovedGuestObjectId])),
                CreateStore(data.DirectoryPath));

            await service.AssignAsync(request, TestIdentity.AdministratorObjectId, CancellationToken.None);

            var post = Assert.Single(graph.Calls, call => call.Method == HttpMethod.Post);
            Assert.Equal($"v1.0/servicePrincipals/{targetId}/appRoleAssignedTo", post.Path);
            Assert.Equal(TestIdentity.ApprovedGuestObjectId, post.Body?["principalId"]?.GetValue<string>());
            Assert.Equal(targetId, post.Body?["resourceId"]?.GetValue<string>());
            Assert.Equal(roleId, post.Body?["appRoleId"]?.GetValue<string>());
        }
    }

    [Fact]
    public async Task Directory_assignment_denies_standard_approved_guest_admin_api_and_gateway_roles_without_writes()
    {
        using var data = new TestDataDirectory();
        var requests = new[]
        {
            new AssignmentRequest(TestIdentity.ApprovedGuestObjectId, "harness", HarnessRoles.Administrator),
            new AssignmentRequest(TestIdentity.ApprovedGuestObjectId, "internal-api", HarnessRoles.Reader),
            new AssignmentRequest(TestIdentity.ApprovedGuestObjectId, "gravitee", HarnessRoles.GraviteeUser)
        };

        foreach (var request in requests)
        {
            var graph = new RecordingGraphClient(call =>
            {
                if (call.Method == HttpMethod.Get &&
                    call.Path.StartsWith($"v1.0/users/{TestIdentity.ApprovedGuestObjectId}?$select=", StringComparison.Ordinal))
                {
                    return DirectoryUserResponse(
                        "Guest",
                        accountEnabled: true,
                        TestIdentity.ApprovedGuestObjectId,
                        "Accepted");
                }
                if (call.Method == HttpMethod.Get &&
                    call.Path.Contains("?$select=appRoles", StringComparison.Ordinal))
                {
                    return new JsonObject
                    {
                        ["appRoles"] = new JsonArray(RoleDefinition(
                            "99999999-9999-4999-8999-999999999999",
                            request.Role))
                    };
                }
                if (call.Method == HttpMethod.Get &&
                    call.Path.Contains("/appRoleAssignedTo?", StringComparison.Ordinal))
                {
                    return Collection();
                }
                if (call.Method == HttpMethod.Post)
                    return new JsonObject();
                throw new InvalidOperationException($"Unexpected Microsoft Graph call: {call.Method} {call.Path}");
            });
            var service = new DirectoryService(
                graph,
                Options.Create(Settings(TestIdentity.ApprovedGuestObjectId)),
                CreateStore(data.DirectoryPath));

            var exception = await Assert.ThrowsAsync<IntegrationException>(() => service.AssignAsync(
                request,
                TestIdentity.AdministratorObjectId,
                CancellationToken.None));

            Assert.Contains(exception.StatusCode, new[] { 400, 403 });
            Assert.DoesNotContain(graph.Calls, call => call.Method == HttpMethod.Post);
        }
    }

    [Fact]
    public async Task Directory_search_scopes_results_to_members_and_explicitly_allowed_guests()
    {
        using var data = new TestDataDirectory();
        var graph = new RecordingGraphClient(call =>
        {
            Assert.Equal(HttpMethod.Get, call.Method);
            var decodedPath = Uri.UnescapeDataString(call.Path);
            Assert.StartsWith("v1.0/users?$filter=", decodedPath, StringComparison.Ordinal);
            Assert.Contains("accountEnabled eq true", decodedPath, StringComparison.Ordinal);
            Assert.Contains("userType eq 'Member'", decodedPath, StringComparison.Ordinal);
            Assert.Contains(TestIdentity.ApprovedGuestObjectId, decodedPath, StringComparison.Ordinal);
            Assert.DoesNotContain(TestIdentity.UnapprovedGuestObjectId, decodedPath, StringComparison.Ordinal);
            Assert.Contains("startswith(displayName,'Ext')", decodedPath, StringComparison.Ordinal);
            Assert.Contains("startswith(userPrincipalName,'Ext')", decodedPath, StringComparison.Ordinal);
            Assert.Contains(
                "$select=id,displayName,userPrincipalName,userType,accountEnabled,externalUserState",
                decodedPath,
                StringComparison.Ordinal);
            return Collection(
                DirectoryUserResponse("Member", accountEnabled: true),
                DirectoryUserResponse(
                    "Guest",
                    accountEnabled: true,
                    TestIdentity.ApprovedGuestObjectId,
                    "Accepted"));
        });
        var service = new DirectoryService(
            graph,
            Options.Create(Settings(TestIdentity.ApprovedGuestObjectId)),
            CreateStore(data.DirectoryPath));

        var users = await service.SearchAsync(" Ext ", CancellationToken.None);

        Assert.Equal(2, users.Count);
        Assert.Contains(users, user => user.Id == TestIdentity.MemberObjectId && user.UserType == "Member");
        var guest = Assert.Single(users, user =>
            user.Id == TestIdentity.ApprovedGuestObjectId && user.UserType == "Guest");
        Assert.False(guest.PrivilegedGuestApproved);
        Assert.Single(graph.Calls);
    }

    [Theory]
    [InlineData("arbitrary-app", HarnessRoles.User)]
    [InlineData(HarnessServicePrincipalId, HarnessRoles.User)]
    [InlineData("harness", "Directory.ReadWrite.All")]
    public async Task Directory_assignment_allowlist_rejects_arbitrary_application_service_principal_and_role(
        string application,
        string role)
    {
        using var data = new TestDataDirectory();
        var graph = new RecordingGraphClient();
        var service = new DirectoryService(graph, Options.Create(Settings()), CreateStore(data.DirectoryPath));

        var exception = await Assert.ThrowsAsync<IntegrationException>(() => service.AssignAsync(
            new AssignmentRequest(TestIdentity.MemberObjectId, application, role),
            TestIdentity.AdministratorObjectId,
            CancellationToken.None));

        Assert.Equal(400, exception.StatusCode);
        Assert.Empty(graph.Calls);
    }

    [Theory]
    [InlineData("Guest", true)]
    [InlineData("Member", false)]
    public async Task Directory_assignment_refuses_guest_or_disabled_target(string userType, bool accountEnabled)
    {
        using var data = new TestDataDirectory();
        var graph = new RecordingGraphClient(call =>
        {
            if (call.Method == HttpMethod.Get &&
                call.Path.StartsWith($"v1.0/users/{TestIdentity.MemberObjectId}?", StringComparison.Ordinal))
            {
                return DirectoryUserResponse(userType, accountEnabled);
            }
            throw new InvalidOperationException($"Unexpected Microsoft Graph call: {call.Method} {call.Path}");
        });
        var service = new DirectoryService(graph, Options.Create(Settings()), CreateStore(data.DirectoryPath));

        var exception = await Assert.ThrowsAsync<IntegrationException>(() => service.AssignAsync(
            new AssignmentRequest(TestIdentity.MemberObjectId, "harness", HarnessRoles.User),
            TestIdentity.AdministratorObjectId,
            CancellationToken.None));

        Assert.Equal(400, exception.StatusCode);
        Assert.Single(graph.Calls);
        Assert.DoesNotContain(graph.Calls, call => call.Method == HttpMethod.Post);
    }

    [Fact]
    public async Task Directory_current_roles_accepts_returned_group_roles_but_enforces_resource_and_role_boundaries()
    {
        using var data = new TestDataDirectory();
        const string administratorRoleId = "44444444-4444-4444-8444-444444444444";
        const string userRoleId = "55555555-5555-4555-8555-555555555555";
        const string unapprovedRoleId = "66666666-6666-4666-8666-666666666666";
        const string unknownRoleId = "77777777-7777-4777-8777-777777777777";
        const string firstGroupObjectId = "88888888-8888-4888-8888-888888888888";
        const string secondGroupObjectId = "99999999-9999-4999-8999-999999999999";
        var graph = new RecordingGraphClient(call =>
        {
            if (call.Method == HttpMethod.Get &&
                call.Path.StartsWith($"v1.0/users/{TestIdentity.MemberObjectId}?$select=", StringComparison.Ordinal))
            {
                return DirectoryUserResponse("Member", accountEnabled: true);
            }
            if (call.Method == HttpMethod.Get &&
                call.Path == $"v1.0/servicePrincipals/{HarnessServicePrincipalId}?$select=appRoles")
            {
                return new JsonObject
                {
                    ["appRoles"] = new JsonArray(
                        RoleDefinition(administratorRoleId, HarnessRoles.Administrator),
                        RoleDefinition(userRoleId, HarnessRoles.User),
                        RoleDefinition(unapprovedRoleId, "Unapproved.Harness.Role"))
                };
            }
            if (call.Method == HttpMethod.Get &&
                call.Path == $"v1.0/users/{TestIdentity.MemberObjectId}/appRoleAssignments?$select=appRoleId,resourceId,principalId&$count=true&$top=100")
            {
                return Collection(
                    RoleAssignment(administratorRoleId, HarnessServicePrincipalId, firstGroupObjectId),
                    RoleAssignment(administratorRoleId, HarnessServicePrincipalId, secondGroupObjectId),
                    RoleAssignment(userRoleId, HarnessServicePrincipalId, firstGroupObjectId),
                    RoleAssignment(administratorRoleId, InternalApiServicePrincipalId, firstGroupObjectId),
                    RoleAssignment(unapprovedRoleId, HarnessServicePrincipalId, firstGroupObjectId),
                    RoleAssignment(unknownRoleId, HarnessServicePrincipalId, firstGroupObjectId));
            }
            throw new InvalidOperationException($"Unexpected Microsoft Graph call: {call.Method} {call.Path}");
        });
        var service = new DirectoryService(graph, Options.Create(Settings()), CreateStore(data.DirectoryPath));

        var roles = await service.GetCurrentRolesAsync(TestIdentity.MemberObjectId, CancellationToken.None);

        Assert.NotNull(roles);
        Assert.Equal(2, roles.Length);
        Assert.Contains(HarnessRoles.Administrator, roles);
        Assert.Contains(HarnessRoles.User, roles);
        Assert.Equal(3, graph.Calls.Count);
        Assert.Contains(graph.Calls, call =>
            call.Path.Contains("/appRoleAssignments?", StringComparison.Ordinal) &&
            call.Path.Contains("$count=true", StringComparison.Ordinal));
        Assert.DoesNotContain(graph.Calls, call =>
            call.Path.Contains("transitiveMemberOf", StringComparison.OrdinalIgnoreCase) ||
            call.Path.Contains("appRoleAssignedTo", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Directory_cannot_remove_last_harness_administrator_and_sends_no_delete()
    {
        using var data = new TestDataDirectory();
        const string administratorRoleId = "44444444-4444-4444-8444-444444444444";
        const string assignmentId = "last-admin-assignment";
        var graph = new RecordingGraphClient(call =>
        {
            if (call.Method == HttpMethod.Get &&
                call.Path.StartsWith($"v1.0/servicePrincipals/{HarnessServicePrincipalId}?$select=appRoles", StringComparison.Ordinal))
            {
                return new JsonObject
                {
                    ["appRoles"] = new JsonArray(new JsonObject
                    {
                        ["id"] = administratorRoleId,
                        ["value"] = HarnessRoles.Administrator,
                        ["displayName"] = "AgentHarness Administrators",
                        ["isEnabled"] = true
                    })
                };
            }
            if (call.Method == HttpMethod.Get &&
                call.Path.StartsWith($"v1.0/servicePrincipals/{HarnessServicePrincipalId}/appRoleAssignedTo?", StringComparison.Ordinal))
            {
                return Collection(new JsonObject
                {
                    ["id"] = assignmentId,
                    ["principalId"] = TestIdentity.AdministratorObjectId,
                    ["principalDisplayName"] = "Only Administrator",
                    ["appRoleId"] = administratorRoleId
                });
            }
            throw new InvalidOperationException($"Unexpected Microsoft Graph call: {call.Method} {call.Path}");
        });
        var service = new DirectoryService(graph, Options.Create(Settings()), CreateStore(data.DirectoryPath));

        var exception = await Assert.ThrowsAsync<IntegrationException>(() => service.RemoveAsync(
            "harness",
            assignmentId,
            TestIdentity.AdministratorObjectId,
            CancellationToken.None));

        Assert.Equal(409, exception.StatusCode);
        Assert.DoesNotContain(graph.Calls, call => call.Method == HttpMethod.Delete);
    }

    [Theory]
    [InlineData("../appsettings.json")]
    [InlineData("Harness/../appsettings.json")]
    [InlineData(@"C:\a365sdk\src\AgentHarness\Program.cs")]
    public void Source_catalog_rejects_traversal_and_nonembedded_paths(string path)
    {
        var exception = Assert.Throws<IntegrationException>(() => new SourceCatalog().Read(path));

        Assert.Equal(404, exception.StatusCode);
    }

    [Fact]
    public void Purview_restrict_access_decision_blocks()
    {
        var decision = new JsonObject
        {
            ["processingErrors"] = new JsonArray(),
            ["policyActions"] = new JsonArray(new JsonObject
            {
                ["action"] = "restrictAccess",
                ["restrictionAction"] = "block"
            })
        };

        var exception = Assert.Throws<IntegrationException>(() => PurviewService.EnforceDecision(decision));

        Assert.Equal(403, exception.StatusCode);
    }

    [Fact]
    public void Purview_malformed_processing_error_and_unknown_action_decisions_fail_closed()
    {
        var decisions = new[]
        {
            new JsonObject
            {
                ["processingErrors"] = new JsonArray()
            },
            new JsonObject
            {
                ["processingErrors"] = new JsonArray(new JsonObject { ["code"] = "partialFailure" }),
                ["policyActions"] = new JsonArray()
            },
            new JsonObject
            {
                ["processingErrors"] = new JsonArray(),
                ["policyActions"] = new JsonArray(new JsonObject { ["action"] = "unrecognizedAction" })
            }
        };

        foreach (var decision in decisions)
        {
            var exception = Assert.Throws<IntegrationException>(() => PurviewService.EnforceDecision(decision));
            Assert.Equal(503, exception.StatusCode);
        }
    }

    [Fact]
    public async Task Purview_upload_without_applicable_inline_policy_fails_closed()
    {
        using var data = new TestDataDirectory();
        var graph = new RecordingGraphClient(call =>
        {
            if (call.Path.EndsWith("/protectionScopes/compute", StringComparison.Ordinal))
                return ScopeResponse("scope-1", "downloadText", "evaluateInline");
            if (call.Path.EndsWith("/processContent", StringComparison.Ordinal))
                return AllowDecision("unchanged");
            throw new InvalidOperationException($"Unexpected Microsoft Graph call: {call.Method} {call.Path}");
        });
        var service = CreatePurviewService(graph, data.DirectoryPath, requireInlinePolicy: true);

        var exception = await Assert.ThrowsAsync<IntegrationException>(() => service.EvaluateAsync(
            TestIdentity.MemberObjectId,
            "Protected user prompt",
            "uploadText",
            "inline-policy-required",
            CancellationToken.None));

        Assert.Equal(503, exception.StatusCode);
    }

    [Theory]
    [InlineData("uploadText,downloadText", "evaluateInline", "Verified")]
    [InlineData("uploadText", "evaluateOffline", "Blocked")]
    [InlineData("downloadText", "evaluateInline", "Blocked")]
    public async Task Governance_purview_readiness_checks_the_current_user_and_application(
        string activities, string executionMode, string expectedState)
    {
        using var data = new TestDataDirectory();
        var graph = new RecordingGraphClient(call =>
        {
            if (call.Path.StartsWith("v1.0/servicePrincipals/", StringComparison.Ordinal))
                return new JsonObject
                {
                    ["appRoles"] = new JsonArray(
                        RoleDefinition(Guid.NewGuid().ToString(), HarnessRoles.Administrator),
                        RoleDefinition(Guid.NewGuid().ToString(), HarnessRoles.User)),
                    ["appRoleAssignmentRequired"] = true
                };
            Assert.Equal(HttpMethod.Post, call.Method);
            Assert.Equal($"v1.0/users/{TestIdentity.ApprovedGuestObjectId}/dataSecurityAndGovernance/protectionScopes/compute", call.Path);
            Assert.Equal("uploadText,downloadText", call.Body?["activities"]?.GetValue<string>());
            var location = Assert.Single(call.Body!["locations"]!.AsArray());
            Assert.Equal("microsoft.graph.policyLocationApplication", location?["@odata.type"]?.GetValue<string>());
            Assert.Equal(HarnessClientId, location?["value"]?.GetValue<string>());
            return ScopeResponse("scope-1", activities, executionMode);
        });
        var service = new GovernanceService(graph, Options.Create(Settings(TestIdentity.ApprovedGuestObjectId)),
            new ConfigurationBuilder().Build(), CreateStore(data.DirectoryPath), new CountingHttpClientFactory());

        var checks = await service.CheckAsync(TestIdentity.ApprovedGuestObjectId, CancellationToken.None);

        Assert.Equal(expectedState, Assert.Single(checks, check => check.Name == "Purview DLP").State);
    }

    [Fact]
    public async Task Governance_purview_readiness_does_not_claim_protection_when_the_scope_check_fails()
    {
        using var data = new TestDataDirectory();
        var graph = new RecordingGraphClient(_ => throw new IntegrationException("Microsoft Graph is unavailable."));
        var service = new GovernanceService(graph, Options.Create(Settings()),
            new ConfigurationBuilder().Build(), CreateStore(data.DirectoryPath), new CountingHttpClientFactory());

        var checks = await service.CheckAsync(TestIdentity.MemberObjectId, CancellationToken.None);

        Assert.Equal("Pending", Assert.Single(checks, check => check.Name == "Purview DLP").State);
    }

    [Fact]
    public async Task Purview_download_is_still_evaluated_without_requiring_an_inline_scope()
    {
        using var data = new TestDataDirectory();
        var graph = new RecordingGraphClient(call =>
        {
            if (call.Path.EndsWith("/protectionScopes/compute", StringComparison.Ordinal))
                return ScopeResponse("scope-1", "uploadText", "evaluateInline");
            if (call.Path.EndsWith("/processContent", StringComparison.Ordinal))
                return AllowDecision("unchanged");
            throw new InvalidOperationException($"Unexpected Microsoft Graph call: {call.Method} {call.Path}");
        });
        var service = CreatePurviewService(graph, data.DirectoryPath, requireInlinePolicy: true);

        var result = await service.EvaluateAsync(
            TestIdentity.MemberObjectId,
            "Protected model response",
            "downloadText",
            "output-evaluation",
            CancellationToken.None);

        Assert.Contains("evaluated", result, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(graph.Calls, call => call.Method == HttpMethod.Post &&
            call.Path.EndsWith("/processContent", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Purview_policy_modified_refreshes_scope_without_replaying_the_evaluated_content()
    {
        using var data = new TestDataDirectory();
        var computeCount = 0;
        var processCount = 0;
        var graph = new RecordingGraphClient(call =>
        {
            if (call.Path.EndsWith("/protectionScopes/compute", StringComparison.Ordinal))
            {
                computeCount++;
                return ScopeResponse($"scope-{computeCount}", "uploadText,downloadText", "evaluateInline");
            }
            if (call.Path.EndsWith("/processContent", StringComparison.Ordinal))
            {
                processCount++;
                return AllowDecision("modified");
            }
            throw new InvalidOperationException($"Unexpected Microsoft Graph call: {call.Method} {call.Path}");
        });
        var service = CreatePurviewService(graph, data.DirectoryPath, requireInlinePolicy: true);

        var result = await service.EvaluateAsync(
            TestIdentity.MemberObjectId,
            "Prompt evaluated against the current policy",
            "uploadText",
            "policy-refresh",
            CancellationToken.None);

        Assert.Contains("applicable inline policy", result, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(2, computeCount);
        Assert.Equal(1, processCount);
        await service.EvaluateAsync(
            TestIdentity.MemberObjectId,
            "Safe output evaluated against the refreshed policy",
            "downloadText",
            "policy-refresh",
            CancellationToken.None);
        Assert.Equal(3, computeCount);
        Assert.Equal(2, processCount);
        var processCalls = graph.Calls
            .Where(call => call.Path.EndsWith("/processContent", StringComparison.Ordinal))
            .ToArray();
        Assert.Equal(new[] { "scope-1", "scope-2" }, processCalls.Select(call => call.Etag).ToArray());
    }

    [Fact]
    public async Task Purview_modified_decision_still_blocks_restricted_content_after_scope_refresh()
    {
        using var data = new TestDataDirectory();
        var computeCount = 0;
        var graph = new RecordingGraphClient(call =>
        {
            if (call.Path.EndsWith("/protectionScopes/compute", StringComparison.Ordinal))
                return ScopeResponse($"scope-{++computeCount}", "uploadText", "evaluateInline");
            if (call.Path.EndsWith("/processContent", StringComparison.Ordinal))
                return new JsonObject
                {
                    ["processingErrors"] = new JsonArray(),
                    ["policyActions"] = new JsonArray(new JsonObject
                    {
                        ["action"] = "restrictAccess", ["restrictionAction"] = "block"
                    }),
                    ["protectionScopeState"] = "modified"
                };
            throw new InvalidOperationException("Unexpected Graph request.");
        });
        var service = CreatePurviewService(graph, data.DirectoryPath, requireInlinePolicy: true);

        var exception = await Assert.ThrowsAsync<IntegrationException>(() => service.EvaluateAsync(
            TestIdentity.MemberObjectId, "Synthetic restricted content", "uploadText", "modified-block", CancellationToken.None));

        Assert.Equal(403, exception.StatusCode);
        Assert.Equal(2, computeCount);
        Assert.Single(graph.Calls, call => call.Path.EndsWith("/processContent", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Purview_modified_scope_cannot_remove_the_required_inline_protection()
    {
        using var data = new TestDataDirectory();
        var computeCount = 0;
        var graph = new RecordingGraphClient(call =>
        {
            if (call.Path.EndsWith("/protectionScopes/compute", StringComparison.Ordinal))
                return ScopeResponse($"scope-{++computeCount}", "uploadText",
                    computeCount == 1 ? "evaluateInline" : "evaluateOffline");
            if (call.Path.EndsWith("/processContent", StringComparison.Ordinal))
                return AllowDecision("modified");
            throw new InvalidOperationException("Unexpected Graph request.");
        });
        var service = CreatePurviewService(graph, data.DirectoryPath, requireInlinePolicy: true);

        var exception = await Assert.ThrowsAsync<IntegrationException>(() => service.EvaluateAsync(
            TestIdentity.MemberObjectId, "Safe content", "uploadText", "lost-inline", CancellationToken.None));

        Assert.Equal(503, exception.StatusCode);
        Assert.Equal(2, computeCount);
        Assert.Single(graph.Calls, call => call.Path.EndsWith("/processContent", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Agent_runtime_stops_on_upload_policy_block_before_inference()
    {
        using var data = new TestDataDirectory();
        var failure = new IntegrationException("Purview blocked the prompt.", 403);
        var purview = new BlockingPurviewService(failure);
        var http = new CountingHttpClientFactory();
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["AzureOpenAI:Endpoint"] = "https://unit-test.openai.azure.com",
            ["AzureOpenAI:Deployment"] = "unit-test"
        }).Build();
        using var loggerFactory = LoggerFactory.Create(_ => { });
        var store = CreateStore(data.DirectoryPath);
        var runtime = new AgentRuntime(
            configuration,
            Options.Create(Settings()),
            http,
            purview,
            store,
            loggerFactory,
            UnusedService<AfRegistration>(),
            UnusedService<SkRegistration>(),
            new RecordingGraphClient());
        var agent = new AgentRecord(
            Guid.NewGuid().ToString(),
            "Purview order test",
            "agent-framework",
            "Inference must not start after an upload block.",
            TestIdentity.AdministratorObjectId,
            DateTimeOffset.UtcNow);

        var exception = await Assert.ThrowsAsync<IntegrationException>(() => runtime.RunAsync(
            agent,
            "Blocked prompt",
            TestIdentity.MemberObjectId,
            CancellationToken.None));

        Assert.Same(failure, exception);
        Assert.Equal(new[] { "uploadText" }, purview.Activities);
        Assert.Equal(0, http.CreateClientCount);
        Assert.Empty(store.GetEvidence(agent.Id));
        Assert.Contains(store.GetAudit(), entry =>
            entry.Action == "AgentRun" &&
            entry.Target == agent.Id &&
            entry.Outcome == "Blocked or failed");
    }

    [Fact]
    public async Task Agent_runtime_disables_externally_disabled_identity_before_purview_or_model()
    {
        using var data = new TestDataDirectory();
        const string blueprintObjectId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
        const string blueprintClientId = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
        const string agentObjectId = "ffffffff-ffff-4fff-8fff-ffffffffffff";
        const string agentClientId = "12121212-1212-4212-8212-121212121212";
        var graph = new RecordingGraphClient(call =>
        {
            if (call.Method == HttpMethod.Get &&
                call.Path == $"beta/servicePrincipals/{agentObjectId}/microsoft.graph.agentIdentity?$select=id,appId,agentIdentityBlueprintId,accountEnabled")
            {
                return new JsonObject
                {
                    ["id"] = agentObjectId,
                    ["appId"] = agentClientId,
                    ["agentIdentityBlueprintId"] = blueprintClientId,
                    ["accountEnabled"] = false
                };
            }
            throw new InvalidOperationException($"Unexpected Microsoft Graph call: {call.Method} {call.Path}");
        });
        var purview = new CountingPurviewService();
        var http = new CountingHttpClientFactory();
        var store = CreateStore(data.DirectoryPath);
        using var loggerFactory = LoggerFactory.Create(_ => { });
        var runtime = new AgentRuntime(
            new ConfigurationBuilder().Build(),
            Options.Create(Settings()),
            http,
            purview,
            store,
            loggerFactory,
            null!,
            null!,
            graph);
        var agent = new AgentRecord(
            Guid.NewGuid().ToString(),
            "Externally disabled agent",
            "agent-framework",
            "Entra disablement must block before policy or inference.",
            TestIdentity.AdministratorObjectId,
            DateTimeOffset.UtcNow,
            BlueprintObjectId: blueprintObjectId,
            BlueprintClientId: blueprintClientId,
            AgentObjectId: agentObjectId,
            AgentClientId: agentClientId,
            RegistryId: Guid.NewGuid().ToString(),
            ScheduleEnabled: true,
            Status: "Registered");
        store.SaveAgent(agent);

        var exception = await Assert.ThrowsAsync<IntegrationException>(() => runtime.RunAsync(
            agent,
            "This prompt must not reach Purview or a model.",
            TestIdentity.MemberObjectId,
            CancellationToken.None));

        Assert.Equal(403, exception.StatusCode);
        Assert.Single(graph.Calls);
        Assert.Empty(purview.Activities);
        Assert.Equal(0, http.CreateClientCount);
        var disabled = store.GetAgent(agent.Id);
        Assert.NotNull(disabled);
        Assert.Equal("Disabled", disabled.Status);
        Assert.False(disabled.ScheduleEnabled);
    }

    [Fact]
    public void Tool_policy_text_removes_recognized_image_bytes_but_preserves_caption_and_sibling_text()
    {
        const string toolResult = """
            {
              "toolName": "screen_capture",
              "content": [
                {
                  "type": "image",
                  "mimeType": "image/png",
                  "data": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB",
                  "caption": "Login screen"
                },
                {
                  "type": "text",
                  "text": "The sign-in button is visible."
                }
              ],
              "summary": "Captured current desktop."
            }
            """;

        var filtered = JsonNode.Parse(AgentRuntime.ToolPolicyText(toolResult))!.AsObject();
        var content = filtered["content"]!.AsArray();
        var image = content[0]!.AsObject();
        var text = content[1]!.AsObject();

        Assert.Equal("[Image bytes are not inspected by text DLP]", image["data"]!.GetValue<string>());
        Assert.Equal("Login screen", image["caption"]!.GetValue<string>());
        Assert.Equal("The sign-in button is visible.", text["text"]!.GetValue<string>());
        Assert.Equal("Captured current desktop.", filtered["summary"]!.GetValue<string>());
    }

    [Fact]
    public void Tool_policy_text_preserves_fake_image_and_plaintext_data()
    {
        const string toolResult = """
            {
              "content": [
                {
                  "type": "image",
                  "mimeType": "image/png",
                  "data": "not-actual-png-bytes"
                },
                {
                  "type": "text",
                  "mimeType": "text/plain",
                  "data": "iVBORw0KGgo this is ordinary text"
                }
              ]
            }
            """;

        var filtered = JsonNode.Parse(AgentRuntime.ToolPolicyText(toolResult))!.AsObject();
        var content = filtered["content"]!.AsArray();

        Assert.Equal("not-actual-png-bytes", content[0]!["data"]!.GetValue<string>());
        Assert.Equal("iVBORw0KGgo this is ordinary text", content[1]!["data"]!.GetValue<string>());
    }

    [Fact]
    public void Harness_store_persists_agent_evidence_and_audit_across_restart()
    {
        using var data = new TestDataDirectory();
        var agent = new AgentRecord(
            Guid.NewGuid().ToString(),
            "Persistent agent",
            "semantic-kernel",
            "Persists across store construction.",
            TestIdentity.AdministratorObjectId,
            DateTimeOffset.UtcNow,
            Status: "Registered");
        var firstStore = CreateStore(data.DirectoryPath);
        firstStore.SaveAgent(agent);
        firstStore.AddEvidence(agent.Id, "Validate", "Verified", "Evidence persisted.");
        firstStore.Audit(TestIdentity.AdministratorObjectId, "PersistenceTest", agent.Id, "Succeeded");

        var restartedStore = CreateStore(data.DirectoryPath);
        var loaded = restartedStore.GetAgent(agent.Id);
        var evidence = Assert.Single(restartedStore.GetEvidence(agent.Id));
        var audit = Assert.Single(restartedStore.GetAudit(), entry => entry.Action == "PersistenceTest");

        Assert.NotNull(loaded);
        Assert.Equal(agent.Id, loaded.Id);
        Assert.Equal(agent.Name, loaded.Name);
        Assert.Equal(agent.Framework, loaded.Framework);
        Assert.Equal(agent.Status, loaded.Status);
        Assert.Equal("Validate", evidence.Stage);
        Assert.Equal("Verified", evidence.State);
        Assert.Equal("Evidence persisted.", evidence.Summary);
        Assert.Equal(agent.Id, audit.Target);
        Assert.Equal("Succeeded", audit.Outcome);
    }

    [Fact]
    public async Task Agent_registration_retry_uses_saved_typed_identity_checkpoints_and_copilot_registry()
    {
        using var data = new TestDataDirectory();
        var store = CreateStore(data.DirectoryPath);
        var agentId = Guid.NewGuid().ToString();
        const string blueprintObjectId = "55555555-5555-4555-8555-555555555555";
        const string blueprintClientId = "66666666-6666-4666-8666-666666666666";
        const string agentObjectId = "77777777-7777-4777-8777-777777777777";
        const string agentClientId = "88888888-8888-4888-8888-888888888888";
        var principalCreated = false;
        var registryAttempts = 0;
        var graph = new RecordingGraphClient(call =>
        {
            if (call.Method == HttpMethod.Get &&
                call.Path.StartsWith("v1.0/applications/microsoft.graph.agentIdentityBlueprint?", StringComparison.Ordinal))
            {
                return Collection();
            }
            if (call.Method == HttpMethod.Post &&
                call.Path == "v1.0/applications/microsoft.graph.agentIdentityBlueprint")
            {
                return new JsonObject
                {
                    ["id"] = blueprintObjectId,
                    ["appId"] = blueprintClientId
                };
            }
            if (call.Method == HttpMethod.Get &&
                call.Path.StartsWith("v1.0/servicePrincipals?$filter=appId", StringComparison.Ordinal))
            {
                return principalCreated
                    ? Collection(new JsonObject { ["id"] = "blueprint-principal" })
                    : Collection();
            }
            if (call.Method == HttpMethod.Post &&
                call.Path == "v1.0/servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal")
            {
                principalCreated = true;
                return new JsonObject { ["id"] = "blueprint-principal" };
            }
            if (call.Method == HttpMethod.Get &&
                call.Path.StartsWith("beta/servicePrincipals/microsoft.graph.agentIdentity?", StringComparison.Ordinal))
            {
                return Collection();
            }
            if (call.Method == HttpMethod.Post &&
                call.Path == "beta/servicePrincipals/microsoft.graph.agentIdentity")
            {
                return new JsonObject
                {
                    ["id"] = agentObjectId,
                    ["appId"] = agentClientId,
                    ["agentIdentityBlueprintId"] = blueprintClientId
                };
            }
            if (call.Method == HttpMethod.Post &&
                call.Path == "beta/copilot/agentRegistrations")
            {
                registryAttempts++;
                if (registryAttempts == 1)
                    throw new IntegrationException("Registry temporarily unavailable.", 503);
                return new JsonObject
                {
                    ["id"] = agentId,
                    ["sourceAgentId"] = agentClientId
                };
            }
            throw new InvalidOperationException($"Unexpected Microsoft Graph call: {call.Method} {call.Path}");
        });
        var service = new AgentProvisioningService(graph, store, Options.Create(Settings()));
        store.SaveAgent(new AgentRecord(
            agentId,
            "Retry checkpoint agent",
            "agent-framework",
            "Retains identity checkpoints when registry registration fails.",
            TestIdentity.AdministratorObjectId,
            DateTimeOffset.UtcNow));

        var firstFailure = await Assert.ThrowsAsync<IntegrationException>(() => service.RegisterAsync(
            agentId,
            TestIdentity.AdministratorObjectId,
            CancellationToken.None));
        Assert.Equal(503, firstFailure.StatusCode);
        var checkpoint = store.GetAgent(agentId);
        Assert.NotNull(checkpoint);
        Assert.Equal(blueprintObjectId, checkpoint.BlueprintObjectId);
        Assert.Equal(blueprintClientId, checkpoint.BlueprintClientId);
        Assert.Equal(agentObjectId, checkpoint.AgentObjectId);
        Assert.Equal(agentClientId, checkpoint.AgentClientId);
        Assert.Null(checkpoint.RegistryId);
        Assert.Contains(store.GetEvidence(agentId), evidence =>
            evidence.Stage == "Register" && evidence.State == "Blocked");

        var registered = await service.RegisterAsync(
            agentId,
            TestIdentity.AdministratorObjectId,
            CancellationToken.None);

        Assert.Equal(agentId, registered.RegistryId);
        Assert.Equal("Registered", registered.Status);
        Assert.Single(graph.Calls, call =>
            call.Method == HttpMethod.Post &&
            call.Path == "v1.0/applications/microsoft.graph.agentIdentityBlueprint");
        Assert.Single(graph.Calls, call =>
            call.Method == HttpMethod.Post &&
            call.Path == "v1.0/servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal");
        Assert.Single(graph.Calls, call =>
            call.Method == HttpMethod.Post &&
            call.Path == "beta/servicePrincipals/microsoft.graph.agentIdentity");
        var registryCalls = graph.Calls.Where(call =>
            call.Method == HttpMethod.Post &&
            call.Path == "beta/copilot/agentRegistrations").ToArray();
        Assert.Equal(2, registryCalls.Length);
        Assert.DoesNotContain(graph.Calls, call =>
            call.Path.Contains("agentRegistry", StringComparison.OrdinalIgnoreCase));
        var registryBody = Assert.IsType<JsonObject>(registryCalls[^1].Body);
        Assert.Equal(agentId, registryBody["id"]!.GetValue<string>());
        Assert.Equal(blueprintClientId, registryBody["agentIdentityBlueprintId"]!.GetValue<string>());
        Assert.Equal(agentClientId, registryBody["agentIdentityId"]!.GetValue<string>());
        Assert.Equal(agentClientId, registryBody["sourceAgentId"]!.GetValue<string>());
        Assert.Equal(HarnessClientId, registryBody["managedByAppId"]!.GetValue<string>());
    }

    [Fact]
    public async Task Agent_identity_replication_error_recovers_by_lookup_without_duplicate_create()
    {
        using var data = new TestDataDirectory();
        var store = CreateStore(data.DirectoryPath);
        var agentId = Guid.NewGuid().ToString();
        const string blueprintObjectId = "99999999-9999-4999-8999-999999999999";
        const string blueprintClientId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        const string agentObjectId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        const string agentClientId = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
        var identityLookupCount = 0;
        var identityCreateCount = 0;
        var graph = new RecordingGraphClient(call =>
        {
            if (call.Method == HttpMethod.Get &&
                call.Path.StartsWith("v1.0/servicePrincipals?$filter=appId", StringComparison.Ordinal))
            {
                return Collection(new JsonObject { ["id"] = "blueprint-principal" });
            }
            if (call.Method == HttpMethod.Get &&
                call.Path.StartsWith("beta/servicePrincipals/microsoft.graph.agentIdentity?", StringComparison.Ordinal))
            {
                identityLookupCount++;
                return identityLookupCount == 1
                    ? Collection()
                    : Collection(new JsonObject
                    {
                        ["id"] = agentObjectId,
                        ["appId"] = agentClientId,
                        ["agentIdentityBlueprintId"] = blueprintClientId
                    });
            }
            if (call.Method == HttpMethod.Post &&
                call.Path == "beta/servicePrincipals/microsoft.graph.agentIdentity")
            {
                identityCreateCount++;
                throw new IntegrationException("Microsoft Graph returned 400.", 400)
                {
                    ServiceMessage = "The referenced object does not exist yet."
                };
            }
            if (call.Method == HttpMethod.Post &&
                call.Path == "beta/copilot/agentRegistrations")
            {
                return new JsonObject
                {
                    ["id"] = agentId,
                    ["sourceAgentId"] = agentClientId
                };
            }
            throw new InvalidOperationException($"Unexpected Microsoft Graph call: {call.Method} {call.Path}");
        });
        store.SaveAgent(new AgentRecord(
            agentId,
            "Replication recovery agent",
            "agent-framework",
            "Recovers the replicated identity without creating a duplicate.",
            TestIdentity.AdministratorObjectId,
            DateTimeOffset.UtcNow,
            BlueprintObjectId: blueprintObjectId,
            BlueprintClientId: blueprintClientId,
            Status: "Blueprint created"));
        var service = new AgentProvisioningService(graph, store, Options.Create(Settings()));

        var registered = await service.RegisterAsync(
            agentId,
            TestIdentity.AdministratorObjectId,
            CancellationToken.None);

        Assert.Equal(agentObjectId, registered.AgentObjectId);
        Assert.Equal(agentClientId, registered.AgentClientId);
        Assert.Equal(agentId, registered.RegistryId);
        Assert.Equal(2, identityLookupCount);
        Assert.Equal(1, identityCreateCount);
        Assert.Single(graph.Calls, call =>
            call.Method == HttpMethod.Post &&
            call.Path == "beta/servicePrincipals/microsoft.graph.agentIdentity");
    }

    [Fact]
    public async Task Agent_enable_restores_registered_status_and_keeps_schedule_disabled()
    {
        using var data = new TestDataDirectory();
        var store = CreateStore(data.DirectoryPath);
        var agentObjectId = Guid.NewGuid().ToString();
        var agent = new AgentRecord(
            Guid.NewGuid().ToString(),
            "Disabled registered agent",
            "agent-framework",
            "Explicit enablement must not restart its schedule.",
            TestIdentity.AdministratorObjectId,
            DateTimeOffset.UtcNow,
            BlueprintObjectId: Guid.NewGuid().ToString(),
            BlueprintClientId: Guid.NewGuid().ToString(),
            AgentObjectId: agentObjectId,
            AgentClientId: Guid.NewGuid().ToString(),
            RegistryId: Guid.NewGuid().ToString(),
            ScheduleEnabled: true,
            Status: "Disabled");
        store.SaveAgent(agent);
        var graph = new RecordingGraphClient(call =>
        {
            if (call.Method == HttpMethod.Patch &&
                call.Path == $"beta/servicePrincipals/{agentObjectId}/microsoft.graph.agentIdentity")
            {
                return new JsonObject();
            }
            if (call.Method == HttpMethod.Get &&
                call.Path == $"beta/servicePrincipals/{agentObjectId}/microsoft.graph.agentIdentity?$select=id,accountEnabled")
            {
                return new JsonObject
                {
                    ["id"] = agentObjectId,
                    ["accountEnabled"] = true
                };
            }
            throw new InvalidOperationException($"Unexpected Microsoft Graph call: {call.Method} {call.Path}");
        });
        var service = new AgentProvisioningService(graph, store, Options.Create(Settings()));

        await service.EnableAsync(agent.Id, TestIdentity.AdministratorObjectId, CancellationToken.None);

        var enabled = store.GetAgent(agent.Id);
        Assert.NotNull(enabled);
        Assert.Equal("Registered", enabled.Status);
        Assert.False(enabled.ScheduleEnabled);
        var patch = Assert.Single(graph.Calls, call => call.Method == HttpMethod.Patch);
        var body = Assert.IsType<JsonObject>(patch.Body);
        Assert.True(body["accountEnabled"]!.GetValue<bool>());
        Assert.Single(graph.Calls, call =>
            call.Method == HttpMethod.Get &&
            call.Path == $"beta/servicePrincipals/{agentObjectId}/microsoft.graph.agentIdentity?$select=id,accountEnabled");
    }

    [Fact]
    public async Task Agent_enable_remains_paused_until_stale_read_converges()
    {
        using var data = new TestDataDirectory();
        var store = CreateStore(data.DirectoryPath);
        var agentObjectId = Guid.NewGuid().ToString();
        var agent = new AgentRecord(
            Guid.NewGuid().ToString(),
            "Propagation-delayed agent",
            "agent-framework",
            "Enablement remains paused until Entra read-back converges.",
            TestIdentity.AdministratorObjectId,
            DateTimeOffset.UtcNow,
            BlueprintObjectId: Guid.NewGuid().ToString(),
            BlueprintClientId: Guid.NewGuid().ToString(),
            AgentObjectId: agentObjectId,
            AgentClientId: Guid.NewGuid().ToString(),
            RegistryId: Guid.NewGuid().ToString(),
            ScheduleEnabled: true,
            Status: "Disabled");
        store.SaveAgent(agent);
        var firstStaleRead = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var readCount = 0;
        var graph = new RecordingGraphClient(call =>
        {
            if (call.Method == HttpMethod.Patch &&
                call.Path == $"beta/servicePrincipals/{agentObjectId}/microsoft.graph.agentIdentity")
            {
                return new JsonObject();
            }
            if (call.Method == HttpMethod.Get &&
                call.Path == $"beta/servicePrincipals/{agentObjectId}/microsoft.graph.agentIdentity?$select=id,accountEnabled")
            {
                readCount++;
                if (readCount == 1)
                {
                    firstStaleRead.TrySetResult(true);
                    return new JsonObject
                    {
                        ["id"] = agentObjectId,
                        ["accountEnabled"] = false
                    };
                }
                return new JsonObject
                {
                    ["id"] = agentObjectId,
                    ["accountEnabled"] = true
                };
            }
            throw new InvalidOperationException($"Unexpected Microsoft Graph call: {call.Method} {call.Path}");
        });
        var service = new AgentProvisioningService(graph, store, Options.Create(Settings()));

        var enableTask = service.EnableAsync(agent.Id, TestIdentity.AdministratorObjectId, CancellationToken.None);
        await firstStaleRead.Task.WaitAsync(TimeSpan.FromSeconds(3));

        var paused = store.GetAgent(agent.Id);
        Assert.NotNull(paused);
        Assert.Equal("Disabled", paused.Status);
        Assert.False(paused.ScheduleEnabled);
        Assert.False(enableTask.IsCompleted);

        await enableTask;

        var enabled = store.GetAgent(agent.Id);
        Assert.NotNull(enabled);
        Assert.Equal("Registered", enabled.Status);
        Assert.False(enabled.ScheduleEnabled);
        Assert.Equal(2, readCount);
    }

    private static HarnessOptions Settings(params string[] allowedGuestIds) =>
        Settings(allowedGuestIds, []);

    private static HarnessOptions Settings(
        string[] allowedGuestIds,
        string[] allowedGuestAdministratorIds) => new()
    {
        TenantId = TestIdentity.TenantId,
        ClientId = HarnessClientId,
        ServicePrincipalId = HarnessServicePrincipalId,
        InternalApiServicePrincipalId = InternalApiServicePrincipalId,
        GraviteeServicePrincipalId = GraviteeServicePrincipalId,
        AllowedB2BGuestObjectIds = allowedGuestIds,
        AllowedB2BGuestAdministratorObjectIds = allowedGuestAdministratorIds
    };

    private static HarnessStore CreateStore(string dataPath)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Data:Path"] = dataPath
        }).Build();
        return new HarnessStore(configuration);
    }

    private static PurviewService CreatePurviewService(
        IGraphClient graph,
        string dataPath,
        bool requireInlinePolicy)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Purview:Enabled"] = "true",
            ["Purview:RequireInlinePolicy"] = requireInlinePolicy.ToString()
        }).Build();
        return new PurviewService(graph, Options.Create(Settings()), configuration, CreateStore(dataPath));
    }

    private static JsonObject DirectoryUserResponse(
        string userType,
        bool accountEnabled,
        string objectId = TestIdentity.MemberObjectId,
        string? externalUserState = null) => new()
    {
        ["id"] = objectId,
        ["displayName"] = "Target User",
        ["userPrincipalName"] = "target@example.test",
        ["userType"] = userType,
        ["accountEnabled"] = accountEnabled,
        ["externalUserState"] = externalUserState
    };

    private static JsonObject RoleDefinition(string id, string value) => new()
    {
        ["id"] = id,
        ["value"] = value,
        ["displayName"] = value,
        ["isEnabled"] = true
    };

    private static JsonObject RoleAssignment(string appRoleId, string resourceId, string principalId) => new()
    {
        ["appRoleId"] = appRoleId,
        ["resourceId"] = resourceId,
        ["principalId"] = principalId
    };

    private static JsonObject ScopeResponse(
        string etag,
        string activities,
        string executionMode) => new()
    {
        ["_etag"] = etag,
        ["value"] = new JsonArray(new JsonObject
        {
            ["activities"] = activities,
            ["executionMode"] = executionMode
        })
    };

    private static JsonObject AllowDecision(string protectionScopeState) => new()
    {
        ["processingErrors"] = new JsonArray(),
        ["policyActions"] = new JsonArray(new JsonObject
        {
            ["action"] = "restrictAccess",
            ["restrictionAction"] = "allow"
        }),
        ["protectionScopeState"] = protectionScopeState
    };

    private static JsonObject Collection(params JsonNode[] values) => new()
    {
        ["value"] = new JsonArray(values)
    };

    private static T UnusedService<T>() where T : class =>
        DispatchProxy.Create<T, UnexpectedDispatchProxy>();

    private sealed class BlockingPurviewService(IntegrationException failure) : IPurviewService
    {
        public List<string> Activities { get; } = [];

        public Task<string> EvaluateAsync(
            string userId,
            string content,
            string activity,
            string correlationId,
            CancellationToken ct)
        {
            Activities.Add(activity);
            return Task.FromException<string>(failure);
        }
    }

    private sealed class CountingPurviewService : IPurviewService
    {
        public List<string> Activities { get; } = [];

        public Task<string> EvaluateAsync(
            string userId,
            string content,
            string activity,
            string correlationId,
            CancellationToken ct)
        {
            Activities.Add(activity);
            return Task.FromResult("Purview evaluated test content.");
        }
    }

    public class UnexpectedDispatchProxy : DispatchProxy
    {
        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args) =>
            throw new InvalidOperationException($"Unexpected call to {targetMethod?.DeclaringType?.Name}.{targetMethod?.Name}.");
    }

    private sealed class CountingHttpClientFactory : IHttpClientFactory
    {
        public int CreateClientCount { get; private set; }

        public HttpClient CreateClient(string name)
        {
            CreateClientCount++;
            return new HttpClient(new RejectingHandler());
        }
    }

    private sealed class RejectingHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException($"Unexpected outbound request: {request.Method} {request.RequestUri}");
    }
}
