// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using AgentHarness;

namespace AgentHarness.Tests;

public sealed class HarnessApiTests
{
    [Fact]
    public async Task Configured_customer_tenant_is_allowed_and_other_tenants_remain_rejected()
    {
        using var data = new TestDataDirectory();
        using var factory = new HarnessWebApplicationFactory(data.DirectoryPath, tenantId: TestIdentity.OtherTenantId);
        using var configuredUser = HarnessHttp.CreateClient(factory, HarnessRoles.User, TestIdentity.OtherTenantId);
        using var foreignUser = HarnessHttp.CreateClient(factory, HarnessRoles.User, TestIdentity.TenantId);

        using var allowed = await configuredUser.GetAsync("/api/agents");
        using var denied = await foreignUser.GetAsync("/api/agents");

        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
    }

    [Fact]
    public async Task Missing_customer_tenant_never_authorizes_a_principal()
    {
        using var data = new TestDataDirectory();
        using var factory = new HarnessWebApplicationFactory(data.DirectoryPath, tenantId: "");
        using var client = HarnessHttp.CreateClient(factory, HarnessRoles.Administrator);

        using var sessionResponse = await client.GetAsync("/api/session");
        var session = await sessionResponse.Content.ReadFromJsonAsync<JsonElement>();
        Assert.False(session.GetProperty("authenticated").GetBoolean());
        Assert.False(session.GetProperty("identityConfigured").GetBoolean());
        using var denied = await client.GetAsync("/api/agents");
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
    }

    [Fact]
    public async Task Anonymous_session_is_public_but_harness_api_and_csrf_are_401_without_redirect()
    {
        using var data = new TestDataDirectory();
        using var factory = new HarnessWebApplicationFactory(data.DirectoryPath);
        using var client = HarnessHttp.CreateClient(factory, objectId: "");

        using var sessionResponse = await client.GetAsync("/api/session");
        Assert.Equal(HttpStatusCode.OK, sessionResponse.StatusCode);
        var session = await sessionResponse.Content.ReadFromJsonAsync<JsonElement>();
        Assert.False(session.GetProperty("authenticated").GetBoolean());

        foreach (var path in new[] { "/api/agents", "/api/csrf", "/api/demo" })
        {
            using var response = await client.GetAsync(path);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Null(response.Headers.Location);
            Assert.NotEqual("text/html", response.Content.Headers.ContentType?.MediaType);
        }
    }

    [Theory]
    [InlineData("matching role from another tenant", TestIdentity.OtherTenantId, "0", HarnessRoles.Administrator)]
    [InlineData("guest account with a matching role", TestIdentity.TenantId, "1", HarnessRoles.User)]
    [InlineData("tenant member without an assigned harness role", TestIdentity.TenantId, "0", null)]
    public async Task Tenant_guest_and_assignment_boundaries_reject_invalid_principals(
        string scenario,
        string tenantId,
        string accountType,
        string? role)
    {
        _ = scenario;
        using var data = new TestDataDirectory();
        using var factory = new HarnessWebApplicationFactory(data.DirectoryPath);
        using var client = HarnessHttp.CreateClient(factory, role, tenantId, accountType);

        foreach (var path in new[] { "/api/agents", "/api/demo" })
        {
            using var response = await client.GetAsync(path);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Null(response.Headers.Location);
        }
    }

    [Fact]
    public async Task Approved_guest_user_can_use_harness_routes_but_not_administration()
    {
        using var data = new TestDataDirectory();
        using var factory = new HarnessWebApplicationFactory(
            data.DirectoryPath,
            allowedGuestIds: [TestIdentity.ApprovedGuestObjectId]);
        using var client = HarnessHttp.CreateClient(
            factory,
            HarnessRoles.User,
            accountType: "1",
            objectId: TestIdentity.ApprovedGuestObjectId);

        using var sessionResponse = await client.GetAsync("/api/session");
        Assert.Equal(HttpStatusCode.OK, sessionResponse.StatusCode);
        var session = await sessionResponse.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(session.GetProperty("authenticated").GetBoolean());
        Assert.False(session.GetProperty("administrator").GetBoolean());

        foreach (var path in new[] { "/api/agents", "/api/demo" })
        {
            using var response = await client.GetAsync(path);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        using var adminResponse = await client.GetAsync("/api/admin/audit");
        Assert.Equal(HttpStatusCode.Forbidden, adminResponse.StatusCode);
    }

    [Fact]
    public async Task Guest_policy_rejects_unapproved_admin_only_and_foreign_tenant_principals()
    {
        using var data = new TestDataDirectory();
        using var factory = new HarnessWebApplicationFactory(
            data.DirectoryPath,
            allowedGuestIds: [TestIdentity.ApprovedGuestObjectId]);
        var principals = new[]
        {
            (TestIdentity.UnapprovedGuestObjectId, TestIdentity.TenantId, "1", HarnessRoles.User),
            (TestIdentity.ApprovedGuestObjectId, TestIdentity.TenantId, "1", HarnessRoles.Administrator),
            (TestIdentity.ApprovedGuestObjectId, TestIdentity.OtherTenantId, "1", HarnessRoles.User)
        };

        foreach (var (objectId, tenantId, accountType, role) in principals)
        {
            using var client = HarnessHttp.CreateClient(factory, role, tenantId, accountType, objectId);
            using var response = await client.GetAsync("/api/agents");
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);

            using var sessionResponse = await client.GetAsync("/api/session");
            var session = await sessionResponse.Content.ReadFromJsonAsync<JsonElement>();
            Assert.False(session.GetProperty("authenticated").GetBoolean());
            Assert.False(session.GetProperty("administrator").GetBoolean());
        }
    }

    [Fact]
    public async Task Allowlisted_guest_object_id_cannot_admin_when_account_type_is_member_or_missing()
    {
        using var data = new TestDataDirectory();
        using var factory = new HarnessWebApplicationFactory(
            data.DirectoryPath,
            allowedGuestIds: [TestIdentity.ApprovedGuestObjectId]);

        foreach (var accountType in new string?[] { "0", null })
        {
            using var client = HarnessHttp.CreateClient(
                factory,
                $"{HarnessRoles.User},{HarnessRoles.Administrator}",
                accountType: accountType,
                objectId: TestIdentity.ApprovedGuestObjectId);

            using var userResponse = await client.GetAsync("/api/agents");
            Assert.Equal(HttpStatusCode.OK, userResponse.StatusCode);

            using var adminResponse = await client.GetAsync("/api/admin/audit");
            Assert.Equal(HttpStatusCode.Forbidden, adminResponse.StatusCode);

            using var sessionResponse = await client.GetAsync("/api/session");
            var session = await sessionResponse.Content.ReadFromJsonAsync<JsonElement>();
            Assert.True(session.GetProperty("authenticated").GetBoolean());
            Assert.False(session.GetProperty("administrator").GetBoolean());
        }
    }

    [Fact]
    public async Task Explicitly_privileged_guest_with_admin_role_can_use_user_and_admin_routes()
    {
        using var data = new TestDataDirectory();
        using var factory = new HarnessWebApplicationFactory(
            data.DirectoryPath,
            allowedGuestIds: [TestIdentity.ApprovedGuestObjectId],
            allowedGuestAdministratorIds: [TestIdentity.ApprovedGuestObjectId]);
        using var client = HarnessHttp.CreateClient(
            factory,
            HarnessRoles.Administrator,
            accountType: "1",
            objectId: TestIdentity.ApprovedGuestObjectId);

        using var userResponse = await client.GetAsync("/api/agents");
        using var adminResponse = await client.GetAsync("/api/admin/audit");
        using var sessionResponse = await client.GetAsync("/api/session");
        var session = await sessionResponse.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal(HttpStatusCode.OK, userResponse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, adminResponse.StatusCode);
        Assert.True(session.GetProperty("authenticated").GetBoolean());
        Assert.True(session.GetProperty("administrator").GetBoolean());
    }

    [Fact]
    public async Task Privileged_guest_administration_requires_both_admin_allowlist_and_admin_role()
    {
        using var data = new TestDataDirectory();
        using var privilegedFactory = new HarnessWebApplicationFactory(
            data.DirectoryPath,
            allowedGuestIds: [TestIdentity.ApprovedGuestObjectId],
            allowedGuestAdministratorIds: [TestIdentity.ApprovedGuestObjectId]);
        using var userOnlyClient = HarnessHttp.CreateClient(
            privilegedFactory,
            HarnessRoles.User,
            accountType: "1",
            objectId: TestIdentity.ApprovedGuestObjectId);

        using var userResponse = await userOnlyClient.GetAsync("/api/agents");
        using var missingRoleResponse = await userOnlyClient.GetAsync("/api/admin/audit");
        Assert.Equal(HttpStatusCode.OK, userResponse.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, missingRoleResponse.StatusCode);

        using var standardFactory = new HarnessWebApplicationFactory(
            data.DirectoryPath,
            allowedGuestIds: [TestIdentity.ApprovedGuestObjectId]);
        using var adminRoleOnlyClient = HarnessHttp.CreateClient(
            standardFactory,
            HarnessRoles.Administrator,
            accountType: "1",
            objectId: TestIdentity.ApprovedGuestObjectId);

        using var missingAllowlistResponse = await adminRoleOnlyClient.GetAsync("/api/admin/audit");
        Assert.Equal(HttpStatusCode.Forbidden, missingAllowlistResponse.StatusCode);
    }

    [Fact]
    public async Task Guest_admin_allowlist_without_base_guest_approval_grants_no_access()
    {
        using var data = new TestDataDirectory();
        using var factory = new HarnessWebApplicationFactory(
            data.DirectoryPath,
            allowedGuestAdministratorIds: [TestIdentity.ApprovedGuestObjectId]);
        using var client = HarnessHttp.CreateClient(
            factory,
            $"{HarnessRoles.User},{HarnessRoles.Administrator}",
            accountType: "1",
            objectId: TestIdentity.ApprovedGuestObjectId);

        using var userResponse = await client.GetAsync("/api/agents");
        using var adminResponse = await client.GetAsync("/api/admin/audit");
        using var sessionResponse = await client.GetAsync("/api/session");
        var session = await sessionResponse.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal(HttpStatusCode.Forbidden, userResponse.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, adminResponse.StatusCode);
        Assert.False(session.GetProperty("authenticated").GetBoolean());
        Assert.False(session.GetProperty("administrator").GetBoolean());
    }

    [Fact]
    public async Task Normal_user_is_forbidden_from_admin_route_while_administrator_is_allowed()
    {
        using var data = new TestDataDirectory();
        using var factory = new HarnessWebApplicationFactory(data.DirectoryPath);
        using var userClient = HarnessHttp.CreateClient(factory, HarnessRoles.User);
        using var adminClient = HarnessHttp.CreateClient(
            factory,
            HarnessRoles.Administrator,
            objectId: TestIdentity.AdministratorObjectId);

        using var userResponse = await userClient.GetAsync("/api/admin/audit");
        using var adminResponse = await adminClient.GetAsync("/api/admin/audit");

        Assert.Equal(HttpStatusCode.Forbidden, userResponse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, adminResponse.StatusCode);
    }

    [Fact]
    public async Task Agent_mutation_requires_real_antiforgery_token_and_valid_token_creates_agent()
    {
        using var data = new TestDataDirectory();
        using var factory = new HarnessWebApplicationFactory(data.DirectoryPath);
        using var client = HarnessHttp.CreateClient(
            factory,
            HarnessRoles.Administrator,
            objectId: TestIdentity.AdministratorObjectId);
        var request = new NewAgentRequest("Focused test agent", "agent-framework", "Created through the protected API.");

        using var missingTokenResponse = await client.PostAsJsonAsync("/api/admin/agents", request);
        Assert.Equal(HttpStatusCode.BadRequest, missingTokenResponse.StatusCode);

        var token = await HarnessHttp.GetCsrfTokenAsync(client);
        using var createdResponse = await HarnessHttp.PostJsonWithCsrfAsync(client, "/api/admin/agents", request, token);
        Assert.Equal(HttpStatusCode.Created, createdResponse.StatusCode);
        var created = await createdResponse.Content.ReadFromJsonAsync<AgentRecord>();
        Assert.NotNull(created);
        Assert.Equal(request.Name, created.Name);
        Assert.Equal(request.Framework, created.Framework);
        Assert.Equal(TestIdentity.AdministratorObjectId, created.CreatedBy);

        var store = factory.Services.GetRequiredService<HarnessStore>();
        Assert.NotNull(store.GetAgent(created.Id));
        Assert.Contains(store.GetAudit(), entry =>
            entry.ActorId == TestIdentity.AdministratorObjectId &&
            entry.Action == "AgentDraftCreated" &&
            entry.Target == created.Id &&
            entry.Outcome == "Succeeded");
    }

    [Fact]
    public async Task Admin_agent_creation_rejects_invalid_name_framework_and_description()
    {
        using var data = new TestDataDirectory();
        using var factory = new HarnessWebApplicationFactory(data.DirectoryPath);
        using var client = HarnessHttp.CreateClient(
            factory,
            HarnessRoles.Administrator,
            objectId: TestIdentity.AdministratorObjectId);
        var token = await HarnessHttp.GetCsrfTokenAsync(client);
        var invalidRequests = new[]
        {
            new NewAgentRequest("ab", "agent-framework", "Name is too short."),
            new NewAgentRequest("Unsupported framework", "arbitrary-runtime", "Framework must be allowlisted."),
            new NewAgentRequest("Description boundary", "semantic-kernel", new string('x', 1001))
        };

        foreach (var request in invalidRequests)
        {
            using var response = await HarnessHttp.PostJsonWithCsrfAsync(client, "/api/admin/agents", request, token);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
    }

    [Fact]
    public async Task Harness_user_run_requires_csrf_and_returns_the_runtime_result()
    {
        using var data = new TestDataDirectory();
        var runtime = new RecordingAgentRuntime
        {
            Result = new RunResult(
                "Policy-approved response",
                "0123456789abcdef0123456789abcdef",
                "agent-framework",
                ["Purview evaluated input.", "Purview evaluated output."],
                true)
        };
        using var factory = new HarnessWebApplicationFactory(data.DirectoryPath, runtime);
        var agent = new AgentRecord(
            Guid.NewGuid().ToString(),
            "Runtime boundary test",
            "agent-framework",
            "Exercises the authenticated run route.",
            TestIdentity.AdministratorObjectId,
            DateTimeOffset.UtcNow);
        factory.Services.GetRequiredService<HarnessStore>().SaveAgent(agent);
        using var client = HarnessHttp.CreateClient(factory, HarnessRoles.User);
        var request = new RunRequest("Return a governed response.");

        using var missingTokenResponse = await client.PostAsJsonAsync($"/api/agents/{agent.Id}/run", request);
        Assert.Equal(HttpStatusCode.BadRequest, missingTokenResponse.StatusCode);

        var token = await HarnessHttp.GetCsrfTokenAsync(client);
        using var response = await HarnessHttp.PostJsonWithCsrfAsync(client, $"/api/agents/{agent.Id}/run", request, token);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<RunResult>();
        Assert.NotNull(result);
        Assert.Equal(runtime.Result.Text, result.Text);
        Assert.Equal(runtime.Result.TraceId, result.TraceId);
        Assert.Equal(runtime.Result.Framework, result.Framework);
        Assert.Equal(runtime.Result.Steps, result.Steps);
        Assert.True(result.Live);

        var call = Assert.Single(runtime.Calls);
        Assert.Equal(agent.Id, call.Agent.Id);
        Assert.Equal(request.Prompt, call.Prompt);
        Assert.Equal(TestIdentity.MemberObjectId, call.UserId);
    }

    [Fact]
    public async Task Demo_returns_ordered_per_agent_contract_for_the_current_harness_user_without_external_checks()
    {
        using var data = new TestDataDirectory();
        using var factory = new HarnessWebApplicationFactory(data.DirectoryPath);
        var agent = OverviewAgent();
        factory.Services.GetRequiredService<HarnessStore>().SaveAgent(agent);
        using var client = HarnessHttp.CreateClient(factory, HarnessRoles.User);

        using var response = await client.GetAsync("/api/demo");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        var overview = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(new[] { "observedAt", "hosting", "agents" }, overview.EnumerateObject().Select(x => x.Name));
        Assert.InRange(overview.GetProperty("observedAt").GetDateTimeOffset(),
            DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(1));
        var hosting = overview.GetProperty("hosting");
        Assert.Equal("/healthz", hosting.GetProperty("healthUrl").GetString());
        Assert.Equal(!string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("WEBSITE_INSTANCE_ID")),
            hosting.GetProperty("azureHosted").GetBoolean());
        Assert.Equal("Responding", hosting.GetProperty("state").GetString());
        Assert.Contains("does not verify model inference", hosting.GetProperty("detail").GetString());
        var agents = overview.GetProperty("agents").EnumerateArray().ToArray();
        Assert.NotEmpty(agents);
        foreach (var item in agents)
        {
            Assert.Equal(new[] { "id", "name", "framework", "status", "identity", "capabilities", "stages" },
                item.EnumerateObject().Select(x => x.Name));
            Assert.Equal(new[] { "blueprintClientId", "agentClientId", "registryId" },
                item.GetProperty("identity").EnumerateObject().Select(x => x.Name));
            var capabilities = item.GetProperty("capabilities").EnumerateArray().ToArray();
            Assert.Equal(new[] { "identity", "observability", "tooling", "notifications" },
                capabilities.Select(x => x.GetProperty("id").GetString()));
            Assert.Equal(new[]
            {
                "Harness/AgentProvisioningService.cs", "Harness/Program.cs",
                "Harness/AgentRuntime.cs", "Harness/HarnessChannelAgent.cs"
            }, capabilities.Select(x => x.GetProperty("sourcePath").GetString()));
            foreach (var capability in capabilities)
            {
                Assert.Equal(new[] { "id", "title", "state", "detail", "blocker", "sourcePath", "actionRoute", "traceId" },
                    capability.EnumerateObject().Select(x => x.Name));
                Assert.Contains(capability.GetProperty("actionRoute").GetString(),
                    new[] { "builder-register", "builder-extend", "builder-validate" });
            }
            var stages = item.GetProperty("stages").EnumerateArray().ToArray();
            Assert.Equal(new[] { "register", "extend", "validate", "operate" },
                stages.Select(x => x.GetProperty("id").GetString()));
            Assert.Equal(new[] { "builder-register", "builder-extend", "builder-validate", "builder-operate" },
                stages.Select(x => x.GetProperty("actionRoute").GetString()));
            foreach (var stage in stages)
                Assert.Equal(new[] { "id", "title", "state", "detail", "actionRoute" },
                    stage.EnumerateObject().Select(x => x.Name));
        }
        var saved = Assert.Single(agents, x => x.GetProperty("id").GetString() == agent.Id);
        Assert.Equal(agent.Name, saved.GetProperty("name").GetString());
        Assert.Equal(agent.Framework, saved.GetProperty("framework").GetString());
        Assert.Equal(agent.Status, saved.GetProperty("status").GetString());
        Assert.Equal(agent.AgentClientId, saved.GetProperty("identity").GetProperty("agentClientId").GetString());
        Assert.Empty(factory.Graph.Calls);
    }

    [Fact]
    public void Demo_identity_metadata_generic_verified_evidence_and_configuration_do_not_prove_workload_delivery()
    {
        using var data = new TestDataDirectory();
        var (store, overview) = CreateOverview(data.DirectoryPath, exporter: true, channels: true);
        var agent = OverviewAgent() with { AgentUserId = Guid.NewGuid().ToString() };
        store.SaveAgent(agent);
        store.AddEvidence(agent.Id, "Validate", "Verified", "Real inference, MCP, and notification delivery.");
        store.AddEvidence(agent.Id, "Validate", "Verified", "Identity read-back.", "identity-validation");
        store.AddEvidence(agent.Id, "Validate", "Verified", "Registry read-back.", "registry-validation");
        store.AddEvidence(agent.Id, "Validate", "Verified", "A channel message was processed.", "message-processed");
        store.AddEvidence(agent.Id, "Validate", "Blocked", "A runtime attempt was blocked.", "runtime-turn");

        var result = Assert.Single(overview.GetOverview().Agents);

        Assert.Equal(new[] { "Registered", "Not validated", "Not validated", "Not validated" },
            result.Capabilities.Select(x => x.State));
        Assert.All(result.Capabilities.Skip(1), capability =>
        {
            Assert.False(string.IsNullOrWhiteSpace(capability.Blocker));
            Assert.Null(capability.TraceId);
        });
        Assert.Contains("not a fresh tenant recheck", result.Capabilities[0].Detail);
        Assert.Contains("configured", result.Capabilities[1].Detail);
        Assert.Equal("Not validated", result.Stages[2].State);
        Assert.Contains("inline Purview policy", result.Stages[2].Detail);
    }

    [Fact]
    public void Demo_registration_requires_all_three_ids_even_when_the_saved_status_says_registered()
    {
        using var data = new TestDataDirectory();
        var (store, overview) = CreateOverview(data.DirectoryPath);
        var registered = OverviewAgent() with { Status = "Registered" };
        store.SaveAgent(registered);
        var incomplete = new[]
        {
            registered with { Id = Guid.NewGuid().ToString(), BlueprintClientId = null },
            registered with { Id = Guid.NewGuid().ToString(), AgentClientId = " " },
            registered with { Id = Guid.NewGuid().ToString(), RegistryId = null }
        };
        foreach (var agent in incomplete) store.SaveAgent(agent);

        var agents = overview.GetOverview().Agents;

        Assert.Equal(registered.Id, Assert.Single(agents, x => x.Capabilities[0].State == "Registered").Id);
        foreach (var agent in incomplete)
        {
            var result = Assert.Single(agents, x => x.Id == agent.Id);
            Assert.Equal("Not registered", result.Capabilities[0].State);
            Assert.False(string.IsNullOrWhiteSpace(result.Capabilities[0].Blocker));
            Assert.Contains("Missing:", result.Stages[0].Detail);
            Assert.Equal("Not registered", result.Stages[0].State);
        }
    }

    [Fact]
    public void Demo_disabled_agent_stays_disabled_despite_saved_registration_and_historical_runtime_proof()
    {
        using var data = new TestDataDirectory();
        var (store, overview) = CreateOverview(data.DirectoryPath, exporter: true, channels: true);
        var agent = OverviewAgent() with { Status = "Disabled", AgentUserId = Guid.NewGuid().ToString() };
        store.SaveAgent(agent);
        foreach (var check in new[] { "runtime-turn", "mcp-discovery", "notification-received" })
            store.AddEvidence(agent.Id, "Validate", "Verified", "Historical observation.", check);

        var result = Assert.Single(overview.GetOverview().Agents);

        Assert.Equal("Disabled", result.Status);
        Assert.All(result.Capabilities, capability =>
        {
            Assert.Equal("Disabled", capability.State);
            Assert.Contains("Re-enable explicitly", capability.Blocker);
        });
        Assert.All(result.Stages, stage => Assert.Equal("Disabled", stage.State));
        Assert.Contains("not a fresh directory check", result.Stages[3].Detail);
    }

    [Fact]
    public void Demo_typed_turn_discovery_and_notification_proof_are_distinct_and_keep_delivery_unverified()
    {
        using var data = new TestDataDirectory();
        var (store, _) = CreateOverview(data.DirectoryPath, exporter: true, channels: true);
        var agent = OverviewAgent() with { AgentUserId = Guid.NewGuid().ToString() };
        store.SaveAgent(agent);
        string traceId;
        using (var activity = new Activity("demo-proof").SetIdFormat(ActivityIdFormat.W3C).Start())
        {
            traceId = activity.TraceId.ToString();
            store.AddEvidence(agent.Id, "Validate", "Verified", "Completed inference and Purview evaluation.", "runtime-turn");
            store.AddEvidence(agent.Id, "Validate", "Verified", "Governed MCP tools registered.", "mcp-discovery");
            store.AddEvidence(agent.Id, "Validate", "Verified", "Authenticated notification received.", "notification-received");
        }
        var (_, restartedOverview) = CreateOverview(data.DirectoryPath, exporter: true, channels: true);

        var result = Assert.Single(restartedOverview.GetOverview().Agents);

        Assert.Equal(new[] { "Registered", "Trace observed", "Tools discovered", "Notification received" },
            result.Capabilities.Select(x => x.State));
        Assert.All(result.Capabilities.Skip(1), capability =>
        {
            Assert.Equal(traceId, capability.TraceId);
            Assert.False(string.IsNullOrWhiteSpace(capability.Blocker));
        });
        Assert.Contains("not destination delivery", result.Capabilities[1].Detail);
        Assert.Contains("Discovery does not prove", result.Capabilities[2].Detail);
        Assert.Contains("does not prove a successful reply", result.Capabilities[3].Detail);
        Assert.Equal("Turn observed", result.Stages[2].State);
        Assert.Contains("inline policy coverage", result.Stages[2].Detail);
        Assert.Equal("Controls available", result.Stages[3].State);
        Assert.DoesNotContain(result.Stages, stage => stage.State == "Complete");
    }

    [Fact]
    public void Demo_historical_proof_does_not_enable_exporters_channels_agent_users_or_unselected_extensions()
    {
        using var data = new TestDataDirectory();
        var (store, overview) = CreateOverview(data.DirectoryPath);
        var agent = OverviewAgent();
        store.SaveAgent(agent);
        foreach (var check in new[] { "runtime-turn", "mcp-discovery", "notification-received" })
            store.AddEvidence(agent.Id, "Validate", "Verified", "Historical observation.", check);

        var result = Assert.Single(overview.GetOverview().Agents);

        Assert.Equal(new[] { "Registered", "Agent 365 exporter off", "Channel not connected", "Needs agent user" },
            result.Capabilities.Select(x => x.State));
        Assert.Contains("Enable the Agent 365 exporter", result.Capabilities[1].Blocker);
        Assert.Contains("delegated consent", result.Capabilities[2].Blocker);
        Assert.Contains("agent user and mailbox", result.Capabilities[3].Blocker);
        store.SaveAgent(agent with { Capabilities = [], AgentUserId = Guid.NewGuid().ToString() });
        var (_, enabledHost) = CreateOverview(data.DirectoryPath, exporter: true, channels: true);
        var unselected = Assert.Single(enabledHost.GetOverview().Agents);
        Assert.Equal("Not enabled", unselected.Capabilities[2].State);
        Assert.Equal("Not enabled", unselected.Capabilities[3].State);
        Assert.Equal("Not extended", unselected.Stages[1].State);
        Assert.Contains("Select Observability", unselected.Capabilities[1].Blocker);
    }

    [Theory]
    [InlineData(false, true, "Blocked", "no simulated or local policy fallback")]
    [InlineData(true, false, "Validation required", "Require and verify")]
    public void Demo_validation_does_not_ignore_disabled_purview_or_missing_inline_requirement(
        bool purview, bool inline, string state, string detail)
    {
        using var data = new TestDataDirectory();
        var (store, overview) = CreateOverview(data.DirectoryPath, purview: purview, inline: inline);
        var agent = OverviewAgent();
        store.SaveAgent(agent);
        store.AddEvidence(agent.Id, "Validate", "Verified", "A prior turn completed.", "runtime-turn");

        var result = Assert.Single(overview.GetOverview().Agents);

        Assert.Equal(state, result.Stages[2].State);
        Assert.Contains(detail, result.Stages[2].Detail);
    }

    private static AgentRecord OverviewAgent() => new(
        Guid.NewGuid().ToString(), "Overview proof boundary agent", "agent-framework",
        "Only actual, scoped evidence can validate a capability.", TestIdentity.AdministratorObjectId,
        DateTimeOffset.UtcNow, BlueprintClientId: Guid.NewGuid().ToString(),
        AgentClientId: Guid.NewGuid().ToString(), RegistryId: Guid.NewGuid().ToString(),
        Capabilities: ["observability", "workiq", "notifications", "purview"],
        Status: "Identity validated; runtime checks pending");

    private static (HarnessStore Store, DemoOverviewService Overview) CreateOverview(
        string directoryPath, bool exporter = false, bool channels = false, bool purview = true, bool inline = true)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Data:Path"] = directoryPath,
            ["APPLICATIONINSIGHTS_CONNECTION_STRING"] = "test-connection",
            ["WEBSITE_INSTANCE_ID"] = "configuration-is-not-hosting-proof",
            ["Agent365:EnableExporter"] = exporter.ToString(),
            ["AgentChannels:Enabled"] = channels.ToString(),
            ["Purview:Enabled"] = purview.ToString(),
            ["Purview:RequireInlinePolicy"] = inline.ToString()
        }).Build();
        var store = new HarnessStore(configuration);
        return (store, new DemoOverviewService(store, configuration, Options.Create(new HarnessOptions())));
    }
}
