# Customer governance setup and validation

This runbook describes how to configure and validate **your own** AgentHarness sample environment. It contains no deployment results. A registered agent, consented permission, assigned license, or reachable portal does not establish policy enforcement.

## 1. Establish customer scope

Use one explicitly selected tenant and the individual harness application. Obtain approval before granting permissions, creating policies, activating collection, associating billing, or enabling paid protection plans.

Populate ignored `infra\entra-state.json` through the customer bootstrap workflow described in [the deployment guide](../infra/OPERATIONS.md). Purview tooling uses customer state including `TenantId`, `SubscriptionId`, `ClientId`, `AdministratorObjectId`, `AdministratorUpn`, and `TenantDomain`. Keep runtime configuration in ignored `appsettings.Local.json`, environment variables, or an approved configuration/secret store.

- Match the harness client ID, enterprise application object ID, tenant, and intended users to authoritative directory read-back.
- Keep tenant validation and application-role authorization enabled. Approve B2B guest object IDs and privileged guest access separately; invitation acceptance alone grants no harness access. Create approval records through the customer-configured invitation workflow: approvals are bound to that tenant and its applications, not portable between environments.
- Never replace an unsupported individual-app policy with an all-app or tenant-wide policy to make a test pass.
- Keep credentials, policy IDs, user identifiers, resource addresses, diagnostic traces, and customer acceptance records out of the repository.

## 2. Verify prerequisites

| Area | Customer action |
| --- | --- |
| Licensing and availability | Confirm the required Agent 365, Purview, workload, and preview entitlements for the selected users and capabilities |
| Graph consent | Review the runtime's application permissions, including its protection-scope/content-processing permissions (`ProtectionScopes.Compute.All` and `Content.Process.All`); consent is not a policy |
| Administrative authority | Use an authorized Purview/Security & Compliance connection; keep setup administration separate from the runtime identity |
| Inline DLP | Configure an applicable, enabled policy for the exact harness app and intended users |
| Collection and billing | Obtain separate approval for prompt/response capture, retention, access, and any required subscription association or pay-as-you-go configuration |
| Audit and investigation | Verify Audit activation and the appropriate search, case, reviewer, and investigator roles |
| Azure and Defender | Select the intended subscription explicitly; assess model authorization, diagnostics, Defender AI plan, and resource coverage independently |

Consult [Entra-registered AI app guidance](https://learn.microsoft.com/en-us/purview/ai-entra-registered) and [collection-policy prerequisites](https://learn.microsoft.com/en-us/purview/collection-policies-policy-reference) for applicable licensing and billing requirements. Do not infer Microsoft 365 billing association from an Azure resource's existence.

To check Audit from an authorized **Exchange Online PowerShell** session:

```powershell
Get-AdminAuditLogConfig | Format-List UnifiedAuditLogIngestionEnabled
```

Do not use the same property from Security & Compliance PowerShell as an activation test: Microsoft documents that it returns `False` there even when auditing is enabled. Audit activation is a separate authorized administrative change; allow for propagation and event-ingestion delay. See [Audit guidance](https://learn.microsoft.com/en-us/purview/audit-log-enable-disable).

## 3. Preview and configure only the individual app

Use PowerShell 7.2 or later and the ExchangeOnlineManagement module version required by the setup script. Inspect the current help before selecting an authentication mode:

```powershell
Get-Help .\tools\Configure-Purview.ps1 -Full
.\tools\Configure-Purview.ps1 -Action Preview -PolicySet DlpOnly
```

Preview requires customer configuration but does not authenticate or change services. `DlpOnly` selects DLP setup without collection; specify it explicitly. `All` additionally requests collection and requires separate approval.

For service operations, use an explicitly chosen, authorized Security & Compliance connection in the **same PowerShell process**. Obtain its connection ID from your session rather than copying an identifier from another environment:

```powershell
Get-ConnectionInformation |
    Select-Object ConnectionId, TenantID, IsEopSession, ModulePrefix, State

# Set $sccConnectionId to the approved connection for your configured tenant.
.\tools\Configure-Purview.ps1 -Action Verify -PolicySet DlpOnly -ConnectionId $sccConnectionId

# Only after reviewing Preview and approving the app-scoped changes:
.\tools\Configure-Purview.ps1 -Action Apply -PolicySet DlpOnly `
    -PrerequisitesConfirmed -ConnectionId $sccConnectionId
```

`PrerequisitesConfirmed` is an operator attestation, not automatic discovery or activation. The tool does not activate Audit or billing. Its optional temporary app-only authentication can create elevated directory grants and certificate material: review that mode's requirements, explicitly authorize it, and verify cleanup of owned grants, identities, certificates, and keys. Never paste tokens into command lines, transcripts, or evidence files.

Read back policy configuration independently:

- The policy must target **only your harness app**, with an individual Entra application location and the `Application` enforcement plane.
- Confirm policy/rule association, enabled mode, intended user inclusion, classifier, and the supported `UploadText=Block` action.
- Treat conflicting existing scope or an unexpected response schema as an error. Inspect partial creation before rerunning; do not delete unrelated policies.
- Collection is distinct from DLP. If separately authorized, verify capture settings, app scope, retention/access controls, and actual ingestion. Collection can retain prompts and responses.
- An upload-blocking rule does not establish output-blocking coverage. Do not invent an unsupported `DownloadText` restriction.

Microsoft documents custom-app DLP setup through [PowerShell](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/new-dlpcompliancerule#example-4), not a generic portal-created Microsoft 365 policy. Review [custom-app configuration](https://learn.microsoft.com/en-us/purview/developer/configurepurview) without automatically adopting broad one-click policy scope.

## 4. Validate the runtime boundary

Use the harness application's approved Graph credential and a user bound to validated authentication. An administrator-token probe or arbitrary caller-supplied user ID does not validate the runtime's user context.

1. Compute protection scopes with `POST /v1.0/users/{authenticated-user-object-id}/dataSecurityAndGovernance/protectionScopes/compute`, using the actual harness client ID as the application location.
2. Require an applicable scope for the exact application and activity with `executionMode=evaluateInline`. An empty list, another app, or `evaluateOffline` alone is not sufficient. Preserve the returned ETag.
3. Submit input to `POST /v1.0/users/{authenticated-user-object-id}/dataSecurityAndGovernance/processContent` as `uploadText`, binding conversation and application metadata consistently. Enforce a service-returned block **before** a model, tool, API, or delegated-agent call.
4. Evaluate tool-result text and buffer/evaluate model output as `downloadText` before release. Do not expose partial streaming output. Only claim output blocking when an applicable supported policy actually returns a blocking decision.
5. Fail closed on missing/invalid decisions, processing errors, unknown actions, authentication failures, throttling, or timeouts. `202 Accepted` and `204 No Content` do not supply a synchronous inline decision.
6. If `protectionScopeState=modified`, refresh cached scopes while enforcing the original returned decision. Do not discard a block or replay content in a scope-refresh loop.

Application credentials use `/users/{id}`, not `/me`. See [compute protection scopes](https://learn.microsoft.com/en-us/graph/api/userprotectionscopecontainer-compute?view=graph-rest-1.0), [process content](https://learn.microsoft.com/en-us/graph/api/userdatasecurityandgovernance-processcontent?view=graph-rest-1.0), and [API integration and ETag handling](https://learn.microsoft.com/en-us/purview/developer/use-the-api).

### Synthetic acceptance checks

Run only with approved synthetic content and authorized external-service usage.

| Scenario | Required observation |
| --- | --- |
| Harmless control interaction | Actual permitted input decision, downstream execution, and successful output evaluation |
| Classifier-matching synthetic prompt | Actual policy-returned block, correct UI response, and no model/tool execution |
| Evaluation/provider failure | No prompt-derived or buffered model content released |
| Supported output-blocking policy | An actual output block enforced before response release; otherwise make no output-protection claim |
| Guest access | An actual authorized guest sign-in and direct role/approval checks; app-only per-user evaluation is not interactive sign-in evidence |

Use a documented synthetic classifier fixture from the Microsoft API examples, not real customer, employee, or payment information. A generic HTTP rejection, regex match, or simulated response is not a successful Purview detection test. Inspect downstream dependency telemetry to distinguish a policy block from a prerequisite failure.

### Windows 365 image boundary

The sample's text-classification representation excludes recognized screenshot image bytes, but the original image is still passed to the computer-use model. **Text DLP does not govern screenshot pixels.** Use an approved demonstration desktop and separately assess Cloud PC access, device compliance, image transfer, and image-governance controls.

## 5. Investigate without publishing customer evidence

Retain only necessary, access-controlled evidence outside source control: scoped tenant/app/user identifiers, UTC observation times, policy/rule references, conversation/request/trace correlation, and redacted decisions. Never include tokens, secrets, authorization headers, or sensitive prompt/response bodies in general application logs. Apply customer retention and deletion requirements to local state, exports, and service-side collection.

Verify each service independently:

- **Observability:** confirm destination traces and dependencies. A local trace ID does not establish Azure Monitor or Agent 365 exporter delivery.
- **DSPM/collection:** verify the individual-app capture policy and ingested activities after service propagation.
- **Audit:** find actual correlated interaction records with authorized search access.
- **eDiscovery:** confirm captured interactions through an authorized case/search; collection and access controls are prerequisites.
- **Communication Compliance / Insider Risk:** require separately approved applicable policies, reviewers/investigators, and actual matches/signals.
- **Defender:** check the selected subscription's AI plan and relevant resource coverage, then investigate actual alerts. Purview enforcement and Defender protection are different controls.
- **Work IQ, notifications, and Windows 365:** validate the authenticated channel, delegated authorization, and actual workload operation separately from identity registration.

Portal links are navigation aids, not integration evidence: [Microsoft 365 administration](https://admin.microsoft.com/), [Entra](https://entra.microsoft.com/), [Purview](https://purview.microsoft.com/), [Defender](https://security.microsoft.com/), [Azure](https://portal.azure.com/), and [Intune](https://intune.microsoft.com/).
