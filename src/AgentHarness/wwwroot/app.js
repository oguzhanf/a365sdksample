// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

(() => {
    "use strict";

    const ADMIN_ROLE = "AgentHarnessAdministrators";
    const USER_ROLE = "AgentHarnessUsers";
    const UPSTREAM_COMMIT = "44eeeea2572a6600f69c4cd996cbf3a025637743";
    const UPSTREAM_REPOSITORY = "https://github.com/microsoft/Agent365-Samples";
    const BUILDER_VIEWS = new Set(["builder-register", "builder-extend", "builder-validate", "builder-operate"]);
    const VIEW_TITLES = Object.freeze({
        dashboard: "Dashboard",
        samples: ".NET Samples",
        "builder-register": "Agent Builder · Register",
        "builder-extend": "Agent Builder · Extend",
        "builder-validate": "Agent Builder · Validate",
        "builder-operate": "Agent Builder · Operate",
        authorization: "API Authorization Lab",
        code: "Code Explorer",
        governance: "Governance / Portals",
        administration: "Administration"
    });
    const APPLICATION_ROLES = Object.freeze({
        harness: Object.freeze(["AgentHarnessAdministrators", "AgentHarnessUsers"]),
        "internal-api": Object.freeze(["InternalApi.Reader", "InternalApi.Approver"]),
        gravitee: Object.freeze(["Gravitee.Administrator", "Gravitee.User"])
    });
    const FRAMEWORK_ORDER = Object.freeze(["agent-framework", "semantic-kernel", "autonomous", "w365"]);
    const SAMPLE_DOCS = Object.freeze({
        "agent-framework": "https://learn.microsoft.com/microsoft-agent-365/developer/",
        "semantic-kernel": "https://learn.microsoft.com/semantic-kernel/",
        autonomous: "https://learn.microsoft.com/microsoft-agent-365/developer/observability",
        w365: "https://learn.microsoft.com/azure/foundry-classic/openai/how-to/computer-use"
    });
    const CAPABILITY_DEFINITIONS = Object.freeze({
        identity: Object.freeze({
            title: "Identity",
            purpose: "Register a typed Entra blueprint, its agent identity, and the Agent 365 registry relationship.",
            portalPatterns: Object.freeze([/agent id/i, /entra/i, /agent 365.*registry/i, /registry/i])
        }),
        observability: Object.freeze({
            title: "Observability",
            purpose: "Instrument SDK and runtime activity while keeping local traces separate from verified telemetry export.",
            portalPatterns: Object.freeze([/application insights/i, /monitor/i, /observability/i])
        }),
        tooling: Object.freeze({
            title: "Tooling",
            purpose: "Connect governed Agent 365 tools, including Work IQ tooling where selected, and verify consent at runtime.",
            portalPatterns: Object.freeze([/agent 365.*tool/i, /microsoft 365/i, /foundry/i, /work iq/i])
        }),
        notifications: Object.freeze({
            title: "Notifications",
            purpose: "Handle Agent 365 notifications after the required agent user, mailbox, endpoint, and tenant support exist.",
            portalPatterns: Object.freeze([/agent 365/i, /microsoft 365 admin/i, /exchange/i, /teams/i])
        })
    });
    const STAGE_DEFINITIONS = Object.freeze({
        register: Object.freeze({ title: "Register", route: "builder-register" }),
        extend: Object.freeze({ title: "Extend", route: "builder-extend" }),
        validate: Object.freeze({ title: "Validate", route: "builder-validate" }),
        operate: Object.freeze({ title: "Operate", route: "builder-operate" })
    });
    const DASHBOARD_SOURCE_PATHS = new Set([
        "Harness/AgentProvisioningService.cs",
        "Harness/AgentRuntime.cs",
        "Harness/HarnessChannelAgent.cs",
        "Harness/Program.cs"
    ]);
    const OVERVIEW_STATE_LABELS = Object.freeze({
        registered: "Registered",
        verified: "Verified",
        "controls available": "Controls available",
        "not registered": "Not registered",
        "not configured": "Not configured",
        "not validated": "Not validated",
        "needs agent user": "Needs agent user",
        disabled: "Disabled",
        "agent 365 exporter off": "Agent 365 exporter off",
        "trace observed": "Trace observed",
        "not enabled": "Not enabled",
        "channel not connected": "Channel not connected",
        "tools discovered": "Tools discovered",
        "notification received": "Notification received",
        "capabilities selected": "Capabilities selected",
        "not extended": "Not extended",
        "turn observed": "Turn observed",
        blocked: "Blocked",
        "validation required": "Validation required"
    });
    const OVERVIEW_SUCCESS_STATES = new Set(["registered", "verified", "controls available"]);

    const state = {
        session: null,
        demo: null,
        demoPromise: null,
        demoError: null,
        health: null,
        healthPromise: null,
        healthError: null,
        dashboardNeedsRefresh: true,
        samples: null,
        samplePayload: null,
        samplePromise: null,
        agents: null,
        agentPromise: null,
        selectedAgentId: null,
        evidence: new Map(),
        evidencePromises: new Map(),
        sources: null,
        sourcesPromise: null,
        selectedSourcePath: null,
        selectedSourceText: "",
        pendingSourceHint: null,
        integrations: null,
        portals: null,
        portalsPromise: null,
        governanceLoaded: false,
        lastRun: null,
        currentRoute: null,
        selectedDirectoryUser: null,
        assignments: [],
        audit: [],
        credentialTimer: null,
        credentialTimeout: null,
        credentialExpiresAt: null
    };

    let csrfToken = null;

    class ApiError extends Error {
        constructor(status, message, traceId = null, payload = null) {
            super(message);
            this.name = "ApiError";
            this.status = status;
            this.traceId = traceId;
            this.payload = payload;
        }
    }

    function byId(id) {
        return document.getElementById(id);
    }

    function all(selector, root = document) {
        return Array.from(root.querySelectorAll(selector));
    }

    function make(tag, options = {}, children = []) {
        const element = document.createElement(tag);
        if (options.className) {
            element.className = options.className;
        }
        if (options.text !== undefined && options.text !== null) {
            element.textContent = String(options.text);
        }
        if (options.attrs) {
            Object.entries(options.attrs).forEach(([name, value]) => {
                if (value !== undefined && value !== null) {
                    element.setAttribute(name, String(value));
                }
            });
        }
        if (options.disabled !== undefined) {
            element.disabled = Boolean(options.disabled);
        }
        const items = Array.isArray(children) ? children : [children];
        items.forEach((child) => {
            if (child === null || child === undefined) {
                return;
            }
            element.append(child instanceof Node ? child : document.createTextNode(String(child)));
        });
        return element;
    }

    function replace(element, ...children) {
        element.replaceChildren(...children.filter((child) => child !== null && child !== undefined));
    }

    function safeString(value, fallback = "") {
        return typeof value === "string" ? value : fallback;
    }

    function tenantLabel(session = state.session) {
        return safeString(session?.tenant).trim() || "Customer tenant";
    }

    function tenantIdentifier(session = state.session) {
        return safeString(session?.tenantId).trim() || "Not configured";
    }

    function renderTenantMetadata(session) {
        all("[data-tenant-name]").forEach((element) => {
            element.textContent = tenantLabel(session);
        });
        all("[data-tenant-id]").forEach((element) => {
            element.textContent = tenantIdentifier(session);
        });
    }

    function normalizedArray(value) {
        return Array.isArray(value) ? value : [];
    }

    function normalizedOverviewState(value) {
        return safeString(value).trim().toLowerCase();
    }

    function overviewStateLabel(value) {
        const normalized = normalizedOverviewState(value);
        return OVERVIEW_STATE_LABELS[normalized] || safeString(value).trim() || "Not reported";
    }

    function overviewStateKind(value) {
        const normalized = normalizedOverviewState(value);
        if (OVERVIEW_SUCCESS_STATES.has(normalized)) {
            return "success";
        }
        if (normalized === "disabled") {
            return "danger";
        }
        if (normalized === "blocked") {
            return "danger";
        }
        if ([
            "not registered",
            "not configured",
            "not validated",
            "needs agent user",
            "agent 365 exporter off",
            "not enabled",
            "channel not connected",
            "not extended",
            "validation required"
        ].includes(normalized)) {
            return "warning";
        }
        if ([
            "trace observed",
            "tools discovered",
            "notification received",
            "capabilities selected",
            "turn observed"
        ].includes(normalized)) {
            return "info";
        }
        return "neutral";
    }

    function overviewBadge(value) {
        return badge(overviewStateLabel(value), overviewStateKind(value));
    }

    function isOverviewSuccess(value) {
        return OVERVIEW_SUCCESS_STATES.has(normalizedOverviewState(value));
    }

    function formatDate(value) {
        if (!value) {
            return "Not recorded";
        }
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) {
            return String(value);
        }
        return new Intl.DateTimeFormat(undefined, {
            dateStyle: "medium",
            timeStyle: "short"
        }).format(date);
    }

    function formatTime(value = new Date()) {
        const date = value instanceof Date ? value : new Date(value);
        if (Number.isNaN(date.getTime())) {
            return "";
        }
        return new Intl.DateTimeFormat(undefined, {
            hour: "numeric",
            minute: "2-digit",
            second: "2-digit"
        }).format(date);
    }

    function initials(name) {
        const parts = safeString(name, "Harness user")
            .trim()
            .split(/\s+/)
            .filter(Boolean)
            .slice(0, 2);
        const value = parts.map((part) => part.charAt(0)).join("").toUpperCase();
        return value || "AH";
    }

    function safeExternalUrl(value) {
        if (typeof value !== "string" || !value.trim()) {
            return null;
        }
        try {
            const url = new URL(value);
            return url.protocol === "https:" || url.protocol === "http:" ? url.href : null;
        } catch {
            return null;
        }
    }

    function externalLink(label, url, className = "") {
        const safeUrl = safeExternalUrl(url);
        if (!safeUrl) {
            return null;
        }
        return make("a", {
            className,
            text: label,
            attrs: {
                href: safeUrl,
                target: "_blank",
                rel: "noopener noreferrer"
            }
        });
    }

    function kindForState(value) {
        const normalized = safeString(value).trim().toLowerCase();
        if (!normalized) {
            return "neutral";
        }
        if (
            normalized.includes("blocked") ||
            normalized.includes("failed") ||
            normalized.includes("error") ||
            normalized.includes("disabled") ||
            normalized.includes("denied")
        ) {
            return "danger";
        }
        if (
            normalized.includes("pending") ||
            normalized.includes("required") ||
            normalized.includes("unavailable") ||
            normalized.includes("unknown") ||
            normalized.includes("partial")
        ) {
            return "warning";
        }
        if (
            normalized === "verified" ||
            normalized === "succeeded" ||
            normalized === "healthy" ||
            normalized === "live" ||
            normalized === "enabled" ||
            normalized === "registered"
        ) {
            return "success";
        }
        if (
            normalized.includes("configured") ||
            normalized.includes("created") ||
            normalized.includes("ready") ||
            normalized.includes("draft") ||
            normalized.includes("recorded") ||
            normalized.includes("validated")
        ) {
            return "info";
        }
        return "neutral";
    }

    function badge(text, kind = null) {
        const resolvedKind = kind || kindForState(text);
        return make("span", {
            className: `badge badge-${resolvedKind}`,
            text: text || "Not reported"
        });
    }

    function loadingStatus(message) {
        return make("div", { className: "status-panel", attrs: { role: "status" } }, [
            make("span", { className: "spinner", attrs: { "aria-hidden": "true" } }),
            make("div", {}, [
                make("strong", { text: message }),
                make("p", { text: "Waiting for the same-origin API response." })
            ])
        ]);
    }

    function statusPanel(title, detail, kind = "neutral") {
        return make("div", {
            className: `status-panel${kind === "neutral" ? "" : ` status-panel-${kind}`}`,
            attrs: { role: kind === "error" ? "alert" : "status" }
        }, [
            make("div", {}, [
                make("strong", { text: title }),
                make("p", { text: detail })
            ])
        ]);
    }

    function setBusy(button, busy, busyLabel = "Working") {
        if (!button) {
            return;
        }
        if (busy) {
            if (!button.dataset.originalLabel) {
                button.dataset.originalLabel = button.textContent;
            }
            button.disabled = true;
            button.textContent = busyLabel;
            button.setAttribute("aria-busy", "true");
        } else {
            button.disabled = false;
            button.textContent = button.dataset.originalLabel || button.textContent;
            button.removeAttribute("aria-busy");
        }
    }

    function toast(title, detail = "", kind = "info") {
        const region = byId("toast-region");
        const item = make("div", {
            className: `toast toast-${kind}`,
            attrs: { role: kind === "error" ? "alert" : "status" }
        });
        const indicator = make("span", {
            className: `badge badge-${kind === "error" ? "danger" : kind === "success" ? "success" : "info"}`,
            text: kind === "error" ? "Error" : kind === "success" ? "Done" : "Notice"
        });
        const copy = make("div", {}, [
            make("strong", { text: title }),
            detail ? make("p", { text: detail }) : null
        ]);
        const dismiss = make("button", {
            className: "toast-dismiss",
            text: "×",
            attrs: { type: "button", "aria-label": "Dismiss notification" }
        });
        dismiss.addEventListener("click", () => item.remove());
        item.append(indicator, copy, dismiss);
        region.append(item);
        window.setTimeout(() => item.remove(), kind === "error" ? 10000 : 6500);
    }

    function friendlyError(error) {
        const detail = error instanceof Error && error.message ? error.message : "The request did not complete.";
        if (!(error instanceof ApiError)) {
            return `The request could not be completed. ${detail}`;
        }
        let lead;
        switch (error.status) {
            case 400:
                lead = "The request was rejected as invalid.";
                break;
            case 401:
                lead = "Your session is no longer authenticated.";
                break;
            case 403:
                lead = "The current enterprise application role or policy does not permit this operation.";
                break;
            case 404:
                lead = "The requested harness record or allowlisted source was not found.";
                break;
            case 409:
                lead = "The operation conflicts with the agent's current state or prerequisites.";
                break;
            case 429:
                lead = "The harness rate limit was reached. Wait before trying again.";
                break;
            case 503:
                lead = "A deployment or integration prerequisite is unavailable. No simulated success was substituted.";
                break;
            default:
                lead = error.status >= 500
                    ? "The backend could not complete the operation."
                    : "The request could not be completed.";
                break;
        }
        return detail && !lead.includes(detail) ? `${lead} ${detail}` : lead;
    }

    function errorStatus(error, title = "Request failed") {
        const content = statusPanel(title, friendlyError(error), "error");
        if (error instanceof ApiError && error.traceId) {
            content.append(make("code", {
                className: "timeline-correlation",
                text: `Trace ${error.traceId}`
            }));
        }
        return content;
    }

    function messageFromPayload(payload, status) {
        if (typeof payload === "string" && payload.trim()) {
            return payload.trim();
        }
        if (payload && typeof payload === "object") {
            const candidates = [payload.detail, payload.error, payload.message, payload.title];
            const message = candidates.find((candidate) => typeof candidate === "string" && candidate.trim());
            if (message) {
                return message.trim();
            }
        }
        return `Request returned HTTP ${status}.`;
    }

    async function readResponse(response, responseType = "auto") {
        if (response.status === 204) {
            return null;
        }
        if (responseType === "text") {
            return response.text();
        }
        const contentType = response.headers.get("content-type") || "";
        if (contentType.includes("json")) {
            try {
                return await response.json();
            } catch {
                return null;
            }
        }
        const text = await response.text();
        if (responseType === "json") {
            try {
                return JSON.parse(text);
            } catch {
                return text;
            }
        }
        return text;
    }

    async function fetchCsrf(force = false) {
        if (csrfToken && !force) {
            return csrfToken;
        }
        const response = await fetch("/api/csrf", {
            method: "GET",
            credentials: "same-origin",
            headers: { Accept: "application/json" }
        });
        const payload = await readResponse(response);
        if (!response.ok) {
            throw new ApiError(
                response.status,
                messageFromPayload(payload, response.status),
                payload && typeof payload === "object" ? payload.traceId || null : null,
                payload
            );
        }
        if (!payload || typeof payload.token !== "string" || !payload.token) {
            throw new ApiError(500, "The backend did not return an antiforgery token.");
        }
        csrfToken = payload.token;
        return csrfToken;
    }

    async function api(path, options = {}, retryingCsrf = false) {
        const method = safeString(options.method, "GET").toUpperCase();
        const mutation = !["GET", "HEAD"].includes(method);
        const headers = new Headers(options.headers || {});
        headers.set("Accept", options.responseType === "text" ? "text/plain" : "application/json");
        let body;

        if (options.body !== undefined) {
            headers.set("Content-Type", "application/json");
            body = JSON.stringify(options.body);
        }
        if (mutation) {
            headers.set("X-AgentHarness-CSRF", await fetchCsrf());
        }

        let response;
        try {
            response = await fetch(path, {
                method,
                headers,
                body,
                credentials: "same-origin"
            });
        } catch (error) {
            throw new ApiError(0, error instanceof Error ? error.message : "Network request failed.");
        }

        const payload = await readResponse(response, options.responseType || "auto");
        if (!response.ok) {
            const message = messageFromPayload(payload, response.status);
            if (
                mutation &&
                !retryingCsrf &&
                response.status === 400 &&
                message.toLowerCase().includes("antiforgery")
            ) {
                csrfToken = null;
                await fetchCsrf(true);
                return api(path, options, true);
            }
            const traceId = payload && typeof payload === "object"
                ? payload.traceId || (payload.extensions && payload.extensions.traceId) || null
                : null;
            throw new ApiError(response.status, message, traceId, payload);
        }
        return payload;
    }

    async function ensureSamples(force = false) {
        if (state.samples && !force) {
            return state.samples;
        }
        if (state.samplePromise && !force) {
            return state.samplePromise;
        }
        state.samplePromise = api("/api/samples").then((payload) => {
            if (!payload || !Array.isArray(payload.samples)) {
                throw new ApiError(500, "The sample catalog response did not include a samples array.");
            }
            if (payload.commit !== UPSTREAM_COMMIT) {
                throw new ApiError(500, "The sample catalog commit does not match the pinned frontend provenance.");
            }
            state.samplePayload = payload;
            state.samples = payload.samples;
            return state.samples;
        }).finally(() => {
            state.samplePromise = null;
        });
        return state.samplePromise;
    }

    async function ensureAgents(force = false) {
        if (state.agents && !force) {
            return state.agents;
        }
        if (state.agentPromise && !force) {
            return state.agentPromise;
        }
        state.agentPromise = api("/api/agents").then((payload) => {
            if (!Array.isArray(payload)) {
                throw new ApiError(500, "The agent catalog response was not an array.");
            }
            state.agents = payload;
            if (!findAgent(state.selectedAgentId)) {
                state.selectedAgentId = orderedAgents()[0]?.id || null;
            }
            return state.agents;
        }).finally(() => {
            state.agentPromise = null;
        });
        return state.agentPromise;
    }

    async function ensureDemo(force = false) {
        if (state.demo && !force && !state.dashboardNeedsRefresh) {
            return state.demo;
        }
        if (state.demoPromise) {
            return state.demoPromise;
        }
        state.demoPromise = api("/api/demo").then((payload) => {
            if (!payload || typeof payload !== "object" || !Array.isArray(payload.agents)) {
                throw new ApiError(500, "The Agent 365 SDK overview did not include an agents array.");
            }
            state.demo = payload;
            state.demoError = null;
            state.dashboardNeedsRefresh = false;
            const agents = normalizedArray(payload.agents);
            if (agents.length && !agents.some((agent) => agent.id === state.selectedAgentId)) {
                state.selectedAgentId = agents[0].id || null;
            }
            return payload;
        }).catch((error) => {
            state.demo = null;
            state.demoError = error;
            state.dashboardNeedsRefresh = true;
            throw error;
        }).finally(() => {
            state.demoPromise = null;
        });
        return state.demoPromise;
    }

    async function ensureHealth(force = false) {
        if (state.health && !force) {
            return state.health;
        }
        if (state.healthPromise) {
            return state.healthPromise;
        }
        state.healthPromise = api("/healthz").then((payload) => {
            state.health = {
                ok: true,
                payload,
                observedAt: new Date().toISOString()
            };
            state.healthError = null;
            return state.health;
        }).catch((error) => {
            state.health = null;
            state.healthError = error;
            throw error;
        }).finally(() => {
            state.healthPromise = null;
        });
        return state.healthPromise;
    }

    async function ensurePortals(force = false) {
        if (state.portals && !force) {
            return state.portals;
        }
        if (state.portalsPromise) {
            return state.portalsPromise;
        }
        state.portalsPromise = api("/api/portals").then((payload) => {
            state.portals = Array.isArray(payload) ? payload : [];
            return state.portals;
        }).finally(() => {
            state.portalsPromise = null;
        });
        return state.portalsPromise;
    }

    async function ensureSources(force = false) {
        if (state.sources && !force) {
            return state.sources;
        }
        if (state.sourcesPromise && !force) {
            return state.sourcesPromise;
        }
        state.sourcesPromise = api("/api/sources").then((payload) => {
            if (!Array.isArray(payload)) {
                throw new ApiError(500, "The source index response was not an array.");
            }
            state.sources = payload
                .filter((path) => typeof path === "string" && (path.startsWith("Harness/") || path.startsWith("Upstream/")))
                .sort((left, right) => left.localeCompare(right));
            return state.sources;
        }).finally(() => {
            state.sourcesPromise = null;
        });
        return state.sourcesPromise;
    }

    function orderedAgents() {
        return normalizedArray(state.agents).slice().sort((left, right) => {
            const leftRank = FRAMEWORK_ORDER.indexOf(left.framework);
            const rightRank = FRAMEWORK_ORDER.indexOf(right.framework);
            const normalizedLeft = leftRank === -1 ? Number.MAX_SAFE_INTEGER : leftRank;
            const normalizedRight = rightRank === -1 ? Number.MAX_SAFE_INTEGER : rightRank;
            if (normalizedLeft !== normalizedRight) {
                return normalizedLeft - normalizedRight;
            }
            return safeString(left.name).localeCompare(safeString(right.name));
        });
    }

    function findAgent(id) {
        return normalizedArray(state.agents).find((agent) => agent.id === id) || null;
    }

    function findOverviewAgent(id) {
        return normalizedArray(state.demo?.agents).find((agent) => agent.id === id) || null;
    }

    function findSample(frameworkId) {
        return normalizedArray(state.samples).find((sample) => sample.id === frameworkId) || null;
    }

    function findSeededAgent(frameworkId) {
        return orderedAgents().find((agent) => agent.framework === frameworkId && safeString(agent.id).startsWith("a3650000-")) ||
            orderedAgents().find((agent) => agent.framework === frameworkId) ||
            null;
    }

    function upsertAgent(agent) {
        if (!agent || typeof agent.id !== "string") {
            return;
        }
        const agents = normalizedArray(state.agents).slice();
        const index = agents.findIndex((candidate) => candidate.id === agent.id);
        if (index >= 0) {
            agents[index] = agent;
        } else {
            agents.push(agent);
        }
        state.agents = agents;
        state.selectedAgentId = agent.id;
        populateAgentSelects();
        updateAgentDependentUi(true);
        state.dashboardNeedsRefresh = true;
        renderSamples();
    }

    function pinnedSourceUrl(sourcePath) {
        const path = safeString(sourcePath).replace(/\\/g, "/").replace(/^\/+/, "");
        if (!path.startsWith("dotnet/") || path.includes("..")) {
            return `${UPSTREAM_REPOSITORY}/tree/${UPSTREAM_COMMIT}`;
        }
        const encodedPath = path.split("/").map((segment) => encodeURIComponent(segment)).join("/");
        return `${UPSTREAM_REPOSITORY}/tree/${UPSTREAM_COMMIT}/${encodedPath}`;
    }

    function sourceHintForSample(sample) {
        const path = safeString(sample?.sourcePath).replace(/\\/g, "/").replace(/^dotnet\//, "");
        return path && !path.includes("..") ? `Upstream/${path}/` : "Upstream/";
    }

    function exactVerified(integration) {
        return safeString(integration?.state).trim().toLowerCase() === "verified";
    }

    function matchingIntegration(pattern) {
        return normalizedArray(state.integrations).find((integration) => {
            const haystack = `${safeString(integration.name)} ${safeString(integration.detail)}`;
            return pattern.test(haystack);
        }) || null;
    }

    function hasPurviewRunEvidence() {
        if (!state.lastRun || !state.lastRun.live || !Array.isArray(state.lastRun.steps)) {
            return false;
        }
        return state.lastRun.steps.filter((step) => safeString(step).toLowerCase().includes("purview")).length >= 2;
    }

    function renderLandingStatus(session) {
        const container = byId("landing-status");
        const items = [
            {
                label: "Entra application",
                value: session.identityConfigured ? "Identifiers reported" : "Identifiers not reported",
                detail: session.identityConfigured
                    ? "Application identifiers are present; live sign-in is separate evidence."
                    : "Runtime application identifiers are not configured."
            },
            {
                label: "Sign-in credential",
                value: session.signInReady ? "Sign-in attempt available" : "Sign-in unavailable",
                detail: session.signInReady
                    ? "The backend reports a credential; successful authentication is verified only after sign-in."
                    : "No sign-in credential is available to complete the OpenID Connect challenge."
            },
            {
                label: "Azure hosting",
                value: session.hostingConfigured ? "Hosting settings reported" : "Deployment not confirmed",
                detail: session.hostingConfigured
                    ? "A subscription setting is present; this does not confirm a deployed or reachable resource."
                    : "No subscription configuration confirms an Azure deployment."
            }
        ];
        replace(container, ...items.map((item) => make("div", { className: "landing-state" }, [
            make("span", { text: item.label }),
            make("strong", { text: item.value }),
            make("small", { text: item.detail })
        ])));
    }

    function showSignedOut(session) {
        clearCredentials("");
        renderTenantMetadata(session);
        state.currentRoute = null;
        byId("boot-screen").hidden = true;
        byId("app-shell").hidden = true;
        byId("signed-out").hidden = false;
        renderLandingStatus(session);
        const signInReady = Boolean(session.signInReady);
        byId("sign-in-link").hidden = !signInReady;
        byId("sign-in-unavailable").hidden = signInReady;
        document.title = "Sign in · AgentHarness";
    }

    function applyRoleVisibility() {
        const administrator = Boolean(state.session?.administrator);
        all(".admin-only:not([data-view])").forEach((element) => {
            element.hidden = !administrator;
        });
        all(".non-admin-only").forEach((element) => {
            element.hidden = administrator;
        });
    }

    function showAuthenticatedApp() {
        renderTenantMetadata(state.session);
        byId("boot-screen").hidden = true;
        byId("signed-out").hidden = true;
        byId("app-shell").hidden = false;
        applyRoleVisibility();

        const name = safeString(state.session?.name, "Harness user");
        byId("session-name").textContent = name;
        byId("session-role").textContent = state.session?.administrator
            ? ADMIN_ROLE
            : USER_ROLE;
        byId("session-avatar").textContent = initials(name);
        byId("dashboard-session-time").textContent = `Session checked at ${formatTime()}`;

        const requested = location.hash.replace(/^#/, "");
        const route = Object.prototype.hasOwnProperty.call(VIEW_TITLES, requested) ? requested : "dashboard";
        if (!location.hash) {
            history.replaceState(null, "", "#dashboard");
        }
        activateRoute(route, false);
    }

    function showSessionLoadError(error) {
        const card = document.querySelector(".boot-card");
        const retry = make("button", {
            className: "button button-primary",
            text: "Retry session check",
            attrs: { type: "button" }
        });
        retry.addEventListener("click", () => {
            replace(card, loadingStatus("Retrying session check"));
            initializeSession();
        });
        replace(card,
            make("img", {
                className: "brand-mark brand-mark-large",
                attrs: { src: "/favicon.svg", alt: "", "aria-hidden": "true" }
            }),
            make("p", { className: "eyebrow", text: "Microsoft Agent 365 .NET sample" }),
            make("h1", { text: "Session check unavailable" }),
            statusPanel("The frontend could not reach /api/session", friendlyError(error), "error"),
            retry
        );
        byId("boot-screen").setAttribute("aria-busy", "false");
    }

    function metricCard(label, value, detail) {
        return make("article", { className: "metric-card" }, [
            make("span", { text: label }),
            make("strong", { text: value }),
            make("p", { text: detail })
        ]);
    }

    function dashboardRouteLink(route, label, className = "button button-primary button-small") {
        const resolved = BUILDER_VIEWS.has(route) ? route : "builder-validate";
        const link = make("a", {
            className,
            text: label,
            attrs: { href: `#${resolved}` }
        });
        link.addEventListener("click", () => {
            if (state.selectedAgentId) {
                setSelectedAgent(state.selectedAgentId, false);
            }
        });
        return link;
    }

    function matchingPortalForCapability(capabilityId) {
        const patterns = CAPABILITY_DEFINITIONS[capabilityId]?.portalPatterns || [];
        return normalizedArray(state.portals).find((portal) => {
            const haystack = [
                portal.name,
                portal.category,
                portal.description
            ].map((value) => safeString(value)).join(" ");
            return patterns.some((pattern) => pattern.test(haystack));
        }) || null;
    }

    function dashboardSourceButton(sourcePath) {
        const normalized = safeString(sourcePath).replace(/\\/g, "/");
        const button = make("button", {
            className: "button button-secondary button-small",
            text: "View .NET source",
            attrs: {
                type: "button",
                title: normalized || "No source path returned"
            },
            disabled: !DASHBOARD_SOURCE_PATHS.has(normalized)
        });
        if (DASHBOARD_SOURCE_PATHS.has(normalized)) {
            button.addEventListener("click", () => openDashboardSource(normalized));
        }
        return button;
    }

    function capabilityEvidence(capability, agent) {
        const content = [
            make("p", {
                className: "capability-evidence-detail",
                text: safeString(capability?.detail, "No authenticated capability detail was returned.")
            })
        ];
        if (capability?.id === "identity") {
            const identity = agent?.identity && typeof agent.identity === "object" ? agent.identity : {};
            const rows = [
                ["Blueprint client ID", identity.blueprintClientId],
                ["Agent client ID", identity.agentClientId],
                ["Registry ID", identity.registryId]
            ].filter(([, value]) => safeString(value));
            if (rows.length) {
                content.push(make("dl", { className: "capability-identity-list" }, rows.flatMap(([label, value]) => [
                    make("dt", { text: label }),
                    make("dd", {}, [make("code", { text: value, attrs: { title: value } })])
                ])));
            } else {
                content.push(make("p", {
                    className: "capability-evidence-empty",
                    text: "No identity identifiers were returned by the overview."
                }));
            }
        }
        if (capability?.traceId) {
            content.push(make("p", { className: "capability-trace" }, [
                make("span", { text: "Trace" }),
                make("code", { text: capability.traceId, attrs: { title: capability.traceId } })
            ]));
        }
        if (capability?.sourcePath) {
            content.push(make("p", { className: "capability-source-path" }, [
                make("span", { text: "Source" }),
                make("code", { text: capability.sourcePath, attrs: { title: capability.sourcePath } })
            ]));
        }
        return make("div", { className: "capability-evidence" }, [
            make("span", { className: "capability-label", text: "Actual backend evidence" }),
            ...content
        ]);
    }

    function capabilityCard(capability, agent) {
        const capabilityId = safeString(capability?.id);
        const definition = CAPABILITY_DEFINITIONS[capabilityId] || {
            title: safeString(capability?.title, "Capability"),
            purpose: "No documentation purpose is available for this capability identifier."
        };
        const blocker = safeString(capability?.blocker);
        const route = BUILDER_VIEWS.has(capability?.actionRoute)
            ? capability.actionRoute
            : "builder-validate";
        const routeTitle = VIEW_TITLES[route]?.replace("Agent Builder · ", "") || "builder stage";
        const actions = make("div", { className: "capability-actions" }, [
            dashboardRouteLink(route, `Open ${routeTitle}`),
            dashboardSourceButton(capability?.sourcePath)
        ]);
        const portal = matchingPortalForCapability(capabilityId);
        const portalLink = portal
            ? externalLink(
                "Open related portal",
                portal.url,
                "button button-ghost button-small"
            )
            : null;
        if (portalLink) {
            portalLink.title = safeString(portal.name, "Related administrative portal");
            actions.append(portalLink);
        }
        return make("article", {
            className: "sdk-capability-card",
            attrs: { "data-capability-id": capabilityId || "unknown" }
        }, [
            make("div", { className: "sdk-capability-header" }, [
                make("div", {}, [
                    make("span", { className: "capability-number", text: String(Object.keys(CAPABILITY_DEFINITIONS).indexOf(capabilityId) + 1).padStart(2, "0") }),
                    make("h3", { text: safeString(capability?.title, definition.title) })
                ]),
                overviewBadge(capability?.state)
            ]),
            make("p", { className: "capability-purpose", text: definition.purpose }),
            capabilityEvidence(capability, agent),
            make("div", {
                className: `capability-blocker${blocker ? " capability-blocker-active" : ""}`
            }, [
                make("strong", { text: "Concrete blocker" }),
                make("p", {
                    text: blocker || (
                        isOverviewSuccess(capability?.state)
                            ? "No blocker was reported by the authenticated overview."
                            : "The overview did not return a specific blocker; this state is not treated as complete."
                    )
                })
            ]),
            actions
        ]);
    }

    function placeholderCapability(capabilityId, detail) {
        const definition = CAPABILITY_DEFINITIONS[capabilityId];
        return {
            id: capabilityId,
            title: definition.title,
            state: "Not reported",
            detail,
            blocker: "No authoritative per-agent overview is available.",
            sourcePath: null,
            actionRoute: capabilityId === "identity" ? "builder-register" : "builder-extend",
            traceId: null
        };
    }

    function renderDashboardCapabilities() {
        const container = byId("dashboard-capabilities");
        const agent = findOverviewAgent(state.selectedAgentId);
        const detail = state.demoError
            ? "The authenticated overview request did not complete."
            : state.demo
                ? "No selected agent capability was returned."
                : "Waiting for the authenticated overview response.";
        const byCapability = new Map(
            normalizedArray(agent?.capabilities).map((capability) => [safeString(capability?.id), capability])
        );
        replace(container, ...Object.keys(CAPABILITY_DEFINITIONS).map((capabilityId) =>
            capabilityCard(byCapability.get(capabilityId) || placeholderCapability(capabilityId, detail), agent)
        ));
    }

    function journeyCard(stage, index) {
        const stageId = safeString(stage?.id);
        const definition = STAGE_DEFINITIONS[stageId] || {
            title: safeString(stage?.title, "Stage"),
            route: "builder-validate"
        };
        const route = BUILDER_VIEWS.has(stage?.actionRoute)
            ? stage.actionRoute
            : definition.route;
        return make("article", {
            className: "sdk-journey-card",
            attrs: { "data-stage-id": stageId || "unknown" }
        }, [
            make("div", { className: "journey-card-header" }, [
                make("span", { className: "journey-number", text: String(index + 1) }),
                overviewBadge(stage?.state)
            ]),
            make("h3", { text: safeString(stage?.title, definition.title) }),
            make("p", { text: safeString(stage?.detail, "No authenticated stage detail was returned.") }),
            dashboardRouteLink(route, `Open ${definition.title}`, "text-link journey-link")
        ]);
    }

    function renderDashboardJourney() {
        const container = byId("dashboard-journey");
        const agent = findOverviewAgent(state.selectedAgentId);
        const byStage = new Map(
            normalizedArray(agent?.stages).map((stage) => [safeString(stage?.id), stage])
        );
        const fallbackDetail = state.demo
            ? "No selected agent stage result was returned."
            : "Waiting for the authenticated overview response.";
        replace(container, ...Object.keys(STAGE_DEFINITIONS).map((stageId, index) => {
            const definition = STAGE_DEFINITIONS[stageId];
            return journeyCard(byStage.get(stageId) || {
                id: stageId,
                title: definition.title,
                state: "Not reported",
                detail: fallbackDetail,
                actionRoute: definition.route
            }, index);
        }));
    }

    function dashboardErrorCopy(error) {
        if (!(error instanceof ApiError)) {
            return {
                title: "Agent 365 SDK overview unavailable",
                detail: "The request did not complete. No live overview was synthesized."
            };
        }
        switch (error.status) {
            case 401:
                return {
                    title: "Dashboard authentication required",
                    detail: "The protected overview rejected this session. Sign in again; the UI will not substitute cached or mock capability state."
                };
            case 403:
                return {
                    title: "Dashboard role not authorized",
                    detail: `The current principal is not authorized for the protected overview. Access still depends on ${ADMIN_ROLE} or ${USER_ROLE}.`
                };
            case 404:
                return {
                    title: "Agent 365 SDK overview not available yet",
                    detail: "GET /api/demo returned 404. The capability and onboarding labels remain visible, but no live state was invented."
                };
            case 503:
                return {
                    title: "Agent 365 SDK overview temporarily unavailable",
                    detail: "The backend reported an unavailable deployment or integration prerequisite. No mock success was substituted."
                };
            default:
                return {
                    title: "Agent 365 SDK overview unavailable",
                    detail: `${friendlyError(error)} No live capability state was synthesized.`
                };
        }
    }

    function renderDashboardOverviewStatus() {
        const container = byId("dashboard-overview-status");
        if (state.demoError) {
            const copy = dashboardErrorCopy(state.demoError);
            const retry = make("button", {
                className: "button button-secondary button-small",
                text: "Retry overview",
                attrs: { type: "button" }
            });
            retry.addEventListener("click", () => loadDashboard(true));
            const panel = statusPanel(copy.title, copy.detail, state.demoError.status === 404 ? "warning" : "error");
            panel.append(retry);
            replace(container, panel);
            return;
        }
        if (!state.demo) {
            replace(container, loadingStatus("Loading authenticated Agent 365 SDK evidence"));
            return;
        }
        if (!normalizedArray(state.demo.agents).length) {
            replace(container, statusPanel(
                "No agents in the authenticated overview",
                "GET /api/demo returned zero agents. Capability and onboarding cards remain unverified until an agent record is returned.",
                "warning"
            ));
            return;
        }
        replace(container);
    }

    function renderDashboardHero() {
        const badgeElement = byId("dashboard-hosting-badge");
        let text = "Checking host";
        let kind = "neutral";
        if (state.health?.ok && state.demo) {
            text = "Host and protected API responded";
            kind = "info";
        } else if (state.demo) {
            text = "Protected API responded";
            kind = "info";
        } else if (state.health?.ok) {
            text = "Health endpoint responded";
            kind = "info";
        } else if (state.healthError || state.demoError) {
            text = "Hosting evidence incomplete";
            kind = "warning";
        }
        badgeElement.textContent = text;
        badgeElement.className = `badge badge-${kind}`;
        byId("dashboard-observed-at").textContent = state.demo?.observedAt
            ? `Overview observed ${formatDate(state.demo.observedAt)}`
            : "No overview observation returned";
    }

    function ledgerRow(label, stateText, detail, kind) {
        return make("div", { className: "ledger-row" }, [
            make("strong", { text: label }),
            badge(stateText, kind),
            make("p", { text: detail })
        ]);
    }

    function renderDashboardMetrics() {
        const metrics = byId("dashboard-metrics");
        const agents = normalizedArray(state.demo?.agents);
        const agent = findOverviewAgent(state.selectedAgentId);
        const capabilityCount = normalizedArray(agent?.capabilities).filter((capability) => isOverviewSuccess(capability?.state)).length;
        const stageCount = normalizedArray(agent?.stages).filter((stage) => isOverviewSuccess(stage?.state)).length;
        replace(metrics,
            metricCard(
                "Agents in overview",
                `${agents.length} agent${agents.length === 1 ? "" : "s"}`,
                "Count returned by the authenticated Agent 365 SDK overview."
            ),
            metricCard(
                "Selected agent state",
                agent ? overviewStateLabel(agent.status) : "No agent selected",
                agent
                    ? `${safeString(agent.name, "Unnamed agent")} · ${safeString(agent.framework, "framework not reported")}`
                    : "Select an agent after the overview returns records."
            ),
            metricCard(
                "SDK capabilities",
                `${capabilityCount} of 4 positive`,
                "Only Registered, Verified, or Controls available count as positive."
            ),
            metricCard(
                "Onboarding journey",
                `${stageCount} of 4 positive`,
                "Stage progress comes from the selected agent; host response does not advance it."
            )
        );
    }

    function renderDashboardLedger() {
        const session = state.session;
        const runtimeState = state.lastRun
            ? state.lastRun.live
                ? {
                    text: "Observed live",
                    kind: "success",
                    detail: `The backend returned live=true with trace ${safeString(state.lastRun.traceId, "not returned")}.`
                }
                : {
                    text: "Non-live response",
                    kind: "warning",
                    detail: "The backend explicitly returned live=false; no live inference claim is made."
                }
            : {
                text: "Not observed",
                kind: "warning",
                detail: "Run a sample to request actual text, steps, and a trace identifier."
            };
        const hosting = state.demo?.hosting && typeof state.demo.hosting === "object"
            ? state.demo.hosting
            : {};
        const healthDetail = state.health?.ok
            ? `GET ${safeString(hosting.healthUrl, "/healthz")} returned successfully at ${formatDate(state.health.observedAt)}. This proves hosting responded, not model, tool, notification, or telemetry delivery.`
            : state.healthError
                ? `The health request did not complete: ${friendlyError(state.healthError)}`
                : "The health endpoint has not returned an observation in this browser session.";
        const overviewDetail = state.demo
            ? "GET /api/demo completed as an authenticated, role-protected request. Its per-agent evidence is displayed above."
            : state.demoError
                ? dashboardErrorCopy(state.demoError).detail
                : "The authenticated overview has not returned yet.";

        replace(byId("readiness-ledger"),
            ledgerRow(
                "Configured-tenant session",
                "Verified for this session",
                `The authenticated session reports tenant ${tenantLabel(session)} (${tenantIdentifier(session)}).`,
                "success"
            ),
            ledgerRow(
                "Hosting health endpoint",
                state.health?.ok ? "Responded" : "Not observed",
                healthDetail,
                state.health?.ok ? "info" : "warning"
            ),
            ledgerRow(
                "Protected overview request",
                state.demo ? "Authenticated response" : "Not observed",
                overviewDetail,
                state.demo ? "info" : "warning"
            ),
            ledgerRow(
                "Azure hosting report",
                hosting.azureHosted === true ? "Azure host reported" : "Not reported",
                safeString(hosting.detail, "No hosting detail was returned by the authenticated overview."),
                hosting.azureHosted === true ? "info" : "neutral"
            ),
            ledgerRow(
                "Agent runtime execution",
                runtimeState.text,
                runtimeState.detail,
                runtimeState.kind
            ),
            ledgerRow(
                "Protection and delivery",
                "Independent verification required",
                "Purview policy coverage, notification delivery, Windows 365 access, and telemetry export are not inferred from code wiring.",
                "warning"
            )
        );
    }

    function renderDashboardAgents() {
        const container = byId("dashboard-agent-list");
        if (!state.demo && !state.demoError) {
            replace(container, loadingStatus("Loading authenticated agent overview"));
            return;
        }
        if (state.demoError) {
            replace(container, errorStatus(state.demoError, "Authenticated agent overview unavailable"));
            return;
        }
        const agents = normalizedArray(state.demo?.agents).slice(0, 4);
        if (!agents.length) {
            replace(container, statusPanel(
                "No agent records in overview",
                "The authenticated overview returned zero agents; no catalog completion is inferred.",
                "warning"
            ));
            return;
        }
        replace(container, ...agents.map((agent) => {
            const positiveCapabilities = normalizedArray(agent.capabilities)
                .filter((capability) => isOverviewSuccess(capability?.state)).length;
            return make("article", { className: "compact-agent" }, [
                make("div", { className: "compact-agent-header" }, [
                    make("strong", { text: safeString(agent.name, "Unnamed agent") }),
                    overviewBadge(agent.status)
                ]),
                make("small", { text: safeString(agent.framework, "Framework not reported") }),
                make("p", {
                    text: `${positiveCapabilities} of 4 capability states are explicitly positive; identity and registry identifiers are evidence, not proof of workload delivery.`
                })
            ]);
        }));
    }

    function populateTopAgentSelectFromOverview() {
        if (state.agents) {
            populateAgentSelects();
            return;
        }
        const select = byId("top-agent-select");
        const agents = normalizedArray(state.demo?.agents);
        const options = agents.length
            ? agents.map((agent) => make("option", {
                text: `${safeString(agent.name, "Unnamed agent")} — ${safeString(agent.framework, "framework not reported")}`,
                attrs: { value: agent.id }
            }))
            : [make("option", { text: "No agents returned", attrs: { value: "" } })];
        replace(select, ...options);
        select.value = state.selectedAgentId || "";
        select.disabled = agents.length === 0;
    }

    function renderDashboard() {
        renderDashboardHero();
        renderDashboardOverviewStatus();
        renderDashboardCapabilities();
        renderDashboardJourney();
        renderDashboardMetrics();
        renderDashboardLedger();
        renderDashboardAgents();
    }

    async function loadDashboard(force = false) {
        const forceOverview = force || state.dashboardNeedsRefresh;
        if (forceOverview) {
            state.demo = null;
            state.demoError = null;
        }
        renderDashboard();
        const [demoResult, healthResult, samplesResult, agentsResult, portalsResult] = await Promise.allSettled([
            ensureDemo(forceOverview),
            ensureHealth(forceOverview),
            ensureSamples(),
            ensureAgents(forceOverview),
            ensurePortals(force)
        ]);
        if (agentsResult.status === "fulfilled") {
            populateAgentSelects();
        } else {
            populateTopAgentSelectFromOverview();
        }
        if (demoResult.status === "fulfilled" && !findOverviewAgent(state.selectedAgentId)) {
            state.selectedAgentId = normalizedArray(state.demo?.agents)[0]?.id || state.selectedAgentId;
        }
        if (samplesResult.status === "fulfilled" && agentsResult.status === "fulfilled") {
            populateAgentSelects();
        }
        if (healthResult.status === "rejected" && !state.healthError) {
            state.healthError = healthResult.reason;
        }
        if (portalsResult.status === "rejected") {
            state.portals = [];
        }
        renderDashboard();
    }

    function sampleDisclosures(sample) {
        const messages = [];
        const capabilities = normalizedArray(sample.capabilities).map((value) => safeString(value).toLowerCase());
        if (capabilities.some((capability) => capability.includes("notification"))) {
            const notification = matchingIntegration(/notification/i);
            if (!exactVerified(notification)) {
                messages.push("Notifications remain pending until the API verifies the agent user, mailbox, messaging endpoint, and tenant availability.");
            }
        }
        if (sample.id === "w365") {
            const w365 = matchingIntegration(/windows\s*365|w365/i);
            if (!exactVerified(w365)) {
                messages.push("Windows 365 remains pending until access, an agent user, a computer-use model, and governed MCP tools are verified.");
            }
        }
        const purview = matchingIntegration(/purview/i);
        if (!hasPurviewRunEvidence() || (purview && !exactVerified(purview))) {
            messages.push("Purview remains pending until an applicable inline policy and both input/output run evaluations are verified. This harness offers no policy bypass.");
        }
        return messages;
    }

    function renderSamples() {
        const container = byId("sample-list");
        if (!state.samples || !state.agents) {
            replace(container, loadingStatus("Loading samples and seeded agents"));
            return;
        }
        const query = safeString(byId("sample-search").value).trim().toLowerCase();
        const visible = state.samples.filter((sample) => {
            const haystack = [
                sample.name,
                sample.framework,
                sample.description,
                ...normalizedArray(sample.capabilities),
                ...normalizedArray(sample.prerequisites)
            ].map((value) => safeString(value)).join(" ").toLowerCase();
            return !query || haystack.includes(query);
        });
        byId("sample-count").textContent = `${visible.length} of ${state.samples.length} samples`;

        if (!visible.length) {
            replace(container, statusPanel("No samples match the filter", "Clear or change the search text.", "warning"));
            return;
        }

        replace(container, ...visible.map((sample) => {
            const agent = findSeededAgent(sample.id);
            const capabilityList = make("ul", { className: "chip-list", attrs: { "aria-label": "Capabilities" } },
                normalizedArray(sample.capabilities).map((capability) => make("li", { className: "chip", text: capability }))
            );
            const prerequisiteList = make("ul", {},
                normalizedArray(sample.prerequisites).map((prerequisite) => make("li", { text: prerequisite }))
            );
            const actions = make("div", { className: "sample-card-actions" });
            const run = make("button", {
                className: "button button-primary button-small",
                text: "Open in runner",
                attrs: { type: "button" },
                disabled: !agent
            });
            run.addEventListener("click", () => {
                if (!agent) {
                    return;
                }
                setSelectedAgent(agent.id, true);
                byId("sample-runner").scrollIntoView({ behavior: "smooth", block: "start" });
                byId("sample-prompt").focus();
            });
            const inspect = make("button", {
                className: "button button-secondary button-small",
                text: "Inspect embedded source",
                attrs: { type: "button" }
            });
            inspect.addEventListener("click", () => openSourceForSample(sample));
            const pinned = externalLink("Pinned source", pinnedSourceUrl(sample.sourcePath), "button button-ghost button-small");
            const docs = externalLink("Documentation", SAMPLE_DOCS[sample.id] || SAMPLE_DOCS["agent-framework"], "button button-ghost button-small");
            actions.append(run, inspect);
            if (pinned) {
                actions.append(pinned);
            }
            if (docs) {
                actions.append(docs);
            }

            const disclosures = sampleDisclosures(sample);
            return make("article", { className: "sample-card" }, [
                make("div", { className: "sample-card-header" }, [
                    make("div", {}, [
                        make("h2", { text: safeString(sample.name, "Unnamed sample") }),
                        make("span", { className: "sample-framework", text: safeString(sample.framework, safeString(sample.id)) })
                    ]),
                    agent
                        ? badge(safeString(agent.status, "Draft"))
                        : badge("Seeded record missing", "danger")
                ]),
                make("p", { className: "sample-description", text: safeString(sample.description, "No description returned.") }),
                capabilityList,
                make("div", { className: "sample-section" }, [
                    make("strong", { text: "Prerequisites" }),
                    prerequisiteList
                ]),
                make("div", { className: "sample-section" }, [
                    make("strong", { text: "Upstream source path" }),
                    make("code", { className: "sample-source-path", text: safeString(sample.sourcePath, "Not returned") })
                ]),
                ...disclosures.map((message) => make("p", { className: "sample-disclosure", text: message })),
                actions
            ]);
        }));
    }

    async function loadSamples() {
        replace(byId("sample-list"), loadingStatus("Loading samples and seeded agents"));
        const results = await Promise.allSettled([ensureSamples(), ensureAgents()]);
        const failure = results.find((result) => result.status === "rejected");
        if (failure) {
            replace(byId("sample-list"), errorStatus(failure.reason, "Sample workbench unavailable"));
            byId("sample-count").textContent = "Catalog unavailable";
            return;
        }
        populateAgentSelects();
        renderSamples();
    }

    function populateAgentSelects() {
        if (!state.agents) {
            return;
        }
        const agents = orderedAgents();
        if (!findAgent(state.selectedAgentId)) {
            state.selectedAgentId = agents[0]?.id || null;
        }
        const selects = [...all("[data-agent-select]"), byId("sample-agent-select")];
        selects.forEach((select) => {
            if (!select) {
                return;
            }
            const options = [];
            if (!agents.length) {
                options.push(make("option", { text: "No agents returned", attrs: { value: "" } }));
            } else {
                agents.forEach((agent) => {
                    const sample = findSample(agent.framework);
                    const seeded = safeString(agent.id).startsWith("a3650000-") ? " · seeded" : "";
                    options.push(make("option", {
                        text: `${safeString(agent.name, "Unnamed agent")} — ${safeString(sample?.framework, safeString(agent.framework))}${seeded}`,
                        attrs: { value: agent.id }
                    }));
                });
            }
            replace(select, ...options);
            select.value = state.selectedAgentId || "";
            select.disabled = agents.length === 0;
        });
        updateAgentDependentUi(false);
    }

    function selectedAgent() {
        return findAgent(state.selectedAgentId);
    }

    function setSelectedAgent(id, resetPrompts = false) {
        if (!findAgent(id) && !findOverviewAgent(id)) {
            return;
        }
        state.selectedAgentId = id;
        all("[data-agent-select]").forEach((select) => {
            if (Array.from(select.options).some((option) => option.value === id)) {
                select.value = id;
            }
        });
        if (Array.from(byId("sample-agent-select").options).some((option) => option.value === id)) {
            byId("sample-agent-select").value = id;
        }
        updateAgentDependentUi(resetPrompts);
        if (state.currentRoute === "dashboard") {
            renderDashboard();
        }
        if (BUILDER_VIEWS.has(state.currentRoute)) {
            loadSelectedEvidence();
        }
    }

    function promptForAgent(agent) {
        const sample = findSample(agent?.framework);
        return safeString(sample?.prompt, "");
    }

    function setPromptValue(element, value) {
        element.value = value;
        updatePromptCount(element);
    }

    function updatePromptCount(textarea) {
        const target = textarea.id === "sample-prompt"
            ? byId("sample-prompt-count")
            : byId("operate-prompt-count");
        if (target) {
            target.textContent = `${textarea.value.length.toLocaleString()} / 12,000`;
        }
    }

    function identityItem(label, value, useCode = true) {
        const display = value === null || value === undefined || value === "" ? "Not recorded" : String(value);
        const content = make(useCode ? "code" : "strong", {
            text: display,
            attrs: { title: display }
        });
        return make("div", { className: "identity-item" }, [
            make("span", { text: label }),
            content
        ]);
    }

    function updateAgentDependentUi(resetPrompts) {
        const agent = selectedAgent();
        const registerSummary = byId("register-agent-summary");
        const operateSummary = byId("operate-agent-summary");
        if (!agent) {
            replace(registerSummary, statusPanel("No agent selected", "The backend did not return an agent record.", "warning"));
            replace(operateSummary, make("span", { text: "No agent selected." }));
            return;
        }

        replace(registerSummary,
            identityItem("Status", safeString(agent.status, "Draft"), false),
            identityItem("Framework ID", safeString(agent.framework, "Not recorded")),
            identityItem("Blueprint object ID", agent.blueprintObjectId),
            identityItem("Blueprint client ID", agent.blueprintClientId),
            identityItem("Agent object ID", agent.agentObjectId),
            identityItem("Agent client ID", agent.agentClientId),
            identityItem("Registry ID", agent.registryId),
            identityItem("Agent user ID", agent.agentUserId)
        );

        replace(operateSummary,
            make("span", {}, [make("strong", { text: "Status: " }), safeString(agent.status, "Draft")]),
            make("span", {}, [make("strong", { text: "Framework: " }), safeString(agent.framework, "Not recorded")]),
            make("span", {}, [make("strong", { text: "Schedule: " }), agent.scheduleEnabled ? "Enabled" : "Disabled"]),
            make("span", {}, [make("strong", { text: "Registry: " }), agent.registryId ? "Recorded" : "Pending"])
        );

        const selectedCapabilities = new Set(normalizedArray(agent.capabilities));
        all('#extend-agent-form input[name="capability"]').forEach((checkbox) => {
            checkbox.checked = selectedCapabilities.has(checkbox.value);
        });

        const schedule = byId("schedule-enabled");
        const agentDisabled = agent.status === "Disabled";
        const eligible = agent.framework === "autonomous" && !agentDisabled;
        schedule.checked = Boolean(agent.scheduleEnabled);
        schedule.disabled = !eligible;
        byId("schedule-status-copy").textContent = agent.framework !== "autonomous"
            ? "Only the autonomous framework can be scheduled."
            : agentDisabled
                ? "The selected agent is disabled. Enabling it never resumes the schedule; save this toggle explicitly after recovery."
                : agent.registryId
                    ? `Backend setting is currently ${agent.scheduleEnabled ? "enabled" : "disabled"}.`
                    : "Registration is required before enabling a schedule.";
        const scheduleSubmit = byId("schedule-form").querySelector('button[type="submit"]');
        scheduleSubmit.disabled = !eligible;

        const identityPanel = byId("identity-state-panel");
        const identityTitle = byId("identity-state-title");
        const identityCopy = byId("identity-state-copy");
        const identityButton = byId("agent-state-button");
        identityPanel.classList.toggle("panel-danger", !agentDisabled);
        identityPanel.classList.toggle("panel-muted", agentDisabled);
        identityTitle.textContent = agentDisabled ? "Recover disabled agent" : "Disable agent";
        identityCopy.textContent = agentDisabled
            ? "Enabling asks Entra to set the registered agent identity to accountEnabled=true. It never resumes an autonomous schedule; use the separate Schedule control to opt in again."
            : "Disabling asks Entra to set the registered agent identity to accountEnabled=false, stops new harness runs, and clears the schedule only after the backend confirms the operation.";
        identityButton.textContent = agentDisabled ? "Enable in Entra" : "Disable selected agent";
        identityButton.className = `button ${agentDisabled ? "button-primary" : "button-danger"}`;
        identityButton.disabled = !agent.agentObjectId;

        if (resetPrompts || !byId("sample-prompt").value) {
            setPromptValue(byId("sample-prompt"), promptForAgent(agent));
        }
        if (resetPrompts || !byId("operate-prompt").value) {
            setPromptValue(byId("operate-prompt"), promptForAgent(agent));
        }
    }

    async function loadEvidence(agentId, force = false) {
        if (!agentId) {
            return [];
        }
        if (state.evidence.has(agentId) && !force) {
            return state.evidence.get(agentId);
        }
        if (state.evidencePromises.has(agentId) && !force) {
            return state.evidencePromises.get(agentId);
        }
        const request = api(`/api/agents/${encodeURIComponent(agentId)}/evidence`).then((payload) => {
            if (!Array.isArray(payload)) {
                throw new ApiError(500, "The evidence response was not an array.");
            }
            state.evidence.set(agentId, payload);
            return payload;
        }).finally(() => {
            state.evidencePromises.delete(agentId);
        });
        state.evidencePromises.set(agentId, request);
        return request;
    }

    function evidenceMarkerClass(value) {
        const normalized = safeString(value).toLowerCase();
        if (normalized.includes("verified")) {
            return "timeline-marker-verified";
        }
        if (normalized.includes("configured")) {
            return "timeline-marker-configured";
        }
        if (normalized.includes("pending")) {
            return "timeline-marker-pending";
        }
        if (normalized.includes("blocked") || normalized.includes("failed")) {
            return "timeline-marker-blocked";
        }
        return "";
    }

    function renderTimeline(container, evidence, stage = null) {
        const entries = stage
            ? normalizedArray(evidence).filter((entry) => safeString(entry.stage).toLowerCase() === stage.toLowerCase())
            : normalizedArray(evidence);
        if (!entries.length) {
            replace(container, statusPanel(
                "No evidence recorded for this view",
                "This is an empty evidence result, not a successful validation.",
                "warning"
            ));
            return;
        }
        replace(container, ...entries.map((entry) => {
            const marker = make("span", {
                className: `timeline-marker ${evidenceMarkerClass(entry.state)}`,
                attrs: { "aria-hidden": "true" }
            });
            const stageBlock = make("div", { className: "timeline-stage" }, [
                make("strong", { text: safeString(entry.stage, "Unspecified stage") }),
                make("small", { text: safeString(entry.state, "State not reported") })
            ]);
            const detail = make("div", { className: "timeline-detail" }, [
                make("p", { text: safeString(entry.summary, "No summary returned.") })
            ]);
            const time = make("div", { className: "timeline-time" }, [
                make("time", {
                    text: formatDate(entry.observedAt),
                    attrs: entry.observedAt ? { datetime: entry.observedAt } : {}
                }),
                entry.correlationId
                    ? make("code", {
                        className: "timeline-correlation",
                        text: entry.correlationId,
                        attrs: { title: `Correlation ID ${entry.correlationId}` }
                    })
                    : null
            ]);
            return make("article", { className: "timeline-item" }, [marker, stageBlock, detail, time]);
        }));
    }

    async function loadSelectedEvidence(force = false) {
        const agent = selectedAgent();
        const targets = [
            { element: byId("register-evidence"), stage: "Register" },
            { element: byId("extend-evidence"), stage: "Extend" },
            { element: byId("validate-evidence"), stage: null }
        ];
        if (!agent) {
            targets.forEach(({ element }) => {
                replace(element, statusPanel("No agent selected", "Select an agent to load evidence.", "warning"));
            });
            return;
        }
        targets.forEach(({ element }) => replace(element, loadingStatus("Loading recorded evidence")));
        try {
            const evidence = await loadEvidence(agent.id, force);
            targets.forEach(({ element, stage }) => renderTimeline(element, evidence, stage));
        } catch (error) {
            targets.forEach(({ element }) => replace(element, errorStatus(error, "Evidence unavailable")));
        }
    }

    async function loadBuilderView() {
        const containers = [byId("register-evidence"), byId("extend-evidence"), byId("validate-evidence")];
        if (!state.agents) {
            containers.forEach((container) => replace(container, loadingStatus("Loading agent catalog")));
        }
        const results = await Promise.allSettled([ensureSamples(), ensureAgents()]);
        const failure = results.find((result) => result.status === "rejected");
        if (failure) {
            containers.forEach((container) => replace(container, errorStatus(failure.reason, "Agent Builder unavailable")));
            return;
        }
        populateAgentSelects();
        await loadSelectedEvidence();
    }

    async function performAgentMutation(button, path, body, busyLabel, successTitle) {
        if (!state.session?.administrator) {
            toast("Administrator role required", `The ${ADMIN_ROLE} app role is required.`, "error");
            return null;
        }
        setBusy(button, true, busyLabel);
        try {
            const result = await api(path, { method: "POST", body });
            state.dashboardNeedsRefresh = true;
            toast(successTitle, "The UI now reflects the backend response and refreshed evidence.", "success");
            return result;
        } catch (error) {
            toast(successTitle, friendlyError(error), "error");
            return null;
        } finally {
            setBusy(button, false);
        }
    }

    async function registerSelectedAgent() {
        const agent = selectedAgent();
        if (!agent) {
            return;
        }
        const button = byId("register-agent-button");
        const result = await performAgentMutation(
            button,
            `/api/admin/agents/${encodeURIComponent(agent.id)}/register`,
            {},
            "Registering",
            "Registration request completed"
        );
        if (result) {
            upsertAgent(result);
            state.evidence.delete(agent.id);
            await loadSelectedEvidence(true);
        }
    }

    async function validateSelectedAgent() {
        const agent = selectedAgent();
        if (!agent) {
            return;
        }
        const button = byId("validate-agent-button");
        const result = await performAgentMutation(
            button,
            `/api/admin/agents/${encodeURIComponent(agent.id)}/validate`,
            {},
            "Validating",
            "Validation request completed"
        );
        if (result) {
            if (Array.isArray(result)) {
                state.evidence.set(agent.id, result);
            } else {
                state.evidence.delete(agent.id);
            }
            await ensureAgents(true);
            populateAgentSelects();
            await loadSelectedEvidence(true);
        }
    }

    async function extendSelectedAgent(event) {
        event.preventDefault();
        const agent = selectedAgent();
        if (!agent) {
            return;
        }
        const form = event.currentTarget;
        const button = form.querySelector('button[type="submit"]');
        const capabilities = all('input[name="capability"]:checked', form).map((input) => input.value);
        const result = await performAgentMutation(
            button,
            `/api/admin/agents/${encodeURIComponent(agent.id)}/extend`,
            { capabilities },
            "Applying",
            "Capabilities updated"
        );
        if (result) {
            upsertAgent(result);
            state.evidence.delete(agent.id);
            await loadSelectedEvidence(true);
        }
    }

    async function createAgent(event) {
        event.preventDefault();
        if (!state.session?.administrator) {
            return;
        }
        const form = event.currentTarget;
        const button = form.querySelector('button[type="submit"]');
        const data = new FormData(form);
        const body = {
            name: safeString(data.get("name")).trim(),
            framework: safeString(data.get("framework")),
            description: safeString(data.get("description")).trim()
        };
        const result = await performAgentMutation(
            button,
            "/api/admin/agents",
            body,
            "Creating",
            "Agent draft created"
        );
        if (result) {
            form.reset();
            upsertAgent(result);
            await loadSelectedEvidence(true);
        }
    }

    async function saveSchedule(event) {
        event.preventDefault();
        const agent = selectedAgent();
        if (!agent) {
            return;
        }
        const button = event.currentTarget.querySelector('button[type="submit"]');
        const enabled = byId("schedule-enabled").checked;
        const result = await performAgentMutation(
            button,
            `/api/admin/agents/${encodeURIComponent(agent.id)}/schedule`,
            { enabled },
            "Saving",
            "Schedule setting updated"
        );
        if (result) {
            const refreshed = await ensureAgents(true);
            if (refreshed) {
                populateAgentSelects();
            }
        }
    }

    function confirmAction(title, message, confirmLabel = "Confirm") {
        const dialog = byId("confirm-dialog");
        if (typeof dialog.showModal !== "function") {
            return Promise.resolve(window.confirm(message));
        }
        byId("confirm-dialog-title").textContent = title;
        byId("confirm-dialog-message").textContent = message;
        byId("confirm-dialog-accept").textContent = confirmLabel;
        if (dialog.open) {
            dialog.close("cancel");
        }
        return new Promise((resolve) => {
            const onClose = () => {
                dialog.removeEventListener("close", onClose);
                resolve(dialog.returnValue === "confirm");
            };
            dialog.addEventListener("close", onClose);
            dialog.showModal();
        });
    }

    async function changeSelectedAgentState() {
        const agent = selectedAgent();
        if (!agent) {
            return;
        }
        const enabling = agent.status === "Disabled";
        const confirmed = await confirmAction(
            enabling ? "Enable registered agent" : "Disable registered agent",
            enabling
                ? `Enable ${safeString(agent.name, "the selected agent")} in Entra? This requests accountEnabled=true only. Its autonomous schedule remains disabled until an administrator explicitly saves the Schedule toggle.`
                : `Disable ${safeString(agent.name, "the selected agent")}? The backend will request accountEnabled=false in Entra and stop new harness runs only after that operation succeeds.`,
            enabling ? "Enable in Entra" : "Disable agent"
        );
        if (!confirmed) {
            return;
        }
        const button = byId("agent-state-button");
        const result = await performAgentMutation(
            button,
            `/api/admin/agents/${encodeURIComponent(agent.id)}/${enabling ? "enable" : "disable"}`,
            {},
            enabling ? "Enabling" : "Disabling",
            enabling ? "Agent enabled; schedule remains separate" : "Agent disable request completed"
        );
        if (result) {
            await ensureAgents(true);
            populateAgentSelects();
            state.evidence.delete(agent.id);
            await loadSelectedEvidence(true);
        }
    }

    function renderRunResult(container, result, agent) {
        container.classList.remove("empty-result");
        const live = result && result.live === true;
        const title = live ? "Live backend result" : "Backend returned a non-live result";
        const header = make("div", { className: "run-result-header" }, [
            make("div", {}, [
                make("h3", { text: title }),
                make("div", { className: "run-meta" }, [
                    make("span", {}, [make("strong", { text: "Agent: " }), safeString(agent?.name, "Not returned")]),
                    make("span", {}, [make("strong", { text: "Framework: " }), safeString(result?.framework, "Not returned")]),
                    make("span", {}, [make("strong", { text: "Trace: " }), make("code", { text: safeString(result?.traceId, "Not returned") })])
                ])
            ]),
            badge(live ? "live=true" : "live=false", live ? "success" : "warning")
        ]);
        const output = make("pre", {
            className: "run-output",
            text: safeString(result?.text, "The backend returned an empty text field.")
        });
        const steps = normalizedArray(result?.steps);
        const stepSection = make("div", {}, [
            make("h3", { text: "Execution steps returned by backend" }),
            steps.length
                ? make("ol", { className: "run-steps" }, steps.map((step) => make("li", { text: safeString(step, "Empty step") })))
                : statusPanel("No steps returned", "The UI will not invent execution or policy steps.", "warning")
        ]);
        const sample = findSample(agent?.framework);
        const actions = make("div", { className: "button-row" });
        if (sample) {
            const sourceButton = make("button", {
                className: "button button-secondary button-small",
                text: "Inspect framework source",
                attrs: { type: "button" }
            });
            sourceButton.addEventListener("click", () => openSourceForSample(sample));
            actions.append(sourceButton);
        }
        replace(container, header, output, stepSection, actions);
    }

    async function runAgent(form, container) {
        const agent = selectedAgent();
        if (!agent) {
            replace(container, statusPanel("No agent selected", "Select an agent before running a prompt.", "warning"));
            return;
        }
        const promptElement = form.querySelector("textarea");
        const prompt = promptElement.value;
        const button = form.querySelector('button[type="submit"]');
        setBusy(button, true, "Running");
        container.classList.remove("empty-result");
        replace(container, loadingStatus("Waiting for backend execution"));
        try {
            const result = await api(`/api/agents/${encodeURIComponent(agent.id)}/run`, {
                method: "POST",
                body: { prompt }
            });
            state.lastRun = {
                ...result,
                agentId: agent.id,
                observedAt: new Date().toISOString()
            };
            state.dashboardNeedsRefresh = true;
            renderRunResult(container, result, agent);
            renderSamples();
            renderPrerequisites();
            state.evidence.delete(agent.id);
            if (BUILDER_VIEWS.has(state.currentRoute)) {
                loadSelectedEvidence(true);
            }
        } catch (error) {
            replace(container, errorStatus(error, "Agent run did not complete"));
        } finally {
            setBusy(button, false);
        }
    }

    function stringifyForDisplay(value) {
        if (typeof value === "string") {
            return value;
        }
        try {
            return JSON.stringify(value, null, 2);
        } catch {
            return String(value);
        }
    }

    function renderClaims(claims) {
        if (!claims || (typeof claims === "object" && !Array.isArray(claims) && Object.keys(claims).length === 0)) {
            return statusPanel("No claims returned", "The backend did not include selected claims for this operation.", "warning");
        }
        const rows = Array.isArray(claims)
            ? claims.map((value, index) => [String(index), stringifyForDisplay(value)])
            : Object.entries(claims).map(([key, value]) => [key, stringifyForDisplay(value)]);
        const table = make("table", { className: "claims-table" });
        const body = make("tbody");
        rows.forEach(([key, value]) => {
            body.append(make("tr", {}, [
                make("th", { text: key, attrs: { scope: "row" } }),
                make("td", { text: value })
            ]));
        });
        table.append(body);
        return table;
    }

    function renderGatewayResult(result) {
        const container = byId("gateway-result");
        container.classList.remove("empty-result");
        const statusCode = Number.isFinite(Number(result?.statusCode)) ? Number(result.statusCode) : null;
        const successful = statusCode !== null && statusCode >= 200 && statusCode < 300;
        byId("gateway-result-badge").replaceWith(
            Object.assign(badge(
                statusCode === null ? "Status not returned" : `HTTP ${statusCode}`,
                statusCode === null ? "warning" : successful ? "success" : "danger"
            ), { id: "gateway-result-badge" })
        );
        const summary = make("div", { className: "gateway-summary" }, [
            make("div", { className: "gateway-stat" }, [
                make("span", { text: "Status code" }),
                make("strong", { text: statusCode === null ? "Not returned" : String(statusCode) })
            ]),
            make("div", { className: "gateway-stat" }, [
                make("span", { text: "Decision" }),
                make("strong", { text: safeString(result?.decision, "Not returned") })
            ]),
            make("div", { className: "gateway-stat" }, [
                make("span", { text: "Trace ID" }),
                make("code", { text: safeString(result?.traceId, "Not returned") })
            ])
        ]);
        const claims = make("section", { className: "response-section" }, [
            make("h3", { text: "Selected claims returned by backend" }),
            renderClaims(result?.claims)
        ]);
        const body = make("section", { className: "response-section" }, [
            make("h3", { text: "Synthetic API body" }),
            make("pre", { className: "json-output", text: stringifyForDisplay(result?.body) })
        ]);
        const note = statusPanel(
            "Token boundary preserved",
            "This response displays a decision, selected claims, and synthetic API content. No raw access token is requested or rendered.",
            "success"
        );
        replace(container, summary, claims, body, note);
    }

    async function invokeGateway(event) {
        event.preventDefault();
        const form = event.currentTarget;
        const button = byId("gateway-submit");
        const operation = safeString(new FormData(form).get("operation"));
        setBusy(button, true, "Invoking");
        byId("gateway-result").classList.remove("empty-result");
        replace(byId("gateway-result"), loadingStatus("Waiting for gateway decision"));
        try {
            const result = await api("/api/gateway/invoke", {
                method: "POST",
                body: { operation }
            });
            renderGatewayResult(result);
        } catch (error) {
            replace(byId("gateway-result"), errorStatus(error, "Gateway invocation failed"));
            const currentBadge = byId("gateway-result-badge");
            currentBadge.textContent = error instanceof ApiError && error.status ? `HTTP ${error.status}` : "Request failed";
            currentBadge.className = "badge badge-danger";
        } finally {
            setBusy(button, false);
        }
    }

    function renderSourceList() {
        const container = byId("source-list");
        if (!state.sources) {
            replace(container, loadingStatus("Loading embedded source index"));
            return;
        }
        const query = safeString(byId("source-search").value).trim().toLowerCase();
        const paths = state.sources.filter((path) => !query || path.toLowerCase().includes(query));
        byId("source-count").textContent = `${paths.length} of ${state.sources.length} files`;
        if (!paths.length) {
            replace(container, statusPanel("No source paths match", "Change or clear the source filter.", "warning"));
            return;
        }

        const children = [];
        ["Harness/", "Upstream/"].forEach((prefix) => {
            const group = paths.filter((path) => path.startsWith(prefix));
            if (!group.length) {
                return;
            }
            children.push(make("p", {
                className: "source-group-label",
                text: prefix === "Harness/" ? "Harness source" : "Pinned upstream source"
            }));
            group.forEach((path) => {
                const button = make("button", {
                    className: "source-item",
                    text: path,
                    attrs: {
                        type: "button",
                        role: "option",
                        "aria-selected": path === state.selectedSourcePath ? "true" : "false",
                        title: path
                    }
                });
                button.addEventListener("click", () => openSource(path));
                children.push(button);
            });
        });
        replace(container, ...children);
    }

    function setSourceExternalLink(path) {
        const link = byId("source-external-link");
        if (!path.startsWith("Upstream/")) {
            link.hidden = true;
            return;
        }
        let repositoryPath = path.slice("Upstream/".length);
        repositoryPath = repositoryPath === "LICENSE" ? "LICENSE" : `dotnet/${repositoryPath}`;
        const encoded = repositoryPath.split("/").map((segment) => encodeURIComponent(segment)).join("/");
        link.href = `${UPSTREAM_REPOSITORY}/blob/${UPSTREAM_COMMIT}/${encoded}`;
        link.hidden = false;
    }

    async function openSource(path) {
        if (!state.sources || !state.sources.includes(path) || (!path.startsWith("Harness/") && !path.startsWith("Upstream/"))) {
            toast("Source path rejected", "Only exact paths returned by the embedded source allowlist can be opened.", "error");
            return;
        }
        state.selectedSourcePath = path;
        state.selectedSourceText = "";
        renderSourceList();
        byId("source-kind").textContent = path.startsWith("Upstream/") ? "Pinned upstream source · MIT" : "Current harness source";
        byId("source-viewer-title").textContent = path;
        byId("source-provenance").textContent = path.startsWith("Upstream/")
            ? `Embedded from Microsoft Agent365-Samples commit ${UPSTREAM_COMMIT}.`
            : "Embedded from the current AgentHarness build.";
        setSourceExternalLink(path);
        byId("source-code-panel").hidden = true;
        byId("source-loading").hidden = false;
        replace(byId("source-loading"), loadingStatus("Loading exact source text"));
        byId("copy-source-button").disabled = true;
        try {
            const source = await api(`/api/source?path=${encodeURIComponent(path)}`, { responseType: "text" });
            if (state.selectedSourcePath !== path) {
                return;
            }
            state.selectedSourceText = safeString(source);
            byId("source-code").textContent = state.selectedSourceText;
            byId("source-loading").hidden = true;
            byId("source-code-panel").hidden = false;
            byId("copy-source-button").disabled = !(navigator.clipboard && window.isSecureContext);
        } catch (error) {
            replace(byId("source-loading"), errorStatus(error, "Source file unavailable"));
        }
    }

    async function loadCodeView() {
        if (!state.sources) {
            replace(byId("source-list"), loadingStatus("Loading embedded source index"));
        }
        try {
            await ensureSources();
            renderSourceList();
            let target = state.selectedSourcePath;
            if (state.pendingSourceHint) {
                const hint = state.pendingSourceHint;
                if (DASHBOARD_SOURCE_PATHS.has(hint)) {
                    target = state.sources.includes(hint) ? hint : target;
                    if (!state.sources.includes(hint)) {
                        toast("Dashboard source unavailable", "The exact backend source path is not in the embedded allowlist.", "error");
                    }
                } else {
                    target = state.sources.find((path) => path.startsWith(hint) && path.endsWith("/Program.cs")) ||
                        state.sources.find((path) => path.startsWith(hint)) ||
                        target;
                }
                state.pendingSourceHint = null;
            }
            target = target ||
                state.sources.find((path) => path === "Harness/Program.cs") ||
                state.sources[0] ||
                null;
            if (target && target !== state.selectedSourcePath) {
                await openSource(target);
            } else if (target && !state.selectedSourceText) {
                await openSource(target);
            }
        } catch (error) {
            replace(byId("source-list"), errorStatus(error, "Source index unavailable"));
            byId("source-count").textContent = "Source index unavailable";
        }
    }

    function openDashboardSource(sourcePath) {
        const normalized = safeString(sourcePath).replace(/\\/g, "/");
        if (!DASHBOARD_SOURCE_PATHS.has(normalized)) {
            toast("Source path rejected", "Dashboard source actions are restricted to the four embedded harness paths.", "error");
            return;
        }
        state.pendingSourceHint = normalized;
        if (state.currentRoute === "code") {
            loadCodeView();
        } else {
            location.hash = "#code";
        }
    }

    function openSourceForSample(sample) {
        state.pendingSourceHint = sourceHintForSample(sample);
        if (state.currentRoute === "code") {
            loadCodeView();
        } else {
            location.hash = "#code";
        }
    }

    function renderIntegrations(error = null) {
        const container = byId("integration-list");
        if (error) {
            replace(container, errorStatus(error, "Integration checks unavailable"));
            return;
        }
        if (!state.integrations) {
            replace(container, loadingStatus("Running backend integration checks"));
            return;
        }
        if (!state.integrations.length) {
            replace(container, statusPanel(
                "No integration checks returned",
                "No integration state is inferred from an empty API response.",
                "warning"
            ));
            return;
        }
        replace(container, ...state.integrations.map((integration) => {
            const header = make("div", { className: "integration-card-header" }, [
                make("h3", { text: safeString(integration.name, "Unnamed integration") }),
                badge(safeString(integration.state, "State not reported"))
            ]);
            const card = make("article", { className: "integration-card" }, [
                header,
                make("p", { text: safeString(integration.detail, "No detail returned by the integration check.") })
            ]);
            const portal = externalLink("Open related portal", integration.portal);
            if (portal) {
                card.append(portal);
            }
            return card;
        }));
    }

    function renderPrerequisites() {
        const container = byId("prerequisite-list");
        if (!state.governanceLoaded && !state.integrations) {
            replace(container, loadingStatus("Waiting for integration evidence"));
            return;
        }
        const definitions = [
            {
                key: "w365",
                name: "Windows 365 for Agents",
                pattern: /windows\s*365|w365/i,
                requirement: "Requires provisioned access, an agent user, a computer-use model deployment, governed MCP discovery, and an agentic delegated token."
            },
            {
                key: "notifications",
                name: "Agent 365 notifications",
                pattern: /notification/i,
                requirement: "Requires a provisioned agent user, mailbox, published messaging endpoint, and applicable tenant availability."
            },
            {
                key: "purview",
                name: "Microsoft Purview protection",
                pattern: /purview/i,
                requirement: "Requires an applicable inline policy before inference and successful evaluation of submitted input and released output. There is no bypass toggle, and configured code alone is not policy coverage."
            }
        ];
        replace(container, ...definitions.map((definition) => {
            const integration = matchingIntegration(definition.pattern);
            const apiVerified = exactVerified(integration);
            const runtimeVerified = definition.key !== "purview" || hasPurviewRunEvidence();
            const verified = apiVerified && runtimeVerified;
            let detail = definition.requirement;
            if (integration) {
                detail += ` Backend check returned "${safeString(integration.state, "state not reported")}": ${safeString(integration.detail, "no detail returned")}`;
            } else {
                detail += " No matching integration check was returned.";
            }
            if (definition.key === "purview" && apiVerified && !runtimeVerified) {
                detail += " A live run with both input and output evaluation evidence has not been observed in this browser session.";
            }
            return make("article", {
                className: `prerequisite-card${verified ? " prerequisite-verified" : ""}`
            }, [
                make("div", { className: "prerequisite-card-header" }, [
                    make("h3", { text: definition.name }),
                    badge(verified ? "Verified" : "Pending verification", verified ? "success" : "warning")
                ]),
                make("p", { text: detail })
            ]);
        }));
    }

    function renderPortals(error = null) {
        const container = byId("portal-list");
        if (error) {
            replace(container, errorStatus(error, "Portal catalog unavailable"));
            return;
        }
        if (!state.portals) {
            replace(container, loadingStatus("Loading portal catalog"));
            return;
        }
        if (!state.portals.length) {
            replace(container, statusPanel(
                "No portals returned",
                "The frontend does not invent portal links when the API catalog is empty.",
                "warning"
            ));
            return;
        }
        const groups = new Map();
        state.portals.forEach((portal) => {
            const category = safeString(portal.category, "Other");
            if (!groups.has(category)) {
                groups.set(category, []);
            }
            groups.get(category).push(portal);
        });
        const sections = Array.from(groups.entries()).sort(([left], [right]) => left.localeCompare(right)).map(([category, portals]) => {
            const grid = make("div", { className: "portal-grid" });
            portals.sort((left, right) => safeString(left.name).localeCompare(safeString(right.name))).forEach((portal) => {
                const safeUrl = safeExternalUrl(portal.url);
                if (safeUrl) {
                    grid.append(make("a", {
                        className: "portal-card",
                        attrs: {
                            href: safeUrl,
                            target: "_blank",
                            rel: "noopener noreferrer"
                        }
                    }, [
                        make("strong", { text: safeString(portal.name, "Unnamed portal") }),
                        make("p", { text: safeString(portal.description, "No description returned.") }),
                        make("span", { text: "Open portal in new tab" })
                    ]));
                } else {
                    grid.append(make("div", { className: "portal-card" }, [
                        make("strong", { text: safeString(portal.name, "Unnamed portal") }),
                        make("p", { text: safeString(portal.description, "No description returned.") }),
                        make("span", { text: "API did not return a valid HTTP(S) URL" })
                    ]));
                }
            });
            return make("section", { className: "portal-group" }, [
                make("h3", { text: category }),
                grid
            ]);
        });
        replace(container, ...sections);
    }

    async function loadGovernance(force = false) {
        if (!force && state.governanceLoaded) {
            renderIntegrations();
            renderPrerequisites();
            renderPortals();
            return;
        }
        state.integrations = null;
        state.portals = null;
        renderIntegrations();
        renderPrerequisites();
        renderPortals();
        const [integrations, portals] = await Promise.allSettled([
            api("/api/integrations"),
            api("/api/portals")
        ]);
        state.governanceLoaded = true;
        if (integrations.status === "fulfilled") {
            state.integrations = Array.isArray(integrations.value) ? integrations.value : [];
            renderIntegrations();
        } else {
            state.integrations = [];
            renderIntegrations(integrations.reason);
        }
        renderPrerequisites();
        renderSamples();
        if (portals.status === "fulfilled") {
            state.portals = Array.isArray(portals.value) ? portals.value : [];
            renderPortals();
        } else {
            state.portals = [];
            renderPortals(portals.reason);
        }
    }

    function populateRoleOptions() {
        const application = byId("assignment-application").value;
        const guest = state.selectedDirectoryUser?.userType === "Guest" && !state.selectedDirectoryUser?.privilegedGuestApproved;
        const roles = normalizedArray(APPLICATION_ROLES[application])
            .filter((role) => !guest || (application === "harness" && role === USER_ROLE));
        replace(byId("assignment-role"), ...roles.map((role) => make("option", {
            text: role,
            attrs: { value: role }
        })));
    }

    function tableEmpty(message) {
        return make("div", { className: "status-panel" }, [
            make("div", {}, [
                make("strong", { text: "No records" }),
                make("p", { text: message })
            ])
        ]);
    }

    function renderAssignments() {
        const container = byId("assignment-list");
        const assignments = normalizedArray(state.assignments);
        byId("assignment-summary").textContent = `${assignments.length} assignment${assignments.length === 1 ? "" : "s"} returned`;
        if (!assignments.length) {
            replace(container, tableEmpty("No approved role assignments were returned for this application."));
            return;
        }
        const table = make("table", { className: "data-table" });
        table.append(make("caption", { text: "Current enterprise application role assignments" }));
        table.append(make("thead", {}, [
            make("tr", {}, [
                make("th", { text: "Principal", attrs: { scope: "col" } }),
                make("th", { text: "Role", attrs: { scope: "col" } }),
                make("th", { text: "Principal ID", attrs: { scope: "col" } }),
                make("th", { text: "Action", attrs: { scope: "col" } })
            ])
        ]));
        const body = make("tbody");
        assignments.forEach((assignment) => {
            const remove = make("button", {
                className: "button button-ghost button-small",
                text: "Remove",
                attrs: {
                    type: "button",
                    "aria-label": `Remove ${safeString(assignment.role, "role")} from ${safeString(assignment.principalDisplayName, "principal")}`
                }
            });
            remove.addEventListener("click", () => removeAssignment(assignment, remove));
            body.append(make("tr", {}, [
                make("td", {}, [
                    make("span", { className: "cell-primary", text: safeString(assignment.principalDisplayName, "Unnamed principal") })
                ]),
                make("td", {}, [make("code", { text: safeString(assignment.role, "Role not returned") })]),
                make("td", {}, [make("code", { text: safeString(assignment.principalId, "Not returned") })]),
                make("td", {}, [remove])
            ]));
        });
        table.append(body);
        replace(container, table);
    }

    async function loadAssignments() {
        const application = byId("assignment-application").value;
        byId("assignment-summary").textContent = "Loading assignments";
        replace(byId("assignment-list"), loadingStatus("Loading application role assignments"));
        try {
            const result = await api(`/api/admin/assignments?application=${encodeURIComponent(application)}`);
            state.assignments = Array.isArray(result) ? result : [];
            renderAssignments();
        } catch (error) {
            state.assignments = [];
            byId("assignment-summary").textContent = "Assignments unavailable";
            replace(byId("assignment-list"), errorStatus(error, "Assignments unavailable"));
        }
    }

    function selectDirectoryUser(user) {
        state.selectedDirectoryUser = user;
        if (user.userType === "Guest" && !user.privilegedGuestApproved && byId("assignment-application").value !== "harness") {
            byId("assignment-application").value = "harness";
            loadAssignments();
        }
        populateRoleOptions();
        all(".directory-user").forEach((button) => {
            button.setAttribute("aria-pressed", button.dataset.userId === user.id ? "true" : "false");
        });
        byId("selected-user-name").textContent = safeString(user.displayName, "Unnamed user");
        byId("selected-user-upn").textContent = safeString(user.userPrincipalName, "User principal name not returned");
        byId("selected-directory-user").hidden = false;
    }

    function renderDirectoryUsers(users) {
        const container = byId("directory-results");
        if (!users.length) {
            replace(container, statusPanel(
                "No enabled members or approved B2B guests matched",
                "Try another display name or user principal name prefix.",
                "warning"
            ));
            return;
        }
        replace(container, ...users.map((user) => {
            const button = make("button", {
                className: "directory-user",
                attrs: {
                    type: "button",
                    "aria-pressed": state.selectedDirectoryUser?.id === user.id ? "true" : "false"
                }
            }, [
                make("span", {}, [
                    make("strong", { text: safeString(user.displayName, "Unnamed user") }),
                    make("small", { text: safeString(user.userPrincipalName, "User principal name not returned") }),
                    make("small", { text: user.userType === "Guest"
                        ? `${user.privilegedGuestApproved ? "Explicitly approved B2B administrator" : "Approved B2B guest"} · ${safeString(user.externalUserState, "Acceptance not reported")}`
                        : "Tenant member" })
                ]),
                make("span", { text: "Select" })
            ]);
            button.dataset.userId = safeString(user.id);
            button.addEventListener("click", () => selectDirectoryUser(user));
            return button;
        }));
    }

    async function searchDirectory(event) {
        event.preventDefault();
        const form = event.currentTarget;
        const button = form.querySelector('button[type="submit"]');
        const query = byId("directory-query").value.trim();
        setBusy(button, true, "Searching");
        replace(byId("directory-results"), loadingStatus("Searching members and approved B2B guests"));
        try {
            const result = await api(`/api/admin/users?query=${encodeURIComponent(query)}`);
            renderDirectoryUsers(Array.isArray(result) ? result : []);
        } catch (error) {
            replace(byId("directory-results"), errorStatus(error, "Directory search failed"));
        } finally {
            setBusy(button, false);
        }
    }

    async function assignSelectedRole() {
        const user = state.selectedDirectoryUser;
        if (!user) {
            return;
        }
        const application = byId("assignment-application").value;
        const role = byId("assignment-role").value;
        if (!normalizedArray(APPLICATION_ROLES[application]).includes(role)) {
            toast("Role rejected", "Only the approved roles shown by this interface can be requested.", "error");
            return;
        }
        const button = byId("assign-role-button");
        setBusy(button, true, "Assigning");
        try {
            await api("/api/admin/assignments", {
                method: "POST",
                body: { userId: user.id, application, role }
            });
            toast("Role assignment completed", `${role} was requested for ${safeString(user.displayName, "the selected member")}.`, "success");
            await Promise.all([loadAssignments(), loadAudit()]);
        } catch (error) {
            toast("Role assignment failed", friendlyError(error), "error");
        } finally {
            setBusy(button, false);
        }
    }

    async function removeAssignment(assignment, button) {
        const confirmed = await confirmAction(
            "Remove application role",
            `Remove ${safeString(assignment.role, "the selected role")} from ${safeString(assignment.principalDisplayName, "this principal")}? The backend prevents removal of the last harness administrator.`,
            "Remove role"
        );
        if (!confirmed) {
            return;
        }
        setBusy(button, true, "Removing");
        try {
            await api(
                `/api/admin/assignments/${encodeURIComponent(assignment.application)}/${encodeURIComponent(assignment.id)}`,
                { method: "DELETE" }
            );
            toast("Role removed", "The assignment list and audit stream are being refreshed.", "success");
            await Promise.all([loadAssignments(), loadAudit()]);
        } catch (error) {
            toast("Role removal failed", friendlyError(error), "error");
        } finally {
            setBusy(button, false);
        }
    }

    function renderAudit() {
        const container = byId("audit-list");
        if (!state.audit.length) {
            replace(container, tableEmpty("No audit events were returned."));
            return;
        }
        const table = make("table", { className: "data-table" });
        table.append(make("caption", { text: "Recent AgentHarness audit events" }));
        table.append(make("thead", {}, [
            make("tr", {}, [
                make("th", { text: "Time", attrs: { scope: "col" } }),
                make("th", { text: "Action", attrs: { scope: "col" } }),
                make("th", { text: "Target", attrs: { scope: "col" } }),
                make("th", { text: "Outcome", attrs: { scope: "col" } }),
                make("th", { text: "Actor / trace", attrs: { scope: "col" } })
            ])
        ]));
        const body = make("tbody");
        state.audit.forEach((event) => {
            body.append(make("tr", {}, [
                make("td", {}, [
                    make("time", {
                        text: formatDate(event.timestamp),
                        attrs: event.timestamp ? { datetime: event.timestamp } : {}
                    })
                ]),
                make("td", {}, [make("span", { className: "cell-primary", text: safeString(event.action, "Action not returned") })]),
                make("td", {}, [make("code", { text: safeString(event.target, "Target not returned") })]),
                make("td", {}, [badge(safeString(event.outcome, "Outcome not returned"))]),
                make("td", {}, [
                    make("code", { text: safeString(event.actorId, "Actor not returned") }),
                    event.traceId
                        ? make("span", { className: "cell-secondary", text: `Trace ${event.traceId}` })
                        : make("span", { className: "cell-secondary", text: "No trace ID recorded" })
                ])
            ]));
        });
        table.append(body);
        replace(container, table);
    }

    async function loadAudit() {
        replace(byId("audit-list"), loadingStatus("Loading audit stream"));
        try {
            const result = await api("/api/admin/audit");
            state.audit = Array.isArray(result) ? result : [];
            renderAudit();
        } catch (error) {
            state.audit = [];
            replace(byId("audit-list"), errorStatus(error, "Audit stream unavailable"));
        }
    }

    function clearDirectorySelection() {
        state.selectedDirectoryUser = null;
        byId("selected-directory-user").hidden = true;
        all(".directory-user").forEach((button) => button.setAttribute("aria-pressed", "false"));
    }

    async function loadAdministration() {
        if (!state.session?.administrator) {
            return;
        }
        populateRoleOptions();
        await Promise.all([loadAssignments(), loadAudit()]);
    }

    function clearCredentials(message = "Credential display cleared.") {
        if (state.credentialTimer) {
            window.clearInterval(state.credentialTimer);
            state.credentialTimer = null;
        }
        if (state.credentialTimeout) {
            window.clearTimeout(state.credentialTimeout);
            state.credentialTimeout = null;
        }
        state.credentialExpiresAt = null;
        byId("credential-username").textContent = "";
        byId("credential-password").textContent = "";
        replace(byId("credential-url"));
        byId("credential-display").hidden = true;
        byId("credential-progress").value = 30;
        byId("credential-countdown").textContent = "30 seconds remaining";
        if (message) {
            replace(byId("credential-status"), statusPanel("Credentials cleared", message, "success"));
        } else {
            replace(byId("credential-status"));
        }
    }

    function updateCredentialCountdown() {
        if (!state.credentialExpiresAt) {
            return;
        }
        const remaining = Math.max(0, Math.ceil((state.credentialExpiresAt - Date.now()) / 1000));
        byId("credential-countdown").textContent = `${remaining} second${remaining === 1 ? "" : "s"} remaining`;
        byId("credential-progress").value = remaining;
        if (remaining <= 0) {
            clearCredentials("The 30-second reveal window expired.");
        }
    }

    async function revealCredentials() {
        const button = byId("reveal-credentials");
        clearCredentials("");
        setBusy(button, true, "Retrieving");
        replace(byId("credential-status"), loadingStatus("Requesting credentials from backend"));
        try {
            const result = await api("/api/admin/gravitee/credentials", {
                method: "POST",
                body: {}
            });
            if (
                !result ||
                typeof result.username !== "string" ||
                typeof result.password !== "string" ||
                typeof result.url !== "string"
            ) {
                throw new ApiError(500, "The credential response did not include username, password, and URL.");
            }
            const urlContainer = byId("credential-url");
            const link = externalLink(result.url, result.url);
            replace(urlContainer, link || make("span", { text: result.url }));
            byId("credential-username").textContent = result.username;
            byId("credential-password").textContent = result.password;
            byId("credential-display").hidden = false;
            replace(byId("credential-status"), statusPanel(
                "Credentials revealed",
                "The values below will be removed from the document after 30 seconds or when this page is hidden.",
                "success"
            ));
            state.credentialExpiresAt = Date.now() + 30000;
            updateCredentialCountdown();
            state.credentialTimer = window.setInterval(updateCredentialCountdown, 1000);
            state.credentialTimeout = window.setTimeout(
                () => clearCredentials("The 30-second reveal window expired."),
                30000
            );
        } catch (error) {
            replace(byId("credential-status"), errorStatus(error, "Credential retrieval failed"));
        } finally {
            setBusy(button, false);
        }
    }

    async function copyCredential(elementId, label) {
        const value = byId(elementId).textContent;
        if (!value || !navigator.clipboard || !window.isSecureContext) {
            toast("Clipboard unavailable", "Use a secure browser context and select the value manually.", "error");
            return;
        }
        try {
            await navigator.clipboard.writeText(value);
            toast(`${label} copied`, "Clipboard copy was initiated by your explicit click.", "success");
        } catch (error) {
            toast("Clipboard write failed", error instanceof Error ? error.message : "The browser rejected the clipboard request.", "error");
        }
    }

    async function copySource() {
        if (!state.selectedSourceText || !navigator.clipboard || !window.isSecureContext) {
            toast("Clipboard unavailable", "Open a source file in a secure browser context before copying.", "error");
            return;
        }
        try {
            await navigator.clipboard.writeText(state.selectedSourceText);
            toast("Source copied", "The exact allowlisted source text was copied.", "success");
        } catch (error) {
            toast("Source copy failed", error instanceof Error ? error.message : "The browser rejected the clipboard request.", "error");
        }
    }

    function openNavigation() {
        document.body.classList.add("nav-opened");
        byId("nav-open").setAttribute("aria-expanded", "true");
        byId("nav-scrim").hidden = false;
        byId("nav-close").focus();
    }

    function closeNavigation(returnFocus = false) {
        document.body.classList.remove("nav-opened");
        byId("nav-open").setAttribute("aria-expanded", "false");
        byId("nav-scrim").hidden = true;
        if (returnFocus && window.matchMedia("(max-width: 860px)").matches) {
            byId("nav-open").focus();
        }
    }

    async function activateRoute(route, focusHeading = true) {
        let resolved = Object.prototype.hasOwnProperty.call(VIEW_TITLES, route) ? route : "dashboard";
        if (resolved === "administration" && !state.session?.administrator) {
            resolved = "dashboard";
            if (location.hash !== "#dashboard") {
                history.replaceState(null, "", "#dashboard");
            }
            toast("Administrator role required", `Administration is shown only for ${ADMIN_ROLE}.`, "error");
        }
        if (state.currentRoute === "administration" && resolved !== "administration") {
            clearCredentials("Credential display cleared when leaving Administration.");
        }
        state.currentRoute = resolved;
        all("[data-view]").forEach((view) => {
            view.hidden = view.dataset.view !== resolved;
        });
        all("[data-view-target]").forEach((link) => {
            if (link.dataset.viewTarget === resolved) {
                link.setAttribute("aria-current", "page");
            } else {
                link.removeAttribute("aria-current");
            }
        });
        byId("current-view-title").textContent = VIEW_TITLES[resolved];
        document.title = `${VIEW_TITLES[resolved]} · AgentHarness`;
        closeNavigation(false);

        switch (resolved) {
            case "dashboard":
                await loadDashboard();
                break;
            case "samples":
                await loadSamples();
                break;
            case "builder-register":
            case "builder-extend":
            case "builder-validate":
            case "builder-operate":
                await loadBuilderView();
                break;
            case "code":
                await loadCodeView();
                break;
            case "governance":
                await loadGovernance();
                break;
            case "administration":
                await loadAdministration();
                break;
            default:
                break;
        }

        if (focusHeading) {
            const view = all("[data-view]").find((candidate) => candidate.dataset.view === resolved);
            const heading = view?.querySelector("h1");
            if (heading) {
                heading.focus({ preventScroll: true });
            }
            window.scrollTo({ top: 0, behavior: "auto" });
        }
    }

    async function logout() {
        const button = byId("logout-button");
        setBusy(button, true, "Signing out");
        clearCredentials("");
        try {
            await api("/api/logout", { method: "POST", body: {} });
            csrfToken = null;
            const session = await api("/api/session");
            state.session = session;
            showSignedOut(session);
        } catch (error) {
            if (error instanceof ApiError && error.status === 401) {
                csrfToken = null;
                const session = await api("/api/session");
                state.session = session;
                showSignedOut(session);
            } else {
                toast("Sign-out failed", friendlyError(error), "error");
            }
        } finally {
            setBusy(button, false);
        }
    }

    function bindEvents() {
        byId("nav-open").addEventListener("click", openNavigation);
        byId("nav-close").addEventListener("click", () => closeNavigation(true));
        byId("nav-scrim").addEventListener("click", () => closeNavigation(true));
        byId("logout-button").addEventListener("click", logout);

        window.addEventListener("hashchange", () => {
            if (!state.session?.authenticated) {
                return;
            }
            activateRoute(location.hash.replace(/^#/, "") || "dashboard");
        });
        document.addEventListener("keydown", (event) => {
            if (event.key === "Escape" && document.body.classList.contains("nav-opened")) {
                closeNavigation(true);
            }
        });

        byId("sample-search").addEventListener("input", renderSamples);
        byId("sample-agent-select").addEventListener("change", (event) => setSelectedAgent(event.target.value, true));
        all("[data-agent-select]").forEach((select) => {
            select.addEventListener("change", (event) => setSelectedAgent(event.target.value, true));
        });
        byId("sample-prompt").addEventListener("input", (event) => updatePromptCount(event.target));
        byId("operate-prompt").addEventListener("input", (event) => updatePromptCount(event.target));
        byId("sample-prompt-reset").addEventListener("click", () => {
            setPromptValue(byId("sample-prompt"), promptForAgent(selectedAgent()));
        });
        byId("operate-prompt-reset").addEventListener("click", () => {
            setPromptValue(byId("operate-prompt"), promptForAgent(selectedAgent()));
        });
        byId("sample-run-form").addEventListener("submit", (event) => {
            event.preventDefault();
            runAgent(event.currentTarget, byId("sample-run-result"));
        });
        byId("operate-run-form").addEventListener("submit", (event) => {
            event.preventDefault();
            runAgent(event.currentTarget, byId("operate-run-result"));
        });

        byId("register-agent-button").addEventListener("click", registerSelectedAgent);
        byId("validate-agent-button").addEventListener("click", validateSelectedAgent);
        byId("extend-agent-form").addEventListener("submit", extendSelectedAgent);
        byId("new-agent-form").addEventListener("submit", createAgent);
        byId("schedule-form").addEventListener("submit", saveSchedule);
        byId("agent-state-button").addEventListener("click", changeSelectedAgentState);
        all(".refresh-evidence").forEach((button) => {
            button.addEventListener("click", () => loadSelectedEvidence(true));
        });

        byId("gateway-form").addEventListener("submit", invokeGateway);

        byId("source-search").addEventListener("input", renderSourceList);
        byId("copy-source-button").addEventListener("click", copySource);

        byId("refresh-governance").addEventListener("click", (event) => {
            setBusy(event.currentTarget, true, "Refreshing");
            loadGovernance(true).finally(() => setBusy(event.currentTarget, false));
        });

        byId("assignment-application").addEventListener("change", () => {
            clearDirectorySelection();
            populateRoleOptions();
            loadAssignments();
        });
        byId("directory-search-form").addEventListener("submit", searchDirectory);
        byId("assign-role-button").addEventListener("click", assignSelectedRole);
        byId("refresh-assignments").addEventListener("click", loadAssignments);
        byId("refresh-audit").addEventListener("click", loadAudit);

        byId("reveal-credentials").addEventListener("click", revealCredentials);
        byId("clear-credentials").addEventListener("click", () => clearCredentials("Credentials were cleared by explicit user action."));
        byId("copy-credential-username").addEventListener("click", () => copyCredential("credential-username", "Username"));
        byId("copy-credential-password").addEventListener("click", () => copyCredential("credential-password", "Password"));

        document.addEventListener("visibilitychange", () => {
            if (document.hidden && !byId("credential-display").hidden) {
                clearCredentials("Credential display cleared because the page was hidden.");
            } else {
                updateCredentialCountdown();
            }
        });

        if (!navigator.clipboard || !window.isSecureContext) {
            byId("copy-source-button").disabled = true;
            byId("copy-credential-username").disabled = true;
            byId("copy-credential-password").disabled = true;
            byId("copy-source-button").title = "Clipboard API requires a supported secure browser context.";
            byId("copy-credential-username").title = "Clipboard API requires a supported secure browser context.";
            byId("copy-credential-password").title = "Clipboard API requires a supported secure browser context.";
        }
    }

    async function initializeSession() {
        try {
            const session = await api("/api/session");
            if (!session || typeof session !== "object") {
                throw new ApiError(500, "The session endpoint did not return an object.");
            }
            state.session = session;
            byId("boot-screen").setAttribute("aria-busy", "false");
            if (session.authenticated) {
                showAuthenticatedApp();
            } else {
                showSignedOut(session);
            }
        } catch (error) {
            showSessionLoadError(error);
        }
    }

    function initialize() {
        bindEvents();
        updatePromptCount(byId("sample-prompt"));
        updatePromptCount(byId("operate-prompt"));
        populateRoleOptions();
        initializeSession();
    }

    initialize();
})();
