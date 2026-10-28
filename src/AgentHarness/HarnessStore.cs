// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace AgentHarness;

public sealed class HarnessStore
{
    private readonly string connectionString;
    private readonly string _directory;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public HarnessStore(IConfiguration configuration)
    {
        var directory = configuration["Data:Path"] ?? Path.Combine(AppContext.BaseDirectory, "data");
        _directory = directory;
        Directory.CreateDirectory(directory);
        connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = Path.Combine(directory, "harness.db"),
            Mode = SqliteOpenMode.ReadWriteCreate,
            DefaultTimeout = 30,
            Pooling = false
        }.ToString();
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS agents (id TEXT PRIMARY KEY, document TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS evidence (id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, document TEXT NOT NULL, observed_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS audit (id TEXT PRIMARY KEY, document TEXT NOT NULL, recorded_at TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS ix_evidence_agent ON evidence(agent_id, observed_at);
            """;
        command.ExecuteNonQuery();
    }

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(connectionString);
        connection.Open();
        return connection;
    }

    public AgentRecord? GetAgent(string id)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT document FROM agents WHERE id = $id";
        command.Parameters.AddWithValue("$id", id);
        return command.ExecuteScalar() is string json ? JsonSerializer.Deserialize<AgentRecord>(json, Json) : null;
    }

    public IReadOnlyList<AgentRecord> GetAgents() => Read<AgentRecord>("SELECT document FROM agents ORDER BY rowid DESC");

    public void SaveAgent(AgentRecord agent)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "INSERT INTO agents(id, document) VALUES ($id, $document) ON CONFLICT(id) DO UPDATE SET document = excluded.document";
        command.Parameters.AddWithValue("$id", agent.Id);
        command.Parameters.AddWithValue("$document", JsonSerializer.Serialize(agent, Json));
        command.ExecuteNonQuery();
    }

    public void AddEvidence(string agentId, string stage, string state, string summary, string? checkId = null)
    {
        var evidence = new Evidence(Guid.NewGuid().ToString(), agentId, stage, state, summary, DateTimeOffset.UtcNow,
            System.Diagnostics.Activity.Current?.TraceId.ToString(), checkId);
        Insert("evidence", evidence.Id, JsonSerializer.Serialize(evidence, Json), evidence.ObservedAt, agentId);
    }

    public IReadOnlyList<Evidence> GetEvidence(string agentId) =>
        Read<Evidence>("SELECT document FROM evidence WHERE agent_id = $id ORDER BY observed_at DESC LIMIT 100", agentId);

    public void Audit(string actorId, string action, string target, string outcome)
    {
        var entry = new AuditEvent(Guid.NewGuid().ToString(), actorId, action, target, outcome, DateTimeOffset.UtcNow,
            System.Diagnostics.Activity.Current?.TraceId.ToString());
        Insert("audit", entry.Id, JsonSerializer.Serialize(entry, Json), entry.Timestamp);
    }

    public IReadOnlyList<AuditEvent> GetAudit() => Read<AuditEvent>("SELECT document FROM audit ORDER BY recorded_at DESC LIMIT 100");

    public void ExportCatalog() =>
        File.WriteAllText(Path.Combine(_directory, "agent-catalog.json"), JsonSerializer.Serialize(GetAgents(), Json));

    private void Insert(string table, string id, string document, DateTimeOffset timestamp, string? agentId = null)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = table == "evidence"
            ? "INSERT INTO evidence(id, agent_id, document, observed_at) VALUES($id, $agent, $document, $time)"
            : "INSERT INTO audit(id, document, recorded_at) VALUES($id, $document, $time)";
        command.Parameters.AddWithValue("$id", id);
        command.Parameters.AddWithValue("$document", document);
        command.Parameters.AddWithValue("$time", timestamp.ToString("O"));
        if (agentId is not null) command.Parameters.AddWithValue("$agent", agentId);
        command.ExecuteNonQuery();
    }

    private List<T> Read<T>(string sql, string? id = null)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        if (id is not null) command.Parameters.AddWithValue("$id", id);
        using var reader = command.ExecuteReader();
        var result = new List<T>();
        while (reader.Read()) result.Add(JsonSerializer.Deserialize<T>(reader.GetString(0), Json)!);
        return result;
    }
}
