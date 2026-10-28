// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using Microsoft.Agents.Core.Serialization;
using Microsoft.Agents.Storage;
using Microsoft.Data.Sqlite;

namespace AgentHarness;

public sealed class SqliteAgentStorage : IStorage
{
    private readonly string _connectionString;

    public SqliteAgentStorage(IConfiguration configuration)
    {
        var directory = configuration["Data:Path"] ?? Path.Combine(AppContext.BaseDirectory, "data");
        Directory.CreateDirectory(directory);
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = Path.Combine(directory, "channel-state.db"),
            Mode = SqliteOpenMode.ReadWriteCreate, DefaultTimeout = 30, Pooling = false
        }.ToString();
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, payload TEXT NOT NULL, etag TEXT NOT NULL)";
        command.ExecuteNonQuery();
    }

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(_connectionString);
        connection.Open();
        return connection;
    }

    public Task<IDictionary<string, object>> ReadAsync(string[] keys, CancellationToken cancellationToken = default) =>
        ReadAsync<object>(keys, cancellationToken);

    public async Task<IDictionary<string, TStoreItem>> ReadAsync<TStoreItem>(string[] keys, CancellationToken cancellationToken = default) where TStoreItem : class
    {
        var result = new Dictionary<string, TStoreItem>();
        using var connection = Open();
        foreach (var key in keys)
        {
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT payload FROM state WHERE key = $key";
            command.Parameters.AddWithValue("$key", key);
            if (await command.ExecuteScalarAsync(cancellationToken) is string payload)
            {
                using var document = JsonDocument.Parse(payload);
                result[key] = ProtocolJsonSerializer.ToObject<TStoreItem>(document.RootElement)!;
            }
        }
        return result;
    }

    public Task WriteAsync(IDictionary<string, object> changes, CancellationToken cancellationToken = default) =>
        WriteAsync<object>(changes, cancellationToken);

    public async Task WriteAsync<TStoreItem>(IDictionary<string, TStoreItem> changes, CancellationToken cancellationToken = default) where TStoreItem : class
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction();
        foreach (var (key, value) in changes)
        {
            if (value is null) throw new ArgumentException("Agent state cannot be null.", nameof(changes));
            using var read = connection.CreateCommand();
            read.Transaction = transaction;
            read.CommandText = "SELECT etag FROM state WHERE key = $key";
            read.Parameters.AddWithValue("$key", key);
            var existing = await read.ExecuteScalarAsync(cancellationToken) as string;
            var previousTag = value is IStoreItem item ? item.ETag : null;
            if (existing is not null && !string.IsNullOrEmpty(previousTag) && previousTag != "*" && previousTag != existing)
                throw new InvalidOperationException("Agent state ETag conflict.");
            var etag = Guid.NewGuid().ToString("N");
            if (value is IStoreItem tagged) tagged.ETag = etag;
            using var write = connection.CreateCommand();
            write.Transaction = transaction;
            write.CommandText = "INSERT INTO state(key,payload,etag) VALUES($key,$payload,$etag) ON CONFLICT(key) DO UPDATE SET payload=excluded.payload,etag=excluded.etag";
            write.Parameters.AddWithValue("$key", key);
            write.Parameters.AddWithValue("$payload", JsonSerializer.Serialize(value, value.GetType()));
            write.Parameters.AddWithValue("$etag", etag);
            await write.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
    }

    public async Task DeleteAsync(string[] keys, CancellationToken cancellationToken = default)
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction();
        foreach (var key in keys)
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = "DELETE FROM state WHERE key=$key";
            command.Parameters.AddWithValue("$key", key);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
    }
}
