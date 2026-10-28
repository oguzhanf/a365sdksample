// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Data.Sqlite;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSingleton<PurchaseOrderStore>();
var app = builder.Build();
app.MapGet("/healthz", () => new { status = "healthy", application = "AgentHarness internal sample API" });
app.MapGet("/purchaseorders", (PurchaseOrderStore store) => Results.Ok(new
{
    classification = "Synthetic demonstration data",
    authorization = "Enforced by Gravitee; this backend must not have public ingress",
    orders = store.Read()
}));
app.MapPost("/purchaseorders/{id}/approve", (string id, PurchaseOrderStore store) =>
    store.Approve(id) is { } order ? Results.Ok(order) : Results.NotFound());
app.Run();

public sealed record PurchaseOrder(string Id, string Supplier, decimal Amount, string Currency, string Status, string? ApprovedAt);

public sealed class PurchaseOrderStore
{
    private readonly string _connectionString;

    public PurchaseOrderStore(IConfiguration configuration)
    {
        var directory = configuration["Data:Path"] ?? Path.Combine(AppContext.BaseDirectory, "data");
        Directory.CreateDirectory(directory);
        _connectionString = new SqliteConnectionStringBuilder { DataSource = Path.Combine(directory, "purchaseorders.db"), Pooling = false }.ToString();
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS orders (id TEXT PRIMARY KEY,supplier TEXT NOT NULL,amount INTEGER NOT NULL,currency TEXT NOT NULL,status TEXT NOT NULL,approved_at TEXT);
            INSERT OR IGNORE INTO orders VALUES('PO-1001','Example Engineering',125000,'USD','Pending',NULL);
            INSERT OR IGNORE INTO orders VALUES('PO-1002','Example Operations',275000,'USD','Pending',NULL);
            """;
        command.ExecuteNonQuery();
    }

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(_connectionString);
        connection.Open();
        return connection;
    }

    public PurchaseOrder[] Read()
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT id,supplier,amount,currency,status,approved_at FROM orders ORDER BY id";
        using var reader = command.ExecuteReader();
        var orders = new List<PurchaseOrder>();
        while (reader.Read())
            orders.Add(new(reader.GetString(0), reader.GetString(1), reader.GetInt64(2) / 100m, reader.GetString(3), reader.GetString(4), reader.IsDBNull(5) ? null : reader.GetString(5)));
        return orders.ToArray();
    }

    public PurchaseOrder? Approve(string id)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "UPDATE orders SET status='Approved',approved_at=COALESCE(approved_at,$time) WHERE id=$id";
        command.Parameters.AddWithValue("$id", id);
        command.Parameters.AddWithValue("$time", DateTimeOffset.UtcNow.ToString("O"));
        return command.ExecuteNonQuery() == 0 ? null : Read().Single(x => x.Id == id);
    }
}
