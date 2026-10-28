// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Agents.Storage;
using Microsoft.Extensions.Configuration;
using AgentHarness;

namespace AgentHarness.Tests;

public sealed class SqliteAgentStorageTests
{
    [Fact]
    public async Task Typed_store_item_round_trips_across_new_storage_instance()
    {
        using var data = new TestDataDirectory();
        var firstStorage = CreateStorage(data.DirectoryPath);
        var original = new TestChannelState
        {
            ConversationId = "conversation-1",
            Sequence = 7,
            Protected = true
        };

        await firstStorage.WriteAsync(new Dictionary<string, TestChannelState>
        {
            ["channel/conversation-1"] = original
        });
        var persistedEtag = original.ETag;

        var restartedStorage = CreateStorage(data.DirectoryPath);
        var values = await restartedStorage.ReadAsync<TestChannelState>(["channel/conversation-1"]);

        Assert.True(values.TryGetValue("channel/conversation-1", out var restored));
        Assert.Equal("conversation-1", restored.ConversationId);
        Assert.Equal(7, restored.Sequence);
        Assert.True(restored.Protected);
        Assert.False(string.IsNullOrWhiteSpace(persistedEtag));
        Assert.Equal(persistedEtag, restored.ETag);
    }

    [Fact]
    public async Task Etag_conflict_rejects_update_without_overwriting_current_value()
    {
        using var data = new TestDataDirectory();
        var storage = CreateStorage(data.DirectoryPath);
        var original = new TestChannelState { ConversationId = "conversation-1", Sequence = 1 };
        await storage.WriteAsync(new Dictionary<string, TestChannelState> { ["state"] = original });
        var staleEtag = original.ETag;
        var current = new TestChannelState
        {
            ConversationId = "conversation-1",
            Sequence = 2,
            ETag = staleEtag
        };
        await storage.WriteAsync(new Dictionary<string, TestChannelState> { ["state"] = current });
        var currentEtag = current.ETag;
        var stale = new TestChannelState
        {
            ConversationId = "conversation-1",
            Sequence = 99,
            ETag = staleEtag
        };

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            storage.WriteAsync(new Dictionary<string, TestChannelState> { ["state"] = stale }));

        var restartedStorage = CreateStorage(data.DirectoryPath);
        var restored = (await restartedStorage.ReadAsync<TestChannelState>(["state"]))["state"];
        Assert.Equal(2, restored.Sequence);
        Assert.Equal(currentEtag, restored.ETag);
        Assert.NotEqual(stale.ETag, restored.ETag);
    }

    [Fact]
    public async Task Multi_key_write_rolls_back_earlier_update_when_later_item_conflicts()
    {
        using var data = new TestDataDirectory();
        var storage = CreateStorage(data.DirectoryPath);
        var first = new TestChannelState { ConversationId = "first", Sequence = 1 };
        var second = new TestChannelState { ConversationId = "second", Sequence = 1 };
        await storage.WriteAsync(new Dictionary<string, TestChannelState>
        {
            ["first"] = first,
            ["second"] = second
        });
        var firstEtag = first.ETag;
        var staleSecondEtag = second.ETag;
        var currentSecond = new TestChannelState
        {
            ConversationId = "second",
            Sequence = 2,
            ETag = staleSecondEtag
        };
        await storage.WriteAsync(new Dictionary<string, TestChannelState> { ["second"] = currentSecond });
        var currentSecondEtag = currentSecond.ETag;
        var proposedFirst = new TestChannelState
        {
            ConversationId = "first",
            Sequence = 10,
            ETag = firstEtag
        };
        var staleSecond = new TestChannelState
        {
            ConversationId = "second",
            Sequence = 99,
            ETag = staleSecondEtag
        };

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            storage.WriteAsync(new Dictionary<string, TestChannelState>
            {
                ["first"] = proposedFirst,
                ["second"] = staleSecond
            }));

        var restartedStorage = CreateStorage(data.DirectoryPath);
        var restored = await restartedStorage.ReadAsync<TestChannelState>(["first", "second"]);
        Assert.Equal(1, restored["first"].Sequence);
        Assert.Equal(firstEtag, restored["first"].ETag);
        Assert.Equal(2, restored["second"].Sequence);
        Assert.Equal(currentSecondEtag, restored["second"].ETag);
    }

    private static SqliteAgentStorage CreateStorage(string dataPath)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Data:Path"] = dataPath
        }).Build();
        return new SqliteAgentStorage(configuration);
    }
}

public sealed class TestChannelState : IStoreItem
{
    public string ETag { get; set; } = "";
    public string ConversationId { get; set; } = "";
    public int Sequence { get; set; }
    public bool Protected { get; set; }
}
