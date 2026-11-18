using Microsoft.Data.Sqlite;
using UtoAegis.Core.Behavior;
using UtoAegis.Core.History;
using UtoAegis.Core.RiskScoring;
using UtoAegis.Infrastructure.History;

namespace UtoAegis.Infrastructure.Tests;

[TestClass]
public sealed class SqliteBehaviorHistoryStoreTests
{
    private string directory = null!;
    private string databasePath = null!;

    [TestInitialize]
    public void InitializeDirectory()
    {
        directory = Path.Combine(Path.GetTempPath(), "UtoAegis.Tests", Guid.NewGuid().ToString("N"));
        databasePath = Path.Combine(directory, "behavior.db");
    }

    [TestCleanup]
    public void Cleanup()
    {
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(directory))
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [TestMethod]
    public async Task InitializeAsync_NewDatabase_CreatesOwnedSchema()
    {
        var store = new SqliteBehaviorHistoryStore(databasePath);
        await store.InitializeAsync();

        await using var connection = new SqliteConnection($"Data Source={databasePath}");
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA user_version;";
        Assert.AreEqual(1L, await command.ExecuteScalarAsync());
        command.CommandText = "PRAGMA application_id;";
        Assert.AreEqual((long)SqliteBehaviorHistoryStore.ApplicationId, await command.ExecuteScalarAsync());
    }

    [TestMethod]
    public async Task AppendAndListAsync_PreservesBoundedSummary()
    {
        var store = new SqliteBehaviorHistoryStore(databasePath);
        await store.InitializeAsync();
        var expected = Record();

        await store.AppendAsync(expected);
        var records = await store.ListAsync(10);

        Assert.HasCount(1, records);
        Assert.AreEqual(expected.Id, records[0].Id);
        Assert.AreEqual(RiskVerdict.Review, records[0].Verdict);
        CollectionAssert.AreEqual(expected.FeatureIds.ToArray(), records[0].FeatureIds.ToArray());
        CollectionAssert.AreEqual(expected.Categories.ToArray(), records[0].Categories.ToArray());
    }

    [TestMethod]
    public async Task InitializeAsync_NewerSchema_IsRejected()
    {
        Directory.CreateDirectory(directory);
        await using (var connection = new SqliteConnection($"Data Source={databasePath}"))
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText =
                $"PRAGMA application_id = {SqliteBehaviorHistoryStore.ApplicationId}; PRAGMA user_version = 999;";
            await command.ExecuteNonQueryAsync();
        }

        var store = new SqliteBehaviorHistoryStore(databasePath);
        await Assert.ThrowsExactlyAsync<BehaviorHistoryStoreException>(
            async () => await store.InitializeAsync());
    }

    private static BehaviorHistoryRecord Record() => new(
        Guid.Parse("96daa8b0-a7d0-4d3e-b684-4ca387bf80c5"),
        DateTimeOffset.UnixEpoch,
        Guid.Parse("5ae079e4-486b-4312-8ea0-9439d6cad385"),
        42,
        1,
        DateTimeOffset.UnixEpoch,
        DateTimeOffset.UnixEpoch.AddSeconds(5),
        RiskVerdict.Review,
        38,
        100,
        BehaviorProviderState.Healthy,
        "utoaegis.behavior.default",
        1,
        3,
        ["behavior.persistence.public-network-chain"],
        [new BehaviorHistoryCategory(BehaviorFeatureCategory.Persistence, 30)]);
}
