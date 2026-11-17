using Microsoft.Data.Sqlite;
using UtoAegis.Core.Management;
using UtoAegis.Infrastructure.Management;

namespace UtoAegis.Infrastructure.Tests;

[TestClass]
public sealed class SqliteEnrollmentBootstrapStoreTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 11, 17, 18, 0, 0, TimeSpan.Zero);

    private string testDirectory = null!;
    private string databasePath = null!;

    [TestInitialize]
    public void Initialize()
    {
        testDirectory = Path.Combine(
            Path.GetTempPath(),
            "UtoAegis.EnrollmentBootstrap.Tests",
            Guid.NewGuid().ToString("N"));
        databasePath = Path.Combine(testDirectory, "enrollment.db");
    }

    [TestCleanup]
    public void Cleanup()
    {
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(testDirectory))
        {
            Directory.Delete(testDirectory, recursive: true);
        }
    }

    [TestMethod]
    public async Task InitializeAsync_NewDatabase_CreatesStrictSchema()
    {
        var store = CreateStore();

        await store.InitializeAsync();

        await using var connection = new SqliteConnection($"Data Source={databasePath}");
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA user_version;";
        Assert.AreEqual(1L, (long)(await command.ExecuteScalarAsync())!);
    }

    [TestMethod]
    public async Task InitializeAsync_WrongStoreIdentity_RejectsDatabase()
    {
        Directory.CreateDirectory(testDirectory);
        await using (var connection = new SqliteConnection($"Data Source={databasePath}"))
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText =
                """
                CREATE TABLE enrollment_store_metadata (
                    store_identity TEXT PRIMARY KEY NOT NULL,
                    schema_version INTEGER NOT NULL
                ) STRICT;
                INSERT INTO enrollment_store_metadata (store_identity, schema_version)
                VALUES ('different-product', 1);
                PRAGMA user_version = 1;
                """;
            await command.ExecuteNonQueryAsync();
        }

        var exception = await Assert.ThrowsExactlyAsync<DeviceManagementException>(
            async () => await CreateStore().InitializeAsync());

        StringAssert.Contains(exception.Message, "identity");
    }

    [TestMethod]
    public async Task ConsumeAsync_IssuedToken_ReturnsAssignedRingOnce()
    {
        var store = await CreateInitializedStoreAsync();
        using var token = EnrollmentBootstrapToken.Generate();
        await store.IssueAsync(token, new RolloutRing("canary"), Now, Now.AddHours(1));

        var first = await store.ConsumeAsync(token, new string('a', 32), Now.AddMinutes(1));
        var second = await store.ConsumeAsync(token, new string('b', 32), Now.AddMinutes(2));

        Assert.IsNotNull(first);
        Assert.AreEqual("canary", first.RolloutRing.Value);
        Assert.AreEqual(new string('a', 32), first.DeviceId);
        Assert.IsNull(second);
    }

    [TestMethod]
    public async Task ConsumeAsync_ExpiredToken_ReturnsNoAdmission()
    {
        var store = await CreateInitializedStoreAsync();
        using var token = EnrollmentBootstrapToken.Generate();
        await store.IssueAsync(token, new RolloutRing("pilot"), Now, Now.AddMinutes(5));

        var result = await store.ConsumeAsync(token, new string('a', 32), Now.AddMinutes(5));

        Assert.IsNull(result);
    }

    [TestMethod]
    public async Task ConsumeAsync_ConcurrentRequests_AdmitsExactlyOneDevice()
    {
        var store = await CreateInitializedStoreAsync();
        using var token = EnrollmentBootstrapToken.Generate();
        await store.IssueAsync(token, new RolloutRing("stable"), Now, Now.AddHours(1));

        var attempts = await Task.WhenAll(
            store.ConsumeAsync(token, new string('a', 32), Now.AddMinutes(1)).AsTask(),
            store.ConsumeAsync(token, new string('b', 32), Now.AddMinutes(1)).AsTask());

        Assert.HasCount(1, attempts.Where(result => result is not null));
    }

    [TestMethod]
    public async Task IssueAsync_DatabaseContainsHashButNotSecret()
    {
        var store = await CreateInitializedStoreAsync();
        using var token = EnrollmentBootstrapToken.Generate();
        var secret = token.Reveal();
        await store.IssueAsync(token, new RolloutRing("canary"), Now, Now.AddHours(1));

        var databaseBytes = await File.ReadAllBytesAsync(databasePath);
        var databaseText = System.Text.Encoding.UTF8.GetString(databaseBytes);

        Assert.IsFalse(databaseText.Contains(secret, StringComparison.Ordinal));
        Assert.IsTrue(databaseText.Contains(token.ComputeSha256(), StringComparison.Ordinal));
    }

    [TestMethod]
    public async Task IssueAsync_ValidityOverSevenDays_RejectsToken()
    {
        var store = await CreateInitializedStoreAsync();
        using var token = EnrollmentBootstrapToken.Generate();

        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
            await store.IssueAsync(token, new RolloutRing("canary"), Now, Now.AddDays(8)));
    }

    private SqliteEnrollmentBootstrapStore CreateStore() => new(databasePath);

    private async Task<SqliteEnrollmentBootstrapStore> CreateInitializedStoreAsync()
    {
        var store = CreateStore();
        await store.InitializeAsync();
        return store;
    }
}
