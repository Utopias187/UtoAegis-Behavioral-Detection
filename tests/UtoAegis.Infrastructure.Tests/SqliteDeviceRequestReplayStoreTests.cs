using Microsoft.Data.Sqlite;
using UtoAegis.Infrastructure.Management;

namespace UtoAegis.Infrastructure.Tests;

[TestClass]
public sealed class SqliteDeviceRequestReplayStoreTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 11, 17, 22, 0, 0, TimeSpan.Zero);

    private string testDirectory = null!;
    private string databasePath = null!;

    [TestInitialize]
    public void Initialize()
    {
        testDirectory = Path.Combine(Path.GetTempPath(), "UtoAegis.Replay.Tests", Guid.NewGuid().ToString("N"));
        databasePath = Path.Combine(testDirectory, "replay.db");
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
    public async Task TryReserveAsync_SameNonceTwice_RejectsReplay()
    {
        var store = await CreateStoreAsync();

        Assert.IsTrue(await store.TryReserveAsync(new string('a', 32), new string('b', 32), Now, TimeSpan.FromMinutes(10)));
        Assert.IsFalse(await store.TryReserveAsync(new string('a', 32), new string('b', 32), Now.AddSeconds(1), TimeSpan.FromMinutes(10)));
    }

    [TestMethod]
    public async Task TryReserveAsync_SameNonceDifferentDevice_AllowsReservation()
    {
        var store = await CreateStoreAsync();

        Assert.IsTrue(await store.TryReserveAsync(new string('a', 32), new string('c', 32), Now, TimeSpan.FromMinutes(10)));
        Assert.IsTrue(await store.TryReserveAsync(new string('b', 32), new string('c', 32), Now, TimeSpan.FromMinutes(10)));
    }

    [TestMethod]
    public async Task TryReserveAsync_ExpiredReservation_AllowsReuse()
    {
        var store = await CreateStoreAsync();
        await store.TryReserveAsync(new string('a', 32), new string('d', 32), Now, TimeSpan.FromMinutes(1));

        Assert.IsTrue(await store.TryReserveAsync(new string('a', 32), new string('d', 32), Now.AddMinutes(1), TimeSpan.FromMinutes(1)));
    }

    [TestMethod]
    public async Task TryReserveAsync_ConcurrentRequests_AcceptsExactlyOne()
    {
        var store = await CreateStoreAsync();
        var results = await Task.WhenAll(
            store.TryReserveAsync(new string('a', 32), new string('e', 32), Now, TimeSpan.FromMinutes(10)).AsTask(),
            store.TryReserveAsync(new string('a', 32), new string('e', 32), Now, TimeSpan.FromMinutes(10)).AsTask());

        Assert.HasCount(1, results.Where(result => result));
    }

    private async Task<SqliteDeviceRequestReplayStore> CreateStoreAsync()
    {
        var store = new SqliteDeviceRequestReplayStore(databasePath);
        await store.InitializeAsync();
        return store;
    }
}
