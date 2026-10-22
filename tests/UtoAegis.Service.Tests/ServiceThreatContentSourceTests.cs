using UtoAegis.Infrastructure.ThreatIntelligence;

namespace UtoAegis.Service.Tests;

[TestClass]
public sealed class ServiceThreatContentSourceTests
{
    [TestMethod]
    public async Task GetStatusAsync_ExclusiveUpdateLock_UsesReadOnlyStorePath()
    {
        var storePath = Path.Combine(
            Path.GetTempPath(),
            "UtoAegis.Service.Tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(storePath, "versions"));

        try
        {
            await File.WriteAllTextAsync(
                Path.Combine(storePath, ThreatContentStore.StateFileName),
                """
                {
                  "schemaVersion": 1,
                  "active": {
                    "directoryName": "00000000000000000007-2026.10.7",
                    "sequence": 7,
                    "version": "2026.10.7"
                  },
                  "previous": null,
                  "highestAcceptedSequence": 7
                }
                """);
            var lockPath = Path.Combine(storePath, "update.lock");
            await File.WriteAllBytesAsync(lockPath, []);
            using var updateLock = new FileStream(
                lockPath,
                FileMode.Open,
                FileAccess.ReadWrite,
                FileShare.None);
            var source = new ServiceThreatContentSource(
                new ThreatContentStore(storePath));

            var status = await source.GetStatusAsync();

            Assert.IsTrue(status.HasActiveContent);
            Assert.AreEqual("2026.10.7", status.ActiveVersion);
            Assert.AreEqual(7L, status.ActiveSequence);
        }
        finally
        {
            if (Directory.Exists(storePath))
            {
                Directory.Delete(storePath, recursive: true);
            }
        }
    }
}
