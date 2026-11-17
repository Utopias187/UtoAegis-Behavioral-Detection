using System.Security.Cryptography;
using System.Runtime.Versioning;
using UtoAegis.Infrastructure.Management;

namespace UtoAegis.Infrastructure.Tests;

[TestClass]
[SupportedOSPlatform("windows")]
public sealed class WindowsDeviceIdentityKeyStoreTests
{
    private string testDirectory = null!;
    private string keyName = null!;
    private WindowsDeviceIdentityKeyStore keyStore = null!;

    [TestInitialize]
    public void Initialize()
    {
        testDirectory = Path.Combine(
            Path.GetTempPath(),
            "UtoAegis.DeviceKey.Tests",
            Guid.NewGuid().ToString("N"));
        keyName = "UtoAegis.Device.Test." + Guid.NewGuid().ToString("N");
        keyStore = new WindowsDeviceIdentityKeyStore(keyName, machineScope: false);
    }

    [TestCleanup]
    public void Cleanup()
    {
        keyStore.DeleteKey();
        if (Directory.Exists(testDirectory))
        {
            Directory.Delete(testDirectory, recursive: true);
        }
    }

    [TestMethod]
    [SupportedOSPlatform("windows")]
    public async Task CreateOrLoadAsync_NewIdentity_CreatesNonExportableP256Key()
    {
        var store = CreateStateStore();

        using var context = await keyStore.CreateOrLoadAsync(store);

        Assert.AreEqual(256, context.SigningKey.KeySize);
        Assert.AreEqual(keyName, context.Identity.KeyName);
        Assert.ThrowsExactly<CryptographicException>(() =>
            context.SigningKey.ExportPkcs8PrivateKey());
    }

    [TestMethod]
    [SupportedOSPlatform("windows")]
    public async Task CreateOrLoadAsync_ExistingIdentity_PreservesDeviceIdAndKey()
    {
        var store = CreateStateStore();
        string firstDeviceId;
        byte[] firstPublicKey;
        using (var first = await keyStore.CreateOrLoadAsync(store))
        {
            firstDeviceId = first.Identity.DeviceId;
            firstPublicKey = first.SigningKey.ExportSubjectPublicKeyInfo();
        }

        using var second = await keyStore.CreateOrLoadAsync(store);

        Assert.AreEqual(firstDeviceId, second.Identity.DeviceId);
        CollectionAssert.AreEqual(firstPublicKey, second.SigningKey.ExportSubjectPublicKeyInfo());
    }

    [TestMethod]
    [SupportedOSPlatform("windows")]
    public async Task CreateOrLoadAsync_UntrackedExistingKey_FailsClosed()
    {
        var parameters = new CngKeyCreationParameters
        {
            Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
            ExportPolicy = CngExportPolicies.None,
            KeyUsage = CngKeyUsages.Signing
        };
        using (CngKey.Create(CngAlgorithm.ECDsaP256, keyName, parameters))
        {
        }

        var exception = await Assert.ThrowsExactlyAsync<DeviceManagementException>(
            async () => await keyStore.CreateOrLoadAsync(CreateStateStore()));

        StringAssert.Contains(exception.Message, "explicit recovery");
    }

    [TestMethod]
    [SupportedOSPlatform("windows")]
    public async Task ValidateAsync_MissingState_DoesNotCreateIdentity()
    {
        var exception = await Assert.ThrowsExactlyAsync<DeviceManagementException>(
            async () => await keyStore.ValidateAsync(CreateStateStore()));

        StringAssert.Contains(exception.Message, "will not create");
        Assert.IsNull(await CreateStateStore().LoadAsync());
    }

    [TestMethod]
    [SupportedOSPlatform("windows")]
    public async Task RotateAsync_ExpectedIdentity_ArchivesAndReplacesKey()
    {
        var store = CreateStateStore();
        string oldDeviceId;
        byte[] oldPublicKey;
        using (var current = await keyStore.CreateOrLoadAsync(store))
        {
            oldDeviceId = current.Identity.DeviceId;
            oldPublicKey = current.SigningKey.ExportSubjectPublicKeyInfo();
        }

        var archive = Path.Combine(testDirectory, "archive", "retired.json");
        using var rotated = await keyStore.RotateAsync(store, oldDeviceId, archive);

        Assert.AreNotEqual(oldDeviceId, rotated.Identity.DeviceId);
        CollectionAssert.AreNotEqual(oldPublicKey, rotated.SigningKey.ExportSubjectPublicKeyInfo());
        Assert.IsTrue(File.Exists(archive));
        Assert.AreEqual(oldDeviceId, (await new DeviceIdentityStateStore(archive).LoadAsync())!.DeviceId);
    }

    [TestMethod]
    [SupportedOSPlatform("windows")]
    public async Task RemoveAsync_ExpectedIdentity_ArchivesStateAndDeletesKey()
    {
        var store = CreateStateStore();
        string deviceId;
        using (var current = await keyStore.CreateOrLoadAsync(store))
        {
            deviceId = current.Identity.DeviceId;
        }

        var archive = Path.Combine(testDirectory, "archive", "removed.json");
        var removed = await keyStore.RemoveAsync(store, deviceId, archive);

        Assert.AreEqual(deviceId, removed.DeviceId);
        Assert.IsNull(await store.LoadAsync());
        Assert.IsTrue(File.Exists(archive));
        await Assert.ThrowsExactlyAsync<DeviceManagementException>(
            async () => await keyStore.ValidateAsync(store));
    }

    private DeviceIdentityStateStore CreateStateStore() =>
        new(Path.Combine(testDirectory, "state", "identity.json"));
}
