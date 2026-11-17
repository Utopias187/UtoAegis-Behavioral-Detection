using System.Security.Cryptography;
using System.Text;
using UtoAegis.Core.Management;
using UtoAegis.Infrastructure.Management;

namespace UtoAegis.Infrastructure.Tests;

[TestClass]
public sealed class DeviceManagementTests
{
    private string testDirectory = null!;
    private ECDsa signingKey = null!;
    private DeviceIdentityState identity = null!;

    [TestInitialize]
    public void Initialize()
    {
        testDirectory = Path.Combine(
            Path.GetTempPath(),
            "UtoAegis.DeviceManagement.Tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(testDirectory);
        signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        identity = new DeviceIdentityState(
            Guid.NewGuid().ToString("N"),
            "UtoAegis.Device.Test",
            Convert.ToHexString(
                SHA256.HashData(signingKey.ExportSubjectPublicKeyInfo())).ToLowerInvariant(),
            new DateTimeOffset(2026, 11, 17, 12, 0, 0, TimeSpan.Zero));
    }

    [TestCleanup]
    public void Cleanup()
    {
        signingKey.Dispose();
        if (Directory.Exists(testDirectory))
        {
            Directory.Delete(testDirectory, recursive: true);
        }
    }

    [TestMethod]
    public void SignAndVerify_ExactRequest_AcceptsSignature()
    {
        var body = Encoding.UTF8.GetBytes("{\"sequence\":17}");
        var request = CreateSigner().Sign(
            "enrollment-1",
            3,
            new DateTimeOffset(2026, 11, 17, 12, 30, 0, TimeSpan.Zero),
            new string('a', 32),
            "POST",
            "/v1/device/policy?current=16",
            body);

        using var publicKey = ECDsa.Create();
        publicKey.ImportSubjectPublicKeyInfo(signingKey.ExportSubjectPublicKeyInfo(), out _);
        var verifier = new DeviceRequestSignatureVerifier(publicKey);

        Assert.IsTrue(verifier.Verify(
            request,
            "POST",
            "/v1/device/policy?current=16",
            body));
    }

    [TestMethod]
    public void Verify_ChangedBody_RejectsSignature()
    {
        var request = CreateRequest(Encoding.UTF8.GetBytes("original"));
        using var publicKey = ECDsa.Create();
        publicKey.ImportSubjectPublicKeyInfo(signingKey.ExportSubjectPublicKeyInfo(), out _);

        Assert.IsFalse(new DeviceRequestSignatureVerifier(publicKey).Verify(
            request,
            "POST",
            "/v1/device/policy",
            Encoding.UTF8.GetBytes("changed")));
    }

    [TestMethod]
    public void Verify_ChangedTarget_RejectsSignature()
    {
        var request = CreateRequest([]);
        using var publicKey = ECDsa.Create();
        publicKey.ImportSubjectPublicKeyInfo(signingKey.ExportSubjectPublicKeyInfo(), out _);

        Assert.IsFalse(new DeviceRequestSignatureVerifier(publicKey).Verify(
            request,
            "POST",
            "/v1/device/acknowledgement",
            []));
    }

    [TestMethod]
    public void Sign_FingerprintMismatch_RejectsIdentity()
    {
        var changed = new DeviceIdentityState(
            identity.DeviceId,
            identity.KeyName,
            new string('f', 64),
            identity.CreatedUtc);

        Assert.ThrowsExactly<ArgumentException>(() =>
            new DeviceRequestSigner(signingKey, changed));
    }

    [TestMethod]
    public async Task CreateOrLoadAsync_SameIdentity_ReturnsPersistedState()
    {
        var store = CreateStore();

        await store.CreateOrLoadAsync(identity);
        var loaded = await store.CreateOrLoadAsync(identity);

        Assert.AreEqual(identity, loaded);
    }

    [TestMethod]
    public async Task CreateOrLoadAsync_ChangedIdentity_RejectsReplacement()
    {
        var store = CreateStore();
        await store.CreateOrLoadAsync(identity);
        var changed = new DeviceIdentityState(
            Guid.NewGuid().ToString("N"),
            identity.KeyName,
            identity.PublicKeySha256,
            identity.CreatedUtc);

        var exception = await Assert.ThrowsExactlyAsync<DeviceManagementException>(
            async () => await store.CreateOrLoadAsync(changed));

        StringAssert.Contains(exception.Message, "conflicts");
    }

    [TestMethod]
    public async Task LoadAsync_UnknownProperty_RejectsState()
    {
        var path = GetStatePath();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        await File.WriteAllTextAsync(
            path,
            "{\"schemaVersion\":1,\"deviceId\":\"" + identity.DeviceId +
            "\",\"keyName\":\"UtoAegis.Device.Test\",\"publicKeySha256\":\"" +
            identity.PublicKeySha256 +
            "\",\"createdUtc\":\"2026-11-17T12:00:00Z\",\"unexpected\":true}");

        await Assert.ThrowsExactlyAsync<DeviceManagementException>(
            async () => await CreateStore().LoadAsync());
    }

    [TestMethod]
    public async Task LoadAsync_DuplicateProperty_RejectsState()
    {
        var path = GetStatePath();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        await File.WriteAllTextAsync(
            path,
            "{\"schemaVersion\":1,\"schemaVersion\":1,\"deviceId\":\"" + identity.DeviceId +
            "\",\"keyName\":\"UtoAegis.Device.Test\",\"publicKeySha256\":\"" +
            identity.PublicKeySha256 +
            "\",\"createdUtc\":\"2026-11-17T12:00:00Z\"}");

        var exception = await Assert.ThrowsExactlyAsync<DeviceManagementException>(
            async () => await CreateStore().LoadAsync());

        StringAssert.Contains(exception.Message, "Duplicate JSON property");
    }

    [TestMethod]
    public async Task RetireAndRestoreAsync_ExactIdentity_RoundTripsState()
    {
        var store = CreateStore();
        await store.CreateOrLoadAsync(identity);
        var archive = Path.Combine(testDirectory, "archive", "identity.json");

        var retired = await store.RetireAsync(identity.DeviceId, archive);
        Assert.IsNull(await store.LoadAsync());
        await store.RestoreRetiredAsync(archive, identity.DeviceId);

        Assert.AreEqual(identity, retired);
        Assert.AreEqual(identity, await store.LoadAsync());
        Assert.IsFalse(File.Exists(archive));
    }

    [TestMethod]
    public async Task RetireAsync_DifferentDevice_LeavesStateActive()
    {
        var store = CreateStore();
        await store.CreateOrLoadAsync(identity);

        await Assert.ThrowsExactlyAsync<DeviceManagementException>(
            async () => await store.RetireAsync(
                new string('f', 32),
                Path.Combine(testDirectory, "archive", "identity.json")));

        Assert.AreEqual(identity, await store.LoadAsync());
    }

    private DeviceRequestSigner CreateSigner() => new(signingKey, identity);

    private SignedDeviceRequest CreateRequest(byte[] body) =>
        CreateSigner().Sign(
            "enrollment-1",
            3,
            new DateTimeOffset(2026, 11, 17, 12, 30, 0, TimeSpan.Zero),
            new string('a', 32),
            "POST",
            "/v1/device/policy",
            body);

    private DeviceIdentityStateStore CreateStore() => new(GetStatePath());

    private string GetStatePath() => Path.Combine(testDirectory, "state", "identity.json");
}
