using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using UtoAegis.Core.Management;
using UtoAegis.Infrastructure.Management;

namespace UtoAegis.Infrastructure.Tests;

[TestClass]
public sealed class DeviceRequestAdmissionCoordinatorTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 11, 17, 23, 0, 0, TimeSpan.Zero);

    private string testDirectory = null!;
    private string enrollmentDatabasePath = null!;
    private ECDsa deviceKey = null!;
    private DeviceIdentityState identity = null!;
    private SqliteEnrollmentBootstrapStore enrollmentStore = null!;
    private SqliteDeviceRequestReplayStore replayStore = null!;
    private CoordinatorDeviceEnrollment enrollment = null!;

    [TestInitialize]
    public async Task Initialize()
    {
        testDirectory = Path.Combine(
            Path.GetTempPath(),
            "UtoAegis.RequestAdmission.Tests",
            Guid.NewGuid().ToString("N"));
        enrollmentDatabasePath = Path.Combine(testDirectory, "enrollment.db");
        deviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = deviceKey.ExportSubjectPublicKeyInfo();
        identity = new DeviceIdentityState(
            Guid.NewGuid().ToString("N"),
            "UtoAegis.Device.Test",
            Convert.ToHexString(SHA256.HashData(publicKey)).ToLowerInvariant(),
            Now.AddMinutes(-1));
        enrollmentStore = new SqliteEnrollmentBootstrapStore(enrollmentDatabasePath);
        replayStore = new SqliteDeviceRequestReplayStore(
            Path.Combine(testDirectory, "replay.db"));
        await enrollmentStore.InitializeAsync();
        await replayStore.InitializeAsync();
        using var token = EnrollmentBootstrapToken.Generate();
        await enrollmentStore.IssueAsync(
            token,
            new RolloutRing("canary"),
            Now.AddMinutes(-1),
            Now.AddHours(1));
        enrollment = (await enrollmentStore.EnrollAsync(
            token,
            new VerifiedDeviceEnrollmentProof(
                identity.DeviceId,
                Convert.ToBase64String(publicKey),
                identity.PublicKeySha256,
                Now,
                new string('f', 32)),
            new Uri("https://management.example/"),
            Now,
            TimeSpan.FromDays(30)))!;
    }

    [TestCleanup]
    public void Cleanup()
    {
        deviceKey.Dispose();
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(testDirectory))
        {
            Directory.Delete(testDirectory, recursive: true);
        }
    }

    [TestMethod]
    public async Task AuthenticateAsync_ExactFreshRequest_AdmitsDevice()
    {
        var body = Encoding.UTF8.GetBytes("{\"currentPolicySequence\":17}");
        var request = CreateRequest(body, new string('a', 32));

        var authenticated = await CreateCoordinator().AuthenticateAsync(
            request,
            "POST",
            "/v1/device/policy",
            body);

        Assert.AreEqual(enrollment.EnrollmentId, authenticated.Enrollment.EnrollmentId);
        Assert.AreEqual(identity.DeviceId, authenticated.Enrollment.DeviceId);
        Assert.AreEqual(request.Payload.BodySha256, authenticated.BodySha256);
    }

    [TestMethod]
    public async Task AuthenticateAsync_ReplayedNonce_RejectsSecondRequest()
    {
        var request = CreateRequest([], new string('b', 32));
        var coordinator = CreateCoordinator();
        await coordinator.AuthenticateAsync(
            request,
            "POST",
            "/v1/device/policy",
            ReadOnlyMemory<byte>.Empty);

        var exception = await Assert.ThrowsExactlyAsync<DeviceManagementException>(
            async () => await coordinator.AuthenticateAsync(
                request,
                "POST",
                "/v1/device/policy",
                ReadOnlyMemory<byte>.Empty));

        StringAssert.Contains(exception.Message, "nonce");
    }

    [TestMethod]
    public async Task AuthenticateAsync_WrongBody_DoesNotConsumeNonce()
    {
        var body = Encoding.UTF8.GetBytes("exact");
        var request = CreateRequest(body, new string('c', 32));
        var coordinator = CreateCoordinator();
        await Assert.ThrowsExactlyAsync<DeviceManagementException>(
            async () => await coordinator.AuthenticateAsync(
                request,
                "POST",
                "/v1/device/policy",
                Encoding.UTF8.GetBytes("changed")));

        var authenticated = await coordinator.AuthenticateAsync(
            request,
            "POST",
            "/v1/device/policy",
            body);

        Assert.AreEqual(enrollment.EnrollmentId, authenticated.Enrollment.EnrollmentId);
    }

    [TestMethod]
    public async Task AuthenticateAsync_StaleTimestamp_RejectsRequest()
    {
        var request = CreateRequest(
            [],
            new string('d', 32),
            timestampUtc: Now.AddMinutes(-7));

        var exception = await Assert.ThrowsExactlyAsync<DeviceManagementException>(
            async () => await CreateCoordinator().AuthenticateAsync(
                request,
                "POST",
                "/v1/device/policy",
                ReadOnlyMemory<byte>.Empty));

        StringAssert.Contains(exception.Message, "not authorized");
    }

    [TestMethod]
    public async Task AuthenticateAsync_OldCredentialSequence_RejectsRequest()
    {
        var request = CreateRequest(
            [],
            new string('e', 32),
            credentialSequence: enrollment.CredentialSequence + 1);

        await Assert.ThrowsExactlyAsync<DeviceManagementException>(
            async () => await CreateCoordinator().AuthenticateAsync(
                request,
                "POST",
                "/v1/device/policy",
                ReadOnlyMemory<byte>.Empty));
    }

    [TestMethod]
    [DataRow("Suspended")]
    [DataRow("Revoked")]
    public async Task AuthenticateAsync_InactiveEnrollment_RejectsRequest(string status)
    {
        await SetEnrollmentStatusAsync(status);
        var request = CreateRequest([], new string('1', 32));

        await Assert.ThrowsExactlyAsync<DeviceManagementException>(
            async () => await CreateCoordinator().AuthenticateAsync(
                request,
                "POST",
                "/v1/device/policy",
                ReadOnlyMemory<byte>.Empty));
    }

    private DeviceRequestAdmissionCoordinator CreateCoordinator() =>
        new(enrollmentStore, replayStore, new FixedTimeProvider(Now));

    private SignedDeviceRequest CreateRequest(
        byte[] body,
        string nonce,
        DateTimeOffset? timestampUtc = null,
        long? credentialSequence = null) =>
        new DeviceRequestSigner(deviceKey, identity).Sign(
            enrollment.EnrollmentId,
            credentialSequence ?? enrollment.CredentialSequence,
            timestampUtc ?? Now,
            nonce,
            "POST",
            "/v1/device/policy",
            body);

    private async Task SetEnrollmentStatusAsync(string status)
    {
        await using var connection = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = enrollmentDatabasePath,
                Mode = SqliteOpenMode.ReadWrite,
                Pooling = false
            }.ToString());
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText =
            "UPDATE device_enrollments SET status = $status WHERE enrollment_id = $enrollment_id;";
        command.Parameters.AddWithValue("$status", status);
        command.Parameters.AddWithValue("$enrollment_id", enrollment.EnrollmentId);
        Assert.AreEqual(1, await command.ExecuteNonQueryAsync());
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
