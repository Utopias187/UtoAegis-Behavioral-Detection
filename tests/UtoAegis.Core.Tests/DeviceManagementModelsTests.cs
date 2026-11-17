using System.Security.Cryptography;
using System.Text;
using UtoAegis.Core.Management;

namespace UtoAegis.Core.Tests;

[TestClass]
public sealed class DeviceManagementModelsTests
{
    [TestMethod]
    public void DeviceIdentityState_UppercaseHex_NormalizesIdentity()
    {
        var state = new DeviceIdentityState(
            new string('A', 32),
            "UtoAegis.Device.1",
            new string('B', 64),
            new DateTimeOffset(2026, 11, 17, 12, 0, 0, TimeSpan.Zero));

        Assert.AreEqual(new string('a', 32), state.DeviceId);
        Assert.AreEqual(new string('b', 64), state.PublicKeySha256);
    }

    [TestMethod]
    public void DeviceIdentityState_InvalidDeviceId_RejectsIdentity()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new DeviceIdentityState(
            "device-1",
            "UtoAegis.Device.1",
            new string('b', 64),
            DateTimeOffset.UtcNow));
    }

    [TestMethod]
    public void DeviceRequestPayload_MethodCase_ProducesSameCanonicalBytes()
    {
        var first = CreatePayload("post", "/v1/policy?current=7");
        var second = CreatePayload("POST", "/v1/policy?current=7");

        CollectionAssert.AreEqual(first.GetCanonicalBytes(), second.GetCanonicalBytes());
    }

    [TestMethod]
    public void DeviceRequestPayload_AbsoluteUri_RejectsTarget()
    {
        var exception = Assert.ThrowsExactly<ArgumentException>(() =>
            CreatePayload("POST", "https://management.example/v1/policy"));

        StringAssert.Contains(exception.Message, "absolute path");
    }

    [TestMethod]
    public void DeviceRequestPayload_Fragment_RejectsTarget()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            CreatePayload("POST", "/v1/policy#fragment"));
    }

    [TestMethod]
    public void SignedDeviceRequest_DerSignature_RejectsVariableLengthSignature()
    {
        var payload = CreatePayload("POST", "/v1/policy");
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signature = key.SignData(
            payload.GetCanonicalBytes(),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence);

        Assert.ThrowsExactly<ArgumentException>(() =>
            new SignedDeviceRequest(payload, Convert.ToBase64String(signature)));
    }

    [TestMethod]
    public void PolicyAcknowledgement_SameValues_ProducesStableCanonicalBytes()
    {
        var first = CreateAcknowledgement();
        var second = CreateAcknowledgement();

        CollectionAssert.AreEqual(first.GetCanonicalBytes(), second.GetCanonicalBytes());
    }

    [TestMethod]
    public void FleetHealthSnapshot_ErrorCodes_NormalizesAndSortsBoundedValues()
    {
        var health = CreateHealth(["telemetry_degraded", "guard.stopped"]);

        Assert.HasCount(2, health.ErrorCodes);
        Assert.AreEqual("GUARD.STOPPED", health.ErrorCodes[0]);
        Assert.AreEqual("TELEMETRY_DEGRADED", health.ErrorCodes[1]);
        var json = Encoding.UTF8.GetString(health.GetCanonicalBytes());
        StringAssert.Contains(json, "\"policySequence\":17");
        Assert.IsFalse(json.Contains("path", StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void FleetHealthSnapshot_ArbitraryErrorText_RejectsHealth()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            CreateHealth([@"failed at C:\Users\name\secret.txt"]));
    }

    [TestMethod]
    public void FleetHealthSnapshot_TooManyErrors_RejectsHealth()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
            CreateHealth(Enumerable.Range(0, 17).Select(index => $"ERROR_{index}").ToArray()));
    }

    private static DeviceRequestPayload CreatePayload(string method, string pathAndQuery) =>
        new(
            new string('a', 32),
            "enrollment-1",
            4,
            new DateTimeOffset(2026, 11, 17, 12, 0, 0, TimeSpan.Zero),
            new string('b', 32),
            method,
            pathAndQuery,
            new string('c', 64));

    private static PolicyAcknowledgement CreateAcknowledgement() =>
        new(
            new string('d', 32),
            new string('a', 32),
            "enrollment-1",
            "endpoint-policy",
            17,
            new string('c', 64),
            new DateTimeOffset(2026, 11, 17, 12, 30, 0, TimeSpan.Zero));

    private static FleetHealthSnapshot CreateHealth(IReadOnlyCollection<string> errors) =>
        new(
            new string('a', 32),
            "enrollment-1",
            "15.0.0",
            new RolloutRing("canary"),
            "endpoint-policy",
            17,
            new string('c', 64),
            PolicyVerificationState.Verified,
            FleetComponentState.Healthy,
            FleetComponentState.Healthy,
            FleetComponentState.Degraded,
            FleetComponentState.Stopped,
            new DateTimeOffset(2026, 11, 17, 13, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 11, 17, 12, 55, 0, TimeSpan.Zero),
            errors);
}
