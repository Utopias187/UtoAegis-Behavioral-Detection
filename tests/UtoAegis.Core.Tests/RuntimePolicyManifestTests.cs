using UtoAegis.Core.Response;
using UtoAegis.Core.RuntimeIntegrity;

namespace UtoAegis.Core.Tests;

[TestClass]
public sealed class RuntimePolicyManifestTests
{
    [TestMethod]
    public void RuntimeServicePolicy_RecoveringPasswordBackedAccount_RejectsPolicy()
    {
        var exception = Assert.ThrowsExactly<ArgumentException>(() =>
            CreateService(@"CONTOSO\service-user", recover: true));

        StringAssert.Contains(exception.Message, "passwordless");
    }

    [TestMethod]
    public void RuntimeServicePolicy_AuditingPasswordBackedAccount_AllowsPolicy()
    {
        var service = CreateService(@"CONTOSO\service-user", recover: false);

        Assert.IsFalse(service.Recover);
        Assert.AreEqual(@"CONTOSO\service-user", service.Account);
    }

    [TestMethod]
    public void RuntimePolicyManifest_DuplicateServiceName_RejectsPolicy()
    {
        var service = CreateService(@"NT SERVICE\UtoAegis", recover: true);

        var exception = Assert.ThrowsExactly<ArgumentException>(() =>
            new RuntimePolicyManifest(
                1,
                "endpoint-policy",
                "policy-key-1",
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow.AddDays(1),
                new ResponsePolicy(),
                [service, service],
                [],
                TimeSpan.FromMinutes(5),
                2,
                TimeSpan.FromHours(1)));

        StringAssert.Contains(exception.Message, "unique");
    }

    private static RuntimeServicePolicy CreateService(string account, bool recover) =>
        new(
            "UtoAegis",
            Path.GetFullPath("utoaegis-service.exe"),
            new string('a', 64),
            account,
            RuntimeServiceStartMode.DelayedAutomatic,
            recover);
}
