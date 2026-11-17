using UtoAegis.Core.Management;

namespace UtoAegis.Core.Tests;

[TestClass]
public sealed class EnrollmentBootstrapTokenTests
{
    [TestMethod]
    public void Generate_ProducesCanonicalUniqueSecrets()
    {
        using var first = EnrollmentBootstrapToken.Generate();
        using var second = EnrollmentBootstrapToken.Generate();

        Assert.HasCount(EnrollmentBootstrapToken.EncodedLength, first.Reveal());
        Assert.AreNotEqual(first.Reveal(), second.Reveal());
        Assert.HasCount(64, first.ComputeSha256());
    }

    [TestMethod]
    public void Parse_CanonicalValue_RoundTrips()
    {
        using var generated = EnrollmentBootstrapToken.Generate();
        using var parsed = EnrollmentBootstrapToken.Parse(generated.Reveal());

        Assert.AreEqual(generated.Reveal(), parsed.Reveal());
        Assert.AreEqual(generated.ComputeSha256(), parsed.ComputeSha256());
    }

    [TestMethod]
    public void Parse_PaddedBase64_RejectsToken()
    {
        using var generated = EnrollmentBootstrapToken.Generate();

        Assert.ThrowsExactly<ArgumentException>(() =>
            EnrollmentBootstrapToken.Parse(generated.Reveal() + "="));
    }

    [TestMethod]
    public void ToString_DoesNotRevealSecret()
    {
        using var token = EnrollmentBootstrapToken.Generate();

        Assert.AreNotEqual(token.Reveal(), token.ToString());
        StringAssert.Contains(token.ToString(), "redacted");
    }

    [TestMethod]
    public void Dispose_RejectsSecretAccess()
    {
        var token = EnrollmentBootstrapToken.Generate();
        token.Dispose();

        Assert.ThrowsExactly<ObjectDisposedException>(() => token.Reveal());
        Assert.ThrowsExactly<ObjectDisposedException>(() => token.ComputeSha256());
    }
}
