namespace UtoAegis.Core.RuntimeIntegrity;

public sealed record RuntimePathPolicy
{
    public RuntimePathPolicy(string path, string expectedSddl, bool recover)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedSddl);
        var normalizedSddl = expectedSddl.Trim();
        if (normalizedSddl.Length > 16 * 1024 || normalizedSddl.Any(char.IsControl))
        {
            throw new ArgumentException(
                "The expected security descriptor is not valid.",
                nameof(expectedSddl));
        }

        Path = System.IO.Path.GetFullPath(path);
        ExpectedSddl = normalizedSddl;
        Recover = recover;
    }

    public string Path { get; }

    public string ExpectedSddl { get; }

    public bool Recover { get; }
}
