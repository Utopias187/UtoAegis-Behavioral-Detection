namespace UtoAegis.Guard;

internal sealed record RuntimeIntegrityFinding(
    RuntimeIntegrityFindingKind Kind,
    string Target,
    string Expected,
    string Actual,
    bool Recoverable,
    string Message);
