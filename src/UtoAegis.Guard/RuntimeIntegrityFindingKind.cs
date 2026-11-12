namespace UtoAegis.Guard;

internal enum RuntimeIntegrityFindingKind
{
    ServiceMissing = 0,
    ServiceBinaryPathMismatch = 1,
    ServiceAccountMismatch = 2,
    ServiceStartModeMismatch = 3,
    ExecutableMissing = 4,
    ExecutableHashMismatch = 5,
    ProtectedPathMissing = 6,
    ProtectedPathUnsafe = 7,
    SecurityDescriptorMismatch = 8,
    InspectionFailed = 9,
    RecoveryFailed = 10
}
