namespace UtoAegis.Updater;

public sealed record UpdaterSigningKeyPolicy(
    string KeyId,
    string PublicKeyPath,
    UpdaterSigningKeyStatus Status);
