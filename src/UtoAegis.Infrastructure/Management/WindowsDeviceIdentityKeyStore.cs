using System.Runtime.Versioning;
using System.Security.Cryptography;
using UtoAegis.Core.Management;

namespace UtoAegis.Infrastructure.Management;

[SupportedOSPlatform("windows")]
public sealed class WindowsDeviceIdentityKeyStore
{
    private static readonly CngProvider Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider;

    private readonly string keyName;
    private readonly CngKeyOpenOptions openOptions;
    private readonly CngKeyCreationOptions creationOptions;

    public WindowsDeviceIdentityKeyStore(string keyName)
        : this(keyName, machineScope: true)
    {
    }

    internal WindowsDeviceIdentityKeyStore(string keyName, bool machineScope)
    {
        keyName = ValidateKeyName(keyName);
        this.keyName = keyName;
        openOptions = machineScope ? CngKeyOpenOptions.MachineKey : CngKeyOpenOptions.None;
        creationOptions = machineScope ? CngKeyCreationOptions.MachineKey : CngKeyCreationOptions.None;
    }

    public async ValueTask<DeviceIdentityKeyContext> CreateOrLoadAsync(
        DeviceIdentityStateStore stateStore,
        TimeProvider? timeProvider = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stateStore);
        var persisted = await stateStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        if (persisted is not null)
        {
            if (!string.Equals(persisted.KeyName, keyName, StringComparison.Ordinal))
            {
                throw new DeviceManagementException(
                    "The persisted device identity references a different key.");
            }

            return OpenAndValidate(persisted);
        }

        if (CngKey.Exists(keyName, Provider, openOptions))
        {
            throw new DeviceManagementException(
                "A device key exists without matching identity state; explicit recovery is required.");
        }

        CngKey? createdKey = null;
        try
        {
            var parameters = new CngKeyCreationParameters
            {
                Provider = Provider,
                KeyCreationOptions = creationOptions,
                ExportPolicy = CngExportPolicies.None,
                KeyUsage = CngKeyUsages.Signing
            };
            createdKey = CngKey.Create(CngAlgorithm.ECDsaP256, keyName, parameters);
            var signingKey = new ECDsaCng(createdKey);
            createdKey = null;
            var fingerprint = Convert.ToHexString(
                SHA256.HashData(signingKey.ExportSubjectPublicKeyInfo())).ToLowerInvariant();
            var identity = DeviceIdentityState.Create(keyName, fingerprint, timeProvider);
            try
            {
                identity = await stateStore.CreateOrLoadAsync(identity, cancellationToken)
                    .ConfigureAwait(false);
                return new DeviceIdentityKeyContext(identity, signingKey);
            }
            catch
            {
                signingKey.Dispose();
                DeleteKey();
                throw;
            }
        }
        catch (DeviceManagementException)
        {
            throw;
        }
        catch (Exception exception) when (exception is CryptographicException or UnauthorizedAccessException)
        {
            throw new DeviceManagementException(
                "The non-exportable Windows device key could not be created.",
                exception);
        }
        finally
        {
            createdKey?.Dispose();
        }
    }

    internal void DeleteKey()
    {
        if (!CngKey.Exists(keyName, Provider, openOptions))
        {
            return;
        }

        using var key = CngKey.Open(keyName, Provider, openOptions);
        key.Delete();
    }

    private DeviceIdentityKeyContext OpenAndValidate(DeviceIdentityState identity)
    {
        try
        {
            if (!CngKey.Exists(keyName, Provider, openOptions))
            {
                throw new DeviceManagementException(
                    "The persisted device identity key is missing.");
            }

            using var key = CngKey.Open(keyName, Provider, openOptions);
            if (key.AlgorithmGroup != CngAlgorithmGroup.ECDsa ||
                key.ExportPolicy != CngExportPolicies.None ||
                (key.KeyUsage & CngKeyUsages.Signing) == 0)
            {
                throw new DeviceManagementException(
                    "The persisted device key is not a non-exportable ECDSA signing key.");
            }

            var signingKey = new ECDsaCng(key);
            if (signingKey.KeySize != 256)
            {
                signingKey.Dispose();
                throw new DeviceManagementException(
                    "The persisted device key is not an ECDSA P-256 key.");
            }

            var fingerprint = Convert.ToHexString(
                SHA256.HashData(signingKey.ExportSubjectPublicKeyInfo())).ToLowerInvariant();
            if (!CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(fingerprint),
                    Convert.FromHexString(identity.PublicKeySha256)))
            {
                signingKey.Dispose();
                throw new DeviceManagementException(
                    "The persisted device key does not match the identity fingerprint.");
            }

            return new DeviceIdentityKeyContext(identity, signingKey);
        }
        catch (DeviceManagementException)
        {
            throw;
        }
        catch (Exception exception) when (exception is CryptographicException or UnauthorizedAccessException)
        {
            throw new DeviceManagementException(
                "The non-exportable Windows device key could not be opened.",
                exception);
        }
    }

    private static string ValidateKeyName(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        var normalized = value.Trim();
        if (normalized.Length > 128 ||
            !char.IsAsciiLetterOrDigit(normalized[0]) ||
            !char.IsAsciiLetterOrDigit(normalized[^1]) ||
            normalized.Any(character =>
                !char.IsAsciiLetterOrDigit(character) &&
                character is not '.' and not '-' and not '_' and not ':'))
        {
            throw new ArgumentException(
                "The device key name must use 1 to 128 safe ASCII characters.",
                nameof(value));
        }

        return normalized;
    }
}
