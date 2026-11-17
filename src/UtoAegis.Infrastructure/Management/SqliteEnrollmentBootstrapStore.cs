using System.Globalization;
using Microsoft.Data.Sqlite;
using UtoAegis.Core.Management;

namespace UtoAegis.Infrastructure.Management;

public sealed class SqliteEnrollmentBootstrapStore
{
    public const int CurrentSchemaVersion = 1;
    public const string StoreIdentity = "utoaegis-enrollment-bootstrap";

    private readonly string databasePath;

    public SqliteEnrollmentBootstrapStore(string databasePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        this.databasePath = Path.GetFullPath(databasePath);
        var parent = Path.GetDirectoryName(this.databasePath)!;
        if (Path.GetFullPath(parent) == Path.GetPathRoot(parent))
        {
            throw new ArgumentException(
                "The enrollment database must not be stored at a filesystem root.",
                nameof(databasePath));
        }
    }

    public async ValueTask InitializeAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var directory = Path.GetDirectoryName(databasePath)!;
            Directory.CreateDirectory(directory);
            var directoryInfo = new DirectoryInfo(directory);
            directoryInfo.Refresh();
            if (directoryInfo.Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                throw new DeviceManagementException(
                    "The enrollment database directory must not be a reparse point.");
            }

            await using var connection = CreateConnection();
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await using (var pragmaCommand = connection.CreateCommand())
            {
                pragmaCommand.CommandText = "PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;";
                await pragmaCommand.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }

            await using var versionCommand = connection.CreateCommand();
            versionCommand.CommandText = "PRAGMA user_version;";
            var version = Convert.ToInt32(
                await versionCommand.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false),
                CultureInfo.InvariantCulture);
            if (version > CurrentSchemaVersion)
            {
                throw new DeviceManagementException(
                    $"Enrollment database schema version {version} is newer than supported version {CurrentSchemaVersion}.");
            }

            if (version == 0)
            {
                await using var transaction = connection.BeginTransaction(deferred: false);
                await using var command = connection.CreateCommand();
                command.Transaction = transaction;
                command.CommandText =
                    """
                    CREATE TABLE enrollment_store_metadata (
                        store_identity TEXT PRIMARY KEY NOT NULL,
                        schema_version INTEGER NOT NULL
                    ) STRICT;
                    CREATE TABLE bootstrap_tokens (
                        token_sha256 TEXT PRIMARY KEY NOT NULL
                            CHECK(length(token_sha256) = 64),
                        rollout_ring TEXT NOT NULL CHECK(length(rollout_ring) BETWEEN 1 AND 32),
                        issued_utc TEXT NOT NULL,
                        expires_utc TEXT NOT NULL,
                        consumed_utc TEXT NULL,
                        consumed_device_id TEXT NULL
                            CHECK(consumed_device_id IS NULL OR length(consumed_device_id) = 32),
                        CHECK((consumed_utc IS NULL) = (consumed_device_id IS NULL))
                    ) STRICT;
                    INSERT INTO enrollment_store_metadata (store_identity, schema_version)
                    VALUES ('utoaegis-enrollment-bootstrap', 1);
                    PRAGMA user_version = 1;
                    """;
                await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
                await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            }

            await ValidateStoreIdentityAsync(connection, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (DeviceManagementException)
        {
            throw;
        }
        catch (Exception exception) when (IsStorageException(exception))
        {
            throw new DeviceManagementException(
                "The enrollment bootstrap store could not be initialized.",
                exception);
        }
    }

    public async ValueTask IssueAsync(
        EnrollmentBootstrapToken token,
        RolloutRing rolloutRing,
        DateTimeOffset issuedUtc,
        DateTimeOffset expiresUtc,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(rolloutRing);
        var issued = issuedUtc.ToUniversalTime();
        var expires = expiresUtc.ToUniversalTime();
        if (expires <= issued || expires - issued > TimeSpan.FromDays(7))
        {
            throw new ArgumentException(
                "A bootstrap token must be valid for more than zero and no longer than seven days.",
                nameof(expiresUtc));
        }

        try
        {
            await using var connection = CreateConnection();
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var command = connection.CreateCommand();
            command.CommandText =
                """
                INSERT INTO bootstrap_tokens (
                    token_sha256, rollout_ring, issued_utc, expires_utc)
                VALUES ($token_sha256, $rollout_ring, $issued_utc, $expires_utc);
                """;
            command.Parameters.AddWithValue("$token_sha256", token.ComputeSha256());
            command.Parameters.AddWithValue("$rollout_ring", rolloutRing.Value);
            command.Parameters.AddWithValue("$issued_utc", FormatTimestamp(issued));
            command.Parameters.AddWithValue("$expires_utc", FormatTimestamp(expires));
            await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (IsStorageException(exception))
        {
            throw new DeviceManagementException(
                "The enrollment bootstrap token could not be issued.",
                exception);
        }
    }

    public async ValueTask<BootstrapTokenConsumption?> ConsumeAsync(
        EnrollmentBootstrapToken token,
        string deviceId,
        DateTimeOffset nowUtc,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(token);
        var normalizedDeviceId = NormalizeDeviceId(deviceId);
        var now = nowUtc.ToUniversalTime();
        var hash = token.ComputeSha256();
        try
        {
            await using var connection = CreateConnection();
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var transaction = connection.BeginTransaction(deferred: false);
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText =
                """
                UPDATE bootstrap_tokens
                SET consumed_utc = $consumed_utc,
                    consumed_device_id = $device_id
                WHERE token_sha256 = $token_sha256
                  AND consumed_utc IS NULL
                  AND expires_utc > $consumed_utc
                RETURNING rollout_ring;
                """;
            command.Parameters.AddWithValue("$consumed_utc", FormatTimestamp(now));
            command.Parameters.AddWithValue("$device_id", normalizedDeviceId);
            command.Parameters.AddWithValue("$token_sha256", hash);
            var result = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            if (result is not string ring)
            {
                return null;
            }

            return new BootstrapTokenConsumption(
                hash,
                normalizedDeviceId,
                new RolloutRing(ring),
                now);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (IsStorageException(exception))
        {
            throw new DeviceManagementException(
                "The enrollment bootstrap token could not be consumed.",
                exception);
        }
    }

    private SqliteConnection CreateConnection()
    {
        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
            DefaultTimeout = 10
        };
        return new SqliteConnection(builder.ToString());
    }

    private static async ValueTask ValidateStoreIdentityAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT schema_version
            FROM enrollment_store_metadata
            WHERE store_identity = $store_identity
            LIMIT 1;
            """;
        command.Parameters.AddWithValue("$store_identity", StoreIdentity);
        var result = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        if (result is not long schemaVersion || schemaVersion != CurrentSchemaVersion)
        {
            throw new DeviceManagementException(
                "The enrollment database identity or schema version is invalid.");
        }
    }

    private static string NormalizeDeviceId(string deviceId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);
        if (deviceId.Length != 32 || deviceId.Any(character =>
                !char.IsAsciiDigit(character) &&
                character is not (>= 'a' and <= 'f') and not (>= 'A' and <= 'F')))
        {
            throw new ArgumentException(
                "A device ID must contain exactly 32 hexadecimal characters.",
                nameof(deviceId));
        }

        return deviceId.ToLowerInvariant();
    }

    private static string FormatTimestamp(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);

    private static bool IsStorageException(Exception exception) =>
        exception is SqliteException or IOException or UnauthorizedAccessException;
}
