using System.Globalization;
using Microsoft.Data.Sqlite;
using UtoAegis.Core.Management;

namespace UtoAegis.Infrastructure.Management;

public sealed class SqliteEnrollmentBootstrapStore
{
    public const int CurrentSchemaVersion = 2;
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
                    CREATE TABLE device_enrollments (
                        enrollment_id TEXT PRIMARY KEY NOT NULL CHECK(length(enrollment_id) = 32),
                        device_id TEXT UNIQUE NOT NULL CHECK(length(device_id) = 32),
                        public_key_spki_base64 TEXT NOT NULL,
                        public_key_sha256 TEXT UNIQUE NOT NULL CHECK(length(public_key_sha256) = 64),
                        rollout_ring TEXT NOT NULL CHECK(length(rollout_ring) BETWEEN 1 AND 32),
                        credential_sequence INTEGER NOT NULL CHECK(credential_sequence > 0),
                        status TEXT NOT NULL CHECK(status IN ('Active', 'Suspended', 'Revoked')),
                        revocation_generation INTEGER NOT NULL CHECK(revocation_generation >= 0),
                        issued_utc TEXT NOT NULL,
                        expires_utc TEXT NOT NULL,
                        management_origin TEXT NOT NULL
                    ) STRICT;
                    INSERT INTO enrollment_store_metadata (store_identity, schema_version)
                    VALUES ('utoaegis-enrollment-bootstrap', 2);
                    PRAGMA user_version = 2;
                    """;
                await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
                await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            }
            else if (version == 1)
            {
                await ApplyVersionTwoAsync(connection, cancellationToken).ConfigureAwait(false);
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

    public async ValueTask<CoordinatorDeviceEnrollment?> EnrollAsync(
        EnrollmentBootstrapToken token,
        VerifiedDeviceEnrollmentProof proof,
        Uri managementOrigin,
        DateTimeOffset nowUtc,
        TimeSpan credentialLifetime,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(proof);
        if (credentialLifetime < TimeSpan.FromHours(1) || credentialLifetime > TimeSpan.FromDays(90))
        {
            throw new ArgumentOutOfRangeException(nameof(credentialLifetime));
        }

        var origin = DeviceEnrollmentCredential.NormalizeManagementOrigin(managementOrigin);
        var now = nowUtc.ToUniversalTime();
        try
        {
            await using var connection = CreateConnection();
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var transaction = connection.BeginTransaction(deferred: false);
            await using var consume = connection.CreateCommand();
            consume.Transaction = transaction;
            consume.CommandText =
                """
                UPDATE bootstrap_tokens
                SET consumed_utc = $now, consumed_device_id = $device_id
                WHERE token_sha256 = $token_sha256
                  AND consumed_utc IS NULL
                  AND expires_utc > $now
                RETURNING rollout_ring;
                """;
            consume.Parameters.AddWithValue("$now", FormatTimestamp(now));
            consume.Parameters.AddWithValue("$device_id", proof.DeviceId);
            consume.Parameters.AddWithValue("$token_sha256", token.ComputeSha256());
            var ringValue = await consume.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
            if (ringValue is not string ring)
            {
                await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
                return null;
            }

            var enrollment = new CoordinatorDeviceEnrollment(
                Guid.NewGuid().ToString("N"),
                proof.DeviceId,
                proof.PublicKeySpkiBase64,
                proof.PublicKeySha256,
                new RolloutRing(ring),
                1,
                DeviceEnrollmentStatus.Active,
                0,
                now,
                now + credentialLifetime,
                origin);
            await using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText =
                """
                INSERT INTO device_enrollments (
                    enrollment_id, device_id, public_key_spki_base64, public_key_sha256,
                    rollout_ring, credential_sequence, status, revocation_generation,
                    issued_utc, expires_utc, management_origin)
                VALUES (
                    $enrollment_id, $device_id, $public_key_spki_base64, $public_key_sha256,
                    $rollout_ring, $credential_sequence, $status, $revocation_generation,
                    $issued_utc, $expires_utc, $management_origin);
                """;
            insert.Parameters.AddWithValue("$enrollment_id", enrollment.EnrollmentId);
            insert.Parameters.AddWithValue("$device_id", enrollment.DeviceId);
            insert.Parameters.AddWithValue("$public_key_spki_base64", enrollment.PublicKeySpkiBase64);
            insert.Parameters.AddWithValue("$public_key_sha256", enrollment.PublicKeySha256);
            insert.Parameters.AddWithValue("$rollout_ring", enrollment.RolloutRing.Value);
            insert.Parameters.AddWithValue("$credential_sequence", enrollment.CredentialSequence);
            insert.Parameters.AddWithValue("$status", enrollment.Status.ToString());
            insert.Parameters.AddWithValue("$revocation_generation", enrollment.RevocationGeneration);
            insert.Parameters.AddWithValue("$issued_utc", FormatTimestamp(enrollment.IssuedUtc));
            insert.Parameters.AddWithValue("$expires_utc", FormatTimestamp(enrollment.ExpiresUtc));
            insert.Parameters.AddWithValue("$management_origin", enrollment.ManagementOrigin.AbsoluteUri);
            await insert.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            return enrollment;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (IsStorageException(exception))
        {
            throw new DeviceManagementException("The device enrollment could not be committed.", exception);
        }
    }

    public async ValueTask<CoordinatorDeviceEnrollment?> GetEnrollmentAsync(
        string enrollmentId,
        CancellationToken cancellationToken = default)
    {
        enrollmentId = NormalizeHex(enrollmentId, 32, nameof(enrollmentId));
        try
        {
            await using var connection = CreateConnection();
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var command = connection.CreateCommand();
            command.CommandText =
                """
                SELECT enrollment_id, device_id, public_key_spki_base64,
                       public_key_sha256, rollout_ring, credential_sequence,
                       status, revocation_generation, issued_utc, expires_utc,
                       management_origin
                FROM device_enrollments
                WHERE enrollment_id = $enrollment_id
                LIMIT 1;
                """;
            command.Parameters.AddWithValue("$enrollment_id", enrollmentId);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken)
                .ConfigureAwait(false);
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                return null;
            }

            if (!Enum.TryParse<DeviceEnrollmentStatus>(reader.GetString(6), false, out var status) ||
                !Enum.IsDefined(status))
            {
                throw new DeviceManagementException(
                    "The stored device enrollment status is invalid.");
            }

            return new CoordinatorDeviceEnrollment(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetString(3),
                new RolloutRing(reader.GetString(4)),
                reader.GetInt64(5),
                status,
                reader.GetInt64(7),
                ParseTimestamp(reader.GetString(8)),
                ParseTimestamp(reader.GetString(9)),
                new Uri(reader.GetString(10), UriKind.Absolute));
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (DeviceManagementException)
        {
            throw;
        }
        catch (Exception exception) when (
            IsStorageException(exception) ||
            exception is ArgumentException or FormatException or OverflowException)
        {
            throw new DeviceManagementException(
                "The stored device enrollment could not be read.",
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

    private static async ValueTask ApplyVersionTwoAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        await using var transaction = connection.BeginTransaction(deferred: false);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            CREATE TABLE device_enrollments (
                enrollment_id TEXT PRIMARY KEY NOT NULL CHECK(length(enrollment_id) = 32),
                device_id TEXT UNIQUE NOT NULL CHECK(length(device_id) = 32),
                public_key_spki_base64 TEXT NOT NULL,
                public_key_sha256 TEXT UNIQUE NOT NULL CHECK(length(public_key_sha256) = 64),
                rollout_ring TEXT NOT NULL CHECK(length(rollout_ring) BETWEEN 1 AND 32),
                credential_sequence INTEGER NOT NULL CHECK(credential_sequence > 0),
                status TEXT NOT NULL CHECK(status IN ('Active', 'Suspended', 'Revoked')),
                revocation_generation INTEGER NOT NULL CHECK(revocation_generation >= 0),
                issued_utc TEXT NOT NULL,
                expires_utc TEXT NOT NULL,
                management_origin TEXT NOT NULL
            ) STRICT;
            UPDATE enrollment_store_metadata SET schema_version = 2
            WHERE store_identity = 'utoaegis-enrollment-bootstrap';
            PRAGMA user_version = 2;
            """;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
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

    private static string NormalizeHex(string value, int length, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (value.Length != length || value.Any(character =>
                !char.IsAsciiDigit(character) &&
                character is not (>= 'a' and <= 'f') and not (>= 'A' and <= 'F')))
        {
            throw new ArgumentException(
                $"The value must contain exactly {length} hexadecimal characters.",
                parameterName);
        }

        return value.ToLowerInvariant();
    }

    private static DateTimeOffset ParseTimestamp(string value) =>
        DateTimeOffset.ParseExact(
            value,
            "O",
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);

    private static string FormatTimestamp(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);

    private static bool IsStorageException(Exception exception) =>
        exception is SqliteException or IOException or UnauthorizedAccessException;
}
