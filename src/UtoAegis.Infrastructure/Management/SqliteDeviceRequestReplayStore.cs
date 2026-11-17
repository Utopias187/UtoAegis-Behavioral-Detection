using System.Globalization;
using Microsoft.Data.Sqlite;

namespace UtoAegis.Infrastructure.Management;

public sealed class SqliteDeviceRequestReplayStore
{
    public const int MaximumRetainedNoncesPerDevice = 4096;

    private readonly string databasePath;

    public SqliteDeviceRequestReplayStore(string databasePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        this.databasePath = Path.GetFullPath(databasePath);
    }

    public async ValueTask InitializeAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(databasePath)!);
            await using var connection = CreateConnection();
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var command = connection.CreateCommand();
            command.CommandText =
                """
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = FULL;
                CREATE TABLE IF NOT EXISTS request_nonces (
                    device_id TEXT NOT NULL CHECK(length(device_id) = 32),
                    nonce TEXT NOT NULL CHECK(length(nonce) = 32),
                    observed_utc TEXT NOT NULL,
                    expires_utc TEXT NOT NULL,
                    PRIMARY KEY (device_id, nonce)
                ) STRICT;
                CREATE INDEX IF NOT EXISTS ix_request_nonces_expiry
                    ON request_nonces(expires_utc);
                """;
            await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (exception is SqliteException or IOException or UnauthorizedAccessException)
        {
            throw new DeviceManagementException(
                "The request replay store could not be initialized.",
                exception);
        }
    }

    public async ValueTask<bool> TryReserveAsync(
        string deviceId,
        string nonce,
        DateTimeOffset observedUtc,
        TimeSpan retention,
        CancellationToken cancellationToken = default)
    {
        deviceId = NormalizeHex(deviceId, 32, nameof(deviceId));
        nonce = NormalizeHex(nonce, 32, nameof(nonce));
        if (retention < TimeSpan.FromMinutes(1) || retention > TimeSpan.FromHours(24))
        {
            throw new ArgumentOutOfRangeException(
                nameof(retention),
                "Replay reservations must be retained for one minute through 24 hours.");
        }

        var observed = observedUtc.ToUniversalTime();
        try
        {
            await using var connection = CreateConnection();
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var transaction = connection.BeginTransaction(deferred: false);
            await using (var prune = connection.CreateCommand())
            {
                prune.Transaction = transaction;
                prune.CommandText = "DELETE FROM request_nonces WHERE expires_utc <= $observed_utc;";
                prune.Parameters.AddWithValue("$observed_utc", Format(observed));
                await prune.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }

            await using (var count = connection.CreateCommand())
            {
                count.Transaction = transaction;
                count.CommandText = "SELECT COUNT(*) FROM request_nonces WHERE device_id = $device_id;";
                count.Parameters.AddWithValue("$device_id", deviceId);
                var retained = (long)(await count.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false))!;
                if (retained >= MaximumRetainedNoncesPerDevice)
                {
                    await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
                    return false;
                }
            }

            await using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText =
                """
                INSERT OR IGNORE INTO request_nonces (
                    device_id, nonce, observed_utc, expires_utc)
                VALUES ($device_id, $nonce, $observed_utc, $expires_utc);
                """;
            insert.Parameters.AddWithValue("$device_id", deviceId);
            insert.Parameters.AddWithValue("$nonce", nonce);
            insert.Parameters.AddWithValue("$observed_utc", Format(observed));
            insert.Parameters.AddWithValue("$expires_utc", Format(observed + retention));
            var changed = await insert.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            return changed == 1;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (exception is SqliteException or IOException or UnauthorizedAccessException)
        {
            throw new DeviceManagementException("The request nonce could not be reserved.", exception);
        }
    }

    private SqliteConnection CreateConnection() => new(new SqliteConnectionStringBuilder
    {
        DataSource = databasePath,
        Mode = SqliteOpenMode.ReadWriteCreate,
        Cache = SqliteCacheMode.Private,
        Pooling = false,
        DefaultTimeout = 10
    }.ToString());

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

    private static string Format(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
}
