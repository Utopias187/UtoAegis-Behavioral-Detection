using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using UtoAegis.Core.Behavior;
using UtoAegis.Core.History;
using UtoAegis.Core.RiskScoring;

namespace UtoAegis.Infrastructure.History;

public sealed class SqliteBehaviorHistoryStore(string databasePath) : IBehaviorHistoryStore
{
    public const int CurrentSchemaVersion = 1;
    public const int ApplicationId = 1_431_583_561;
    public const int MaximumListLimit = 200;

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly string path = Path.GetFullPath(
        string.IsNullOrWhiteSpace(databasePath)
            ? throw new ArgumentException("Behavior history path is required.", nameof(databasePath))
            : databasePath);

    public async ValueTask InitializeAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            await using var connection = CreateConnection(SqliteOpenMode.ReadWriteCreate);
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var transaction = (SqliteTransaction)await connection
                .BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
            var version = await ScalarAsync(connection, transaction, "PRAGMA user_version;", cancellationToken)
                .ConfigureAwait(false);
            var applicationId = await ScalarAsync(
                connection,
                transaction,
                "PRAGMA application_id;",
                cancellationToken).ConfigureAwait(false);
            if (version > CurrentSchemaVersion)
            {
                throw new BehaviorHistoryStoreException(
                    $"Behavior history schema version {version} is newer than supported version {CurrentSchemaVersion}.");
            }

            if (version > 0 && applicationId != ApplicationId || version == 0 && applicationId != 0)
            {
                throw new BehaviorHistoryStoreException(
                    "The database is not a UtoAegis behavioral history database.");
            }

            if (version == 0)
            {
                await ExecuteAsync(connection, transaction,
                    """
                    CREATE TABLE behavior_history (
                        id TEXT PRIMARY KEY NOT NULL,
                        recorded_utc TEXT NOT NULL,
                        collector_generation_id TEXT NOT NULL,
                        process_id INTEGER NOT NULL CHECK(process_id > 0),
                        process_start_sequence INTEGER NOT NULL CHECK(process_start_sequence > 0),
                        window_started_utc TEXT NULL,
                        window_ended_utc TEXT NULL,
                        verdict TEXT NOT NULL,
                        score INTEGER NOT NULL CHECK(score BETWEEN 0 AND 100),
                        confidence INTEGER NOT NULL CHECK(confidence BETWEEN 0 AND 100),
                        provider_state TEXT NOT NULL,
                        policy_id TEXT NOT NULL,
                        policy_version INTEGER NOT NULL CHECK(policy_version > 0),
                        event_count INTEGER NOT NULL CHECK(event_count >= 0),
                        feature_ids_json TEXT NOT NULL,
                        categories_json TEXT NOT NULL
                    ) STRICT;
                    CREATE INDEX ix_behavior_history_recorded
                        ON behavior_history(recorded_utc DESC);
                    PRAGMA application_id = 1431583561;
                    PRAGMA user_version = 1;
                    """, cancellationToken).ConfigureAwait(false);
            }

            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (BehaviorHistoryStoreException)
        {
            throw;
        }
        catch (Exception exception) when (exception is SqliteException or IOException or UnauthorizedAccessException)
        {
            throw new BehaviorHistoryStoreException("Behavior history initialization failed.", exception);
        }
    }

    public async ValueTask AppendAsync(
        BehaviorHistoryRecord record,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        try
        {
            await using var connection = CreateConnection(SqliteOpenMode.ReadWrite);
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var command = connection.CreateCommand();
            command.CommandText =
                """
                INSERT INTO behavior_history (
                    id, recorded_utc, collector_generation_id, process_id,
                    process_start_sequence, window_started_utc, window_ended_utc,
                    verdict, score, confidence, provider_state, policy_id,
                    policy_version, event_count, feature_ids_json, categories_json)
                VALUES (
                    $id, $recorded, $generation, $pid, $start, $window_start,
                    $window_end, $verdict, $score, $confidence, $provider_state,
                    $policy_id, $policy_version, $event_count, $features, $categories);
                """;
            command.Parameters.AddWithValue("$id", record.Id.ToString("D", CultureInfo.InvariantCulture));
            command.Parameters.AddWithValue("$recorded", Format(record.RecordedUtc));
            command.Parameters.AddWithValue("$generation", record.CollectorGenerationId.ToString("D"));
            command.Parameters.AddWithValue("$pid", record.ProcessId);
            command.Parameters.AddWithValue("$start", record.ProcessStartSequence);
            command.Parameters.AddWithValue("$window_start", DbTime(record.WindowStartedUtc));
            command.Parameters.AddWithValue("$window_end", DbTime(record.WindowEndedUtc));
            command.Parameters.AddWithValue("$verdict", record.Verdict.ToString());
            command.Parameters.AddWithValue("$score", record.Score);
            command.Parameters.AddWithValue("$confidence", record.Confidence);
            command.Parameters.AddWithValue("$provider_state", record.ProviderState.ToString());
            command.Parameters.AddWithValue("$policy_id", record.PolicyId);
            command.Parameters.AddWithValue("$policy_version", record.PolicyVersion);
            command.Parameters.AddWithValue("$event_count", record.EventCount);
            command.Parameters.AddWithValue("$features", JsonSerializer.Serialize(record.FeatureIds, JsonOptions));
            command.Parameters.AddWithValue("$categories", JsonSerializer.Serialize(record.Categories, JsonOptions));
            await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (exception is SqliteException or IOException or UnauthorizedAccessException)
        {
            throw new BehaviorHistoryStoreException("Behavior history append failed.", exception);
        }
    }

    public async ValueTask<IReadOnlyList<BehaviorHistoryRecord>> ListAsync(
        int limit,
        CancellationToken cancellationToken = default)
    {
        if (limit is < 1 or > MaximumListLimit)
        {
            throw new ArgumentOutOfRangeException(nameof(limit));
        }

        try
        {
            await using var connection = CreateConnection(SqliteOpenMode.ReadOnly);
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var command = connection.CreateCommand();
            command.CommandText =
                """
                SELECT id, recorded_utc, collector_generation_id, process_id,
                       process_start_sequence, window_started_utc, window_ended_utc,
                       verdict, score, confidence, provider_state, policy_id,
                       policy_version, event_count, feature_ids_json, categories_json
                FROM behavior_history
                ORDER BY recorded_utc DESC, id
                LIMIT $limit;
                """;
            command.Parameters.AddWithValue("$limit", limit);
            var records = new List<BehaviorHistoryRecord>();
            await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                records.Add(new BehaviorHistoryRecord(
                    Guid.Parse(reader.GetString(0)),
                    ParseTime(reader.GetString(1)),
                    Guid.Parse(reader.GetString(2)),
                    reader.GetInt32(3),
                    reader.GetInt64(4),
                    reader.IsDBNull(5) ? null : ParseTime(reader.GetString(5)),
                    reader.IsDBNull(6) ? null : ParseTime(reader.GetString(6)),
                    Enum.Parse<RiskVerdict>(reader.GetString(7)),
                    reader.GetInt32(8),
                    reader.GetInt32(9),
                    Enum.Parse<BehaviorProviderState>(reader.GetString(10)),
                    reader.GetString(11),
                    reader.GetInt32(12),
                    reader.GetInt32(13),
                    Deserialize<string[]>(reader.GetString(14), "feature IDs"),
                    Deserialize<BehaviorHistoryCategory[]>(reader.GetString(15), "categories")));
            }

            return records;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (BehaviorHistoryStoreException)
        {
            throw;
        }
        catch (Exception exception) when (exception is SqliteException or IOException or UnauthorizedAccessException or
                                           FormatException or JsonException or ArgumentException)
        {
            throw new BehaviorHistoryStoreException("Behavior history read failed.", exception);
        }
    }

    private SqliteConnection CreateConnection(SqliteOpenMode mode) => new(new SqliteConnectionStringBuilder
    {
        DataSource = path,
        Mode = mode,
        Cache = SqliteCacheMode.Private,
        ForeignKeys = true
    }.ToString());

    private static async ValueTask<long> ScalarAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string sql,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        return (long)(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) ?? 0L);
    }

    private static async ValueTask ExecuteAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string sql,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static T Deserialize<T>(string json, string name) =>
        JsonSerializer.Deserialize<T>(json, JsonOptions) ??
        throw new BehaviorHistoryStoreException($"Behavior history contains invalid {name}.");

    private static object DbTime(DateTimeOffset? value) => value is null ? DBNull.Value : Format(value.Value);

    private static string Format(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);

    private static DateTimeOffset ParseTime(string value) =>
        DateTimeOffset.ParseExact(value, "O", CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
}
