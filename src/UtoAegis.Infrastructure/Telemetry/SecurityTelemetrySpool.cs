using System.Security.Cryptography;
using System.Text.Json;
using UtoAegis.Core.Telemetry;

namespace UtoAegis.Infrastructure.Telemetry;

public sealed class SecurityTelemetrySpool : IDisposable
{
    private const int SchemaVersion = 1;
    private static readonly JsonSerializerOptions SerializerOptions =
        new(JsonSerializerDefaults.Web);

    private readonly string _rootPath;
    private readonly string _recordsPath;
    private readonly string _statePath;
    private readonly SecurityTelemetrySpoolOptions _options;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private bool _initialized;

    public SecurityTelemetrySpool(
        string rootPath,
        SecurityTelemetrySpoolOptions? options = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootPath);
        _rootPath = Path.GetFullPath(rootPath);
        _recordsPath = Path.Combine(_rootPath, "records");
        _statePath = Path.Combine(_rootPath, "state.json");
        _options = options ?? new SecurityTelemetrySpoolOptions();
    }

    public async ValueTask InitializeAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await InitializeCoreAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask<SecurityTelemetryEnvelope> AppendAsync(
        SecurityTelemetryEvent telemetryEvent,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(telemetryEvent);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await InitializeCoreAsync(cancellationToken).ConfigureAwait(false);
            var state = await ReadStateAsync(cancellationToken).ConfigureAwait(false);
            var sequence = checked(state.LastSequence + 1);
            using var payloadDocument = JsonDocument.Parse(telemetryEvent.PayloadJson);
            var material = new HashMaterial(
                SchemaVersion,
                sequence,
                telemetryEvent.TimestampUtc,
                telemetryEvent.Source,
                telemetryEvent.EventType,
                telemetryEvent.DeploymentId,
                telemetryEvent.CorrelationId,
                payloadDocument.RootElement.Clone(),
                state.LastHash);
            var hash = ComputeHash(material);
            var envelope = new SecurityTelemetryEnvelope(
                material.SchemaVersion,
                material.Sequence,
                material.TimestampUtc,
                material.Source,
                material.EventType,
                material.DeploymentId,
                material.CorrelationId,
                material.Payload,
                material.PreviousHash,
                hash);
            var bytes = JsonSerializer.SerializeToUtf8Bytes(envelope, SerializerOptions);
            if (bytes.Length > _options.MaximumRecordBytes)
            {
                throw new SecurityTelemetryException(
                    $"The serialized telemetry record exceeds {_options.MaximumRecordBytes} bytes.");
            }

            var recordPath = GetRecordPath(sequence);
            await SecurityTelemetryCheckpointStore.AtomicWriteAsync(
                recordPath,
                bytes,
                cancellationToken).ConfigureAwait(false);
            state = state with { LastSequence = sequence, LastHash = hash };
            await WriteStateAsync(state, cancellationToken).ConfigureAwait(false);
            await PruneAsync(state, cancellationToken).ConfigureAwait(false);
            return envelope;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or JsonException or
                CryptographicException or OverflowException)
        {
            throw new SecurityTelemetryException(
                "The security telemetry record could not be appended.",
                exception);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask<IReadOnlyList<SecurityTelemetryEnvelope>> ReadBatchAsync(
        SecurityTelemetryCheckpoint checkpoint,
        int maximumRecords,
        CancellationToken cancellationToken = default)
    {
        if (maximumRecords is < 1 or > 10_000)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumRecords));
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await InitializeCoreAsync(cancellationToken).ConfigureAwait(false);
            var state = await ReadStateAsync(cancellationToken).ConfigureAwait(false);
            ValidateCheckpoint(checkpoint, state);
            var records = await ReadAndVerifyRecordsAsync(state, cancellationToken)
                .ConfigureAwait(false);
            if (checkpoint.Sequence > state.PrunedThroughSequence)
            {
                var matched = records.FirstOrDefault(record => record.Sequence == checkpoint.Sequence);
                if (matched is null ||
                    !string.Equals(matched.Hash, checkpoint.Hash, StringComparison.Ordinal))
                {
                    throw new SecurityTelemetryException(
                        "The delivery checkpoint does not match the retained telemetry chain.");
                }
            }

            return records
                .Where(record => record.Sequence > checkpoint.Sequence)
                .Take(maximumRecords)
                .ToArray();
        }
        finally
        {
            _gate.Release();
        }
    }

    public void Dispose() => _gate.Dispose();

    private async ValueTask InitializeCoreAsync(CancellationToken cancellationToken)
    {
        if (_initialized)
        {
            return;
        }

        Directory.CreateDirectory(_rootPath);
        Directory.CreateDirectory(_recordsPath);
        ValidateRegularDirectory(_rootPath);
        ValidateRegularDirectory(_recordsPath);
        if (!File.Exists(_statePath))
        {
            if (Directory.EnumerateFiles(_recordsPath, "*.json").Any())
            {
                throw new SecurityTelemetryException(
                    "Telemetry records exist without their chain state.");
            }

            await WriteStateAsync(SpoolState.Empty, cancellationToken).ConfigureAwait(false);
        }

        var state = await ReadStateAsync(cancellationToken).ConfigureAwait(false);
        _ = await ReadAndVerifyRecordsAsync(state, cancellationToken).ConfigureAwait(false);
        _initialized = true;
    }

    private async ValueTask<IReadOnlyList<SecurityTelemetryEnvelope>> ReadAndVerifyRecordsAsync(
        SpoolState state,
        CancellationToken cancellationToken)
    {
        var paths = Directory.EnumerateFiles(_recordsPath, "*.json")
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToArray();
        if (paths.Length > _options.MaximumRecords)
        {
            throw new SecurityTelemetryException(
                "The telemetry spool contains more records than its configured bound.");
        }

        var records = new List<SecurityTelemetryEnvelope>(paths.Length);
        var expectedSequence = state.PrunedThroughSequence + 1;
        var previousHash = state.PrunedThroughHash;
        foreach (var path in paths)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var file = new FileInfo(path);
            if (file.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
                file.Length > _options.MaximumRecordBytes)
            {
                throw new SecurityTelemetryException(
                    "A telemetry spool entry is not a bounded regular file.");
            }

            var bytes = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
            var record = JsonSerializer.Deserialize<SecurityTelemetryEnvelope>(
                bytes,
                SerializerOptions) ?? throw new SecurityTelemetryException(
                    "A telemetry spool record is empty.");
            if (record.SchemaVersion != SchemaVersion ||
                record.Sequence != expectedSequence ||
                !string.Equals(record.PreviousHash, previousHash, StringComparison.Ordinal) ||
                !string.Equals(record.Hash, ComputeHash(record), StringComparison.Ordinal))
            {
                throw new SecurityTelemetryException(
                    "The telemetry hash chain is incomplete or has been modified.");
            }

            records.Add(record);
            expectedSequence++;
            previousHash = record.Hash;
        }

        if (state.LastSequence != expectedSequence - 1 ||
            !string.Equals(state.LastHash, previousHash, StringComparison.Ordinal))
        {
            throw new SecurityTelemetryException(
                "The telemetry chain state does not match the retained records.");
        }

        return records;
    }

    private async ValueTask PruneAsync(SpoolState state, CancellationToken cancellationToken)
    {
        var paths = Directory.EnumerateFiles(_recordsPath, "*.json")
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToArray();
        var removeCount = paths.Length - _options.MaximumRecords;
        if (removeCount <= 0)
        {
            return;
        }

        SecurityTelemetryEnvelope? anchor = null;
        for (var index = 0; index < removeCount; index++)
        {
            var bytes = await File.ReadAllBytesAsync(paths[index], cancellationToken)
                .ConfigureAwait(false);
            anchor = JsonSerializer.Deserialize<SecurityTelemetryEnvelope>(bytes, SerializerOptions)
                ?? throw new SecurityTelemetryException("A telemetry spool record is empty.");
        }

        var prunedState = state with
        {
            PrunedThroughSequence = anchor!.Sequence,
            PrunedThroughHash = anchor.Hash
        };
        await WriteStateAsync(prunedState, cancellationToken).ConfigureAwait(false);
        for (var index = 0; index < removeCount; index++)
        {
            File.Delete(paths[index]);
        }
    }

    private async ValueTask<SpoolState> ReadStateAsync(CancellationToken cancellationToken)
    {
        var bytes = await File.ReadAllBytesAsync(_statePath, cancellationToken).ConfigureAwait(false);
        var state = JsonSerializer.Deserialize<SpoolState>(bytes, SerializerOptions)
            ?? throw new SecurityTelemetryException("The telemetry spool state is empty.");
        if (state.SchemaVersion != SchemaVersion ||
            state.LastSequence < state.PrunedThroughSequence ||
            !IsHash(state.LastHash) ||
            !IsHash(state.PrunedThroughHash))
        {
            throw new SecurityTelemetryException("The telemetry spool state is invalid.");
        }

        return state;
    }

    private ValueTask WriteStateAsync(SpoolState state, CancellationToken cancellationToken) =>
        SecurityTelemetryCheckpointStore.AtomicWriteAsync(
            _statePath,
            JsonSerializer.SerializeToUtf8Bytes(state, SerializerOptions),
            cancellationToken);

    private static void ValidateCheckpoint(
        SecurityTelemetryCheckpoint checkpoint,
        SpoolState state)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);
        if (checkpoint.Sequence < state.PrunedThroughSequence)
        {
            throw new SecurityTelemetryException(
                "The collector checkpoint has fallen behind the bounded telemetry spool.");
        }

        if (checkpoint.Sequence > state.LastSequence || !IsHash(checkpoint.Hash))
        {
            throw new SecurityTelemetryException("The delivery checkpoint is invalid.");
        }

        if (checkpoint.Sequence == state.PrunedThroughSequence &&
            !string.Equals(checkpoint.Hash, state.PrunedThroughHash, StringComparison.Ordinal))
        {
            throw new SecurityTelemetryException(
                "The delivery checkpoint does not match the spool pruning anchor.");
        }
    }

    private string GetRecordPath(long sequence) =>
        Path.Combine(_recordsPath, $"{sequence:D20}.json");

    private static string ComputeHash(SecurityTelemetryEnvelope envelope) =>
        ComputeHash(new HashMaterial(
            envelope.SchemaVersion,
            envelope.Sequence,
            envelope.TimestampUtc,
            envelope.Source,
            envelope.EventType,
            envelope.DeploymentId,
            envelope.CorrelationId,
            envelope.Payload,
            envelope.PreviousHash));

    private static string ComputeHash(HashMaterial material) =>
        Convert.ToHexString(SHA256.HashData(
            JsonSerializer.SerializeToUtf8Bytes(material, SerializerOptions)))
            .ToLowerInvariant();

    private static bool IsHash(string value) =>
        value.Length == 64 && value.All(Uri.IsHexDigit);

    private static void ValidateRegularDirectory(string path)
    {
        var directory = new DirectoryInfo(path);
        directory.Refresh();
        if (!directory.Exists || directory.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new SecurityTelemetryException(
                "The telemetry spool must use regular local directories.");
        }
    }

    private sealed record HashMaterial(
        int SchemaVersion,
        long Sequence,
        DateTimeOffset TimestampUtc,
        string Source,
        string EventType,
        string DeploymentId,
        string CorrelationId,
        JsonElement Payload,
        string PreviousHash);

    private sealed record SpoolState(
        int SchemaVersion,
        long LastSequence,
        string LastHash,
        long PrunedThroughSequence,
        string PrunedThroughHash)
    {
        public static SpoolState Empty { get; } = new(
            SecurityTelemetrySpool.SchemaVersion,
            0,
            new string('0', 64),
            0,
            new string('0', 64));
    }
}
