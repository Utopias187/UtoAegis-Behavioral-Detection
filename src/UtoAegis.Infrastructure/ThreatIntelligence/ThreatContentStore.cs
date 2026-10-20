using UtoAegis.Core.Reputation;
using UtoAegis.Core.ThreatIntelligence;
using UtoAegis.Infrastructure.Reputation;
using System.Globalization;

namespace UtoAegis.Infrastructure.ThreatIntelligence;

public sealed class ThreatContentStore
{
    public const string StateFileName = "state.json";
    public const string ReputationDatabaseFileName = "reputation.db";

    private readonly string _rootPath;
    private readonly string _versionsPath;
    private readonly string _stagingPath;
    private readonly string _statePath;
    private readonly string _lockPath;
    private readonly SignedThreatBundleVerifier? _verifier;

    public ThreatContentStore(string rootPath)
        : this(rootPath, verifier: null, statusOnly: true)
    {
    }

    public ThreatContentStore(string rootPath, SignedThreatBundleVerifier verifier)
        : this(
            rootPath,
            verifier ?? throw new ArgumentNullException(nameof(verifier)),
            statusOnly: false)
    {
    }

    private ThreatContentStore(
        string rootPath,
        SignedThreatBundleVerifier? verifier,
        bool statusOnly)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootPath);
        if (!statusOnly)
        {
            ArgumentNullException.ThrowIfNull(verifier);
        }
        _rootPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(rootPath));
        if (string.Equals(
                _rootPath,
                Path.TrimEndingDirectorySeparator(Path.GetPathRoot(_rootPath)!),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "The threat-content store cannot use a filesystem root.",
                nameof(rootPath));
        }
        _versionsPath = Path.Combine(_rootPath, "versions");
        _stagingPath = Path.Combine(_rootPath, "staging");
        _statePath = Path.Combine(_rootPath, StateFileName);
        _lockPath = Path.Combine(_rootPath, "update.lock");
        _verifier = verifier;
    }

    public async ValueTask<ThreatContentSnapshot> ApplyAsync(
        string bundleDirectory,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        PrepareDirectories();
        await using var operationLock = AcquireOperationLock();
        var state = await ThreatContentStateFile.ReadAsync(_statePath, cancellationToken)
            .ConfigureAwait(false);
        var stagePath = CreateStagingPath();
        string? uncommittedVersionPath = null;
        var stateCommitted = false;

        try
        {
            var verified = await RequireVerifier().VerifyAndStageAsync(
                bundleDirectory,
                stagePath,
                state?.HighestAcceptedSequence ?? 0,
                cancellationToken).ConfigureAwait(false);
            await BuildReputationDatabaseAsync(verified, cancellationToken).ConfigureAwait(false);

            var reference = ThreatContentReference.FromManifest(verified.Manifest);
            var finalPath = GetVersionPath(reference);
            if (Directory.Exists(finalPath) || File.Exists(finalPath))
            {
                throw new ThreatUpdateException(
                    "The verified threat-content version already exists in the store.");
            }

            Directory.Move(stagePath, finalPath);
            uncommittedVersionPath = finalPath;
            var nextState = new ThreatContentState(
                reference,
                state?.Active,
                verified.Manifest.Sequence);
            await WriteStateAsync(nextState, cancellationToken).ConfigureAwait(false);
            stateCommitted = true;
            return CreateSnapshot(verified.Manifest, finalPath);
        }
        catch (OperationCanceledException)
        {
            DeleteOwnedStagingDirectory(stagePath);
            DeleteUncommittedVersionDirectory(uncommittedVersionPath, stateCommitted);
            throw;
        }
        catch (ThreatUpdateException)
        {
            DeleteOwnedStagingDirectory(stagePath);
            DeleteUncommittedVersionDirectory(uncommittedVersionPath, stateCommitted);
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or ReputationStoreException)
        {
            DeleteOwnedStagingDirectory(stagePath);
            DeleteUncommittedVersionDirectory(uncommittedVersionPath, stateCommitted);
            throw new ThreatUpdateException("The threat update could not be activated.", exception);
        }
    }

    public async ValueTask<ThreatContentSnapshot> GetActiveAsync(
        CancellationToken cancellationToken = default)
    {
        PrepareDirectories();
        await using var operationLock = AcquireOperationLock();
        var state = await ThreatContentStateFile.ReadAsync(_statePath, cancellationToken)
            .ConfigureAwait(false) ??
            throw new ThreatUpdateException("The threat-content store has no active version.");
        return await ValidateInstalledAsync(state.Active, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<ThreatContentSnapshot> GetActiveReadOnlyAsync(
        CancellationToken cancellationToken = default)
    {
        EnsureRegularDirectory(_rootPath);
        EnsureRegularDirectory(_versionsPath);
        var state = await ThreatContentStateFile.ReadAsync(_statePath, cancellationToken)
            .ConfigureAwait(false) ??
            throw new ThreatUpdateException("The threat-content store has no active version.");
        var contentPath = GetVersionPath(state.Active);
        var verified = await RequireVerifier().VerifyInstalledAsync(
            contentPath,
            state.Active.Sequence,
            cancellationToken).ConfigureAwait(false);
        await ValidateInstalledDatabaseAsync(
            verified,
            contentPath,
            cancellationToken).ConfigureAwait(false);
        return CreateSnapshot(verified.Manifest, contentPath);
    }

    public async ValueTask<ThreatContentSnapshot> RollbackAsync(
        CancellationToken cancellationToken = default)
    {
        PrepareDirectories();
        await using var operationLock = AcquireOperationLock();
        var state = await ThreatContentStateFile.ReadAsync(_statePath, cancellationToken)
            .ConfigureAwait(false) ??
            throw new ThreatUpdateException("The threat-content store has no active version.");
        if (state.Previous is null)
        {
            throw new ThreatUpdateException(
                "The threat-content store has no previous version to restore.");
        }

        var snapshot = await ValidateInstalledAsync(state.Previous, cancellationToken)
            .ConfigureAwait(false);
        var nextState = new ThreatContentState(
            state.Previous,
            state.Active,
            state.HighestAcceptedSequence);
        await WriteStateAsync(nextState, cancellationToken).ConfigureAwait(false);
        return snapshot;
    }

    public async ValueTask<ThreatContentStoreStatus> GetStatusAsync(
        CancellationToken cancellationToken = default)
    {
        PrepareDirectories();
        await using var operationLock = AcquireOperationLock();
        var state = await ThreatContentStateFile.ReadAsync(_statePath, cancellationToken)
            .ConfigureAwait(false);
        return state is null
            ? new ThreatContentStoreStatus(false, null, null, null, null, 0)
            : new ThreatContentStoreStatus(
                true,
                state.Active.Version,
                state.Active.Sequence,
                state.Previous?.Version,
                state.Previous?.Sequence,
                state.HighestAcceptedSequence);
    }

    public async ValueTask<ThreatContentPruneResult> PruneAsync(
        int maximumRetainedVersions,
        CancellationToken cancellationToken = default)
    {
        if (maximumRetainedVersions is < 2 or > 64)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumRetainedVersions),
                "Between 2 and 64 threat-content versions may be retained.");
        }

        PrepareDirectories();
        await using var operationLock = AcquireOperationLock();
        var state = await ThreatContentStateFile.ReadAsync(_statePath, cancellationToken)
            .ConfigureAwait(false);
        if (state is null)
        {
            return new ThreatContentPruneResult(0, 0, []);
        }

        var versions = ReadStoredVersions();
        var protectedNames = new HashSet<string>(StringComparer.Ordinal)
        {
            state.Active.DirectoryName
        };
        if (state.Previous is not null)
        {
            protectedNames.Add(state.Previous.DirectoryName);
        }

        if (protectedNames.Any(name =>
            versions.All(version => !string.Equals(
                version.DirectoryName,
                name,
                StringComparison.Ordinal))))
        {
            throw new ThreatUpdateException(
                "The threat-content state references a missing version directory.");
        }

        var retainedNames = new HashSet<string>(protectedNames, StringComparer.Ordinal);
        foreach (var version in versions
            .Where(version => !protectedNames.Contains(version.DirectoryName))
            .OrderByDescending(version => version.Sequence)
            .Take(Math.Max(0, maximumRetainedVersions - protectedNames.Count)))
        {
            retainedNames.Add(version.DirectoryName);
        }

        var deleted = new List<string>();
        foreach (var version in versions.Where(version =>
            !retainedNames.Contains(version.DirectoryName)))
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                Directory.Delete(version.Path, recursive: true);
                deleted.Add(version.Version);
            }
            catch (Exception exception) when (
                exception is IOException or UnauthorizedAccessException)
            {
                throw new ThreatUpdateException(
                    $"Threat-content version '{version.Version}' could not be pruned.",
                    exception);
            }
        }

        return new ThreatContentPruneResult(
            deleted.Count,
            versions.Count - deleted.Count,
            deleted);
    }

    private void PrepareDirectories()
    {
        Directory.CreateDirectory(_rootPath);
        EnsureRegularDirectory(_rootPath);
        Directory.CreateDirectory(_versionsPath);
        EnsureRegularDirectory(_versionsPath);
        Directory.CreateDirectory(_stagingPath);
        EnsureRegularDirectory(_stagingPath);
    }

    private List<StoredVersion> ReadStoredVersions()
    {
        var versions = new List<StoredVersion>();
        foreach (var entry in new DirectoryInfo(_versionsPath).EnumerateFileSystemInfos())
        {
            if (entry is not DirectoryInfo directory ||
                directory.Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                throw new ThreatUpdateException(
                    "The threat-content versions directory contains an unsafe entry.");
            }

            const int sequenceLength = 20;
            if (directory.Name.Length <= sequenceLength + 1 ||
                directory.Name[sequenceLength] != '-' ||
                !long.TryParse(
                    directory.Name.AsSpan(0, sequenceLength),
                    NumberStyles.None,
                    CultureInfo.InvariantCulture,
                    out var sequence) ||
                sequence <= 0)
            {
                throw new ThreatUpdateException(
                    "The threat-content versions directory contains a noncanonical version.");
            }

            var version = directory.Name[(sequenceLength + 1)..];
            string canonicalName;
            try
            {
                canonicalName = ThreatContentReference.FormatDirectoryName(sequence, version);
                _ = new ThreatContentReference(canonicalName, sequence, version);
            }
            catch (ArgumentException exception)
            {
                throw new ThreatUpdateException(
                    "The threat-content versions directory contains a noncanonical version.",
                    exception);
            }

            if (!string.Equals(directory.Name, canonicalName, StringComparison.Ordinal))
            {
                throw new ThreatUpdateException(
                    "The threat-content versions directory contains a noncanonical version.");
            }

            versions.Add(new StoredVersion(
                directory.Name,
                version,
                sequence,
                directory.FullName));
        }

        return versions;
    }

    private FileStream AcquireOperationLock()
    {
        try
        {
            return new FileStream(
                _lockPath,
                FileMode.OpenOrCreate,
                FileAccess.ReadWrite,
                FileShare.None,
                bufferSize: 1,
                FileOptions.None);
        }
        catch (IOException exception)
        {
            throw new ThreatUpdateException(
                "Another threat-content operation is already in progress.",
                exception);
        }
    }

    private async ValueTask<ThreatContentSnapshot> ValidateInstalledAsync(
        ThreatContentReference reference,
        CancellationToken cancellationToken)
    {
        var contentPath = GetVersionPath(reference);
        var verificationPath = CreateStagingPath();
        try
        {
            var verified = await RequireVerifier().VerifyInstalledAndStageAsync(
                contentPath,
                verificationPath,
                reference.Sequence,
                cancellationToken).ConfigureAwait(false);
            await ValidateInstalledDatabaseAsync(
                verified,
                contentPath,
                cancellationToken).ConfigureAwait(false);

            return CreateSnapshot(verified.Manifest, contentPath);
        }
        finally
        {
            DeleteOwnedStagingDirectory(verificationPath);
        }
    }

    private static async ValueTask ValidateInstalledDatabaseAsync(
        VerifiedThreatBundle verified,
        string contentPath,
        CancellationToken cancellationToken)
    {
        var databasePath = Path.Combine(contentPath, ReputationDatabaseFileName);
        if (!File.Exists(databasePath))
        {
            throw new ThreatUpdateException(
                "The installed threat content is missing its reputation database.");
        }

        var firstIndicator = verified.Indicators.Indicators.First();
        var database = new SqliteHashReputationStore(databasePath, pooling: false);
        var lookup = await database.LookupAsync(firstIndicator.Sha256, cancellationToken)
            .ConfigureAwait(false);
        if (lookup.Status != HashReputationStatus.Malicious)
        {
            throw new ThreatUpdateException(
                "The installed reputation database does not match the signed indicator feed.");
        }
    }

    private static async ValueTask BuildReputationDatabaseAsync(
        VerifiedThreatBundle verified,
        CancellationToken cancellationToken)
    {
        var databasePath = Path.Combine(
            verified.StagingDirectory,
            ReputationDatabaseFileName);
        var database = new SqliteHashReputationStore(databasePath, pooling: false);
        await database.InitializeAsync(cancellationToken).ConfigureAwait(false);
        var import = await database.ImportAsync(
            verified.Indicators.Indicators,
            cancellationToken).ConfigureAwait(false);
        if (import.ProcessedCount != verified.Indicators.Indicators.Count)
        {
            throw new ThreatUpdateException(
                "The staged reputation database did not import the complete signed feed.");
        }

        var firstIndicator = verified.Indicators.Indicators.First();
        var lookup = await database.LookupAsync(firstIndicator.Sha256, cancellationToken)
            .ConfigureAwait(false);
        if (lookup.Status != HashReputationStatus.Malicious)
        {
            throw new ThreatUpdateException(
                "The staged reputation database failed its validation lookup.");
        }

        await database.PrepareForReadOnlyAsync(cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask WriteStateAsync(
        ThreatContentState state,
        CancellationToken cancellationToken)
    {
        var bytes = ThreatContentStateFile.Serialize(state);
        var temporaryPath = Path.Combine(_rootPath, $"state-{Guid.NewGuid():N}.tmp");
        try
        {
            await using (var stream = new FileStream(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 16 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }

            if (File.Exists(_statePath))
            {
                File.Replace(temporaryPath, _statePath, destinationBackupFileName: null);
            }
            else
            {
                File.Move(temporaryPath, _statePath);
            }
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private string CreateStagingPath() =>
        Path.Combine(_stagingPath, Guid.NewGuid().ToString("N"));

    private string GetVersionPath(ThreatContentReference reference) =>
        Path.Combine(_versionsPath, reference.DirectoryName);

    private SignedThreatBundleVerifier RequireVerifier() =>
        _verifier ?? throw new InvalidOperationException(
            "This threat-content operation requires a configured signature verifier.");

    private static ThreatContentSnapshot CreateSnapshot(
        ThreatUpdateManifest manifest,
        string contentPath) =>
        new(
            manifest,
            contentPath,
            Path.Combine(contentPath, ReputationDatabaseFileName),
            Path.Combine(contentPath, "signatures.jsonl"));

    private static void EnsureRegularDirectory(string path)
    {
        var directory = new DirectoryInfo(path);
        directory.Refresh();
        if (!directory.Exists || directory.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new ThreatUpdateException(
                "Threat-content storage directories cannot be reparse points.");
        }
    }

    private void DeleteOwnedStagingDirectory(string path)
    {
        var parent = Path.GetDirectoryName(path);
        if (!string.Equals(parent, _stagingPath, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    private void DeleteUncommittedVersionDirectory(string? path, bool stateCommitted)
    {
        if (stateCommitted || path is null ||
            !string.Equals(
                Path.GetDirectoryName(path),
                _versionsPath,
                StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    private sealed record StoredVersion(
        string DirectoryName,
        string Version,
        long Sequence,
        string Path);
}
