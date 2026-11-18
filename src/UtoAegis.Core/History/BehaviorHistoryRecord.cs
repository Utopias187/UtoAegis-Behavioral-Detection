using UtoAegis.Core.Behavior;
using UtoAegis.Core.RiskScoring;

namespace UtoAegis.Core.History;

public sealed record BehaviorHistoryCategory(
    BehaviorFeatureCategory Category,
    int AppliedPoints);

public sealed record BehaviorHistoryRecord(
    Guid Id,
    DateTimeOffset RecordedUtc,
    Guid CollectorGenerationId,
    int ProcessId,
    long ProcessStartSequence,
    DateTimeOffset? WindowStartedUtc,
    DateTimeOffset? WindowEndedUtc,
    RiskVerdict Verdict,
    int Score,
    int Confidence,
    BehaviorProviderState ProviderState,
    string PolicyId,
    int PolicyVersion,
    int EventCount,
    IReadOnlyList<string> FeatureIds,
    IReadOnlyList<BehaviorHistoryCategory> Categories)
{
    public static BehaviorHistoryRecord FromAssessment(
        Guid id,
        DateTimeOffset recordedUtc,
        BehaviorAssessment assessment)
    {
        ArgumentNullException.ThrowIfNull(assessment);
        if (id == Guid.Empty || assessment.Subject is null)
        {
            throw new ArgumentException("Behavior history requires an ID and process subject.");
        }

        var subject = assessment.Subject.Value;
        return new BehaviorHistoryRecord(
            id,
            recordedUtc.ToUniversalTime(),
            subject.CollectorGenerationId,
            subject.ProcessId,
            subject.StartSequence,
            assessment.WindowStartedUtc,
            assessment.WindowEndedUtc,
            assessment.Verdict,
            assessment.Score,
            assessment.Confidence,
            assessment.ProviderState,
            assessment.PolicyId,
            assessment.PolicyVersion,
            assessment.EventCount,
            assessment.Features.Select(item => item.Id).Order(StringComparer.Ordinal).ToArray(),
            assessment.Categories
                .Where(item => item.AppliedPoints > 0)
                .Select(item => new BehaviorHistoryCategory(item.Category, item.AppliedPoints))
                .ToArray());
    }
}

public interface IBehaviorHistoryStore
{
    ValueTask InitializeAsync(CancellationToken cancellationToken = default);

    ValueTask AppendAsync(BehaviorHistoryRecord record, CancellationToken cancellationToken = default);

    ValueTask<IReadOnlyList<BehaviorHistoryRecord>> ListAsync(
        int limit,
        CancellationToken cancellationToken = default);
}

public sealed class BehaviorHistoryStoreException : Exception
{
    public BehaviorHistoryStoreException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}
