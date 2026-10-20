namespace UtoAegis.Infrastructure.ThreatIntelligence;

public sealed class ThreatUpdateSequenceException : Exception
{
    public ThreatUpdateSequenceException(long candidateSequence, long highestAcceptedSequence)
        : base(candidateSequence == highestAcceptedSequence
            ? $"Threat content sequence {candidateSequence} is already current."
            : $"Threat content sequence {candidateSequence} is below the accepted sequence floor {highestAcceptedSequence}.")
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(candidateSequence);
        ArgumentOutOfRangeException.ThrowIfNegative(highestAcceptedSequence);
        CandidateSequence = candidateSequence;
        HighestAcceptedSequence = highestAcceptedSequence;
    }

    public long CandidateSequence { get; }

    public long HighestAcceptedSequence { get; }

    public bool IsCurrent => CandidateSequence == HighestAcceptedSequence;
}
