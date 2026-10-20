namespace UtoAegis.Updater;

public sealed record UpdaterRetryPolicy
{
    public UpdaterRetryPolicy(
        int maximumAttempts,
        TimeSpan initialDelay,
        TimeSpan maximumDelay)
    {
        if (maximumAttempts is < 1 or > 10)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumAttempts));
        }

        if (initialDelay < TimeSpan.FromSeconds(1) ||
            initialDelay > TimeSpan.FromMinutes(5))
        {
            throw new ArgumentOutOfRangeException(nameof(initialDelay));
        }

        if (maximumDelay < initialDelay || maximumDelay > TimeSpan.FromHours(1))
        {
            throw new ArgumentOutOfRangeException(nameof(maximumDelay));
        }

        MaximumAttempts = maximumAttempts;
        InitialDelay = initialDelay;
        MaximumDelay = maximumDelay;
    }

    public int MaximumAttempts { get; }

    public TimeSpan InitialDelay { get; }

    public TimeSpan MaximumDelay { get; }

    public TimeSpan GetDelay(int failedAttempt)
    {
        if (failedAttempt < 1 || failedAttempt >= MaximumAttempts)
        {
            throw new ArgumentOutOfRangeException(nameof(failedAttempt));
        }

        var multiplier = Math.Pow(2, failedAttempt - 1);
        var ticks = Math.Min(
            InitialDelay.Ticks * multiplier,
            MaximumDelay.Ticks);
        return TimeSpan.FromTicks(checked((long)ticks));
    }
}
