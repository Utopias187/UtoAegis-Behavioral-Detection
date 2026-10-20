using UtoAegis.Core.Scanning;

namespace UtoAegis.Core.Tests;

[TestClass]
public sealed class ReloadableFileScannerTests
{
    [TestMethod]
    public async Task Replace_SubsequentScanUsesNewGeneration()
    {
        var scanner = new ReloadableFileScanner(new StubScanner("first"));

        var generation = scanner.Replace(new StubScanner("second"));
        var result = await scanner.ScanAsync("sample.bin");

        Assert.AreEqual(2L, generation);
        Assert.AreEqual(generation, scanner.Generation);
        Assert.AreEqual("second", result.Path);
    }

    [TestMethod]
    public async Task Replace_InFlightScanFinishesOnCapturedGeneration()
    {
        var first = new BlockingScanner("first");
        var scanner = new ReloadableFileScanner(first);
        var pendingScan = scanner.ScanAsync("sample.bin").AsTask();
        await first.Started.Task;

        scanner.Replace(new StubScanner("second"));
        first.Release.SetResult();

        var originalResult = await pendingScan;
        var currentResult = await scanner.ScanAsync("sample.bin");
        Assert.AreEqual("first", originalResult.Path);
        Assert.AreEqual("second", currentResult.Path);
    }

    private static FileScanResult Result(string path) =>
        new(
            FileHashScanResult.Failure(
                FileHashScanStatus.FileNotFound,
                path,
                TimeSpan.Zero,
                "test"),
            null,
            null);

    private sealed class StubScanner(string resultPath) : IFileScanner
    {
        public ValueTask<FileScanResult> ScanAsync(
            string path,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(Result(resultPath));
    }

    private sealed class BlockingScanner(string resultPath) : IFileScanner
    {
        public TaskCompletionSource Started { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource Release { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async ValueTask<FileScanResult> ScanAsync(
            string path,
            CancellationToken cancellationToken = default)
        {
            Started.SetResult();
            await Release.Task.WaitAsync(cancellationToken);
            return Result(resultPath);
        }
    }
}
