using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
using UtoAegis.Core.RuntimeIntegrity;

namespace UtoAegis.Guard;

[SupportedOSPlatform("windows")]
internal sealed class WindowsRuntimeIntegrityPlatform : IRuntimeIntegrityPlatform
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryConfig = 0x0001;
    private const uint ServiceChangeConfig = 0x0002;
    private const uint ServiceQueryStatus = 0x0004;
    private const uint ServiceStart = 0x0010;
    private const uint ServiceStop = 0x0020;
    private const uint ServiceNoChange = 0xffffffff;
    private const uint ServiceAutoStart = 2;
    private const uint ServiceDemandStart = 3;
    private const uint ServiceDisabled = 4;
    private const uint ServiceConfigDelayedAutoStartInfo = 3;
    private const uint ScStatusProcessInfo = 0;
    private const uint ServiceControlStop = 1;
    private const uint ServiceStopped = 1;
    private const uint ServiceRunning = 4;
    private const int ErrorServiceDoesNotExist = 1060;

    public async ValueTask<IReadOnlyList<RuntimeIntegrityFinding>> AuditAsync(
        RuntimePolicyManifest policy,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var findings = new List<RuntimeIntegrityFinding>();
        using var manager = OpenScManager(null, null, ScManagerConnect);
        if (manager.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        foreach (var service in policy.Services)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await AuditServiceAsync(manager, service, findings, cancellationToken)
                .ConfigureAwait(false);
        }

        foreach (var path in policy.Paths)
        {
            cancellationToken.ThrowIfCancellationRequested();
            AuditPath(path, findings);
        }

        return findings;
    }

    public ValueTask RecoverAsync(
        RuntimeIntegrityFinding finding,
        RuntimePolicyManifest policy,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(finding);
        ArgumentNullException.ThrowIfNull(policy);
        cancellationToken.ThrowIfCancellationRequested();
        if (!finding.Recoverable)
        {
            throw new InvalidOperationException("The integrity finding is not recoverable.");
        }

        if (finding.Kind is RuntimeIntegrityFindingKind.ServiceBinaryPathMismatch or
            RuntimeIntegrityFindingKind.ServiceAccountMismatch or
            RuntimeIntegrityFindingKind.ServiceStartModeMismatch)
        {
            var service = policy.Services.Single(candidate =>
                string.Equals(candidate.Name, finding.Target, StringComparison.Ordinal));
            RecoverService(service, cancellationToken);
            return ValueTask.CompletedTask;
        }

        if (finding.Kind == RuntimeIntegrityFindingKind.SecurityDescriptorMismatch)
        {
            var path = policy.Paths.Single(candidate => PathEquals(candidate.Path, finding.Target));
            RecoverSecurityDescriptor(path);
            return ValueTask.CompletedTask;
        }

        throw new InvalidOperationException(
            $"Finding kind '{finding.Kind}' does not support automatic recovery.");
    }

    private static async ValueTask AuditServiceAsync(
        SafeServiceHandle manager,
        RuntimeServicePolicy policy,
        List<RuntimeIntegrityFinding> findings,
        CancellationToken cancellationToken)
    {
        using var service = OpenService(manager, policy.Name, ServiceQueryConfig);
        if (service.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            if (error == ErrorServiceDoesNotExist)
            {
                findings.Add(Finding(
                    RuntimeIntegrityFindingKind.ServiceMissing,
                    policy.Name,
                    "installed",
                    "missing",
                    false,
                    "The protected Windows service does not exist."));
                return;
            }

            findings.Add(Finding(
                RuntimeIntegrityFindingKind.InspectionFailed,
                policy.Name,
                "queryable service configuration",
                $"win32:{error}",
                false,
                "The protected Windows service configuration could not be queried."));
            return;
        }

        var configuration = QueryConfiguration(service);
        var actualBinary = ParseBinaryPath(configuration.BinaryPath);
        if (actualBinary is null || !PathEquals(actualBinary, policy.ExecutablePath))
        {
            findings.Add(Finding(
                RuntimeIntegrityFindingKind.ServiceBinaryPathMismatch,
                policy.Name,
                policy.ExecutablePath,
                configuration.BinaryPath,
                policy.Recover,
                "The service binary path or arguments differ from authenticated policy."));
        }

        if (!string.Equals(configuration.Account, policy.Account, StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(Finding(
                RuntimeIntegrityFindingKind.ServiceAccountMismatch,
                policy.Name,
                policy.Account,
                configuration.Account,
                policy.Recover,
                "The service account differs from authenticated policy."));
        }

        var actualStartMode = ToStartMode(configuration.StartType, configuration.DelayedAutomatic);
        if (actualStartMode != policy.StartMode)
        {
            findings.Add(Finding(
                RuntimeIntegrityFindingKind.ServiceStartModeMismatch,
                policy.Name,
                policy.StartMode.ToString(),
                actualStartMode.ToString(),
                policy.Recover,
                "The service start mode differs from authenticated policy."));
        }

        var executable = new FileInfo(policy.ExecutablePath);
        executable.Refresh();
        if (!executable.Exists || executable.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            findings.Add(Finding(
                RuntimeIntegrityFindingKind.ExecutableMissing,
                policy.ExecutablePath,
                policy.ExecutableSha256,
                "missing-or-unsafe",
                false,
                "The protected service executable is missing or is a reparse point."));
            return;
        }

        await using var stream = new FileStream(
            executable.FullName,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        var actualHash = Convert.ToHexString(
            await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false))
            .ToLowerInvariant();
        if (!string.Equals(actualHash, policy.ExecutableSha256, StringComparison.Ordinal))
        {
            findings.Add(Finding(
                RuntimeIntegrityFindingKind.ExecutableHashMismatch,
                policy.ExecutablePath,
                policy.ExecutableSha256,
                actualHash,
                false,
                "The service executable hash differs from authenticated policy."));
        }
    }

    private static void AuditPath(
        RuntimePathPolicy policy,
        List<RuntimeIntegrityFinding> findings)
    {
        var isDirectory = Directory.Exists(policy.Path);
        var isFile = File.Exists(policy.Path);
        if (!isDirectory && !isFile)
        {
            findings.Add(Finding(
                RuntimeIntegrityFindingKind.ProtectedPathMissing,
                policy.Path,
                "existing regular path",
                "missing",
                false,
                "The protected filesystem path does not exist."));
            return;
        }

        var attributes = File.GetAttributes(policy.Path);
        if (attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            findings.Add(Finding(
                RuntimeIntegrityFindingKind.ProtectedPathUnsafe,
                policy.Path,
                "regular path",
                "reparse-point",
                false,
                "The protected filesystem path is a reparse point."));
            return;
        }

        try
        {
            var expected = NormalizeSddl(policy.ExpectedSddl);
            var actual = isDirectory
                ? new DirectoryInfo(policy.Path).GetAccessControl(
                    AccessControlSections.Owner | AccessControlSections.Group |
                    AccessControlSections.Access).GetSecurityDescriptorSddlForm(
                    AccessControlSections.Owner | AccessControlSections.Group |
                    AccessControlSections.Access)
                : new FileInfo(policy.Path).GetAccessControl(
                    AccessControlSections.Owner | AccessControlSections.Group |
                    AccessControlSections.Access).GetSecurityDescriptorSddlForm(
                    AccessControlSections.Owner | AccessControlSections.Group |
                    AccessControlSections.Access);
            actual = NormalizeSddl(actual);
            if (!string.Equals(actual, expected, StringComparison.Ordinal))
            {
                findings.Add(Finding(
                    RuntimeIntegrityFindingKind.SecurityDescriptorMismatch,
                    policy.Path,
                    Sha256Text(expected),
                    Sha256Text(actual),
                    policy.Recover,
                    "The owner, group, or DACL differs from authenticated policy."));
            }
        }
        catch (Exception exception) when (
            exception is ArgumentException or IOException or UnauthorizedAccessException or
                SystemException)
        {
            findings.Add(Finding(
                RuntimeIntegrityFindingKind.InspectionFailed,
                policy.Path,
                "readable security descriptor",
                exception.GetType().Name,
                false,
                "The protected filesystem security descriptor could not be inspected."));
        }
    }

    private static void RecoverService(
        RuntimeServicePolicy policy,
        CancellationToken cancellationToken)
    {
        using var manager = OpenScManager(null, null, ScManagerConnect);
        if (manager.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        using var service = OpenService(
            manager,
            policy.Name,
            ServiceChangeConfig | ServiceQueryStatus | ServiceStart | ServiceStop);
        if (service.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        var status = QueryStatus(service);
        var wasRunning = status.CurrentState != ServiceStopped;
        var startType = policy.StartMode switch
        {
            RuntimeServiceStartMode.Automatic or RuntimeServiceStartMode.DelayedAutomatic =>
                ServiceAutoStart,
            RuntimeServiceStartMode.Manual => ServiceDemandStart,
            RuntimeServiceStartMode.Disabled => ServiceDisabled,
            _ => throw new InvalidOperationException("The authenticated service start mode is invalid.")
        };
        var binaryPath = $"\"{policy.ExecutablePath}\"";
        if (!ChangeServiceConfig(
                service,
                ServiceNoChange,
                startType,
                ServiceNoChange,
                binaryPath,
                null,
                IntPtr.Zero,
                null,
                policy.Account,
                null,
                null))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        var delayed = new ServiceDelayedAutoStartInfo
        {
            DelayedAutoStart = policy.StartMode == RuntimeServiceStartMode.DelayedAutomatic
        };
        var size = Marshal.SizeOf<ServiceDelayedAutoStartInfo>();
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(delayed, buffer, false);
            if (!ChangeServiceConfig2(service, ServiceConfigDelayedAutoStartInfo, buffer))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        if (!wasRunning)
        {
            return;
        }

        if (!ControlService(service, ServiceControlStop, out _))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        WaitForState(service, ServiceStopped, cancellationToken);
        if (policy.StartMode == RuntimeServiceStartMode.Disabled)
        {
            return;
        }

        if (!StartService(service, 0, null))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        WaitForState(service, ServiceRunning, cancellationToken);
    }

    private static void RecoverSecurityDescriptor(RuntimePathPolicy policy)
    {
        var sections = AccessControlSections.Owner | AccessControlSections.Group |
            AccessControlSections.Access;
        if (Directory.Exists(policy.Path))
        {
            var security = new DirectorySecurity();
            security.SetSecurityDescriptorSddlForm(policy.ExpectedSddl, sections);
            new DirectoryInfo(policy.Path).SetAccessControl(security);
            return;
        }

        if (File.Exists(policy.Path))
        {
            var security = new FileSecurity();
            security.SetSecurityDescriptorSddlForm(policy.ExpectedSddl, sections);
            new FileInfo(policy.Path).SetAccessControl(security);
            return;
        }

        throw new FileNotFoundException("The protected path no longer exists.", policy.Path);
    }

    private static ServiceConfigurationSnapshot QueryConfiguration(SafeServiceHandle service)
    {
        _ = QueryServiceConfig(service, IntPtr.Zero, 0, out var required);
        if (required == 0)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        var buffer = Marshal.AllocHGlobal(checked((int)required));
        try
        {
            if (!QueryServiceConfig(service, buffer, required, out _))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            var native = Marshal.PtrToStructure<NativeQueryServiceConfig>(buffer);
            var delayedBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<ServiceDelayedAutoStartInfo>());
            try
            {
                var delayed = false;
                if (QueryServiceConfig2(
                        service,
                        ServiceConfigDelayedAutoStartInfo,
                        delayedBuffer,
                        (uint)Marshal.SizeOf<ServiceDelayedAutoStartInfo>(),
                        out _))
                {
                    delayed = Marshal.PtrToStructure<ServiceDelayedAutoStartInfo>(delayedBuffer)
                        .DelayedAutoStart;
                }

                return new ServiceConfigurationSnapshot(
                    Marshal.PtrToStringUni(native.BinaryPathName) ?? string.Empty,
                    Marshal.PtrToStringUni(native.ServiceStartName) ?? string.Empty,
                    native.StartType,
                    delayed);
            }
            finally
            {
                Marshal.FreeHGlobal(delayedBuffer);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static ServiceStatusProcess QueryStatus(SafeServiceHandle service)
    {
        var size = Marshal.SizeOf<ServiceStatusProcess>();
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (!QueryServiceStatusEx(
                    service,
                    ScStatusProcessInfo,
                    buffer,
                    (uint)size,
                    out _))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return Marshal.PtrToStructure<ServiceStatusProcess>(buffer);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static void WaitForState(
        SafeServiceHandle service,
        uint expectedState,
        CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(30);
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var status = QueryStatus(service);
            if (status.CurrentState == expectedState)
            {
                return;
            }

            if (DateTimeOffset.UtcNow >= deadline)
            {
                throw new TimeoutException(
                    $"The protected service did not reach state {expectedState} within 30 seconds.");
            }

            Thread.Sleep(250);
        }
    }

    private static string? ParseBinaryPath(string value)
    {
        var text = value.Trim();
        if (text.Length == 0)
        {
            return null;
        }

        string path;
        string remainder;
        if (text[0] == '"')
        {
            var closing = text.IndexOf('"', 1);
            if (closing < 2)
            {
                return null;
            }

            path = text[1..closing];
            remainder = text[(closing + 1)..].Trim();
        }
        else
        {
            path = text;
            remainder = string.Empty;
        }

        if (remainder.Length != 0 || !Path.IsPathFullyQualified(path))
        {
            return null;
        }

        return Path.GetFullPath(Environment.ExpandEnvironmentVariables(path));
    }

    private static RuntimeServiceStartMode ToStartMode(uint startType, bool delayed) =>
        startType switch
        {
            ServiceAutoStart when delayed => RuntimeServiceStartMode.DelayedAutomatic,
            ServiceAutoStart => RuntimeServiceStartMode.Automatic,
            ServiceDemandStart => RuntimeServiceStartMode.Manual,
            ServiceDisabled => RuntimeServiceStartMode.Disabled,
            _ => throw new InvalidOperationException(
                $"Unsupported Windows service start type '{startType}'.")
        };

    private static string NormalizeSddl(string sddl)
    {
        var descriptor = new RawSecurityDescriptor(sddl);
        return descriptor.GetSddlForm(
            AccessControlSections.Owner | AccessControlSections.Group |
            AccessControlSections.Access);
    }

    private static string Sha256Text(string value) =>
        Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value)))
            .ToLowerInvariant();

    private static RuntimeIntegrityFinding Finding(
        RuntimeIntegrityFindingKind kind,
        string target,
        string expected,
        string actual,
        bool recoverable,
        string message) =>
        new(kind, target, expected, actual, recoverable, message);

    private static bool PathEquals(string first, string second) =>
        string.Equals(
            Path.TrimEndingDirectorySeparator(first),
            Path.TrimEndingDirectorySeparator(second),
            StringComparison.OrdinalIgnoreCase);

    [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeServiceHandle OpenScManager(
        string? machineName,
        string? databaseName,
        uint desiredAccess);

    [DllImport("advapi32.dll", EntryPoint = "OpenServiceW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeServiceHandle OpenService(
        SafeServiceHandle serviceManager,
        string serviceName,
        uint desiredAccess);

    [DllImport("advapi32.dll", EntryPoint = "QueryServiceConfigW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceConfig(
        SafeServiceHandle service,
        IntPtr serviceConfig,
        uint bufferSize,
        out uint bytesNeeded);

    [DllImport("advapi32.dll", EntryPoint = "QueryServiceConfig2W", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceConfig2(
        SafeServiceHandle service,
        uint infoLevel,
        IntPtr buffer,
        uint bufferSize,
        out uint bytesNeeded);

    [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfigW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ChangeServiceConfig(
        SafeServiceHandle service,
        uint serviceType,
        uint startType,
        uint errorControl,
        string? binaryPathName,
        string? loadOrderGroup,
        IntPtr tagId,
        string? dependencies,
        string? serviceStartName,
        string? password,
        string? displayName);

    [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfig2W", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ChangeServiceConfig2(
        SafeServiceHandle service,
        uint infoLevel,
        IntPtr info);

    [DllImport("advapi32.dll", EntryPoint = "QueryServiceStatusEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatusEx(
        SafeServiceHandle service,
        uint infoLevel,
        IntPtr buffer,
        uint bufferSize,
        out uint bytesNeeded);

    [DllImport("advapi32.dll", EntryPoint = "ControlService", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ControlService(
        SafeServiceHandle service,
        uint control,
        out ServiceStatus status);

    [DllImport("advapi32.dll", EntryPoint = "StartServiceW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool StartService(
        SafeServiceHandle service,
        uint argumentCount,
        string[]? arguments);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr serviceHandle);

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeQueryServiceConfig
    {
        public uint ServiceType;
        public uint StartType;
        public uint ErrorControl;
        public IntPtr BinaryPathName;
        public IntPtr LoadOrderGroup;
        public uint TagId;
        public IntPtr Dependencies;
        public IntPtr ServiceStartName;
        public IntPtr DisplayName;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceDelayedAutoStartInfo
    {
        [MarshalAs(UnmanagedType.Bool)]
        public bool DelayedAutoStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
        public uint ProcessId;
        public uint ServiceFlags;
    }

    private sealed class SafeServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeServiceHandle()
            : base(true)
        {
        }

        protected override bool ReleaseHandle() => CloseServiceHandle(handle);
    }

    private sealed record ServiceConfigurationSnapshot(
        string BinaryPath,
        string Account,
        uint StartType,
        bool DelayedAutomatic);
}
