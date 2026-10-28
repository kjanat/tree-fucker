using System.Diagnostics;
using System.Text.Json;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

// Emit only aggregate counts. The caller pipes stdout and stderr through
// envctl before saving evidence; no ETL with machine-wide process data is saved.
if (!OperatingSystem.IsWindows() || args.Length < 2)
    throw new ArgumentException("Usage: windows_syscalls MINIMUM_PROCESSES BINARY [ARGS...]");
int minimum = int.Parse(args[0]);
if (minimum < 1)
    throw new ArgumentException("MINIMUM_PROCESSES must be positive");
int controller = Environment.ProcessId;
var live = new HashSet<int>();
var calls = new Dictionary<ulong, long>();
int processes = 0;
using var session = new TraceEventSession($"tree-fucker-syscalls-{controller}");
session.BufferSizeMB = 64;
var source = session.Source;
source.Kernel.ProcessStart += data => {
    // Events are consumed in timestamp order on one thread. Retire identities
    // at exit, so an unrelated reuse of a PID never enters the measured cohort.
    if (data.ParentID == controller || live.Contains(data.ParentID)) {
        live.Add(data.ProcessID);
        processes++;
    }
};
source.Kernel.ProcessStop += data => live.Remove(data.ProcessID);
source.Kernel.PerfInfoSysClEnter += data => {
    if (live.Contains(data.ProcessID))
        calls[data.SysCallAddress] = calls.GetValueOrDefault(data.SysCallAddress) + 1;
};
session.EnableKernelProvider(KernelTraceEventParser.Keywords.SystemCall |
    KernelTraceEventParser.Keywords.Process | KernelTraceEventParser.Keywords.Thread);
var consumer = Task.Run(() => source.Process());
var start = new ProcessStartInfo(args[1]) {
    UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true
};
foreach (string argument in args.Skip(2))
    start.ArgumentList.Add(argument);
using var child = Process.Start(start) ?? throw new InvalidOperationException("No workload process");
var stdout = child.StandardOutput.ReadToEndAsync();
var stderr = child.StandardError.ReadToEndAsync();
try {
    using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(3));
    await child.WaitForExitAsync(deadline.Token);
} finally {
    if (!child.HasExited) {
        child.Kill(entireProcessTree: true);
        await child.WaitForExitAsync();
    }
    session.Flush();
    session.Stop();
    await consumer.WaitAsync(TimeSpan.FromSeconds(30));
}
Console.Error.Write(await stdout);
Console.Error.Write(await stderr);
if (child.ExitCode != 0 || source.EventsLost != 0 || processes < minimum || calls.Count == 0)
    throw new InvalidOperationException($"Incomplete trace: exit={child.ExitCode}, lost={source.EventsLost}, processes={processes}, syscall addresses={calls.Count}");
Console.WriteLine(JsonSerializer.Serialize(new {
    processes, events_lost = source.EventsLost,
    syscalls = calls.OrderBy(pair => pair.Key).ToDictionary(pair => $"0x{pair.Key:x}", pair => pair.Value),
    total = calls.Values.Sum(),
    scope = "benchmark controller and descendants; startup, verification, work and teardown",
    keys = "kernel syscall addresses within this boot; no symbol-name inference"
}));
