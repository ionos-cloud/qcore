const std = @import("std");
const Io = std.Io;

const process = @import("process.zig");
const proc = @import("proc.zig");
const core = @import("core.zig");
const globals = @import("globals.zig");
const log = @import("log.zig");
const Info = @import("Info.zig");
const output = @import("output.zig");
const bundle = @import("bundle.zig");
const time = @cImport({
    @cInclude("time.h");
});
const readme = @embedFile("README");

const ptrace = std.posix.ptrace;
const PTRACE = std.os.linux.PTRACE;

// std.c.prlimit doesn't allow us to specify the old_limit argument as null, so we have
// to use it directly.
pub extern "c" fn prlimit(pid: usize, resource: usize, new_limit: usize, old_limit: usize) c_int;

fn usage(program_name: []const u8) void {
    std.debug.print(
        \\Usage: {s} [options] <pid>
        \\
        \\qcore can grab a core dump from a running process with minimal downtime.
        \\It does so by stopping the process, injecting a fork() into it, collecting
        \\some information and letting the process run again.
        \\The child is then used to construct the core dump.
        \\Finally, the target is grabbed again to inject a final wait() to reap the
        \\child not to leave a zombie behind.
        \\qcore also collect additional information about the process and network
        \\state. All information is either written to a directory or directly to a
        \\.tar.zst archive.
        \\See also the README file placed in the output.
        \\qcore is statically linked and can be used on any linux installation.
        \\
        \\  Options:
        \\  -b        : also bundle binary and executable to allow standalone debugging
        \\  -c        : directly generate a compressed archive
        \\  -f        : force operation even though seccomp is enabled. It cannot (yet)
        \\            : detect the exact seccomp filters. Depending on these, it might
        \\            : or might not be safe to proceed.
        \\  -j <n>    : number of threads to use (default num CPUs)
        \\  -o <path> : output path
        \\  -q        : decrease verbosity
        \\  -v        : increase verbosity (default 3, max 9)
        \\
    , .{program_name});
    std.process.exit(1);
}

fn checkElfHeader(gpa: std.mem.Allocator, io: Io, pid: i32) !void {
    const path = try std.fmt.allocPrint(gpa, "/proc/{d}/exe", .{pid});
    defer gpa.free(path);
    const file = std.Io.Dir.openFileAbsolute(io, path, .{}) catch |err| {
        if (err == error.FileNotFound) {
            log.E("Process with PID {} does not exist.", .{pid});
            return error.ProcessNotFound;
        }
        log.E("Failed to open {s}: {}", .{path, err});
        return err;
    };

    defer file.close(io);

    var buffer: [5]u8 = undefined;
    const nread = file.readPositionalAll(io, &buffer, 0) catch |err| {
        log.E("Failed to file ELF header: {}", .{err});
        return err;
    };
    if (nread < buffer.len) {
        log.E("Failed to read complete ELF header, read {} bytes", .{nread});
        return error.ReadFailed;
    }
    if (!std.mem.eql(u8, buffer[0..4], "\x7fELF")) {
        log.E("Target process is not an ELF executable.", .{});
        return error.NotElf;
    }
    if (buffer[4] != 2) {
        log.E("Target process is not a 64-bit ELF executable.", .{});
        return error.NotElf64;
    }
}

fn isSeccompEnabled(target_status: proc.Status) !bool {
    const seccomp_state = target_status.get("Seccomp") orelse {
        log.E("Seccomp state not found in process status.", .{});
        return error.SeccompStateNotFound;
    };
    log.D1("Seccomp state: {s}", .{seccomp_state});
    const seccomp_state_int = try std.fmt.parseInt(usize, seccomp_state, 10);
    return seccomp_state_int != 0;
}

fn forkTarget(gpa: std.mem.Allocator, io: Io, pid: i32, syscall_addr: usize, nproc: usize)
    !struct {i32, i32, process.ThreadInfo, Info }
{
    //
    // attach to the process and stop all threads
    //
    const grab_start = std.Io.Clock.boot.now(io).toNanoseconds();
    const pids = try process.grab(gpa, io, pid);
    const grab_end = std.Io.Clock.boot.now(io).toNanoseconds();
    log.V("Grab took {d}ms", .{@divTrunc(grab_end - grab_start, 1000000)});
    defer process.detach(pids);

    //
    // fetch all registers and other thread info
    //
    const thread_info = try process.fetchThreadInfo(gpa, pids, pid);
    const thread_info_end = std.Io.Clock.boot.now(io).toNanoseconds();
    log.V("Collecting thread info took {d}ms",
        .{@divTrunc(thread_info_end - grab_end, 1000000)});

    //
    // fetch general and network info
    //
    const net_info = try Info.collect(gpa, pid, pids, nproc);
    const net_info_end = std.Io.Clock.boot.now(io).toNanoseconds();
    log.V("Collecting network info took {d}ms",
        .{@divTrunc(net_info_end - thread_info_end, 1000000)});

    //
    // choose injection thread
    //
    const i_pid = try process.findInjectionThread(pids);

    //
    // get fd limit of target
    //
    var rlim: std.c.rlimit = undefined;
    // const ret = std.c.prlimit(pid, std.c.rlimit_resource.NOFILE, null, &rlim);
    const ret = prlimit(@intCast(pid), @intFromEnum(std.c.rlimit_resource.NOFILE),
        0, @intFromPtr(&rlim));
    if (ret == -1) {
        log.E("Failed to get fd limit of target: {}", .{std.c._errno()});
        return error.GetFdLimitFailed;
    }
    log.D1("Target fd limit is {}", .{rlim.cur});

    //
    // inject fork into child
    //
    const inject_start = std.Io.Clock.boot.now(io).toNanoseconds();
    const child_nspid, const child_hostpid = try process.cloneChild(i_pid, syscall_addr,
        rlim.cur);
    const inject_end = std.Io.Clock.boot.now(io).toNanoseconds();
    log.V("Fork took {d}ms", .{@divTrunc(inject_end - inject_start, 1000000)});
    log.D1("Prepared injection thread with pid {}/{}", .{child_nspid, child_hostpid});
    log.I("Target blocked for {d}ms to fork child",
        .{@divTrunc(inject_end - grab_start, 1000000)});

    return .{ child_nspid, child_hostpid, thread_info, net_info };
}

fn dumpThreads(gpa: std.mem.Allocator, out: *output.Output, thread_info: process.ThreadInfo)
    !void
{
    var buffer: std.ArrayList(u8) = .empty;
    defer buffer.deinit(gpa);

    try buffer.print(gpa, "Thread-id Host-PID NS-PID Name\n", .{});
    for (thread_info.items, 1..) |thread, id| {
        try buffer.print(gpa, "{d} {d} {d} {s}\n", .{
            id,
            thread.pid,
            try proc.getNSPidFromStatus(&thread.status.?, "NSpid"),
            thread.state.?.comm
        });
    }

    var file = out.startFile("threads", buffer.items.len, null) catch |err| {
        log.E("Failed to start output file: {}", .{err});
        return err;
    };
    try file.addChunk(buffer.items);
    try file.finish();
}

fn dumpTarget(gpa: std.mem.Allocator, io: Io, out: *output.Output, child: i32, pmaps: proc.Maps,
    thread_info: process.ThreadInfo, target_state: proc.State, target_status: proc.Status,
    is_archive: bool) !void
{
    var sim: output.File = undefined;
    var length: usize = 0;
    // to write to an archive, we have to know the length and the holes in advance,
    // so we have to do a simulation run to get that info.
    if (is_archive) {
        const sim_start = std.Io.Clock.boot.now(io).toNanoseconds();
        sim = try out.startSimulation();
        defer sim.finish() catch {};
        core.dump(gpa, io, &sim, child, pmaps, thread_info, target_state, target_status)
            catch |err|
        {
            log.E("Failed to dump target: {}", .{err});
            return err;
        };
        const sim_end = std.Io.Clock.boot.now(io).toNanoseconds();
        log.V("dump simulation took {d}ms", .{@divTrunc(sim_end - sim_start, 1000000)});
        length = sim.length();
    }
    // do the real dump
    var file = try out.startFile("core", length, sim);
    errdefer file.finish() catch {};
    core.dump(gpa, io, &file, child, pmaps, thread_info, target_state, target_status) catch |err|
    {
        log.E("Failed to dump target: {}", .{err});
        return err;
    };
    file.finish() catch |err| {
        log.E("Failed to finish file: {}", .{err});
        return err;
    };
}

fn cleanupTarget(gpa: std.mem.Allocator, io: Io, pid: i32, child_nspid: i32,
    child_hostpid: i32, syscall_addr: usize) !void
{
    //
    // send kill
    //
    log.D1("Killing child with pid {}", .{child_hostpid});
    std.posix.kill(child_hostpid, std.posix.SIG.KILL) catch |err| {
        log.E("Failed to kill forked child: {}", .{err});
    };

    //
    // wait for child to be defunct
    //
    log.I("Waiting for child to become defunct.", .{});
    while (true) {
        const state = proc.getState(gpa, io, child_hostpid) catch |err| {
            log.E("Failed to get process status: {}", .{err});
            break;
        };
        if (state.state == 'Z')
            break;
        log.D1("Waiting for child, current state: {c}", .{state.state});
        io.sleep(.fromMilliseconds(100), .awake) catch |err| {
            log.E("Failed to sleep: {}", .{err});
            break;
        };
    }
    log.V("Child is defunct", .{});

    //
    // attach and stop the main threads
    //
    log.V("Reaping child", .{});
    log.D1("Attaching to main process pid {}", .{pid});
    const grab_start = std.Io.Clock.boot.now(io).toNanoseconds();
    const restart_sig = try process.grabOne(pid);
    const grab_end = std.Io.Clock.boot.now(io).toNanoseconds();
    log.V("Grab took {d}ms", .{@divTrunc(grab_end - grab_start, 1000000)});
    defer process.detachOne(pid, restart_sig);

    //
    // inject wait4 to reap our child
    //
    process.waitChild(pid, child_nspid, syscall_addr) catch |err| {
        log.E("Failed to wait for forked child: {}", .{err});
    };
    const wait_end = std.Io.Clock.boot.now(io).toNanoseconds();
    log.V("wait took {d}ms", .{@divTrunc(wait_end - grab_end, 1000000)});
    log.I("target blocked for {d}ms to reap child",
        .{@divTrunc(wait_end - grab_start, 1000000)});
}

//
// extract state and status for all threads from the /proc dump during freeze.
// This is pretty cpu-intensive, so we do it afterwards
//
fn extractStateStatus(gpa: std.mem.Allocator, thread_info: *process.ThreadInfo, net_info: Info,
    pid: i32) !struct { proc.State, proc.Status, proc.Maps }
{
    var main_state: ?proc.State = null;
    var main_status: ?proc.Status = null;
    var buf: [256]u8 = undefined;

    for (thread_info.items) |*thread| {
        std.debug.assert(thread.state == null);
        std.debug.assert(thread.status == null);

        const e_state = net_info.files.get(
            try std.fmt.bufPrint(&buf, "/proc/{d}/task/{d}/stat", .{pid, thread.pid})) orelse
        {
            log.E("Thread with pid {} found in thread info but not in network info.",
                .{thread.pid});
            return error.ThreadInfoMismatch;
        };
        thread.state = proc.parseState(gpa, e_state.content) catch |err| {
            log.E("Failed to parse state for thread {}: {}", .{thread.pid, err});
            return err;
        };

        const e_status = net_info.files.get(
            try std.fmt.bufPrint(&buf, "/proc/{d}/task/{d}/status", .{pid, thread.pid})) orelse
        {
            log.E("Thread with pid {} found in thread info but not in network info.",
                .{thread.pid});
            return error.ThreadInfoMismatch;
        };
        thread.status = proc.parseStatus(gpa, e_status.content) catch |err| {
            log.E("Failed to parse status for thread {}: {}", .{thread.pid, err});
            return err;
        };

        if (thread.pid == pid) {
            main_state = thread.state;
            main_status = thread.status;
        }
    }

    if (main_state == null or main_status == null) {
        log.E("Main thread with pid {} not found in thread info.", .{pid});
        return error.MainThreadNotFound;
    }

    const e_smaps = net_info.files.get(
        try std.fmt.bufPrint(&buf, "/proc/{d}/smaps", .{pid})) orelse
    blk: {
        const e_maps = net_info.files.get(
        try std.fmt.bufPrint(&buf, "/proc/{d}/maps", .{pid})) orelse {
            log.E("No smaps/maps file found", .{});
            return error.ThreadInfoMismatch;
        };
        break :blk e_maps;
    };
    const maps = proc.parseMaps(gpa, e_smaps.content) catch |err| {
        log.E("Failed to parse smaps for thread {}: {}", .{pid,  err});
        return err;
    };

    return .{ main_state.?, main_status.?, maps };
}

fn signalHandler(_: std.posix.SIG) callconv(.c) void {
    globals.interrupted.store(true, .seq_cst);
}

fn alarmHandler(_: std.posix.SIG) callconv(.c) void {
}

fn dumpStackTrace(trace: ?*std.builtin.StackTrace) void {
    if (trace) |t| {
        const dt: std.debug.StackTrace = .{
            .return_addresses = t.instruction_addresses[0..t.index],
            .skipped = .none,
        };

        std.debug.dumpStackTrace(&dt);
    }
}

fn formatCurrTime(gpa: std.mem.Allocator) ![]const u8 {
    var buf: [64]u8 = undefined;
    var tm: time.struct_tm = undefined;
    const now = time.time(null);
    _ = time.localtime_r(&now, &tm);
    const len = time.strftime(&buf, buf.len, "%Y%m%d-%H%M%S", &tm);
    if (len == 0) {
        log.E("Failed to format current time", .{});
        return error.FormatTimeFailed;
    }
    return try gpa.dupe(u8, buf[0..len]);
}

//
// Future improvements
//  - support for 32 bit targets
//  - support for other architectures
//  - support for other OSes
//  - speed up:
//    - parallelize seize and collection of threads
//    - mutex around StringHashMap in Info.zig might be a bottleneck
//    - detach each thread right after it is collection, to reduce average block time
//  - make net collection optional
//  - better seccomp check (parse bpf?) to determine if attachment is safe
//  - grab core from multiple processes atomically
//  - compose network state summary file from all collected info
//  - actually free memory for the fun of it
//
pub fn main(init: std.process.Init) !u8 {
    const gpa: std.mem.Allocator = init.arena.allocator();

    const args = try init.minimal.args.toSlice(gpa);
    var force: bool = false;
    var compress: bool = false;
    var log_level: log.Level = log.Level.Info;
    var nproc: usize = try std.Thread.getCpuCount();
    var optind: usize = 1;
    var do_bundle = false;
    var path_prefix: ?[]const u8 = null;

    //
    // parse options
    //
    while (optind < args.len) : (optind += 1) {
        const arg = args[optind];
        if (arg[0] != '-')
            break;
        for (arg[1..], 1..) |c, i| {
            switch (c) {
                'f' => force = true,
                'c' => compress = true,
                'b' => do_bundle = true,
                'j' => {
                    if (i != arg.len - 1) {
                        nproc = try std.fmt.parseInt(usize, arg[i+1..], 10);
                        break;
                    } else {
                        if (optind == args.len - 1) {
                            std.debug.print("-j requires an argument\n", .{});
                            usage(args[0]);
                            return 1;
                        }
                        nproc = try std.fmt.parseInt(usize, args[optind + 1], 10);
                        optind += 1;
                    }
                },
                'o' => {
                    if (i != arg.len - 1) {
                        path_prefix = arg[i+1..];
                        break;
                    } else {
                        if (optind == args.len - 1) {
                            std.debug.print("-o requires an argument\n", .{});
                            usage(args[0]);
                            return 1;
                        }
                        path_prefix = args[optind + 1];
                        optind += 1;
                    }
                },
                'v' => {
                    if (log_level != log.Level.Debug5)
                        log_level = @enumFromInt(@intFromEnum(log_level) + 1);
                },
                'q' => {
                    if (log_level != log.Level.None)
                        log_level = @enumFromInt(@intFromEnum(log_level) - 1);
                },
                else => {
                    usage(args[0]);
                    return 1;
                },
            }
        }
    }
    if (optind == args.len) {
        usage(args[0]);
        return 1;
    }
    if (optind != args.len - 1) {
        std.debug.print("Only one positional argument allowed\n", .{});
        return 1;
    }
    const pid_str = args[optind];
    const pid = try std.fmt.parseInt(i32, pid_str, 10);

    const io = init.io;
    log.init(io, log_level);

    log.D2("force {} compress {} pid {}", .{force, compress, pid});

    //
    // check target is 64 bit ELF
    //
    try checkElfHeader(gpa, io, pid);

    //
    // check seccomp status
    //
    const pre_status = try proc.getStatus(gpa, io, pid);
    if (try isSeccompEnabled(pre_status)) {
        if (force) {
            log.W("Seccomp is enabled for this process, proceeding anyway due to force flag.",
                .{});
        } else {
            log.E("Seccomp is enabled for this process, it is not safe to proceed.", .{});
            log.E("  use -f to ignore.", .{});
            return error.SeccompEnabled;
        }
    }

    //
    // fetch kernel stack information pre-fork
    // unfortunately ptrace interrupts all syscall, so we can't get much information
    // during the freeze. Fetch them best-effort beforehand
    //
    const pre_info_start = std.Io.Clock.boot.now(io).toNanoseconds();
    const pre_info = try Info.collect_pre(gpa, pid, nproc);
    const pre_info_end = std.Io.Clock.boot.now(io).toNanoseconds();
    log.V("Collecting pre info took {d}ms",
        .{@divTrunc(pre_info_end - pre_info_start, 1000000)});

    //
    // determine and open output path
    //
    var output_path_buf: [std.posix.PATH_MAX]u8 = undefined;
    var output_path: []const u8 = undefined;
    const cwd = std.Io.Dir.cwd();
    var name_id: usize = 0;
    var base_path: std.ArrayList(u8) = .empty;
    if (path_prefix) |prefix|
        try base_path.print(gpa, "{s}/", .{ prefix });
    const comm_raw = proc.readProcFile(gpa, io, pid, "comm") catch |err| {
        log.E("Failed to get executable name: {}", .{err});
        return err;
    };
    defer gpa.free(comm_raw);
    // remove trailing newline
    const comm = comm_raw[0..comm_raw.len - 1];
    // sanitize comm: replace / by _, diallow . and ..
    for (comm) |*c| {
        if (c.* == '/')
            c.* = '_';
    }
    if (std.mem.eql(u8, comm, ".") or std.mem.eql(u8, comm, ".."))
        comm[0] = '_';
    const now = try formatCurrTime(gpa);
    defer gpa.free(now);
    try base_path.print(gpa, "core.{s}.{d}.{s}", .{ comm, pid, now });

    while (true) {
        if (name_id == 0)
            output_path = try std.fmt.bufPrint(&output_path_buf, "{s}", .{base_path.items})
        else
            output_path = try std.fmt.bufPrint(&output_path_buf, "{s}-{d}",
                .{base_path.items, name_id});

        cwd.access(io, output_path, .{}) catch |err| {
            if (err != error.FileNotFound) {
                log.E("Failed to access output path: {}", .{err});
                return err;
            }
            break;
        };
        name_id += 1;
        if (name_id == 1000) {
            log.E("Failed to find free output path after 1000 attempts.", .{});
            return error.NoFreeOutputPath;
        }
    }

    const output_type: output.OutputType = if (compress) .archive else .fs;

    var out = output.open(gpa, io, output_path, output_type) catch |err| {
        log.E("Failed to open output: {}", .{err});
        return 1;
    };

    var retcode: u8 = 0;

    //
    // install signal handlers
    // interrupting at the wrong time could crash the target or inject unexpected EINTRs
    //
    const sig_action = std.posix.Sigaction {
        .handler = .{ .handler = signalHandler },
        .flags = std.posix.SA.RESTART,
        .mask = std.posix.sigemptyset(),
    };
    std.posix.sigaction(std.posix.SIG.INT, &sig_action, null);
    std.posix.sigaction(std.posix.SIG.TERM, &sig_action, null);
    std.posix.sigaction(std.posix.SIG.QUIT, &sig_action, null);
    std.posix.sigaction(std.posix.SIG.HUP, &sig_action, null);

    const sig_alarm = std.posix.Sigaction {
        .handler = .{ .handler = alarmHandler },
        .flags = 0,
        .mask = std.posix.sigemptyset(),
    };
    std.posix.sigaction(std.posix.SIG.ALRM, &sig_alarm, null);

    //
    // before we start, hunt for syscall instruction in the maps. We use that
    // later on for injection
    //
    const syscall_addr = process.findSyscall(gpa, io, pid) catch |err| {
        log.E("Failed to find syscall instruction in target: {}", .{err});
        return 1;
    };

    //
    // fork target
    //
    const fork_start = std.Io.Clock.boot.now(io).toNanoseconds();
    const child_nspid, const child_hostpid, var thread_info, const net_info
            = forkTarget(gpa, io, pid, syscall_addr, nproc) catch |err|
    {
        log.E("Failed to fork target: {}", .{err});
        return 1;
    };
    const fork_end = std.Io.Clock.boot.now(io).toNanoseconds();
    log.V("fork took {d}ms overall", .{@divTrunc(fork_end - fork_start, 1000000)});

    //
    // complete thread info state and status fields from net_info
    //
    const target_state, const target_status, const pmaps =
        try extractStateStatus(gpa, &thread_info, net_info, pid);

    //
    // dump target, thread names and core file
    // from here on, we can't just return err, that would skip the cleanup, leaving
    // at least a zombie
    //
    log.I("Dumping forked target", .{});
    dumpThreads(gpa, &out, thread_info) catch |err| {
        log.E("Failed to dump threads: {}", .{err});
        dumpStackTrace(@errorReturnTrace());
        retcode = 1;
    };
    if (retcode == 0) {
        dumpTarget(gpa, io, &out, child_hostpid, pmaps, thread_info, target_state, target_status,
            compress) catch |err|
        {
            log.E("Failed to dump target: {}", .{err});
            dumpStackTrace(@errorReturnTrace());
            retcode = 2;
        };
    }
    const dump_end = std.Io.Clock.boot.now(io).toNanoseconds();
    log.I("dump took {d}ms", .{@divTrunc(dump_end - fork_end, 1000000)});

    //
    // on request add all libraries and files
    //
    if (do_bundle) {
        const bundle_start = std.Io.Clock.boot.now(io).toNanoseconds();
        bundle.bundleFiles(gpa, io, &out, pmaps, pid, child_hostpid) catch |err| {
            log.E("Failed to bundle files: {}", .{err});
            dumpStackTrace(@errorReturnTrace());
            retcode = 4;
        };
        const bundle_end = std.Io.Clock.boot.now(io).toNanoseconds();
        log.V("Writing bundle took {d} ms", .{@divTrunc(bundle_end - bundle_start, 1000000)});
    }

    //
    // cleanup target
    //
    cleanupTarget(gpa, io, pid, child_nspid, child_hostpid, syscall_addr) catch |err| {
        log.E("Failed to clean up target: {}", .{err});
        dumpStackTrace(@errorReturnTrace());
        return 3;
    };

    const detach_end = std.Io.Clock.boot.now(io).toNanoseconds();
    log.V("Detach took {d} ms", .{@divTrunc(detach_end - dump_end, 1000000)});

    if (retcode != 0)
        return retcode;

    //
    // from here on, returning err is fine again. We can also enable signals again
    //
    const default_action = std.posix.Sigaction{
        .handler = .{ .handler = std.posix.SIG.DFL },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &default_action, null);
    std.posix.sigaction(std.posix.SIG.TERM, &default_action, null);
    std.posix.sigaction(std.posix.SIG.QUIT, &default_action, null);
    std.posix.sigaction(std.posix.SIG.HUP, &default_action, null);

    //
    // write out pret info
    //
    const netinfo_start = std.Io.Clock.boot.now(io).toNanoseconds();
    pre_info.writeAll(&out, "pre") catch |err| {
        log.E("Failed to write network info: {}", .{err});
        return err;
    };

    //
    // write out net info
    //
    net_info.writeAll(&out, null) catch |err| {
        log.E("Failed to write network info: {}", .{err});
        return err;
    };
    const netinfo_end = std.Io.Clock.boot.now(io).toNanoseconds();
    log.V("Writing net info took {d} ms", .{@divTrunc(netinfo_end - netinfo_start, 1000000)});

    //
    // parse netlink files to text format
    //
    net_info.writeParsedNetlink(gpa, &out) catch |err| {
        log.E("Failed to write parsed netlink info: {}", .{err});
        return err;
    };

    //
    // add README
    //
    var readme_file = out.startFile("README", readme.len, null) catch |err| {
        log.E("Failed to start README file: {}", .{err});
        return err;
    };
    try readme_file.addChunk(readme);
    try readme_file.finish();

    //
    // flush the archive
    //
    out.close() catch |err| {
        log.E("Failed to close output: {}", .{err});
        return err;
    };

    return retcode;
}
