//
// collect additional information about the process from /proc and netlink.
// This information can later be used to correlate the process state to the
// network state.
// For example the core does not contain information about peers of tcp sockets.
//
// It works in 3 phases.
//  1. collect some information before the freeze that are not available during freeze
//  2. collect all the information and store it in memory. Invoked with target frozen
//  3. write to output files or stream to tar. Invoked after dump is done

const std = @import("std");
const proc = @import("proc.zig");
const log = @import("log.zig");
const process = @import("process.zig");
const output = @import("output.zig");
pub const diag = @cImport({
    @cInclude("linux/inet_diag.h");
    @cInclude("linux/in.h");
    @cInclude("sys/socket.h");
    @cInclude("linux/netlink.h");
    @cInclude("linux/sock_diag.h");
    @cInclude("linux/unix_diag.h");
    @cInclude("linux/tcp.h");
});
const readInt = std.mem.readInt;

const endian = @import("builtin").target.cpu.arch.endian();

const File = struct {
    path: []const u8,
    is_symlink: bool,
    content: []const u8,
};

files: std.StringHashMap(File),

const Fields = @This();

// Files from /proc/<pid>/
const proc_pid_files = [_][]const u8 {
    "smaps", "smaps_rollup", "status", "stat",
    "cmdline", "environ", "limits", "cgroup",
    "io", "mountinfo", "mounts", "numa_maps", "sched", "schedstat",
    "oom_score", "personality",
    // these are superseded by netlink queries, but omit them later
    "net/tcp", "net/tcp6", "net/udp",
    "net/udplite6", "net/raw", "net/raw6", "net/unix", "net/netlink",
    // optional, might remove those
    "net/udp6", "net/udplite",
    "net/packet", "net/sockstat", "net/sockstat6", "net/netstat", "net/snmp",
};

// Symlinks from /proc/<pid>/
const proc_pid_symlinks = [_][]const u8 {
    "cwd", "root", "ns/net", "ns/pid", "ns/mnt",
    "ns/user", "ns/ipc", "ns/uts"
};

// Files from /proc/<pid>/task/<tid>/
const proc_pid_task_files = [_][]const u8 {
    "stat", "status", "syscall"
};

// Files from /proc/<pid>/task/<tid>/ collected in phase 1
const pre_proc_pid_task_files = [_][]const u8 {
    "stack", "wchan", "syscall"
};

const CollectType = enum {
    File,
    Symlink,
    NetlinkIp,
    NetlinkUnix,
};

const Job = struct {
    path: []const u8,
    collect_type: CollectType,
    af: u8 = 0,        // for netlink
    proto: u8 = 0,     // for netlink
};

const JobArgs = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    pid: i32,
    info: *Fields,
    info_mutex: *std.Io.Mutex,
    ignore_errors: bool,
    errors: usize,
    netns_warned: bool = false,
    // qcore's own netns to return to after a netlink dump, or null when the
    // target shares it and no setns is needed
    self_netns: ?std.Io.File = null,
};

// Phase 2 collect
pub fn collect(gpa: std.mem.Allocator, pid: i32, pids: process.PidsMap, nproc: usize) !Fields
{
    var info = Fields {
        .files = .init(gpa),
    };

    var info_mutex: std.Io.Mutex = .init;

    var threaded: std.Io.Threaded = .init(gpa, .{ .async_limit = .limited(nproc) });
    defer threaded.deinit();
    const io = threaded.io();
    var group: std.Io.Group = .init;
    defer group.cancel(io);

    var job_args = JobArgs {
        .gpa = gpa,
        .io = io,
        .pid = pid,
        .info = &info,
        .info_mutex = &info_mutex,
        .ignore_errors = false,
        .errors = 0,
    };

    // Check whether the target's netns differs from ours before any job is
    // queued: jobs may also run on this thread and switch its netns.
    if (!try proc.isSameNamespace(io, pid, "net")) {
        job_args.self_netns = std.Io.Dir.openFileAbsolute(io, "/proc/self/ns/net",
            .{}) catch |err| {
            log.E("Failed to open /proc/self/ns/net: {}", .{err});
            return err;
        };
    }
    defer if (job_args.self_netns) |self_netns| self_netns.close(io);

    const netlink_params = [5]struct {u8, u8, bool, []const u8 } {
        .{ diag.AF_INET,  diag.IPPROTO_TCP, false, "/netlink_tcp.raw" },
        .{ diag.AF_INET6, diag.IPPROTO_TCP, false, "/netlink_tcp6.raw" },
        .{ diag.AF_INET,  diag.IPPROTO_UDP, false, "/netlink_udp.raw" },
        .{ diag.AF_INET6, diag.IPPROTO_UDP, false, "/netlink_udp6.raw" },
        .{ diag.AF_UNIX,  0,                 true, "/netlink_unix.raw" },
    };

    for (netlink_params) |params| {
        group.async(io, jobWorker, .{ &job_args, Job {
            .af = params.@"0",
            .proto = params.@"1",
            .collect_type = if (params.@"2") .NetlinkUnix else .NetlinkIp,
            .path = params.@"3",
        } });
    }

    // queue files
    for (proc_pid_files) |file| {
        const path = try std.fmt.allocPrint(gpa, "/proc/{d}/{s}", .{pid, file});
        group.async(io, jobWorker, .{ &job_args, Job {
            .path = path,
            .collect_type = .File,
        } });
    }

    // queue symlinks
    for (proc_pid_symlinks) |link| {
        const path = try std.fmt.allocPrint(gpa, "/proc/{d}/{s}", .{pid, link});
        group.async(io, jobWorker, .{ &job_args, Job {
            .path = path,
            .collect_type = .Symlink,
        } });
    }

    // queue per-thread files
    var it = pids.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.* == null)
            continue;
        for (proc_pid_task_files) |file| {
            const path = try std.fmt.allocPrint(gpa, "/proc/{d}/task/{d}/{s}",
                .{ pid, entry.key_ptr.*, file });
            group.async(io, jobWorker, .{ &job_args, Job {
                .path = path,
                .collect_type = .File,
            } });
        }
    }

    // queue fd info
    const fd_path = try std.fmt.allocPrint(gpa, "/proc/{d}/fd", .{pid});
    try queueDir(gpa, io, &group, .Symlink, fd_path, &job_args);
    const fdinfo_path = try std.fmt.allocPrint(gpa, "/proc/{d}/fdinfo", .{pid});
    try queueDir(gpa, io, &group, .File, fdinfo_path, &job_args);

    group.await(io) catch |err| {
        log.E("Error while waiting for jobs to complete: {}", .{err});
        return err;
    };

    if (job_args.errors > 0) {
        log.E("{d} errors occurred during collection", .{job_args.errors});
        return error.CollectionFailed;
    }

    log.D1("Collected process information for pid {d}", .{pid});

    return info;
}

// Phase 1 collect
pub fn collect_pre(gpa: std.mem.Allocator, pid: i32, nproc: usize) !Fields {
    var info = Fields {
        .files = .init(gpa),
    };

    var info_mutex: std.Io.Mutex = .init;

    var threaded: std.Io.Threaded = .init(gpa, .{ .async_limit = .limited(nproc) });
    defer threaded.deinit();
    const io = threaded.io();
    var group: std.Io.Group = .init;
    defer group.cancel(io);

    var job_args = JobArgs {
        .gpa = gpa,
        .io = io,
        .pid = pid,
        .info = &info,
        .info_mutex = &info_mutex,
        .ignore_errors = true, // target not stopped, some files might disappear
        .errors = 0,
    };

    // queue per-thread files
    var pathbuf: [200]u8 = undefined;
    const dir_path = try std.fmt.bufPrint(&pathbuf, "/proc/{d}/task", .{pid});
    const dir = std.Io.Dir.openDirAbsolute(io, dir_path, .{
            .follow_symlinks = false,
            .iterate = true,
    }) catch |err| {
        log.E("Failed to read directory {s}: {}", .{dir_path, err});
        return err;
    };
    defer std.Io.Dir.close(dir, io);

    var iter = dir.iterate();
    while (try iter.next(io)) |entry| {
        for (pre_proc_pid_task_files) |file| {
            const path = try std.fmt.allocPrint(gpa, "/proc/{d}/task/{s}/{s}",
                .{ pid, entry.name, file });
            group.async(io, jobWorker, .{ &job_args, Job {
                .path = path,
                .collect_type = .File,
            } });
        }
    }

    group.await(io) catch |err| {
        log.E("Error while waiting for jobs to complete: {}", .{err});
        return err;
    };

    if (job_args.errors > 0) {
        log.E("{d} errors occurred during collection", .{job_args.errors});
        return error.CollectionFailed;
    }

    log.D1("Collected pre-process information for pid {d}", .{pid});

    return info;
}

fn queueDir(gpa: std.mem.Allocator, io: std.Io, group: *std.Io.Group,
    collect_type: CollectType, path: []const u8, job_args: *JobArgs) !void
{
    const dir = std.Io.Dir.openDirAbsolute(io, path, .{
            .follow_symlinks = false,
            .iterate = true,
    }) catch |err| {
        log.E("Failed to read directory {s}: {}", .{path, err});
        return err;
    };
    defer std.Io.Dir.close(dir, io);

    var iter = dir.iterate();
    while (try iter.next(io)) |entry| {
        group.async(io, jobWorker, .{ job_args, Job {
            .path = try std.fmt.allocPrint(gpa, "{s}/{s}", .{path, entry.name}),
            .collect_type = collect_type,
        } });
    }
}

fn jobWorker(args: *JobArgs, job: Job) void {
    const gpa = args.gpa;
    const io = args.io;
    const pid = args.pid;

    log.D2("running job {s}", .{job.path});
    const ret = switch (job.collect_type) {
        .File => collectFile(gpa, io, job.path),
        .Symlink => collectSymlink(gpa, io, job.path),
        .NetlinkIp => collectNetlinkRetry(gpa, io, pid, args.self_netns, job.af, job.proto,
            false, job.path),
        .NetlinkUnix => collectNetlinkRetry(gpa, io, pid, args.self_netns, job.af, job.proto,
            true, job.path),
    };
    args.info_mutex.lock(io) catch
        @panic("Failed to lock info mutex");

    defer args.info_mutex.unlock(io);

    const file = ret catch |err| {
        // a missing privilege to enter the target netns is not fatal; the
        // network state is simply omitted. Every socket-family job hits this
        // for the same reason, so warn only once (serialized via info_mutex).
        if (err == error.SetNsPermission) {
            if (!args.netns_warned) {
                args.netns_warned = true;
                log.W("Cannot enter target netns (need CAP_SYS_ADMIN), " ++
                    "omitting network state", .{});
            }
        } else if (args.ignore_errors) {
            log.D2("Got error {} (ignored): {s}", .{err, job.path});
        } else {
            log.E("Error collecting {s}: {}", .{job.path, err});
            args.errors += 1;
        }
        return;
    };

    args.info.files.put(job.path, file) catch |err| {
        log.E("Failed to store collected file {s}: {}", .{job.path, err});
        args.errors += 1;
        return;
    };
}

fn collectFile(gpa: std.mem.Allocator, io: std.Io, path: []const u8) !File
{
    const content = try proc.slurp(gpa, io, path);
    return File {
        .path = path,
        .is_symlink = false,
        .content = content,
    };
}

fn collectSymlink(gpa: std.mem.Allocator, io: std.Io, path: []const u8) !File
{
    var target: [8192]u8 = undefined;
    const n = std.Io.Dir.readLinkAbsolute(io, path, &target) catch |err| {
        log.E("Failed to read symlink {s}: {}", .{path, err});
        return error.ReadLinkFailed;
    };
    if (n == target.len) {
        log.E("Symlink target too long for {s}", .{path});
        return error.SymlinkTargetTooLong;
    }
    return  File {
        .path = path,
        .is_symlink = true,
        .content = try gpa.dupe(u8, target[0..n]),
    };
}

fn collectNetlinkRetry(gpa: std.mem.Allocator, io: std.Io, pid: i32, self_netns: ?std.Io.File,
    af: u8, proto: u8, is_unix: bool, path: []const u8) !File
{
    for (1..4) |attempt| {
        const ret = collectNetlink(gpa, io, pid, self_netns, af, proto, is_unix, path);
        if (!std.meta.isError(ret)) {
            return ret;
        }
        if (ret != error.NetlinkDumpInterrupted)
            return ret;

        log.W("Netlink dump interrupted for {s}, retrying ({d})", .{path, attempt});
    }

    return error.NetlinkDumpInterrupted;
}

fn collectNetlink(gpa: std.mem.Allocator, io: std.Io, pid: i32, self_netns: ?std.Io.File,
    af: u8, proto: u8, is_unix: bool, path: []const u8) !File
{
    const ns_path = try std.fmt.allocPrint(gpa, "/proc/{d}/ns/net", .{ pid });
    const target_ns = std.Io.Dir.openFileAbsolute(io, ns_path, .{}) catch |err| {
        log.E("Failed to open target netns {s}: {}", .{ns_path, err});
        return err;
    };
    defer target_ns.close(io);

    // Entering the target's network namespace needs CAP_SYS_ADMIN over it. When
    // qcore already shares that netns - the common case for an unprivileged
    // same-host dump - the setns would be a no-op that still requires the
    // capability, so skip it and dump the sockets directly.
    if (self_netns != null) {
        // setns is a raw syscall wrapper returning a usize, so a failure is
        // encoded as -errno in the return value rather than in C errno.
        const ret: isize = @bitCast(std.os.linux.setns(target_ns.handle,
            std.os.linux.CLONE.NEWNET));

        if (ret < 0) {
            const err_no = -ret;

            // Without privilege we cannot enter a foreign netns. Report this as
            // a recoverable error so the caller omits the network state instead
            // of failing the whole dump.
            if (err_no == @intFromEnum(std.os.linux.E.PERM) or
                err_no == @intFromEnum(std.os.linux.E.ACCES)) {
                log.D1("setns to target netns denied (errno {d}) for {s}", .{err_no, path});
                return error.SetNsPermission;
            }
            log.E("Failed to setns to target netns: errno {d}", .{err_no});
            return error.SetNsFailedErro;
        }
    }
    // switch back to qcore's own network namespace when collectNetlink returns
    defer {
        if (self_netns) |self|
            _ = std.os.linux.setns(self.handle, std.os.linux.CLONE.NEWNET);
    }

    const fd = std.c.socket(diag.AF_NETLINK, diag.SOCK_RAW | diag.SOCK_CLOEXEC,
        diag.NETLINK_SOCK_DIAG);
    if (fd < 0) {
        log.E("Failed to create netlink socket: errno {d}", .{std.c._errno().*});
        return error.NetlinkSocketFailed;
    }
    defer _ = std.c.close(fd);

    var iov: [1]std.posix.iovec_const = undefined;
    if (is_unix) {
        const S = extern struct {
            nlh: diag.nlmsghdr,
            r: diag.unix_diag_req,
        };
        var req = std.mem.zeroes(S);
        req.nlh.nlmsg_len = @sizeOf(S);
        req.nlh.nlmsg_type = diag.SOCK_DIAG_BY_FAMILY;
        req.nlh.nlmsg_flags = diag.NLM_F_REQUEST | diag.NLM_F_DUMP;
        req.nlh.nlmsg_seq = 1;
        req.r.sdiag_family = af;
        req.r.udiag_states = 0xffffffff; // all states
        req.r.udiag_show = diag.UDIAG_SHOW_NAME |
                           diag.UDIAG_SHOW_PEER |
                           diag.UDIAG_SHOW_RQLEN |
                           diag.UDIAG_SHOW_MEMINFO;
        iov[0] = .{
            .base = @ptrCast(&req),
            .len = @sizeOf(S),
        };
    } else {
        const S = extern struct {
            nlh: diag.nlmsghdr,
            r: diag.inet_diag_req_v2,
        };
        var req = std.mem.zeroes(S);
        req.nlh.nlmsg_len = @sizeOf(S);
        req.nlh.nlmsg_type = diag.SOCK_DIAG_BY_FAMILY;
        req.nlh.nlmsg_flags = diag.NLM_F_REQUEST | diag.NLM_F_DUMP;
        req.nlh.nlmsg_seq = 1;
        req.r.sdiag_family = af;
        req.r.sdiag_protocol = proto;
        req.r.idiag_ext = (1 << (diag.INET_DIAG_INFO - 1)) |
                          (1 << (diag.INET_DIAG_CONG - 1)) |
                          (1 << (diag.INET_DIAG_TOS - 1)) |
                          (1 << (diag.INET_DIAG_TCLASS - 1)) |
                          (1 << (diag.INET_DIAG_SKMEMINFO - 1)) |
                          (1 << (diag.INET_DIAG_SHUTDOWN - 1));
        req.r.idiag_states = 0xffffffff; // all states
        iov[0] = .{
            .base = @ptrCast(&req),
            .len = @sizeOf(S),
        };
    }
    var sa: diag.sockaddr_nl = .{
        .nl_family = diag.AF_NETLINK,
    };
    const m: std.posix.msghdr_const = .{
        .name = @ptrCast(&sa),
        .namelen = @sizeOf(diag.iovec),
        .control = null,
        .controllen = 0,
        .flags = 0,
        .iov = &iov,
        .iovlen = 1,
    };
    const s_ret = std.c.sendmsg(fd, &m, 0);
    if (s_ret < 0) {
        log.E("Failed to send netlink request: errno {d}", .{std.c._errno().*});
        return error.NetlinkRequestFailed;
    }

    const buffer = gpa.alignedAlloc(u8, .@"8", 65536) catch {
        log.E("Failed to allocate buffer for netlink response", .{});
        return error.NetlinkBufferAllocFailed;
    };
    defer gpa.free(buffer);

    var content: std.ArrayListAligned(u8, .@"8") = .empty;
    defer content.deinit(gpa);

    recv: while (true) {
        const i_len = std.c.recv(fd, buffer.ptr, buffer.len, 0);
        if (i_len < 0) {
            log.E("Failed to receive netlink response: errno {d}", .{std.c._errno().*});
            return error.NetlinkReceiveFailed;
        }
        if (i_len == 0)
            break;
        const len: usize = @intCast(i_len);
        log.D2("Received netlink response of length {d}", .{len});

        // just append the receive block to content for now, we parse it later
        content.appendSlice(gpa, buffer.ptr[0..len]) catch {
            log.E("Failed to append netlink response to content", .{});
            return error.NetlinkAppendFailed;
        };

        // hunt for DONE or ERROR message
        var offset: usize = 0;
        while (offset < len) {
            const rem = len - offset;
            const nlh: *diag.nlmsghdr = @alignCast(@ptrCast(buffer.ptr + offset));
            log.D3("len {d} offset {d} rem {d} nlmsg_len {d} hdrlen {d}",
                .{len, offset, rem, nlh.nlmsg_len, @sizeOf(diag.nlmsghdr)});
            if (rem < @sizeOf(diag.nlmsghdr) or rem < nlh.nlmsg_len) {
                log.E("Invalid netlink message length: {d}", .{nlh.nlmsg_len});
                return error.NetlinkInvalidMessageLength;
            }
            if ((nlh.nlmsg_flags & diag.NLM_F_DUMP_INTR) != 0) {
                log.W("Netlink dump interrupted", .{});
                return error.NetlinkDumpInterrupted;
            }
            log.D3("Netlink message type: {d}", .{nlh.nlmsg_type});
            if (nlh.nlmsg_type == diag.NLMSG_DONE) {
                log.D1("Netlink dump complete", .{});
                break :recv;
            }
            if (nlh.nlmsg_type == diag.NLMSG_ERROR) {
                log.E("Netlink error response received", .{});
                return error.NetlinkErrorResponse;
            }
            offset += std.mem.alignForward(usize, nlh.nlmsg_len, 4); // align to 4 bytes
        }
    }

    // leave namespace per defer above

    return File {
        .path = path,
        .is_symlink = false,
        .content = try content.toOwnedSlice(gpa),
    };
}

// Phase 3, write to files/archive
pub fn writeAll(info: *const Fields, out: *output.Output, prefix: ?[]const u8) !void {
    var it = info.files.iterator();
    var namebuf: [std.posix.PATH_MAX]u8 = undefined;
    while (it.next()) |entry| {
        const file = entry.value_ptr.*;
        const fname = entry.key_ptr.*;
        std.debug.assert(fname[0] == '/');
        if (file.is_symlink) {
            out.addSymlink(fname[1..], file.content) catch |err| {
                log.E("Failed to write symlink {s}: {}", .{fname, err});
                return error.WriteSymlinkFailed;
            };
        } else {
            const name = if (prefix) |pre|
                try std.fmt.bufPrint(namebuf[0..], "{s}/{s}", .{pre, fname[1..]})
            else
                fname[1..];
            var f = out.startFile(name, file.content.len, null) catch |err| {
                log.E("Failed to start file {s}: {}", .{name, err});
                return error.StartFileFailed;
            };
            errdefer f.finish() catch {};
            f.addChunk(file.content) catch |err| {
                log.E("Failed to write file {s}: {}", .{name, err});
                return error.WriteFileFailed;
            };
            f.finish() catch |err| {
                log.E("Failed to finish file {s}: {}", .{name, err});
                return error.FinishFileFailed;
            };
        }
    }
}

pub fn writeParsedNetlink(info: *const Fields, gpa: std.mem.Allocator, out: *output.Output) !void {
    var it = info.files.iterator();
    var namebuf: [std.posix.PATH_MAX]u8 = undefined;
    while (it.next()) |entry| {
        const file = entry.value_ptr.*;
        const fname = entry.key_ptr.*;

        if (!std.mem.startsWith(u8, fname, "/netlink_"))
            continue;
        if (!std.mem.endsWith(u8, fname, ".raw"))
            continue;

        const is_unix = std.mem.find(u8, fname, "unix") != null;
        const name = try std.fmt.bufPrint(namebuf[0..], "{s}.txt", .{fname[1..fname.len - 4]});
        // hunt for DONE or ERROR message
        var offset: usize = 0;
        const content = file.content;
        var parsed: std.ArrayList(u8) = .empty;
        while (offset < content.len) {
            const rem = content.len - offset;
            log.D4("Parsing netlink message at offset {d}, remaining {d} bytes", .{offset, rem});
            const nlh: *const diag.nlmsghdr = @alignCast(@ptrCast(content.ptr + offset));
            log.D4("len {d} offset {d} rem {d} nlmsg_len {d} hdrlen {d}",
                .{content.len, offset, rem, nlh.nlmsg_len, @sizeOf(diag.nlmsghdr)});
            if (rem < @sizeOf(diag.nlmsghdr) or rem < nlh.nlmsg_len) {
                log.E("Invalid netlink message length: {d}", .{nlh.nlmsg_len});
                return error.NetlinkInvalidMessageLength;
            }
            const aligned_len = std.mem.alignForward(usize, nlh.nlmsg_len, 4);
            if (nlh.nlmsg_type == diag.NLMSG_DONE) {
                log.D1("Netlink dump complete", .{});
                break;
            } else if (nlh.nlmsg_type == diag.SOCK_DIAG_BY_FAMILY) {
                log.D3("Netlink message type: {d}", .{nlh.nlmsg_type});
                const msg_start = offset + @sizeOf(diag.nlmsghdr);
                const msg = content[msg_start..offset + nlh.nlmsg_len];
                if (is_unix) {
                    parseDiagMessageUnix(gpa, &parsed, msg) catch |err| {
                        log.E("Failed to parse netlink message: {}", .{err});
                        return error.NetlinkParseFailed;
                    };
                } else {
                    parseDiagMessageInet(gpa, &parsed, msg) catch |err| {
                        log.E("Failed to parse netlink message: {}", .{err});
                        return error.NetlinkParseFailed;
                    };
                }
            } else {
                log.W("Unexpected netlink message type: {d}", .{nlh.nlmsg_type});
                return error.NetlinkInvalidMessageType;
            }
            offset += aligned_len;
        }

        var f = out.startFile(name, parsed.items.len, null) catch |err| {
            log.E("Failed to start file {s}: {}", .{name, err});
            return error.StartFileFailed;
        };
        errdefer f.finish() catch {};

        f.addChunk(parsed.items) catch |err| {
            log.E("Failed to write file {s}: {}", .{name, err});
            return error.WriteFileFailed;
        };
        f.finish() catch |err| {
            log.E("Failed to finish file {s}: {}", .{name, err});
            return error.FinishFileFailed;
        };
    }
}

fn unixTypeName(t: u8) []const u8 {
    return switch (t) {
        1 => "SOCK_STREAM",
        2 => "SOCK_DGRAM",
        3 => "SOCK_RAW",
        4 => "SOCK_RDM",
        5 => "SOCK_SEQPACKET",
        else => "?",
    };
}

fn parseDiagMessageUnix(gpa: std.mem.Allocator, parsed: *std.ArrayList(u8),
    raw: []const u8) !void
{
    if (raw.len < @sizeOf(diag.unix_diag_msg)) {
        log.E("unix diag message too short: {d}", .{raw.len});
        return error.NetlinkParseFailed;
    }

    const msg: *const diag.unix_diag_msg = @alignCast(@ptrCast(raw.ptr));

    try parsed.print(gpa, "socket family=AF_UNIX type={s} ({d}) state={s} ({d})\n", .{
        unixTypeName(msg.udiag_type),
        msg.udiag_type,
        tcpStateName(msg.udiag_state),
        msg.udiag_state,
    });
    try parsed.print(gpa, "  inode={d}\n", .{ msg.udiag_ino });
    try parsed.print(gpa, "  cookie={x:0>8}{x:0>8}\n", .{
        msg.udiag_cookie[1], msg.udiag_cookie[0],
    });

    // Iterate the attributes following the fixed unix_diag_msg part.
    var off: usize = @sizeOf(diag.unix_diag_msg);
    while (off < raw.len) {
        log.D4("Parsing unix diag message attribute at offset {d}, remaining {d} bytes",
            .{off, raw.len - off});
        const rem = raw.len - off;
        if (rem < @sizeOf(diag.nlattr)) {
            log.E("unix diag message attribute too short: {d}", .{rem});
            return error.NetlinkParseFailed;
        }
        const nla: *const diag.nlattr = @alignCast(@ptrCast(raw.ptr + off));
        if (nla.nla_len > rem) {
            log.E("unix diag message attribute length too long: {d}, rem {d}",
                .{ nla.nla_len, rem });
            return error.NetlinkParseFailed;
        }
        const nla_rem = nla.nla_len - @sizeOf(diag.nlattr);
        const attr = raw[off + @sizeOf(diag.nlattr) .. off + nla.nla_len];

        const attr_len: usize = switch (nla.nla_type) {
            diag.UNIX_DIAG_NAME => nla_rem,
            diag.UNIX_DIAG_VFS => @sizeOf(diag.unix_diag_vfs),
            diag.UNIX_DIAG_PEER => 4,
            diag.UNIX_DIAG_ICONS => nla_rem,
            diag.UNIX_DIAG_RQLEN => @sizeOf(diag.unix_diag_rqlen),
            diag.UNIX_DIAG_MEMINFO => 9 * 4,
            diag.UNIX_DIAG_SHUTDOWN => 1,
            diag.UNIX_DIAG_UID => 4,
            else => {
                log.E("unix diag message unknown attribute type: {d}", .{nla.nla_type});
                return error.NetlinkParseFailed;
            },
        };
        if (nla_rem < attr_len) {
            log.E("unix diag message attribute too short for type {d}: want {d}, got {d}",
                .{nla.nla_type, attr_len, nla_rem});
            return error.NetlinkParseFailed;
        }
        switch (nla.nla_type) {
            diag.UNIX_DIAG_NAME => {
                if (attr.len > 0 and attr[0] == 0) {
                    // abstract namespace socket, leading null is shown as '@'
                    try parsed.print(gpa, "  name=@{s}\n", .{ attr[1..] });
                } else {
                    try parsed.print(gpa, "  name={s}\n", .{ attr });
                }
            },
            diag.UNIX_DIAG_VFS => {
                const vfs: *const diag.unix_diag_vfs = @alignCast(@ptrCast(attr.ptr));
                try parsed.print(gpa, "  vfs_ino={d} vfs_dev={d}\n", .{
                    vfs.udiag_vfs_ino, vfs.udiag_vfs_dev,
                });
            },
            diag.UNIX_DIAG_PEER => {
                try parsed.print(gpa, "  peer={d}\n", .{ readInt(u32, attr[0..4], endian) });
            },
            diag.UNIX_DIAG_ICONS => {
                // array of inode numbers of pending connections
                var i: usize = 0;
                try parsed.print(gpa, "  icons=", .{});
                while (i + 4 <= attr.len) : (i += 4) {
                    if (i != 0) try parsed.print(gpa, ",", .{});
                    try parsed.print(gpa, "{d}", .{ readInt(u32, attr[i..][0..4], endian) });
                }
                try parsed.print(gpa, "\n", .{});
            },
            diag.UNIX_DIAG_RQLEN => {
                const rql: *const diag.unix_diag_rqlen = @alignCast(@ptrCast(attr.ptr));
                try parsed.print(gpa, "  rqueue={d} wqueue={d}\n", .{
                    rql.udiag_rqueue, rql.udiag_wqueue,
                });
            },
            diag.UNIX_DIAG_MEMINFO => {
                const names = [_][]const u8 {
                    "rmem_alloc", "rcvbuf",      "wmem_alloc", "sndbuf",
                    "fwd_alloc",  "wmem_queued", "optmem",     "backlog",
                    "drops",
                };
                for (names, 0..) |name, i| {
                    try parsed.print(gpa, "  {s}={d}\n", .{
                        name, readInt(u32, attr[i*4..][0..4], endian),
                    });
                }
            },
            diag.UNIX_DIAG_SHUTDOWN => {
                const sh = attr[0];
                try parsed.print(gpa, "  shutdown={d} (rcv={s} snd={s})\n", .{
                    sh,
                    if (sh & 1 != 0) "closed" else "open",
                    if (sh & 2 != 0) "closed" else "open",
                });
            },
            diag.UNIX_DIAG_UID => {
                try parsed.print(gpa, "  uid={d}\n", .{ readInt(u32, attr[0..4], endian) });
            },
            else => {
                log.W("unix diag message unknown attribute type: {d}", .{nla.nla_type});
            },
        }

        off += std.mem.alignForward(usize, nla.nla_len, 4);
    }

    try parsed.print(gpa, "\n", .{});
}

fn tcpStateName(state: u8) []const u8 {
    return switch (state) {
        1 => "ESTABLISHED",
        2 => "SYN_SENT",
        3 => "SYN_RECV",
        4 => "FIN_WAIT1",
        5 => "FIN_WAIT2",
        6 => "TIME_WAIT",
        7 => "CLOSE",
        8 => "CLOSE_WAIT",
        9 => "LAST_ACK",
        10 => "LISTEN",
        11 => "CLOSING",
        12 => "NEW_SYN_RECV",
        else => "UNKNOWN",
    };
}

fn timerName(timer: u8) []const u8 {
    return switch (timer) {
        0 => "off",
        1 => "retransmit",
        2 => "keepalive",
        3 => "time_wait",
        4 => "zero_window_probe",
        else => "unknown",
    };
}

fn formatAddr(gpa: std.mem.Allocator, parsed: *std.ArrayList(u8), family: u8, addr: [4]u32)
    !void
{
    const bytes = std.mem.asBytes(&addr);
    if (family == diag.AF_INET) {
        try parsed.print(gpa, "{d}.{d}.{d}.{d}", .{ bytes[0], bytes[1], bytes[2], bytes[3] });
    } else if (family == diag.AF_INET6) {
        var i: usize = 0;
        while (i < 16) : (i += 2) {
            if (i != 0) try parsed.print(gpa, ":", .{});
            const word = (@as(u16, bytes[i]) << 8) | bytes[i + 1];
            try parsed.print(gpa, "{x:0>2}", .{word});
        }
    } else {
        try parsed.print(gpa, "<af {d}>", .{family});
    }
}

fn parseDiagMessageInet(gpa: std.mem.Allocator, parsed: *std.ArrayList(u8),
    raw: []const u8) !void
{
    if (raw.len < @sizeOf(diag.inet_diag_msg)) {
        log.E("inet diag message too short: {d}", .{raw.len});
        return error.NetlinkParseFailed;
    }

    const msg: *const diag.inet_diag_msg = @alignCast(@ptrCast(raw.ptr));

    const family = msg.idiag_family;
    const family_s = switch(family) {
        diag.AF_INET => "AF_INET",
        diag.AF_INET6 => "AF_INET6",
        else => "?",
    };

    try parsed.print(gpa, "socket family={s} proto state={s} ({d})\n", .{
        family_s,
        tcpStateName(msg.idiag_state),
        msg.idiag_state,
    });

    // Source / destination endpoints. Ports are big-endian.
    const sport = std.mem.bigToNative(u16, msg.id.idiag_sport);
    const dport = std.mem.bigToNative(u16, msg.id.idiag_dport);
    try parsed.print(gpa, "  local  = ", .{});
    try formatAddr(gpa, parsed, family, msg.id.idiag_src);
    try parsed.print(gpa, ":{d}\n", .{sport});
    try parsed.print(gpa, "  remote = ", .{});
    try formatAddr(gpa, parsed, family, msg.id.idiag_dst);
    try parsed.print(gpa, ":{d}\n", .{dport});

    try parsed.print(gpa, "  if={d}\n", .{ msg.id.idiag_if });
    try parsed.print(gpa, "  cookie={x:0>8}{x:0>8}\n",
        .{ msg.id.idiag_cookie[1], msg.id.idiag_cookie[0] });
    try parsed.print(gpa, "  timer={s}\n", .{ timerName(msg.idiag_timer) });
    try parsed.print(gpa, "  retrans={d}\n", .{ msg.idiag_retrans });
    try parsed.print(gpa, "  expires={d}ms\n", .{ msg.idiag_expires });
    try parsed.print(gpa, "  rqueue={d}\n", .{ msg.idiag_rqueue });
    try parsed.print(gpa, "  wqueue={d}\n", .{ msg.idiag_wqueue });
    try parsed.print(gpa, "  uid={d}\n", .{ msg.idiag_uid });
    try parsed.print(gpa, "  inode={d}\n", .{ msg.idiag_inode });

    // Iterate the attributes following the fixed inet_diag_msg part.
    var off: usize = @sizeOf(diag.inet_diag_msg);
    while (off < raw.len) {
        log.D4("Parsing inet diag message attribute at offset {d}, remaining {d} bytes",
            .{off, raw.len - off});
        const rem = raw.len - off;
        if (rem < @sizeOf(diag.nlattr)) {
            log.E("inet diag message attribute too short: {d}", .{rem});
            return error.NetlinkParseFailed;
        }
        const nla: *const diag.nlattr = @alignCast(@ptrCast(raw.ptr + off));
        if (nla.nla_len > rem) {
            log.E("inet diag message attribute length too long: {d}, rem {d}",
                .{ nla.nla_len, rem });
            return error.NetlinkParseFailed;
        }
        const nla_rem = nla.nla_len - @sizeOf(diag.nlattr);
        var attr = raw[off + @sizeOf(diag.nlattr) .. off + nla.nla_len];

        const attr_len = switch (nla.nla_type) {
            diag.INET_DIAG_MEMINFO => 16,
            diag.INET_DIAG_SKMEMINFO => 9 * 4,
            diag.INET_DIAG_CONG => nla_rem,
            diag.INET_DIAG_TOS => 1,
            diag.INET_DIAG_TCLASS => 1,
            diag.INET_DIAG_SHUTDOWN => 1,
            diag.INET_DIAG_SKV6ONLY => 1,
            diag.INET_DIAG_MARK => 4,
            diag.INET_DIAG_CLASS_ID => 4,
            diag.INET_DIAG_CGROUP_ID => 8,
            diag.INET_DIAG_PROTOCOL => 1,
            diag.INET_DIAG_SOCKOPT => 2,
            diag.INET_DIAG_ULP_INFO => nla_rem,
            diag.INET_DIAG_INFO => nla_rem,
            else => {
                log.E("inet diag message unknown attribute type: {d}", .{nla.nla_type});
                return error.NetlinkParseFailed;
            },
        };
        log.D4("inet diag message attribute type {d} length {d}", .{nla.nla_type, attr_len});
        if (nla_rem < attr_len) {
            log.E("inet diag message attribute too short for type {d}: want {d}, got {d}",
                .{nla.nla_type, attr_len, nla_rem});
            return error.NetlinkParseFailed;
        }
        switch (nla.nla_type) {
            diag.INET_DIAG_MEMINFO => {
                try parsed.print(gpa, "  rmem={d}\n", .{ readInt(u32, attr[0..4], endian) });
                try parsed.print(gpa, "  wmem={d}\n", .{ readInt(u32, attr[4..8], endian) });
                try parsed.print(gpa, "  fmem={d}\n", .{ readInt(u32, attr[8..12], endian) });
                try parsed.print(gpa, "  tmem={d}\n", .{ readInt(u32, attr[12..16], endian) });
            },
            diag.INET_DIAG_SKMEMINFO => {
                const names = [_][]const u8 {
                    "rmem_alloc", "rcvbuf",      "wmem_alloc", "sndbuf",
                    "fwd_alloc",  "wmem_queued", "optmem",     "backlog",
                    "drops",
                };
                for (names, 0..) |name, i| {
                    try parsed.print(gpa, "  {s}={d}\n", .{
                        name, readInt(u32, attr[i*4..][0..4], endian),
                    });
                }
            },
            diag.INET_DIAG_CONG => {
                // null-terminated congestion control algorithm name
                const l = std.mem.find(u8, attr, "\x00") orelse {
                    log.E("inet diag message INET_DIAG_CONG attribute not null-terminated", .{});
                    return error.NetlinkParseFailed;
                };
                try parsed.print(gpa, "  cong={s}\n", .{ attr[0..l] });
            },
            diag.INET_DIAG_TOS => {
                try parsed.print(gpa, "  tos={d}\n", .{ attr[0] });
            },
            diag.INET_DIAG_TCLASS => {
                try parsed.print(gpa, "  tclass={d}\n", .{ attr[0] });
            },
            diag.INET_DIAG_SHUTDOWN => {
                const sh = attr[0];
                try parsed.print(gpa, "  shutdown={d} (rcv={s} snd={s})\n", .{
                    sh,
                    if (sh & 1 != 0) "closed" else "open",
                    if (sh & 2 != 0) "closed" else "open",
                });
            },
            diag.INET_DIAG_SKV6ONLY => {
                try parsed.print(gpa, "  v6only={d}\n", .{ attr[0] });
            },
            diag.INET_DIAG_MARK => {
                try parsed.print(gpa, "  mark={d}\n", .{ readInt(u32, attr[0..4], endian)});
            },
            diag.INET_DIAG_CLASS_ID => {
                try parsed.print(gpa, "  class_id={d}\n", .{readInt(u32, attr[0..4], endian)});
            },
            diag.INET_DIAG_CGROUP_ID => {
                try parsed.print(gpa, "  cgroup_id={d}\n", .{readInt(u64, attr[0..8], endian)});
            },
            diag.INET_DIAG_PROTOCOL => {
                try parsed.print(gpa, "  protocol={d}\n", .{ attr[0] });
            },
            diag.INET_DIAG_INFO => {
                for (tcp_info_fields) |field| {
    //try parsed.print(gpa, "    snd_wscale={d} rcv_wscale={d} delivery_rate_app_limited={d} fastopen_client_fail={d}\n", .{
    //  ti.tcpi_wscale & 0x0f, (ti.tcpi_wscale >> 4) & 0x0f,
    //  ti.tcpi_flags & 0x01, (ti.tcpi_flags >> 1) & 0x03,
//    tcpi_wscale: u8, // snd_wscale:4, rcv_wscale:4
//    tcpi_flags: u8, // delivery_rate_app_limited:1, fastopen_client_fail:2
                    const val: u64 = switch (field[1]) {
                        .u8 => attr[0],
                        .u16 => readInt(u16, attr[0..2], endian),
                        .u32 => readInt(u32, attr[0..4], endian),
                        .u64 => readInt(u64, attr[0..8], endian),
                    };
                    const inc: usize = switch (field[1]) {
                        .u8 => 1,
                        .u16 => 2,
                        .u32 => 4,
                        .u64 => 8,
                    };
                    try parsed.print(gpa, "  {s}={d} (0x{x})\n", .{ field[0], val, val });
                    attr = attr[inc..];
                    if (attr.len == 0)
                        break;
                }
            },
            diag.INET_DIAG_SOCKOPT => {
                // struct inet_diag_sockopt: two bytes of bitfields
                const b0 = attr[0];
                const b1 = attr[1];
                try parsed.print(gpa, "  recverr={d}\n", .{ (b0 >> 0) & 1 });
                try parsed.print(gpa, "  is_icsk={d}\n", .{ (b0 >> 1) & 1 });
                try parsed.print(gpa, "  freebind={d}\n", .{ (b0 >> 2) & 1 });
                try parsed.print(gpa, "  hdrincl={d}\n", .{ (b0 >> 3) & 1 });
                try parsed.print(gpa, "  mc_loop={d}\n", .{ (b0 >> 4) & 1 });
                try parsed.print(gpa, "  transparent={d}\n", .{ (b0 >> 5) & 1 });
                try parsed.print(gpa, "  mc_all={d}\n", .{ (b0 >> 6) & 1 });
                try parsed.print(gpa, "  nodefrag={d}\n", .{ (b0 >> 7) & 1 });
                try parsed.print(gpa, "  bind_address_no_port={d}\n", .{ (b1 >> 0) & 1 });
                try parsed.print(gpa, "  recverr_rfc4884={d}\n", .{ (b1 >> 0) & 1 });
                try parsed.print(gpa, "  defer_connect={d}\n", .{ (b1 >> 1) & 1 });
            },
            diag.INET_DIAG_ULP_INFO => {
                // Nested attributes describing the upper-layer protocol.
                // The first is INET_ULP_INFO_NAME (a null-terminated string);
                // any following TLS/MPTCP info structs are dumped as hex.
                var noff: usize = 0;
                while (noff + @sizeOf(diag.nlattr) <= attr.len) {
                    const nnla: *const diag.nlattr = @alignCast(@ptrCast(attr.ptr + noff));
                    if (nnla.nla_len < @sizeOf(diag.nlattr) or noff + nnla.nla_len > attr.len) {
                        log.E("inet diag INET_DIAG_ULP_INFO nested attribute length invalid: {d}",
                            .{nnla.nla_len});
                        return error.NetlinkParseFailed;
                    }
                    const ndata = attr[noff + @sizeOf(diag.nlattr) .. noff + nnla.nla_len];
                    switch (nnla.nla_type) {
                        diag.INET_ULP_INFO_NAME => {
                            const l = std.mem.find(u8, ndata, "\x00") orelse ndata.len;
                            try parsed.print(gpa, "  ulp={s}\n", .{ ndata[0..l] });
                        },
                        diag.INET_ULP_INFO_TLS => {
                            try parsed.print(gpa, "  ulp_tls={x}\n", .{ ndata });
                        },
                        diag.INET_ULP_INFO_MPTCP => {
                            try parsed.print(gpa, "  ulp_mptcp={x}\n", .{ ndata });
                        },
                        else => {
                            try parsed.print(gpa, "  ulp_info[{d}]={x}\n",
                                .{ nnla.nla_type, ndata });
                        },
                    }
                    noff += std.mem.alignForward(usize, nnla.nla_len, 4);
                }
            },
            else => {
                log.W("inet diag message unknown attribute type: {d}", .{nla.nla_type});
            },
        }

        off += std.mem.alignForward(usize, nla.nla_len, 4);
    }

    try parsed.print(gpa, "\n", .{});
}

const field_type = enum {
    u8,
    u16,
    u32,
    u64,
};

//    const netlink_params = [5]struct {u8, u8, bool, []const u8 } {
const tcp_info_fields = [_]struct { []const u8, field_type } {
    .{ "state", .u8 },
    .{ "ca_state", .u8 },
    .{ "retransmits", .u8 },
    .{ "probes", .u8 },
    .{ "backoff", .u8 },
    .{ "options", .u8 },
    .{ "wscale", .u8 },
    .{ "flags", .u8 },
    .{ "rto", .u32 },
    .{ "ato", .u32 },
    .{ "snd_mss", .u32 },
    .{ "rcv_mss", .u32 },
    .{ "unacked", .u32 },
    .{ "sacked", .u32 },
    .{ "lost", .u32 },
    .{ "retrans", .u32 },
    .{ "fackets", .u32 },
    .{ "last_data_sent", .u32 },
    .{ "last_ack_sent", .u32 },
    .{ "last_data_recv", .u32 },
    .{ "last_ack_recv", .u32 },
    .{ "pmtu", .u32 },
    .{ "rcv_ssthresh", .u32 },
    .{ "rtt", .u32 },
    .{ "rttvar", .u32 },
    .{ "snd_ssthresh", .u32 },
    .{ "snd_cwnd", .u32 },
    .{ "advmss", .u32 },
    .{ "reordering", .u32 },
    .{ "rcv_rtt", .u32 },
    .{ "rcv_space", .u32 },
    .{ "total_retrans", .u32 },
    .{ "pacing_rate", .u64 },
    .{ "max_pacing_rate", .u64 },
    .{ "bytes_acked", .u64 },
    .{ "bytes_received", .u64 },
    .{ "segs_out", .u32 },
    .{ "segs_in", .u32 },
    .{ "notsent_bytes", .u32 },
    .{ "min_rtt", .u32 },
    .{ "data_segs_in", .u32 },
    .{ "data_segs_out", .u32 },
    .{ "delivery_rate", .u64 },
    .{ "busy_time", .u64 },
    .{ "rwnd_limited", .u64 },
    .{ "sndbuf_limited", .u64 },
    .{ "delivered", .u32 },
    .{ "delivered_ce", .u32 },
    .{ "bytes_sent", .u64 },
    .{ "bytes_retrans", .u64 },
    .{ "dsack_dups", .u32 },
    .{ "reord_seen", .u32 },
    .{ "rcv_ooopack", .u32 },
    .{ "snd_wnd", .u32 },
    .{ "rcv_wnd", .u32 },
    .{ "rehash", .u32 },
    .{ "total_rto", .u16 },
    .{ "total_rto_recoveries", .u16 },
    .{ "total_rto_time", .u32 },
};
