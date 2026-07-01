const std = @import("std");
const proc = @import("proc.zig");
const globals = @import("globals.zig");
const log = @import("log.zig");
pub const user = @cImport({
    @cInclude("sys/user.h");
});
const payload = @embedFile("payload");
const Allocator = std.mem.Allocator;

const ptrace = std.posix.ptrace;
const PTRACE = std.os.linux.PTRACE;

// from /usr/include/linux/ptrace.h
const NT_X86_XSTATE: usize = 0x202; // from /usr/include/linux/elf.h

// from /usr/include/linux/wait.h
const __WALL: u32 = 0x40000000;

// for convenience
const usize_neg_1: usize = @bitCast(@as(isize, -1));

const PidState = struct {
    sig: u32 = 0,
 //   regs: ?user.user_regs_struct = null,
};

pub const PidsMap = std.AutoHashMap(i32, ?PidState);

pub const ThreadInfoEntry = struct {
    pid: i32,
    regs: user.user_regs_struct,
    xstate: []u8,
    state: ?proc.State = null,
    status: ?proc.Status = null,
};

pub const ThreadInfo = std.ArrayList(ThreadInfoEntry);

pub fn grab(gpa: Allocator, io: std.Io, pid: i32) !PidsMap {
    log.V("Attempting to attach to process with PID: {d}", .{pid});

    const tasks_dir = try std.fmt.allocPrint(gpa, "/proc/{d}/task", .{pid});
    defer gpa.free(tasks_dir);
    log.D2("Constructed tasks directory path: {s}", .{tasks_dir});

    //
    // send seize + interrupt to all threads, loop until no more threads appear
    //
    var seized_pids: PidsMap = .init(gpa);
    var found = true;
    while (found) {
        log.D1("enter seize loop", .{});
        found = false;
        const tasks = std.Io.Dir.openDirAbsolute(io, tasks_dir, .{
                .follow_symlinks = false,
                .iterate = true,
            }) catch |err| {
            log.E("Failed to read tasks directory {s}: {}", .{tasks_dir, err});
            return err;
        };
        errdefer std.Io.Dir.close(tasks, io);

        var iter = tasks.iterate();
        errdefer detach(seized_pids);
        while (try iter.next(io)) |entry| {
            const task_name = entry.name;
            const task_pid = try std.fmt.parseInt(i32, task_name, 10);

            log.D2("Found task: {}", .{task_pid});
            if (seized_pids.get(task_pid) != null) {
                log.D5("Already seized PID {d}, skipping", .{task_pid});
                continue;
            }
            found = true;
            log.D3("Seized task: {}", .{task_pid});

            ptrace(PTRACE.SEIZE, task_pid, 0, 0) catch |err| {
                if (err == error.ProcessNotFound) {
                    log.D1("Failed to attach: thread {d} gone", .{task_pid});
                    continue;
                }
                return err;
            };
            try seized_pids.put(task_pid, .{});
            try ptrace(PTRACE.INTERRUPT, task_pid, 0, 0);
        }
        std.Io.Dir.close(tasks, io);
    }

    //
    // Wait for all threads to stop. They are either stopped in SIGTRAP from PTRACE_INTERRUPT
    // or any other signal arriving naturally.
    //
    var it = seized_pids.iterator();
    while (it.next()) |entry| {
        const status = try waitpid(entry.key_ptr.*, "seize PID {d}", .{entry.key_ptr.*});
        const st: u32 = @intCast(status);
        log.D2("PID {d} stopped with status {d}", .{entry.key_ptr.*, st});
        if (std.c.W.IFEXITED(st) or std.c.W.IFSIGNALED(st)) {
            log.D1("PID {d} exited or was killed while waiting", .{entry.key_ptr.*});
            entry.value_ptr.* = null; // mark as exited
        } else if (std.c.W.IFSTOPPED(st)) {
            const sig = std.c.W.STOPSIG(st);
            const ptrace_event = (st >> 16);
            if (sig != std.c.SIG.TRAP or ptrace_event != PTRACE.EVENT.STOP) {
                entry.value_ptr.*.?.sig = @intFromEnum(sig); // restart with sig
            }
        }
    }

    log.V("Successfully seized all threads of PID {d}", .{pid});
    return seized_pids;
}

pub fn detach(seized_pids: PidsMap) void {
    var it = seized_pids.iterator();
    while (it.next()) |entry| {
        const pid = entry.key_ptr.*;
        if (entry.value_ptr.*) |val| {
            ptrace(PTRACE.DETACH, pid, 0, val.sig) catch |err| {
                log.E("Failed to detach from PID {d}: {}", .{pid, err});
            };
        }
    }
}

pub fn findInjectionThread(pids: PidsMap) !i32 {
    //
    // pick any thread to inject into
    //
    var it = pids.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.*) |*val| {
            // don't chose a thread with a pending signal, it does not sit in PTRACE_EVENT_STOP
            if (val.sig == 0)
                return entry.key_ptr.*;
        }
    }
    log.E("No threads for injection found, please retry", .{});
    return error.NoThreads;
}

fn waitpid(pid: i32, comptime format: []const u8, args: anytype) !c_int {
    _ = std.c.alarm(5);
    defer _ = std.c.alarm(0);
    var status: c_int = undefined;
    const ret = std.c.waitpid(pid, &status, __WALL);
    if (ret == -1) {
        var buf = [_]u8 {0} ** 1000;
        const reason = try std.fmt.bufPrint(&buf, format, args);
        log.E("Failed to wait for PID {d} for {s}: {}", .{pid, reason, std.c._errno()});
        return error.WaitFailed;
    }
    return status;
}

// block signals
// signals arriving during injection may mess up the control flow
// as we don't go through libc and use syscalls directly, we can't use sigset_t
// for kernel, sigset has only 8 bytes
fn blockSignals(pid: i32) !u64 {
    var original_mask: u64 = undefined;
    var block_all: u64 = 0xffffffffffffffff;

    ptrace(PTRACE.GETSIGMASK, pid, 8, @intFromPtr(&original_mask)) catch |err| {
        log.E("Failed to get original signal mask from {}: {}", .{pid, err});
        return error.GetSigMaskFailed;
    };
    ptrace(PTRACE.SETSIGMASK, pid, 8, @intFromPtr(&block_all)) catch |err| {
        log.E("Failed to set signal mask: {}", .{err});
        return error.SetSigMaskFailed;
    };
    log.D3("Original signal mask is {x}", .{original_mask});

    return original_mask;
}

fn unblockSignals(pid: i32, original_mask: u64) void {
    ptrace(PTRACE.SETSIGMASK, pid, 8, @intFromPtr(&original_mask)) catch |err| {
        log.E("Failed to restore original signal mask: {}", .{err});
    };
}

// prepare registers for the restart later
fn rewindSyscall(regs: user.user_regs_struct) user.user_regs_struct {
    var restart_regs = regs;
    const rax_i64 = @as(i64, @bitCast(regs.rax));
    if (rax_i64 == -512 or rax_i64 == -513 or rax_i64 == -514) {
        restart_regs.rax = regs.orig_rax; // restore original syscall
        restart_regs.rip -= 2;            // rewind to syscall instruction
    } else if (rax_i64 == -516) {
        restart_regs.rax = 219;           // __NR_restart_syscall
        restart_regs.rip -= 2;            // rewind to syscall instruction
    }

    return restart_regs;
}


pub fn cloneChild(pid: i32, syscall_addr: usize, rlim: usize) !struct { i32, i32 }
{
    const original_mask = try blockSignals(pid);
    const stack_size = 2048;
    defer unblockSignals(pid, original_mask);

    //
    // read current registers
    //
    var regs: user.user_regs_struct = undefined;
    ptrace(PTRACE.GETREGS, pid, 0, @intFromPtr(&regs)) catch |err| {
        log.E("Failed to get registers for PID {d} for inject: {}", .{pid, err});
        return err;
    };

    log.D1("Preparing injection into PID {d} rax {x} ({d})",
        .{pid, regs.rax, @as(i64, @bitCast(regs.rax))});

    //
    // read current registers
    // prepare registers for the restart later
    //
    var restart_regs = rewindSyscall(regs);

    defer ptrace(PTRACE.SETREGS, pid, 0, @intFromPtr(&restart_regs)) catch |err| {
        log.E("Failed to restore registers for PID {d}: {}", .{pid, err});
    };

    //
    // mmap us some memory to write the payload to. We want some stack at the top
    // allocate full pages
    //
    const mmap_len: usize = (payload.len + stack_size + 4095) & ~@as(usize, 4095);
    const mmap_addr = mmap(pid, &regs, syscall_addr, mmap_len) catch |err| {
        log.E("Failed to run mmap syscall for injection: {}", .{err});
        return err;
    };
    if (mmap_addr == usize_neg_1) {
        log.E("mmap syscall failed: {}", .{std.c._errno()});
        return error.InvalidMmapAddress;
    }

    log.D3("MMap at {x}", .{mmap_addr});

    //
    // defer munmap
    //
    defer _ = munmap(pid, &regs, syscall_addr, mmap_addr, mmap_len) catch |err| {
        log.E("Failed to run munmap syscall for injection: {}", .{err});
    };

    //
    // write payload to the mmaped region
    //
    var off: usize = 0;
    while (off < payload.len) {
        var data: usize = 0;

        for (0..@min(8, payload.len - off)) |i|
            data |= @as(usize, payload[off + i]) << @intCast(i * 8);

        log.D2("Writing payload chunk {x} at offset {d}", .{data, off});
        ptrace(PTRACE.POKETEXT, pid, mmap_addr + off, data) catch |err| {
            log.E("Failed to write payload at offset {d} for PID {d}: {}",
                .{off, pid, err});
            return err;
        };
        off += 8;
    }

    //
    // trace fork to get the child pid as seen from host
    //
    ptrace(PTRACE.SETOPTIONS, pid, 0, PTRACE.O.TRACECLONE) catch |err| {
        log.E("Failed to set ptrace options for PID {d}: {}", .{pid, err});
        return err;
    };

    //
    // execute payload
    //
    var pl_regs = regs;
    pl_regs.rip = mmap_addr;
    pl_regs.rsp = mmap_addr + mmap_len - 8; // stack grows downwards, leave 8 bytes for safety
    pl_regs.rax = 0;
    pl_regs.r15 = rlim;

    ptrace(PTRACE.SETREGS, pid, 0, @intFromPtr(&pl_regs)) catch |err| {
        log.E("Failed to set registers for PID {d}: {}", .{pid, err});
        return err;
    };

    try runToStop(pid, false, PTRACE.EVENT.CLONE);

    var eventmsg: u64 = undefined;
    ptrace(PTRACE.GETEVENTMSG, pid, 0, @intFromPtr(&eventmsg)) catch |err| {
        log.E("Failed to get event message for PID {d}: {}", .{pid, err});
        return err;
    };
    const child_hostpid: i32 = @intCast(eventmsg);
    log.D1("Payload clone created child with host PID {d}", .{child_hostpid});

    //
    // continue the host to int3
    //
    try runToStop(pid, false, 0);

    //
    // get injection return value
    //
    var regs_after: user.user_regs_struct = undefined;
    ptrace(PTRACE.GETREGS, pid, 0, @intFromPtr(&regs_after)) catch |err| {
        log.E("Failed to get registers for PID {d} after syscall: {}", .{pid, err});
        return err;
    };

    log.D1("Payload executed with return value {x} ({d})",
        .{regs_after.rax, regs_after.rax});

    //
    // gather the childs SIGSTOP
    //
    const status = try waitpid(child_hostpid, "collect STOP", .{});
    log.D1("Child stopped with status 0x{x} for SIGSTOP", .{status});
    if (status >> 16 != PTRACE.EVENT.STOP) {
        log.E("Child did not stop with expected ptrace event, status {x}", .{status});
        return error.WaitForStop;
    }

    //
    // detach from the child
    //
    ptrace(PTRACE.DETACH, child_hostpid, 0, 0) catch |err| {
        log.E("Failed to detach from child PID {d}: {}", .{child_hostpid, err});
        return err;
    };

    //
    // check payload return value, it should be a valid PID
    //
    if (regs_after.rax > std.math.maxInt(i32)) {
        log.E("Payload returned error code {x}", .{regs_after.rax});
        return error.PayloadFailed;
    }
    return .{ @intCast(regs_after.rax), child_hostpid };
}

fn mmap(pid: i32, regs_in: *const user.user_regs_struct, syscall_addr: usize, len: usize) !usize {
    var regs = regs_in.*;
    regs.orig_rax = usize_neg_1;
    regs.rax = 9; // __NR_mmap
    regs.rdi = 0; // addr
    regs.rsi = len;
    regs.rdx = 7; // prot rwx
    regs.r10 = 0x22; // std.os.MAP_ANONYMOUS | std.os.MAP_PRIVATE; // flags
    regs.r8 = @bitCast(@as(i64, -1)); // fd
    regs.r9 = 0; // offset
    regs.rip = syscall_addr;

    return runSyscall(pid, &regs) catch |err| {
        log.E("Failed to run mmap syscall for injection: {}", .{err});
        return err;
    };
}

fn munmap(pid: i32, regs_in: *const user.user_regs_struct, syscall_addr: usize,
    addr: usize, len: usize) !usize
{
    var regs = regs_in.*;
    regs.orig_rax = usize_neg_1;
    regs.rax = 11; // __NR_munmap
    regs.rdi = addr; // addr
    regs.rsi = len;
    regs.rip = syscall_addr;

    return runSyscall(pid, &regs) catch |err| {
        log.E("Failed to run munmap syscall for injection: {}", .{err});
        return err;
    };
}

fn runToStop(pid: i32, singlestep: bool, expected_event: u32) !void {
    log.D1("Continuing PID {d} to expected event {d}", .{pid, expected_event});
    if (singlestep) {
        ptrace(PTRACE.SINGLESTEP, pid, 0, 0) catch |err| {
            log.E("Failed to single step PID {d}: {}", .{pid, err});
            return err;
        };
    } else {
        ptrace(PTRACE.CONT, pid, 0, 0) catch |err| {
            log.E("Failed to continue PID {d}: {}", .{pid, err});
            return err;
        };
    }
    const status = try waitpid(pid, "int3", .{});
    const st: u32 = @intCast(status);
    log.D1("PID {d} stopped with status 0x{x} sig {d} for int3",
        .{pid, st, std.c.W.STOPSIG(st)});
    if (!std.c.W.IFSTOPPED(st)) {
        log.E("PID {d} did not stop with int3, status {d}", .{pid, st});
        return error.WaitForStop;
    }
    const sig = std.c.W.STOPSIG(st);
    if (sig != std.c.SIG.TRAP) {
        log.E("PID {d} stopped with unexpected signal {d}", .{pid, sig});
        return error.WaitForStop;
    }
    if (status >> 16 != expected_event) {
        log.E("PID {d} stopped with unexpected ptrace event {d}", .{pid, status >> 16});
        return error.WaitForStop;
    }
}

fn runSyscall(pid: i32, regs: *const user.user_regs_struct) !c_ulonglong {
    // save original content
    const syscall_addr = regs.*.rip;

    log.D1("Verify the syscall is still there at {x} for PID {d}", .{syscall_addr, pid});
    // can't use std.posix.ptrace here, as it does not return the data
    const orig = std.c.ptrace(PTRACE.PEEKTEXT, pid, @ptrFromInt(syscall_addr), null);
    if (orig & 0xffff != 0x050f) { // 0x0f05 is the syscall instruction
        log.E("Unexpected code at syscall address {x} for PID {d}: {x}",
            .{syscall_addr, pid, orig});
        return error.InvalidSyscallAddress;
    }

    ptrace(PTRACE.SETREGS, pid, 0, @intFromPtr(regs)) catch |err| {
        log.E("Failed to set registers for PID {d}: {}", .{pid, err});
        return err;
    };

    try runToStop(pid, true, 0);

    // get syscall return value
    var regs_after: user.user_regs_struct = undefined;
    ptrace(PTRACE.GETREGS, pid, 0, @intFromPtr(&regs_after)) catch |err| {
        log.E("Failed to get registers for PID {d} after syscall: {}", .{pid, err});
        return err;
    };

    return regs_after.rax;
}

pub fn waitChild(pid: i32, child: i32, syscall_addr: usize) !void {
    const original_mask = try blockSignals(pid);
    defer unblockSignals(pid, original_mask);

    // read current registers
    var regs: user.user_regs_struct = undefined;
    ptrace(PTRACE.GETREGS, pid, 0, @intFromPtr(&regs)) catch |err| {
        log.E("Failed to get registers for PID {d} for inject: {}", .{pid, err});
        return err;
    };

    log.D1("waiting on PID {d} rax {x} ({d})", .{child, regs.rax, @as(i64, @bitCast(regs.rax))});

    // prepare registers for the restart later
    var restart_regs = rewindSyscall(regs);

    defer ptrace(PTRACE.SETREGS, pid, 0, @intFromPtr(&restart_regs)) catch |err| {
        log.E("Failed to restore registers for PID {d}: {}", .{pid, err});
    };

    regs.orig_rax = usize_neg_1;
    regs.rip = syscall_addr;
    regs.rax = 61;
    regs.rdi = @intCast(child);
    regs.rsi = 0;
    regs.rdx = 0x40000000;  // __WALL
    regs.r10 = 0;
    regs.rsp -= 128; // Red zone clearance, not strictly necessary

    // guard rail: wait max 5 seconds
    _ = std.c.alarm(5);
    _ = runSyscall(pid, &regs) catch |err| {
        log.E("Failed to run wait syscall for injection: {}", .{err});
        _ = std.c.alarm(0);
        return err;
    };
    _ = std.c.alarm(0);
}

pub fn fetchThreadInfo(gpa: Allocator, pids: PidsMap, target_pid: i32) !ThreadInfo {
    var xstate_buf: [4096]u8 = undefined;
    var xstate_iov = std.posix.iovec {
        .base = &xstate_buf,
        .len = xstate_buf.len,
    };
    var info = try ThreadInfo.initCapacity(gpa, pids.count());

    log.V("Fetching thread info for {d} threads", .{pids.count()});
    var it = pids.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.* == null)
            continue;
        const pid = entry.key_ptr.*;
        var regs: user.user_regs_struct = undefined;
        ptrace(PTRACE.GETREGS, pid, 0, @intFromPtr(&regs)) catch |err| {
            log.E("Failed to get registers for PID {d} for thread info: {}",
                .{entry.key_ptr.*, err});
            return err;
        };
        xstate_iov.len = xstate_buf.len;
        ptrace(PTRACE.GETREGSET, pid, NT_X86_XSTATE, @intFromPtr(&xstate_iov)) catch |err| {
            log.E("Failed to get xstate for PID {d} for thread info: {}",
                .{entry.key_ptr.*, err});
            return err;
        };
        log.D3("Fetched xstate for PID {d}, size {d}", .{pid, xstate_iov.len});
        // TODO add fallback for older hardware, get fp regs only?

        try info.append(gpa, ThreadInfoEntry {
            .pid = pid,
            .regs = regs,
            .xstate = try gpa.dupe(u8, xstate_buf[0..xstate_iov.len]),
        });

        if (globals.interrupted.load(.seq_cst)) {
            log.I("Fetching state interrupted by user.", .{});
            return error.Interrupted;
        }
    }

    //
    // sort in a way that is useful in gdb. main thread first, other in ascending
    // order of pid
    //
    std.mem.sort(ThreadInfoEntry, info.items, target_pid, cmpInfoEntry);

    return info;
}

fn cmpInfoEntry(target: i32, a: ThreadInfoEntry, b: ThreadInfoEntry) bool {
    if (a.pid == b.pid)
        return false;
    if (a.pid == target)
        return true;
    if (b.pid == target)
        return false;
    if (a.pid < b.pid)
        return true;
    return false;
}

// hunt for syscall instruction in the maps, starting with libc
pub fn findSyscall(gpa: Allocator, io: std.Io, pid: i32) !usize {
    const maps = proc.readMaps(gpa, io, pid) catch |err| {
        log.E("Failed to get maps for PID {d} for syscall search: {}",
            .{pid, err});
        return err;
    };
    var searchlist: std.ArrayList(proc.MapsEntry) = .empty;
    for (maps.entries.items) |map| {
        if ((map.flags & std.elf.PF_X) == 0)
            continue;
        if ((map.ino == 0) or (map.pathname == null) or (map.pathname.?[0] != '/'))
            continue;
        if (searchlist.items.len > 0 and
            std.mem.eql(u8, searchlist.getLast().pathname.?, map.pathname.?))
        {
            continue;
        }
        searchlist.append(gpa, map) catch |err| {
            log.E("Failed to append to search list: {}", .{err});
            return err;
        };
    }
    if (searchlist.items.len == 0) {
        log.E("No suitable memory regions found for syscall search", .{});
        return error.NoSyscall;
    }

    // remove duplicates
    var uniquelist: std.ArrayList(proc.MapsEntry) = .empty;
    uniquelist.append(gpa, searchlist.items[0]) catch |err| {
        log.E("Failed to append to unique list: {}", .{err});
        return err;
    };
    for (searchlist.items[1..]) |entry| {
        if (std.mem.eql(u8, uniquelist.getLast().pathname.?, entry.pathname.?))
            continue;
        uniquelist.append(gpa, entry) catch |err| {
            log.E("Failed to append to unique list: {}", .{err});
            return err;
        };
    }

    // place libc first. binary itself ends up second
    var index: usize = 0;
    for (0..uniquelist.items.len) |i| {
        if (std.mem.find(u8, uniquelist.items[i].pathname.?, "/libc.so")) |_| {
            index = i;
            break;
        }
    }
    const candidate_entry = uniquelist.swapRemove(index);
    try uniquelist.insert(gpa, 0, candidate_entry);

    const mem_path = try std.fmt.allocPrint(gpa, "/proc/{d}/mem", .{pid});
    defer gpa.free(mem_path);
    const mem_file = try std.Io.Dir.openFileAbsolute(io, mem_path, .{});
    defer mem_file.close(io);
    var buffer = gpa.alloc(u8, 65536) catch |err| {
        log.E("Failed to allocate buffer for syscall search: {}", .{err});
        return err;
    };

    for (uniquelist.items) |entry| {
        log.D1("Searching for syscall in {s}", .{entry.pathname.?});
        var pos: usize = 0;
        const size = entry.end - entry.start;
        while (pos < size) {
            const len = @min(buffer.len, size - pos);
            var mem_iovecs = [_][]u8{ buffer[0..len] };
            const n = mem_file.readPositional(io, &mem_iovecs, (entry.start + pos)) catch |err| {
                log.E("Failed to read memory at {x} for PID {d}: {}",
                    .{entry.start + pos, pid, err});
                return err;
            };
            if (n != len) {
                log.E("Short read while reading memory at {x}: expected {x}, got {x}",
                    .{entry.start + pos, len, n});
                return error.ShortRead;
            }
            // ignore edge case where syscall spans two reads
            if (std.mem.find(u8, buffer[0..len], &[2]u8{ 0x0f, 0x05 })) |offset| {
                const syscall_addr = entry.start + pos + offset;
                log.D1("Found syscall instruction offset {d} in {s}",
                    .{pos + offset, entry.pathname.?});
                return syscall_addr;
            }
            pos += len;
        }
    }
    return error.NoSyscall;
}

pub fn grabOne(pid: i32) !u32 {
    ptrace(PTRACE.SEIZE, pid, 0, 0) catch |err| {
        log.E("Failed to attach thread {d}: {}", .{pid, err});
        return err;
    };
    ptrace(PTRACE.INTERRUPT, pid, 0, 0) catch |err| {
        log.E("Failed to interrupt thread {d}: {}", .{pid, err});
        return err;
    };
    const status = try waitpid(pid, "PID", .{});
    const st: u32 = @intCast(status);
    if (std.c.W.IFEXITED(st) or std.c.W.IFSIGNALED(st)) {
        log.E("PID {d} exited or was killed while waiting", .{pid});
        return error.ProcessExited;
    } else if (std.c.W.IFSTOPPED(st)) {
        const sig = std.c.W.STOPSIG(st);
        const ptrace_event = (st >> 16);
        if (sig != std.c.SIG.TRAP or ptrace_event != PTRACE.EVENT.STOP) {
            return @intFromEnum(sig); // restart with sig
        }
    }
    return 0;
}

pub fn detachOne(pid: i32, sig: u32) void {
    ptrace(PTRACE.DETACH, pid, 0, sig) catch |err| {
        log.E("Failed to detach from PID {d}: {}", .{pid, err});
    };
}
