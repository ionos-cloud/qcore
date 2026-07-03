const std = @import("std");
const log = @import("log.zig");

const whitespace = "\t\r\n";

pub const Maps = struct {
    //pub const Error = error{ParseFailed};
    entries: std.ArrayList(MapsEntry),
    arena: std.heap.ArenaAllocator,

    pub fn deinit(self: *Maps) void {
        self.arena.deinit();
    }
};

pub const MapsEntry = struct {
    start: usize,
    end: usize,
    flags: u8,
    shared: bool,
    offset: usize,
    dev: []const u8,
    ino: usize,
    pathname: ?[]const u8,
    dont_dump: bool = false,
    hugetlb: bool = false,
    vm_io: bool = false,
    anonymous: ?usize = null,
    swap: ?usize = null,
    dump_len: usize = 0,
    dump_all: bool = false,
};

pub const State = struct {
    pid: i32,
    comm: []u8,
    state: u8,
    ppid: i32,
    pgrp: i32,
    session: i32,
    tty_nr: i32,
    tpgid: i32,
    flags: u32,
    minflt: u64,
    cminflt: u64,
    majflt: u64,
    cmajflt: u64,
    utime: u64,
    stime: u64,
    cutime: i64,
    cstime: i64,
    priority: i64,
    nice: i64,
    num_threads: i64,
    itrealvalue: i64,
    starttime: u64,
    vsize: u64,
    rss: i64,
    rsslim: u64,
    startcode: u64,
    endcode: u64,
    startstack: u64,
    kstkesp: u64,
    kstkeip: u64,
    signal: u64,
    blocked: u64,
    sigignore: u64,
    sigcatch: u64,
    wchan: u64,
    nswap: u64,
    cnswap: u64,
    exit_signal: i32,
    processor: i32,
    rt_priority: u32,
    policy: u32,
    delayacct_blkio_ticks: u64,
    guest_time: u64,
    cguest_time: i64,
    start_data: u64,
    end_data: u64,
    start_brk: u64,
    arg_start: u64,
    arg_end: u64,
    env_start: u64,
    env_end: u64,
    exit_code: i32,
};

pub const Status = std.StringHashMap([]const u8);

pub fn getStatus(gpa: std.mem.Allocator, io: std.Io, pid: i32) !Status {
    const raw = readProcFile(gpa, io, pid, "status") catch |err| {
        log.E("Failed to read status file for pid {d}: {}", .{pid, err});
        return err;
    };

    return parseStatus(gpa, raw);
}

pub fn parseStatus(gpa: std.mem.Allocator, raw: []const u8) !Status {
    var status: Status = Status.init(gpa);

    var lines = std.mem.tokenizeScalar(u8, raw, '\n');
    while (lines.next()) |line| {
        var parts = std.mem.tokenizeScalar(u8, line, ':');

        const key = parts.next();
        const value = parts.next() orelse {
            log.E("Failed to parse status line: {s}", .{line});
            return error.ParsingError;
        };
        const h_key = try gpa.dupe(u8, key.?);
        const h_value = try gpa.dupe(u8, std.mem.trim(u8, value, whitespace));
        try status.put(h_key, h_value);
    }

    return status;
}

pub fn getNSPidFromStatus(status: *const Status, field: []const u8) !i32 {
    const pids = status.get(field) orelse {
        log.E("{s} not in Status", .{field});
        return error.NSpidNotFound;
    };
    // parse the last pid in the list, which is the pid in the innermost namespace
    const trimmed_pids = std.mem.trim(u8, pids, whitespace);
    var it = std.mem.tokenizeScalar(u8, trimmed_pids, '\t');
    var last_pid: ?i32 = null;
    while (it.next()) |pid_str| {
        const pid = std.fmt.parseInt(i32, pid_str, 10) catch |err| {
            log.E("Failed to parse pid in {s}: {s}", .{field, pid_str});
            return err;
        };
        last_pid = pid;
    }

    return last_pid orelse {
        log.E("No pids found in {s}: {s}", .{field, pids});
        return error.ParsingError;
    };
}

pub fn getState(gpa: std.mem.Allocator, io: std.Io, pid: i32) !State {
    const raw = readProcFile(gpa, io, pid, "stat") catch |err| {
        log.E("Failed to read state file for pid {d}: {}", .{pid, err});
        return err;
    };

    return parseState(gpa, raw);
}

pub fn parseState(gpa: std.mem.Allocator, raw: []const u8) !State {
    var state: State = undefined;
    var rest = raw;

    inline for (std.meta.fields(State)) |field| {
        if (comptime std.mem.eql(u8, field.name, "comm")) {
            // we need to be careful with the comm field, as it can contain spaces and
            // is enclosed in parentheses.
            if (rest[0] != '(') {
                log.E("Expected comm field to start with '(', got: {s}", .{rest});
                return error.ParsingError;
            }
            const end = std.mem.findLast(u8, rest, ")") orelse {
                log.E("Expected comm field to end with ')', got: {s}", .{rest});
                return error.ParsingError;
            };
            @field(state, "comm") = try gpa.dupe(u8, rest[1..end]);
            rest = rest[end + 2..];
        } else {
            const end = std.mem.findAny(u8, rest, " \n") orelse rest.len;
            if (field.type == u8) {
                if (end != 1) {
                    log.E("Expected single byte for field {s}, got: {s}",
                        .{field.name, rest});
                    return error.ParsingError;
                }
                @field(state, field.name) = rest[0];
                rest = rest[2..];
            } else {
                const val = std.fmt.parseInt(field.type, rest[0..end], 10) catch |err| {
                    log.E("Failed to parse field {s}: {s}, error: {}",
                        .{field.name, rest[0..end], err});
                    return error.ParsingError;
                };
                @field(state, field.name) = val;
                rest = rest[end + 1..];
            }
        }
    }

    return state;
}

pub fn slurp(gpa: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
    const file = try std.Io.Dir.openFileAbsolute(io, path, .{});
    defer file.close(io);

    var buffer: [65535]u8 = undefined;
    var out: std.ArrayList(u8) = .empty;

    while (true) {
        const nread = file.readPositionalAll(io, &buffer, out.items.len) catch |err| {
            log.E("Failed to read auxv file: {}", .{err});
            return err;
        };
        if (nread == 0)
            break;

        try out.appendSlice(gpa, buffer[0..nread]);
    }

    return out.toOwnedSlice(gpa);
}

pub fn readProcFile(gpa: std.mem.Allocator, io: std.Io, pid: i32, name: []const u8) ![]u8 {
    const path = try std.fmt.allocPrint(gpa, "/proc/{d}/{s}", .{pid, name});
    defer gpa.free(path);

    return slurp(gpa, io, path);
}

pub fn readMaps(gpa: std.mem.Allocator, io: std.Io, pid: i32) !Maps {
    var content: []const u8 = undefined;
    content = readProcFile(gpa, io, pid, "smaps") catch |err| blk: {
        if (err == error.FileNotFound) {
            log.V("smaps not found, falling back to maps", .{});
            break :blk try readProcFile(gpa, io, pid, "maps");
        }
        return err;
    };

    return parseMaps(gpa, content);
}

pub fn parseMaps(gpa: std.mem.Allocator, content: []const u8) !Maps {
    var arena = std.heap.ArenaAllocator.init(gpa);
    var aa = arena.allocator();
    errdefer arena.deinit();

    var maps = Maps {
        .entries = std.ArrayList(MapsEntry).empty,
        .arena = arena,
    };
    errdefer maps.deinit();

    var it = std.mem.tokenizeScalar(u8, content, '\n');
    while (it.next()) |line| {
        log.D5("Line: {s}", .{line});
        var parts = std.mem.tokenizeScalar(u8, line, ' ');

        const start_end = parts.next();
        if (start_end) |v| {
            if (std.mem.endsWith(u8, v, ":")) {
                if (maps.entries.items.len == 0) {
                    log.E("Detail line before any map entry: {s}", .{line});
                    return error.ParseFailed;
                }
                const last = &maps.entries.items[maps.entries.items.len - 1];
                if (std.mem.startsWith(u8, v, "VmFlags:")) {
                    if (std.mem.find(u8, line, " dd") != null) {
                        log.D1("found dd flag", .{});
                        // set previous map to dont_dump
                        last.dont_dump = true;
                    }
                    if (std.mem.find(u8, line, " sh") != null) {
                        last.shared = true;
                    }
                    if (std.mem.find(u8, line, " ht") != null) {
                        last.hugetlb = true;
                    }
                    if (std.mem.find(u8, line, " io") != null) {
                        last.vm_io = true;
                    }
                } else if (std.mem.startsWith(u8, v, "Anonymous:")) {
                    if (parts.next()) |anon| {
                        const anon_size = std.fmt.parseInt(usize, anon, 10) catch |err| {
                            log.E("Failed to parse anonymous size: {s}", .{anon});
                            return err;
                        };
                        last.anonymous = anon_size;
                    }
                } else if (std.mem.startsWith(u8, v, "Swap:")) {
                    if (parts.next()) |sw| {
                        const swap_size = std.fmt.parseInt(usize, sw, 10) catch |err| {
                            log.E("Failed to parse swap size: {s}", .{sw});
                            return err;
                        };
                        last.swap = swap_size;
                    }
                }
                continue;
            }
        }
        const perms = parts.next();
        const offset = parts.next();
        const dev = parts.next();
        const ino = parts.next();
        const pathname = parts.next();

        if (dev == null) {
            log.E("Failed to parse line: {s}", .{line});
            return error.ParseFailed;
        }

        var se_it = std.mem.splitScalar(u8, start_end.?, '-');
        const start = se_it.next();
        const end = se_it.next();

        if (end == null) {
            log.E("Failed to parse start in line: {s}", .{line});
            return error.ParseFailed;
        }

        var flags: u8 = 0;
        if (perms.?[0] == 'r')
            flags |= std.elf.PF_R;
        if (perms.?[1] == 'w')
            flags |= std.elf.PF_W;
        if (perms.?[2] == 'x')
            flags |= std.elf.PF_X;

        const maps_entry = MapsEntry {
            .start = try std.fmt.parseInt(usize, start.?, 16),
            .end = try std.fmt.parseInt(usize, end.?, 16),
            .flags = flags,
            .shared = false,
            .offset = try std.fmt.parseInt(usize, offset.?, 16),
            .dev = try aa.dupe(u8, dev.?),
            .ino = try std.fmt.parseInt(usize, ino.?, 10),
            .pathname = if (pathname) |o| try aa.dupe(u8, o) else null,
        };
        try maps.entries.append(aa, maps_entry);
    }

    return maps;
}
