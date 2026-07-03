const std = @import("std");
const process = @import("process.zig");
const proc = @import("proc.zig");
const globals = @import("globals.zig");
const log = @import("log.zig");
const output = @import("output.zig");
const elf = std.elf;
const elf64 = std.elf.Elf64;
const Allocator = std.mem.Allocator;

const Notes = std.ArrayList(u8);
const _SC_CLK_TCK = 2;
const kib = 1024;

// ELF core note types, from /usr/include/linux/elf.h
const NT_PRSTATUS: u32 = 1;
const NT_FPREGSET: u32 = 2;
const NT_PRPSINFO: u32 = 3;
const NT_AUXV: u32 = 6;
const NT_FILE: u32 = 0x46494C45; // "FILE"

// pagemap entry bits, from kernel fs/proc/task_mmu.c (not in a uapi header)
const PM_PRESENT: u64 = 1 << 63;
const PM_SWAP: u64 = 1 << 62;
const PM_PFN_MASK: u64 = (1 << 55) - 1;

pub fn dump(gpa: std.mem.Allocator, io: std.Io, file: *output.File, child_pid: i32,
    pmaps: proc.Maps, thread_info: process.ThreadInfo, target_state: proc.State,
    target_status: proc.Status) !void
{
    const page_size = std.heap.pageSize();
    const zeros = [_]u8{0} ** page_size;

    // open target's memory and pagemap files
    const mem_path = try std.fmt.allocPrint(gpa, "/proc/{d}/mem", .{child_pid});
    defer gpa.free(mem_path);
    const mem_file = try std.Io.Dir.openFileAbsolute(io, mem_path, .{});
    defer mem_file.close(io);
    const pagemap_path = try std.fmt.allocPrint(gpa, "/proc/{d}/pagemap", .{child_pid});
    defer gpa.free(pagemap_path);
    const pagemap_file = try std.Io.Dir.openFileAbsolute(io, pagemap_path, .{});
    defer pagemap_file.close(io);

    var mem_buffer = gpa.alloc(u8, 2 * 1048576) catch |err| {
        log.E("Failed to allocate memory buffer: {}", .{err});
        return err;
    };
    defer gpa.free(mem_buffer);
    var pagemap_buffer = gpa.alloc(u8, 2 * 1048576 / page_size * 8) catch |err| {
        log.E("Failed to allocate pagemap buffer: {}", .{err});
        return err;
    };
    defer gpa.free(pagemap_buffer);

    // initialize map filter
    for (pmaps.entries.items) |*map|
        try initMapFilter(map, mem_file, io, page_size);

    //
    // core file layout
    //
    // elf header (ehdr)
    // optional section header (shdr)
    // PT_NOTE header
    // PT_LOAD headers (one per mapping)
    // PT_NOTE data
    //   NT_PRSTATUS (one per thread)
    //   NT_PRPSINFO
    //   NT_AUXV
    //   NT_FILE
    //   NT_FPREGSET
    //   NT_X86_XSTATE
    // alignment padding
    // PT_LOAD data (one per mapping)
    //
    // we calculate all offsets up front so we can later stream the file without seeking
    // so we can compress it while writing.
    //

    //
    // Compose notes section
    //
    var notes: Notes = .empty;
    defer notes.deinit(gpa);

    try addPrpsinfo(gpa, io, &notes, child_pid, target_state, target_status);

    for (thread_info.items) |entry|
        try addPrstatus(gpa, &notes, entry);

    try addAuxv(gpa, &notes, io, child_pid);

    try addFile(gpa, &notes, pmaps, page_size);

    //
    // Write ELF headers
    //
    var xnum = false;
    var shdrsz: usize = 0;
    const nphdr = pmaps.entries.items.len + 1; // +1 for PT_NOTE
    if (nphdr >= std.elf.PN_XNUM - 1) {
        xnum = true;
        shdrsz = @sizeOf(elf64.Shdr);
    }

    var ehdr: elf64.Ehdr = .{
        .ident = [_]u8{0} ** elf.EI.NIDENT,
        .type = elf.ET.CORE,
        .machine = elf.EM.X86_64,
        .version = 1,
        .entry = 0,
        .phoff = @sizeOf(elf64.Ehdr) + shdrsz,
        .shoff = if (xnum) @sizeOf(elf64.Ehdr) else 0,
        .flags = 0,
        .ehsize = @sizeOf(elf64.Ehdr),
        .phentsize = @sizeOf(elf64.Phdr),
        .phnum = if (xnum) elf.PN_XNUM else @as(u16, @intCast(nphdr)),
        .shentsize = if (xnum) @sizeOf(elf64.Shdr) else 0,
        .shnum = if (xnum) 1 else 0,
        .shstrndx = 0,
    };
    ehdr.ident[0] = 0x7F;
    ehdr.ident[1] = 'E';
    ehdr.ident[2] = 'L';
    ehdr.ident[3] = 'F';
    ehdr.ident[elf.EI.CLASS] = elf.ELFCLASS64;
    ehdr.ident[elf.EI.DATA] = elf.ELFDATA2LSB;
    ehdr.ident[elf.EI.VERSION] = 1;
    ehdr.ident[elf.EI.OSABI] = @intFromEnum(elf.OSABI.NONE);

    try file.addChunk(std.mem.asBytes(&ehdr));

    if (xnum) {
        // extended header for more program headers
        var shdr: elf64.Shdr = .{
            .name = 0,
            .type = elf.SHT.NULL,
            .flags = .{ .shf = .{} },
            .addr = 0,
            .offset = 0,
            .size = 0,
            .link = 0,
            .info = @as(u32, @intCast(nphdr)),
            .addralign = 0,
            .entsize = 0,
        };
        try file.addChunk(std.mem.asBytes(&shdr));
    }

    // PT_NOTE header
    var note_phdr: elf64.Phdr = .{
        .type = elf.PT.NOTE,
        .flags = .{},
        .offset = @sizeOf(elf64.Ehdr) + shdrsz + @sizeOf(elf64.Phdr) * @as(u64, nphdr),
        .vaddr = 0,
        .paddr = 0,
        .filesz = @intCast(notes.items.len),
        .memsz = @intCast(notes.items.len),
        .@"align" = 4,
    };
    try file.addChunk(std.mem.asBytes(&note_phdr));

    // PT_LOAD headers
    var offset: usize = note_phdr.offset + note_phdr.filesz;
    const data_align = std.mem.alignForward(usize, offset, std.heap.pageSize()) - offset;

    offset += data_align;
    for (pmaps.entries.items) |map| {
        var map_flags: elf.PF = .{};
        if ((map.flags & std.elf.PF_R) != 0)
            map_flags.R = true;
        if ((map.flags & std.elf.PF_W) != 0)
            map_flags.W = true;
        if ((map.flags & std.elf.PF_X) != 0)
            map_flags.X = true;

        var load_phdr: elf64.Phdr = .{
            .type = elf.PT.LOAD,
            .flags = map_flags,
            .offset = offset,
            .vaddr = map.start,
            .paddr = 0,
            .filesz = map.dump_len,
            .memsz = @intCast(map.end - map.start),
            .@"align" = page_size,
        };
        offset += @intCast(map.dump_len);
        offset = std.mem.alignForward(usize, offset, page_size);

        try file.addChunk(std.mem.asBytes(&load_phdr));
    }

    //
    // write notes
    //
    try file.addChunk(notes.items);

    // pad to page boundary before writing mapping data
    try file.addChunk(zeros[0..(data_align)]);

    // get zero-page PFN so we can omit them from the dump
    const zero_pfn = try getZeroPfn(io, page_size);

    // Without CAP_SYS_ADMIN the kernel zeroes all pagemap PFNs, so the shared
    // zero page can no longer be identified (a real zero-page PFN is never 0).
    // In that case skip the zero-page optimization and dump every present page,
    // otherwise every present page would look like a zero page and anonymous
    // memory (heap, stack, loader state) would be dropped from the core.
    const zero_pfn_valid = zero_pfn != 0;
    if (!zero_pfn_valid)
        log.W("pagemap PFNs unavailable (need CAP_SYS_ADMIN), dumping all present " ++
            "pages; the core may be larger", .{});

    //
    // write PT_LOAD data
    //
    for (pmaps.entries.items) |map| {
        if (map.dump_len == 0)
            continue;

        // check for ^C
        if (globals.interrupted.load(.seq_cst)) {
            log.I("Dump interrupted by user.", .{});
            return error.Interrupted;
        }

        var pos: usize = 0;
        while (pos < map.dump_len) {
            var chunk_size = @min(map.dump_len - pos, mem_buffer.len);

            // read pagemap for this chunk
            const pm_len = chunk_size / page_size * 8;
            var pagemap_iovecs = [_][]u8{ pagemap_buffer[0..pm_len] };
            const pm_n = pagemap_file.readPositional(io, &pagemap_iovecs,
                (map.start + pos) / page_size * 8) catch |err|
            {
                log.E("Failed to read pagemap for pos {x}: {}", .{map.start + pos, err});
                return err;
            };
            if (pm_n != pm_len) {
                log.E("Short read from pagemap for pos {x}: expected {d} entries, got {d}",
                    .{map.start + pos, pm_len, pm_n / @sizeOf(u64)});
                return error.ShortPagemapRead;
            }
            var search_chunk_end = true;
            var chunk_end_zeros: usize = 0;
            for (0..chunk_size / page_size) |i| {
                const entry = @as(u64, @bitCast(pagemap_buffer[i*8..][0..8].*));
                const present = (entry & PM_PRESENT) != 0;
                const swapped = (entry & PM_SWAP) != 0;
                const is_zero = zero_pfn_valid and (entry & PM_PFN_MASK) == zero_pfn;
                const dumpable = (present and !is_zero) or map.dump_all or swapped;
                if (search_chunk_end and !dumpable) {
                    // only read chunk until here
                    chunk_end_zeros = chunk_size - (i * page_size);
                    chunk_size = i * page_size;
                    search_chunk_end = false;
                    log.D4("Chunk 0x{x} not fully dumpable, reducing chunk size to 0x{x}",
                        .{map.start + pos, chunk_size});
                } else if (!search_chunk_end and dumpable) {
                    // move start of next chunk to the next dumpable page
                    chunk_end_zeros = i * page_size - chunk_size;
                    log.D4("Next dumpable page at pos 0x{x}, zeros at end of chunk 0x{x}",
                        .{map.start + pos + (i * page_size), chunk_end_zeros});
                    break;
                }
            }
            if (chunk_size > 0) {
                var iovecs = [_][]u8{ mem_buffer[0..chunk_size] };
                const n = mem_file.readPositional(io, &iovecs, map.start + pos)
                    catch |err|
                blk: {
                    // EIO means the requested page at pos is not readable
                    // skip it and fill the output with zeros
                    if (err != error.InputOutput) {
                        log.E("Failed to read memory file at pos {x}: {}",
                            .{map.start + pos, err});
                        return err;
                    }
                    log.D1("Failed to read memory file at pos {x}: {}, emitting hole",
                        .{map.start + pos, err});
                    break :blk 0;
                };
                if (n > 0)
                    try file.addChunk(mem_buffer[0..n]);
                pos += n;
                if (n < chunk_size) {
                    // short read means we encountered an unreadable page. Emit what we have,
                    // add a hole for the next page and restart
                    log.D1("Short read from mem at pos {x}: expected {d} bytes, got {d}",
                        .{map.start + pos - n, chunk_size, n});
                    try file.addHole(page_size);
                    pos += page_size;
                }
            }
            if (chunk_end_zeros > 0) {
                try file.addHole(chunk_end_zeros);
                pos += chunk_end_zeros;
            }
        }
    }
}

// see also linux fs/coredump.c, vma_dump_size
fn initMapFilter(map: *proc.MapsEntry, mem_file: std.Io.File, io: std.Io,
    page_size: usize) !void
{
    map.dump_len = map.end - map.start;
    map.dump_all = false;

    // skip kernel mappings
    if (map.start & (1 << 63) != 0) {
        map.dump_len = 0;
        return;
    }

    if (map.pathname) |p| {
        // include always
        if (std.mem.eql(u8, p, "[vdso]")) {
            map.dump_all = true;
            return;
        }
    }

    if (map.dont_dump or map.vm_io) {
        map.dump_len = 0;
        return;
    }

    // hugetlb
    if (map.hugetlb) {
        if (map.shared) {
            map.dump_len = 0;   // default filter
        } else if (map.ino != 0) {
            map.dump_all = true;
        }
        return;
    }

    // dump all anon shared mappings
    if (map.shared and map.ino == 0) {
        return;
    }

    // dump dirty segments
    const anon = map.anonymous orelse 0;
    const swap = map.swap orelse 0;
    if (anon > 0 or swap > 0) {
        log.D3("Dumping anonymous mapping 0x{x}-0x{x} with {d} bytes anon",
            .{map.start, map.end, anon});
        if (map.ino != 0)
            map.dump_all = true;
        return;
    } else if (map.anonymous == null or map.swap == null) {
        // fallback path. we don't have smaps info, so rely on a more crude metric
        if ((map.flags & std.elf.PF_X) == 0) {
            if (map.ino != 0)
                map.dump_all = true;
            return;
        }
    }

    // gdb wants to see the ELF headers
    if (map.offset == 0 and (map.flags & std.elf.PF_R) != 0) {
        if ((map.flags & std.elf.PF_X) != 0) {
            map.dump_len = page_size;
            map.dump_all = true;
            return;
        }
        // check if file start with elf magic
        var buffer = [4]u8{0, 0, 0, 0};
        var iovecs = [_][]u8{ buffer[0..4] };
        const n = mem_file.readPositional(io, &iovecs, map.start) catch |err| {
            log.E("Failed to read memory file for ELF check at pos {x}: {}",
                .{map.start, err});
            return err;
        };
        if (n != 4) {
            log.E("Short read from mem for ELF check at pos {x}: expected 4 bytes, got {d}",
                .{map.start, n});
            return error.ShortMemoryRead;
        }
        if (std.mem.eql(u8, buffer[0..4], "\x7fELF")) {
            map.dump_len = page_size;
            map.dump_all = true;
            return;
        }
    }

    map.dump_len = 0;
}

// Estimate the logical (uncompressed, pre-sparse) core size from smaps
// metadata alone, without reading target memory. This mirrors the dumpability
// decisions in initMapFilter: mappings that are dumped in full contribute
// their whole size, page-by-page mappings contribute their resident anonymous
// plus swapped bytes.
//
// The result tracks the core's apparent size, which is an upper bound on the
// actual disk usage: the real dump writes zero pages as sparse holes and, for
// archives, compresses the data. The small ELF-header pages of clean file
// mappings and the note section are not counted, so it can be off by a few
// pages. It is meant only as a pre-flight sanity check.
pub fn estimateCoreSize(maps: proc.Maps) usize {
    var total: usize = 0;

    for (maps.entries.items) |map| {
        // skip kernel mappings
        if (map.start & (1 << 63) != 0)
            continue;
        if (map.dont_dump or map.vm_io)
            continue;

        if (map.pathname) |p| {
            if (std.mem.eql(u8, p, "[vdso]")) {
                total += map.end - map.start;
                continue;
            }
        }

        if (map.hugetlb) {
            if (!map.shared and map.ino != 0)
                total += map.end - map.start;
            continue;
        }

        // smaps reports Anonymous/Swap in kibibytes
        const anon = (map.anonymous orelse 0) * kib;
        const swap = (map.swap orelse 0) * kib;

        // shared anonymous mappings are dumped page by page
        if (map.shared and map.ino == 0) {
            total += anon + swap;
            continue;
        }

        if (anon > 0 or swap > 0) {
            if (map.ino != 0) {
                total += map.end - map.start; // dirty file mapping: dumped in full
            } else {
                total += anon + swap;         // anonymous: resident + swapped
            }
        }
    }

    return total;
}

fn addNote(gpa: Allocator, notes: *Notes, ntype: u32,
    name: []const u8, desc: []const u8) !void
{
    const hdr = elf.Elf64_Nhdr {
        .n_namesz = @intCast(name.len + 1),
        .n_descsz = @intCast(desc.len),
        .n_type = ntype,
    };

    const pad = [_]u8{0} ** 4;
    try notes.appendSlice(gpa, std.mem.asBytes(&hdr));
    try notes.appendSlice(gpa, name);
    // terminator
    try notes.appendSlice(gpa, pad[0..1]);
    // pad to 4 byte alignment
    try notes.appendSlice(gpa, pad[0..(4 - (name.len + 1) % 4) % 4]);
    try notes.appendSlice(gpa, desc);
    try notes.appendSlice(gpa, pad[0..(4 - desc.len % 4) % 4]);
}

fn addAuxv(gpa: Allocator, notes: *Notes, io: std.Io, pid: i32) !void {
    const auxv = proc.readProcFile(gpa, io, pid, "auxv") catch |err| {
        log.E("Failed to get auxv: {}", .{err});
        return err;
    };
    defer gpa.free(auxv);

    try addNote(gpa, notes, NT_AUXV, "CORE", auxv);
}

fn addPrstatus(gpa: Allocator, notes: *Notes, entry: process.ThreadInfoEntry) !void
{
    const ElfSiginfo = extern struct {
        signo: c_int = 0,                   // Signal number.
        code: c_int = 0,                    // Extra code.
        errno: c_int = 0,                   // Errno.
    };
    const ElfPrstatus = extern struct {
        info: ElfSiginfo = .{},             // Info associated with signal.
        cursig: i16 = 0,                    // Current signal.
        sigpend: c_ulong = 0,               // Set of pending signals.
        sighold: c_ulong = 0,               // Set of held signals.
        pid: c_int = 0,                     // Process ID.
        ppid: c_int = 0,                    // Parent process ID.
        pgrp: c_int = 0,                    // Process group ID.
        sid: c_int = 0,                     // Session ID.
        utime: std.posix.timeval = .{ .sec = 0, .usec = 0 }, // User time.
        stime: std.posix.timeval = .{ .sec = 0, .usec = 0 }, // System time.
        cutime: std.posix.timeval = .{ .sec = 0, .usec = 0 },// Cumulative user time.
        cstime: std.posix.timeval = .{ .sec = 0, .usec = 0 },// Cumulative system time.
        reg: process.user.user_regs_struct, // GP registers.
        fpvalid: c_int = 0,                 // True if math copro being used.
    };

    // status
    if (entry.status == null) {
        log.E("process status not found", .{});
        return error.StatusNotFound;
    }
    const status = &entry.status.?;

    // signals
    const sigpend_str = status.get("SigPnd") orelse {
        log.E("SigPnd not found in process status.", .{});
        return error.SigPndNotFound;
    };
    const sighold_str = status.get("SigBlk") orelse {
        log.E("SigBlk not found in process status.", .{});
        return error.SigBlkNotFound;
    };
    const sigpend = try std.fmt.parseInt(c_ulong, sigpend_str, 16);
    const sighold = try std.fmt.parseInt(c_ulong, sighold_str, 16);

    // times
    const state = entry.state orelse {
        log.E("process state not found", .{});
        return error.StateNotFound;
    };
    const hz_u: u64 = @intCast(std.c.sysconf(_SC_CLK_TCK));
    const hz_i: i64 = @intCast(hz_u);
    const utime_usec = state.utime * 1_000_000 / hz_u;
    const stime_usec = state.stime * 1_000_000 / hz_u;
    const cutime_usec = @divTrunc(state.cutime * 1_000_000, hz_i);
    const cstime_usec = @divTrunc(state.cstime * 1_000_000, hz_i);

    const pid = proc.getNSPidFromStatus(status, "NSpid") catch |err| {
        log.E("Failed to get NSpid from status: {}", .{err});
        return err;
    };
    const pgrp = proc.getNSPidFromStatus(status, "NSpgid") catch |err| {
        log.E("Failed to get NSpid from status: {}", .{err});
        return err;
    };
    const sid = proc.getNSPidFromStatus(status, "NSsid") catch |err| {
        log.E("Failed to get NSpid from status: {}", .{err});
        return err;
    };

    const prstatus: ElfPrstatus = .{
        .sigpend = sigpend,
        .sighold = sighold,
        .pid = pid,
        .ppid = state.ppid, // outside of namespace
        .pgrp = pgrp,
        .sid = sid,
        .utime = std.posix.timeval {
            .sec = @intCast(utime_usec / 1_000_000),
            .usec = @intCast(utime_usec % 1_000_000),
        },
        .stime = std.posix.timeval {
            .sec = @intCast(stime_usec / 1_000_000),
            .usec = @intCast(stime_usec % 1_000_000),
        },
        .cutime = std.posix.timeval {
            .sec = @intCast(@divTrunc(cutime_usec, 1_000_000)),
            .usec = @intCast(@mod(cutime_usec, 1_000_000)),
        },
        .cstime = std.posix.timeval {
            .sec = @intCast(@divTrunc(cstime_usec, 1_000_000)),
            .usec = @intCast(@mod(cstime_usec, 1_000_000)),
        },

        .reg = entry.regs,
        .fpvalid = 1,
    };

    try addNote(gpa, notes, NT_PRSTATUS, "CORE", std.mem.asBytes(&prstatus));

    try addNote(gpa, notes, NT_FPREGSET, "CORE", entry.xstate[0..512]);

    try addNote(gpa, notes, process.NT_X86_XSTATE, "LINUX", entry.xstate);
}

fn addPrpsinfo(gpa: Allocator, io: std.Io, notes: *Notes, child: i32,
    target_state: proc.State, target_status: proc.Status) !void
{
    const ElfPrpsinfo = extern struct {
        pr_state: u8 = 0,                  // Numeric process state.
        pr_sname: u8 = 0,                  // Char for pr_state.
        pr_zomb: c_char = 0,               // Zombie.
        pr_nice: c_char = 0,               // Nice value.
        pr_flag: c_ulong = 0,              // Flags.
        // TODO: ushort on 32-bit excutables
        pr_uid: c_uint = 0,                // User ID.
        pr_gid: c_uint = 0,                // Group ID.
        pr_pid: c_int = 0,                 // Process ID.
        pr_ppid: c_int = 0,                // Parent process ID.
        pr_pgrp: c_int = 0,                // Process group ID.
        pr_sid: c_int = 0,                 // Session ID.
        pr_fname: [16]u8 = undefined,      // Filename of executable.
        pr_psargs: [80]u8 = undefined,     // Initial part of arg list.
    };
    log.D3("target_status len: {d}", .{target_status.count()});
    const uid_str = target_status.get("Uid") orelse {
        log.E("Uid not found in process status.", .{});
        return error.UidNotFound;
    };
    const gid_str = target_status.get("Gid") orelse {
        log.E("Gid not found in process status.", .{});
        return error.GidNotFound;
    };
    // we only care about the real uid/gid
    const uid_end = std.mem.findAny(u8, uid_str, " \t") orelse uid_str.len;
    const gid_end = std.mem.findAny(u8, gid_str, " \t") orelse gid_str.len;
    const uid = try std.fmt.parseInt(c_uint, uid_str[0..uid_end], 10);
    const gid = try std.fmt.parseInt(c_uint, gid_str[0..gid_end], 10);

    var prpsinfo: ElfPrpsinfo = .{
        .pr_state = 0,
        .pr_sname = 'R',
        .pr_zomb = 0,
        .pr_nice = @intCast(target_state.nice),
        .pr_flag = 0,
        .pr_uid = uid,
        .pr_gid = gid,
        .pr_pid = target_state.pid,
        .pr_ppid = target_state.ppid,
        .pr_pgrp = target_state.pgrp,
        .pr_sid = target_state.session,
    };

    const comm_len = @min(target_state.comm.len, prpsinfo.pr_fname.len - 1);
    @memcpy(prpsinfo.pr_fname[0..comm_len], target_state.comm[0..comm_len]);
    prpsinfo.pr_fname[comm_len] = 0; // ensure null termination

    // get command line arguments
    const cmdline = proc.readProcFile(gpa, io, child, "cmdline") catch |err| {
        log.E("Failed to get comm: {}", .{err});
        return err;
    };
    defer gpa.free(cmdline);
    // replace all 0 bytes with spaces to join the arguments
    // leave the terminator alone
    for (cmdline[0..cmdline.len -| 1]) |*b| {
        if (b.* == 0) {
            b.* = ' ';
        }
    }
    const cmd_len = @min(cmdline.len, prpsinfo.pr_psargs.len - 1);
    @memcpy(prpsinfo.pr_psargs[0..cmd_len], cmdline[0..cmd_len]);
    prpsinfo.pr_psargs[cmd_len] = 0; // ensure null termination

    try addNote(gpa, notes, NT_PRPSINFO, "CORE", std.mem.asBytes(&prpsinfo));
}

fn addFile(gpa: Allocator, notes: *Notes, pmaps: proc.Maps, page_size: usize) !void
{
    var headers: std.ArrayList(c_long) = .empty;
    var body: std.ArrayList(u8) = .empty;
    defer headers.deinit(gpa);
    defer body.deinit(gpa);

    // header
    try headers.append(gpa, 0); // count, fill in later
    try headers.append(gpa, std.heap.pageSize());

    // mapping array
    var nfiles: c_long = 0;
    for (pmaps.entries.items) |map| {
        if (map.pathname) |p| {
            if (p[0] != '/')
                continue;
            nfiles += 1;
            try body.appendSlice(gpa, p);
            try body.append(gpa, 0); // null terminator

            try headers.append(gpa, @intCast(map.start));
            try headers.append(gpa, @intCast(map.end));
            try headers.append(gpa, @intCast(map.offset / page_size));
        }
    }
    headers.items[0] = nfiles;
    // join header and body
    var note_data: std.ArrayList(u8) = .empty;
    defer note_data.deinit(gpa);
    for (headers.items) |h|
        try note_data.appendSlice(gpa, std.mem.asBytes(&h));
    try note_data.appendSlice(gpa, body.items);

    log.D3("file note data len: {d}", .{note_data.items.len});
    try addNote(gpa, notes, NT_FILE, "CORE", note_data.items);
}

// to get the zero PFN, we map a single page for us, read it to get the PFN assigned,
// and read the PFN from pagemap
fn getZeroPfn(io: std.Io, page_size: usize) !u64
{
    const mem = std.posix.mmap(null, page_size, .{ .READ = true },
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0) catch |err| {
        log.E("Failed to mmap for zero page PFN: {}", .{err});
        return err;
    };
    defer std.posix.munmap(mem);

    const pagemap_file = std.Io.Dir.openFileAbsolute(io, "/proc/self/pagemap", .{}) catch |err| {
        log.E("Failed to open pagemap for zero page PFN: {}", .{err});
        return err;
    };
    defer pagemap_file.close(io);

    // fault in the page
    const v: u8 = @as(*const volatile u8, @ptrCast(mem)).*;
    std.mem.doNotOptimizeAway(v);

    var buffer = [_]u8{0} ** 8;
    var pagemap_iovecs = [_][]u8{ &buffer };
    log.D3("Reading pagemap for zero page at pos {x}", .{@intFromPtr(mem.ptr)});
    const pm_n = pagemap_file.readPositional(io, &pagemap_iovecs,
        @intFromPtr(mem.ptr) / page_size * 8) catch |err|
    {
        log.E("Failed to read pagemap for pos (zp): {}", .{err});
        return err;
    };
    if (pm_n != 8) {
        log.E("Short read from pagemap for pos (zp), got {d}", .{pm_n});
        return error.ShortPagemapRead;
    }

    const zero_pfn = @as(u64, @bitCast(buffer)) & PM_PFN_MASK;
    log.D2("Zero page PFN: {x}", .{zero_pfn});
    return zero_pfn;
}
