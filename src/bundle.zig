const std = @import("std");
const output = @import("output.zig");
const proc = @import("proc.zig");
const log = @import("log.zig");

const elf = std.elf;
const elf64 = std.elf.Elf64;

//
// add executables and libraries to allow standalone debugging of the dump
//
pub fn bundleFiles(gpa: std.mem.Allocator, io: std.Io, out: *output.Output, pmaps: proc.Maps,
    pid: i32, child_pid: i32) !void
{
    var prev_path: ?[]const u8 = null;
    var namebuf: [std.posix.PATH_MAX]u8 = undefined;
    const page_size = std.heap.pageSize();

    for (pmaps.entries.items) |map| {
        if (map.pathname == null or map.pathname.?.len == 0 or map.pathname.?[0] != '/')
            continue;
        if (prev_path != null and std.mem.eql(u8, prev_path.?, map.pathname.?))
            continue;
        if (prev_path == null) {
            const path = try std.fmt.bufPrint(&namebuf, "root/{s}", .{ map.pathname.? });
            out.addSymlink("exe", path) catch |err| {
                log.E("Failed to add symlink for executable: {}", .{err});
                return err;
            };
        }
        prev_path = map.pathname;
        const path = map.pathname.?;
        try copyFileToOutput(io, out, path, pid);

        // special case: if libc is linked, also add libthread_db
        if (std.mem.startsWith(u8, std.fs.path.basename(path), "libc.so")) {
            log.D2("libc detected, looking for libthread_db.so.1 in {s}",
                .{std.fs.path.dirname(path).?});
            var threadbuf: [std.posix.PATH_MAX]u8 = undefined;

            const libthread_proc_path = try std.fmt.bufPrint(&threadbuf,
                "/proc/{d}/root{s}/libthread_db.so.1",
                .{ pid, std.fs.path.dirname(path) orelse "" });
            if (std.Io.Dir.accessAbsolute(io, libthread_proc_path, .{})) |_| {
                log.D1("adding libthread_db.so.1 to bundle", .{});
                const libthread_path = try std.fmt.bufPrint(&threadbuf,
                    "{s}/libthread_db.so.1", .{ std.fs.path.dirname(path) orelse "." });
                try copyFileToOutput(io, out, libthread_path, pid);
            } else |err| {
                log.V("libthread_db {s} not found or not accessible: {}",
                    .{libthread_proc_path, err});
            }
        }
    }

    // The files we added from maps might be behind symlinks. This makes it impossible
    // for gdb to find them. For convenience, we extract the names as seen by the
    // linker and add all symlinks necessary to resolve them.
    if (pmaps.entries.items.len == 0) {
        log.W("No memory mappings found for process {}, skipping symlink bundling", .{pid});
        return;
    }
    const exe_base = pmaps.entries.items[0].start;
    if (pmaps.entries.items[0].end - exe_base < page_size) {
        log.W("First memory mapping is too small, skipping symlink bundling", .{});
        return;
    }
    const paths = extractPathsFromLinkerSection(gpa, io, page_size, exe_base, child_pid)
        catch |err|
    {
        log.W("Failed to extract paths from linker section: {}", .{err});
        return;
    };
    var symlinks: std.StringHashMap([]const u8) = .init(gpa);
    defer {
        var sit = symlinks.iterator();
        while (sit.next()) |kv| {
            gpa.free(kv.key_ptr.*);
            gpa.free(kv.value_ptr.*);
        }
        symlinks.deinit();
    }
    for (paths) |path| {
        if (path.len == 0 or path[0] != '/') {
            log.D3("Skipping invalid path from linker section: {s}", .{path});
            continue;
        }
        // go step by step
        resolveTargetSymlink(gpa, io, out, path, pid, &symlinks) catch |err| {
            log.W("Failed to resolve symlink for {s}: {}", .{path, err});
            continue;
        };
    }
}

fn copyFileToOutput(io: std.Io, out: *output.Output, path: []const u8, pid: i32) !void {
    var namebuf: [std.posix.PATH_MAX]u8 = undefined;
    var buffer: [65536]u8 = undefined;

    const proc_path = try std.fmt.bufPrint(&namebuf, "/proc/{d}/root{s}", .{ pid, path });
    log.D2("Adding file {s} to bundle", .{proc_path});

    const file = std.Io.Dir.openFileAbsolute(io, proc_path, .{
        .follow_symlinks = false,       // symlinks are unexpected here
    }) catch |err| {
        log.E("Failed to open file {s}: {}", .{proc_path, err});
        return err;
    };
    defer file.close(io);
    const name = std.fmt.bufPrint(&namebuf, "root/{s}", .{path[1..]}) catch |err| {
        log.E("Failed to format file name for {s}: {}", .{path, err});
        return err;
    };
    const len = file.length(io) catch |err| {
        log.E("Failed to get length of file {s}: {}", .{path, err});
        return err;
    };
    var out_file = out.startFile(name, len, null) catch |err| {
            log.E("Failed to start output file: {}", .{err});
            return err;
    };
    var offset: usize = 0;
    while (true) {
        const nread = file.readPositionalAll(io, &buffer, offset) catch |err| {
            log.E("Failed to read file {s}: {}", .{path, err});
            return err;
        };
        if (nread == 0)
            break;
        try out_file.addChunk(buffer[0..nread]);
        offset += nread;
    }
    try out_file.finish();
}

fn readMem(io: std.Io, mem_file: std.Io.File, buf: []u8, offset: usize) !void {
    const nread = mem_file.readPositionalAll(io, buf, offset) catch |err| {
        log.E("Failed to read mem file at offset {x}: {}", .{offset, err});
        return err;
    };
    if (nread != buf.len) {
        log.E("Expected to read {d} bytes from mem file, but got {d}", .{buf.len, nread});
        return error.UnexpectedReadSize;
    }
}

fn readString(gpa: std.mem.Allocator, io: std.Io, mem_file: std.Io.File, offset: usize,
    page_size: usize) ![]const u8
{
    var name_buf: [std.posix.PATH_MAX]u8 = undefined;

    const max_read = page_size - offset % page_size;
    try readMem(io, mem_file, name_buf[0..max_read], offset);
    if (std.mem.indexOf(u8, name_buf[0..max_read], &[1]u8{0})) |len| {
        return gpa.dupe(u8, name_buf[0..len]);
    }
    // no null terminator found in the first page, try reading the next page
    readMem(io, mem_file, name_buf[max_read..], offset + max_read) catch |err| {
        log.E("Failed to read mem file for string continuation at offset {x}: {}",
            .{offset + max_read, err});
        return err;
    };
    if (std.mem.indexOf(u8, name_buf[max_read..], &[1]u8{0})) |len| {
        return gpa.dupe(u8, name_buf[0..len]);
    }

    log.E("String at offset {x} is too long, no null terminator found within {d} bytes",
        .{offset, std.posix.PATH_MAX});

    return error.StringTooLong;
}

fn extractPathsFromLinkerSection(gpa: std.mem.Allocator, io: std.Io, page_size: usize,
    exe_base: usize, child_pid: i32) ![][]const u8
{
    var names: std.ArrayList([]const u8) = .empty;
    var mem_file_buf: [100]u8 = undefined;
    const mem_buf = try gpa.alignedAlloc(u8, .@"8", page_size);
    defer gpa.free(mem_buf);
    const mem_path = try std.fmt.bufPrint(&mem_file_buf, "/proc/{d}/mem", .{child_pid});
    const mem_file = std.Io.Dir.openFileAbsolute(io, mem_path, .{}) catch |err| {
        log.E("Failed to open mem file {s}: {}", .{mem_path, err});
        return err;
    };
    defer mem_file.close(io);
    try readMem(io, mem_file, mem_buf, exe_base);

    const ehdr: *elf64.Ehdr = @ptrCast(mem_buf.ptr);
    log.D3("ELF header: e_phoff={x}, e_phnum={d}, e_phentsize={d}",
        .{ehdr.phoff, ehdr.phnum, ehdr.phentsize});

    if (ehdr.type != elf.ET.DYN and ehdr.type != elf.ET.EXEC) {
        log.E("ELF file is not of type DYN or EXEC: {d}", .{ehdr.type});
        return error.InvalidElf;
    }

    if (ehdr.phentsize != @sizeOf(elf64.Phdr)) {
        log.E("ELF program header entry size is not expected: {d}", .{ehdr.phentsize});
        return error.InvalidElf;
    }

    if (ehdr.phoff % 8 != 0) {
        log.E("ELF program header offset is not aligned to 8 bytes: {x}", .{ehdr.phoff});
        return error.InvalidElf;
    }
    if (ehdr.phoff >= page_size) {
        log.E("ELF program header offset out of bounds: {x}", .{ehdr.phoff});
        return error.InvalidElf;
    }
    const phnum = @min(ehdr.phnum, (page_size - ehdr.phoff) / ehdr.phentsize);
    const phdrs_many_ptr: [*]elf64.Phdr = @ptrCast(@alignCast(mem_buf.ptr + ehdr.phoff));
    const phdrs = phdrs_many_ptr[0..phnum];

    const dyn_hdr = for (phdrs) |phdr| {
        log.D3("Program header: type={x}, offset={x}, filesz={d} vaddr={x}",
            .{phdr.type, phdr.offset, phdr.filesz, phdr.vaddr});
        if (phdr.type == elf.PT.DYNAMIC) {
            break phdr;
        }
    } else {
        log.E("No PT_DYNAMIC program header found in ELF file", .{});
        return error.NoDynamicSection;
    };

    // impose a high limit on the size to avoid a huge allocation in case of a malformed target
    if (dyn_hdr.filesz > 16 * 1048576) {
        log.E("PT_DYNAMIC section too large: {d}", .{dyn_hdr.filesz});
        return error.InvalidElf;
    }
    const dyn_buf = try gpa.alignedAlloc(u8, .@"8", dyn_hdr.filesz);
    defer gpa.free(dyn_buf);

    const dyn_vaddr = if (ehdr.type == elf.ET.DYN)
        std.math.add(u64, exe_base, dyn_hdr.vaddr) catch {
            log.E("PT_DYNAMIC vaddr {x} overflows for base {x}", .{dyn_hdr.vaddr, exe_base});
            return error.InvalidElf;
        }
    else
        dyn_hdr.vaddr;
    try readMem(io, mem_file, dyn_buf, dyn_vaddr);

    const dyn_many_ptr: [*]elf.Elf64_Dyn = @ptrCast(dyn_buf.ptr);
    const dyns = dyn_many_ptr[0..(dyn_hdr.filesz / @sizeOf(elf.Elf64_Dyn))];

    const r_debug_addr = for (dyns) |dyn| {
        log.D3("Dynamic section: d_tag={x}, d_val={x}", .{
            dyn.d_tag, dyn.d_val
        });
        if (dyn.d_tag == elf.DT_NULL) {
            log.E("End of dynamic section reached without finding DT_DEBUG", .{});
            return error.NoDebugEntry;
        }
        if (dyn.d_tag == elf.DT_DEBUG) {
            log.D3("Found DT_DEBUG entry in dynamic section, d_val={x}", .{dyn.d_val});
            break dyn.d_val;
        }
    } else {
        log.E("No DT_DEBUG entry found in dynamic section", .{});
        return error.NoDebugEntry;
    };

    // The GDB rendezvous structure
    const R_Debug = extern struct {
        r_version: i32,
        _pad: i32 = 0,
        r_map: u64,     // Pointer to the first link_map!
        r_brk: u64,
        r_state: i32,
        _pad2: i32 = 0,
        r_ldbase: u64,
    };
    var r_debug = try gpa.alignedAlloc(R_Debug, .@"8", 1);
    defer gpa.free(r_debug);
    try readMem(io, mem_file, @ptrCast(&r_debug[0]), r_debug_addr);
    if (r_debug[0].r_version != 1) {
        log.E("Unsupported r_debug version: {d}", .{r_debug[0].r_version});
        return error.UnsupportedRDebugVersion;
    }
    var link_map = r_debug[0].r_map;

    const Link_Map = extern struct {
        l_addr: u64,
        l_name: u64, // char*
        l_ld: u64,   // Elf64_Dyn*
        l_next: u64, // Link_Map*
        l_prev: u64, // Link_Map*
    };

    var link_map_entry = try gpa.alignedAlloc(Link_Map, .@"8", 1);
    defer gpa.free(link_map_entry);
    var entries: usize = 0;
    while (link_map != 0) {
        // the chain lives in target memory and may be crafted to form a cycle
        entries += 1;
        if (entries > 100000) {
            log.E("Link map chain too long, aborting", .{});
            return error.LinkMapTooLong;
        }
        try readMem(io, mem_file, @ptrCast(&link_map_entry[0]), link_map);

        log.D4("Link map entry: l_addr={x}, l_name={x}, l_ld={x}, l_next={x}, l_prev={x}",
            .{link_map_entry[0].l_addr, link_map_entry[0].l_name, link_map_entry[0].l_ld,
                link_map_entry[0].l_next, link_map_entry[0].l_prev});

        if (link_map_entry[0].l_name == 0) {
            log.E("Link map entry has null name pointer, aborting", .{});
            return error.NullLinkMapName;
        }

        const name = try readString(gpa, io, mem_file, link_map_entry[0].l_name, page_size);
        log.D3("Link map entry name: {s}", .{name});
        names.append(gpa, name) catch |err| {

            log.E("Failed to append name to list: {}", .{err});
            return err;
        };

        link_map = link_map_entry[0].l_next;
    }

    return names.toOwnedSlice(gpa);
}

// walk the symlink chain as seen by the target. So we have to always add the /proc/pid/root
// prefix for readlink.
// Add symlinks to output
fn resolveTargetSymlink(gpa: std.mem.Allocator, io: std.Io, out: *output.Output,
    target_path: []const u8, pid: i32, symlinks: *std.StringHashMap([]const u8)) !void
{
    var proc_buf: [std.posix.PATH_MAX]u8 = undefined;
    var link_buf: [std.posix.PATH_MAX]u8 = undefined;
    var rel_buf: [std.posix.PATH_MAX]u8 = undefined;
    var name_buf: [std.posix.PATH_MAX]u8 = undefined;

    var current_path = try gpa.dupe(u8, target_path);
    defer gpa.free(current_path);

    var depth: usize = 0;
    while (depth < 40) : (depth += 1) {
        log.D3("Resolving path {s}, depth {d}", .{current_path, depth});
        var path_change = false;
        var it = std.mem.tokenizeScalar(u8, current_path, '/');
        var checked_path: std.ArrayList(u8) = .empty;
        defer checked_path.deinit(gpa);
        while (it.next()) |component| {
            log.D4("Checking component {s} in path {s}", .{component, current_path});
            try checked_path.print(gpa, "/{s}", .{component});

            log.D4("Checking path {s} for symlink", .{checked_path.items});
            const proc_path = try std.fmt.bufPrint(&proc_buf, "/proc/{d}/root{s}",
                .{pid, checked_path.items});

            if (std.Io.Dir.readLinkAbsolute(io, proc_path, &link_buf)) |link_len| {
                // case: is symlink
                var link_target = link_buf[0..link_len];
                log.D3("File {s} is a symlink, target is {s}", .{proc_path, link_target});
                if (link_len > 0 and link_target[0] == '/') {
                    const link_dir = std.fs.path.dirname(checked_path.items) orelse "/";
                    const rel_target = try std.fs.path.relative(gpa, "/", null,
                        link_dir, link_target);
                    log.D4("relative target: {s}", .{rel_target});
                    link_target = try std.fmt.bufPrint(&rel_buf, "{s}", .{rel_target});
                    gpa.free(rel_target);
                }
                log.D1("emit symlink {s} -> {s}", .{checked_path.items, link_target});
                if (symlinks.get(checked_path.items)) |existing| {
                    if (!std.mem.eql(u8, existing, link_target)) {
                        log.E(
                            \\Symlink {s} already exists with different target {s},
                            \\ new target is {s}
                            , .{checked_path.items, existing, link_target});
                        return error.ConflictingSymlink;
                    }
                } else {
                    // the map outlives checked_path and the link buffers
                    // scope errdefer to the put. After that they are owned by the map.
                    {
                        const key = try gpa.dupe(u8, checked_path.items);
                        errdefer gpa.free(key);
                        const val = try gpa.dupe(u8, link_target);
                        errdefer gpa.free(val);
                        try symlinks.put(key, val);
                    }
                    const name = try std.fmt.bufPrint(&name_buf, "root{s}",
                        .{checked_path.items});
                    out.addSymlink(name, link_target) catch |err| {
                        log.E("Failed to add symlink to output: {}", .{err});
                        return err;
                    };
                }

                const resolved = if (link_target[0] == '/')
                    // absolute symlink, use as is
                    try gpa.dupe(u8, link_target)
                else
                    try std.fs.path.resolve(gpa, &.{ std.fs.path.dirname(checked_path.items).?,
                        link_target });
                defer gpa.free(resolved);

                const remainder = current_path[checked_path.items.len..];
                log.D3("Resolved symlink target {s}, remainder of path is {s}",
                    .{resolved, remainder});
                const new_path = try std.fs.path.join(gpa, &.{resolved, remainder});

                gpa.free(current_path);
                current_path = new_path;
                path_change = true;
                break;
            } else |err| {
                if (err == error.NotLink) {
                    // case: not symlink
                    log.D3("File {s} is not a symlink, moving to next component", .{proc_path});
                    continue;
                }
                log.W("Error reading link {s}: {}", .{proc_path, err});
                return err;
            }
        }
        if (!path_change) {
            log.D3("No symlink found in path {s}, stopping resolution", .{current_path});
            break;
        }
    }
}
