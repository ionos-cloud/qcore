const std = @import("std");
const log = @import("log.zig");
const ar = @cImport({
    @cInclude("archive.h");
    @cInclude("archive_entry.h");
});

const OutputFs = struct {
    io: std.Io,
    dir: ?std.Io.Dir,
    name: []const u8,
};

const zeroLen = 65536;
// core dumps and bundled files contain the target's memory, so they must not be
// readable by anyone but the user qcore runs as
const file_mode = 0o600;
const OutputArchive = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    archive: ?*ar.struct_archive,
    prefix: []const u8,
    zeros: []u8,    // zeroLen size
    filename: []const u8,
};

const FileFs = struct {
    output: *OutputFs,
    file: std.Io.File,
    file_pos: usize,
};

const FileArchive = struct {
    output: *OutputArchive,
    sim: ?Simulation,
    entry: *ar.struct_archive_entry,
    pos: usize,
    length: usize,
};

const Chunk = struct {
    offset: usize,
    length: usize,
};

const Simulation = struct {
    output: *OutputArchive,
    pos: usize,
    chunks: std.ArrayList(Chunk),
};

pub const OutputType = enum {
    fs,
    archive,
};

pub const FileType = enum {
    fs,
    archive,
    sim,
};

pub const Output = union(OutputType) {
    fs: OutputFs,
    archive: OutputArchive,

    // length is ignored for fs-based files
    pub fn startFile(output: *Output, name: []const u8, length: usize, sim: ?File) !File {
        if (name[0] == '/') {
            log.E("File name must be relative, got: {s}", .{name});
            return error.InvalidFileName;
        }
        if (output.* == .fs) {
            const dirname = if (std.fs.path.dirname(name)) |d| d else "./";
            output.fs.dir.?.createDirPath(output.fs.io, dirname) catch {
                log.E("Failed to create directory path for file: {s}", .{name});
                return error.CreateDirFailed;
            };
            const f = output.fs.dir.?.createFile(output.fs.io, name,
                .{ .permissions = .fromMode(file_mode) }) catch
            {
                log.E("Failed to create file: {s}", .{name});
                return error.CreateFileFailed;
            };
            return File {
                .fs = FileFs {
                    .output = &output.fs,
                    .file = f,
                    .file_pos = 0,
                },
            };
        } else if (output.* == .archive) {
            var ret: c_int = 0;
            const entry = ar.archive_entry_new() orelse {
                log.E("Failed to create archive entry", .{});
                return error.CreateArchiveEntryFailed;
            };
            errdefer ar.archive_entry_free(entry);

            // zero-terminate, prepend prefix
            var name_buf: [std.posix.PATH_MAX]u8 = undefined;
            const name_z = std.fmt.bufPrintZ(&name_buf, "{s}/{s}",
                .{output.archive.prefix, name}) catch
            {
                log.E("File name too long for archive entry: {s}", .{name});
                return error.InvalidFileName;
            };
            ar.archive_entry_set_pathname(entry, name_z);
            ar.archive_entry_set_size(entry, @intCast(length));
            ar.archive_entry_set_filetype(entry, 0o100000); // AE_IFREG
            ar.archive_entry_set_perm(entry, file_mode);
            ar.archive_entry_set_uid(entry, 0);
            ar.archive_entry_set_gid(entry, 0);
            ar.archive_entry_set_uname(entry, "root");
            ar.archive_entry_set_gname(entry, "root");
            const now = std.Io.Clock.real.now(output.archive.io).toSeconds();
            ar.archive_entry_set_mtime(entry, now, 0);

            if (sim) |sim_e| {
                if (sim_e != .sim) {
                    log.E("Simulation file must be of type sim", .{});
                    return error.InvalidSimulationFile;
                }
                for (sim_e.sim.chunks.items) |chunk| {
                    log.D4("Simulated chunk: offset={d}, length={d}",
                        .{chunk.offset, chunk.length});
                    ar.archive_entry_sparse_add_entry(entry, @intCast(chunk.offset),
                        @intCast(chunk.length));
                }
            }
            ret = ar.archive_write_header(output.archive.archive, entry);
            if (ret != ar.ARCHIVE_OK) {
                log.E("Error writing header for {s}: {s}",
                    .{name, ar.archive_error_string(output.archive.archive)});
                return error.WriteHeaderFailed;
            }
            return File {
                .archive = FileArchive {
                    .output = &output.archive,
                    .sim = if (sim) |s| s.sim else null,
                    .entry = entry,
                    .pos = 0,
                    .length = length,
                },
            };
        } else {
            return error.InvalidOutputType;
        }
    }

    pub fn startSimulation(output: *Output) !File {
        if (output.* == .fs) {
            @panic("Simulation is not useful with fs output");
        } else if (output.* == .archive) {
            return File {
                .sim = Simulation {
                    .output = &output.archive,
                    .pos = 0,
                    .chunks = .empty,
                },
            };
        } else {
            return error.InvalidOutputType;
        }
    }

    pub fn addSymlink(output: *Output, name: []const u8, link_target: []const u8)
        !void
    {
        if (name[0] == '/') {
            log.E("Symlink name must be relative, got: {s}", .{name});
            return error.InvalidFileName;
        }
        if (output.* == .fs) {
            const dirname = if (std.fs.path.dirname(name)) |d| d else "./";
            output.fs.dir.?.createDirPath(output.fs.io, dirname) catch {
                log.E("Failed to create directory path for file: {s}", .{name});
                return error.CreateDirFailed;
            };
            output.fs.dir.?.symLink(output.fs.io, link_target, name, .{}) catch |err| {
                log.E("Failed to create symlink {s} -> {s}: {}", .{name, link_target, err});
                return error.CreateSymlinkFailed;
            };
        } else if (output.* == .archive) {
            var ret: c_int = 0;
            const entry = ar.archive_entry_new() orelse {
                log.E("Failed to create archive entry for symlink", .{});
                return error.CreateArchiveEntryFailed;
            };
            errdefer ar.archive_entry_free(entry);

            // zero-terminate
            var name_buf: [std.posix.PATH_MAX]u8 = undefined;
            const name_z = std.fmt.bufPrintZ(&name_buf, "{s}/{s}",
                .{output.archive.prefix, name}) catch
            {
                log.E("Symlink name too long for archive entry: {s}", .{name});
                return error.InvalidFileName;
            };
            ar.archive_entry_set_pathname(entry, name_z);
            ar.archive_entry_set_filetype(entry, 0o120000); // AE_IFLNK
            ar.archive_entry_set_perm(entry, 0o755);
            ar.archive_entry_set_uid(entry, 0);
            ar.archive_entry_set_gid(entry, 0);
            ar.archive_entry_set_uname(entry, "root");
            ar.archive_entry_set_gname(entry, "root");
            const now = std.Io.Clock.real.now(output.archive.io).toSeconds();
            ar.archive_entry_set_mtime(entry, now, 0);
            const target_z = std.fmt.bufPrintZ(&name_buf, "{s}", .{link_target}) catch {
                log.E("Symlink name too long for archive entry: {s}", .{link_target});
                return error.InvalidFileName;
            };
            ar.archive_entry_set_symlink(entry, target_z);

            ret = ar.archive_write_header(output.archive.archive, entry);
            if (ret != ar.ARCHIVE_OK) {
                log.E("Error writing header for symlink {s} -> {s}: {s}",
                    .{name, link_target, ar.archive_error_string(output.archive.archive)});
                return error.WriteHeaderFailed;
            }
        } else {
            return error.InvalidOutputType;
        }
    }

    pub fn close(output: *Output) !void {
        if (output.* == .fs) {
            if (output.fs.dir) |dir| {
                output.fs.dir = null;
                dir.close(output.fs.io);
            }
        } else if (output.* == .archive) {
            if (output.archive.archive) |a| {
                output.archive.archive = null;
                log.D1("archive close called", .{});
                var ret: c_int = 0;
                ret = ar.archive_write_close(a);
                if (ret != ar.ARCHIVE_OK) {
                    log.E("Failed to close archive: {s}",
                        .{ar.archive_error_string(a)});
                    return error.CloseArchiveFailed;
                }
                ret = ar.archive_write_free(a);
                if (ret != ar.ARCHIVE_OK) {
                    log.E("Failed to free archive: {s}",
                        .{ar.archive_error_string(a)});
                    return error.CloseArchiveFailed;
                }
            }
        } else {
            return error.InvalidOutputType;
        }
    }

    pub fn remove(output: *Output) void {
        output.close() catch |err| {
            log.E("Failed to close output before remove: {}", .{err});
        };
        if (output.* == .fs) {
            std.Io.Dir.deleteTree(std.Io.Dir.cwd(), output.fs.io, output.fs.name) catch |err| {
                log.E("Failed to remove output directory {s}: {}", .{output.fs.name, err});
            };
        } else if (output.* == .archive) {
            const cwd = std.Io.Dir.cwd();
            cwd.deleteFile(output.archive.io, output.archive.filename) catch |err|
            {
                log.E("Failed to remove archive file {s}: {}", .{output.archive.filename, err});
            };
        } else {
            unreachable;
        }
    }
};

pub fn open(gpa: std.mem.Allocator, io: std.Io, name: []const u8, output_type: OutputType)
    !Output
{
    if (output_type == .fs) {
        const cwd = std.Io.Dir.cwd();
        cwd.createDir(io, name, .default_dir) catch |err| {
            log.E("Failed to create output directory {s}: {}", .{name, err});
            return error.CreateDirFailed;
        };
        const dir = try cwd.openDir(io, name, .{});
        return Output{
            .fs = OutputFs {
                .io = io,
                .dir = dir,
                .name = try gpa.dupe(u8, name),
            },
        };
    } else if (output_type == .archive) {
        var buffer: [std.posix.PATH_MAX]u8 = undefined;
        const out_filename = try std.fmt.bufPrintZ(&buffer, "{s}.tar.zst", .{name});
        var ret: c_int = 0;

        const a = ar.archive_write_new() orelse {
            log.E("Failed to create archive", .{});
            return error.CreateArchiveFailed;
        };
        errdefer _ = ar.archive_write_free(a);

        ret = ar.archive_write_set_format_pax_restricted(a);
        if (ret != ar.ARCHIVE_OK) {
            log.E("Failed to set archive format: {s}", .{ar.archive_error_string(a)});
            return error.CreateArchiveFailed;
        }
        ret = ar.archive_write_add_filter_zstd(a);
        if (ret != ar.ARCHIVE_OK) {
            log.E("Failed to set archive filter: {s}", .{ar.archive_error_string(a)});
            return error.CreateArchiveFailed;
        }

        if (ar.archive_write_open_filename(a, out_filename) != ar.ARCHIVE_OK) {
            log.E("Could not open {s}: {s}\n", .{ out_filename, ar.archive_error_string(a) });
            return error.CreateArchiveFailed;
        }

        const zeros = try gpa.alloc(u8, zeroLen);
        @memset(zeros, 0);

        return Output {
            .archive = OutputArchive {
                .gpa = gpa,
                .io = io,
                .archive = a,
                .prefix = try gpa.dupe(u8, name),
                .zeros = zeros,
                .filename = try gpa.dupe(u8, out_filename),
            },
        };
    } else {
        return error.InvalidOutputType;
    }
}

pub const File = union(FileType) {
    fs: FileFs,
    archive: FileArchive,
    sim: Simulation,

    pub fn addChunk(file: *File, data: []const u8) !void {
        if (file.* == .fs) {
            const f = &file.fs;
            const iovecs = [_][]const u8{ data };
            const sz = f.file.writePositional(file.fs.output.io, &iovecs, f.file_pos)
                catch |err|
            {
                log.E("Failed to write file: {}", .{err});
                return error.WriteFileFailed;
            };
            if (sz != data.len) {
                log.E("Short write for file: wrote {d} bytes, expected {d}", .{sz, data.len});
                return error.WriteFileIncomplete;
            }
            f.file_pos += sz;
        } else if (file.* == .archive) {
            const ret = ar.archive_write_data(file.archive.output.archive, data.ptr, data.len);
            if (ret < 0) {
                log.E("Error writing data for archive entry: {s}",
                    .{ar.archive_error_string(file.archive.output.archive)});
                return error.WriteArchiveFailed;
            }
            file.archive.pos += data.len;
        } else if (file.* == .sim) {
            log.D3("Sim output: wrote {d} bytes", .{data.len});
            file.sim.chunks.append(file.sim.output.gpa, Chunk {
                .offset = file.sim.pos,
                .length = data.len,
            }) catch |err| {
                log.E("Failed to record hole in simulation: {}", .{err});
                return error.RecordHoleFailed;
            };
            file.sim.pos += data.len;
        } else {
            return error.InvalidOutputType;
        }
    }

    pub fn addHole(file: *File, len: usize) !void {
        if (file.* == .fs) {
            file.fs.file_pos += len;
        } else if (file.* == .archive) {
            if (file.archive.sim == null) {
                log.E("Holes are only supported for simulated archive entries", .{});
                return error.InvalidHoleForArchive;
            }
            const output = file.archive.output;
            var left = len;
            while (left > 0) {
                const chunk = @min(left, zeroLen);
                const ret = ar.archive_write_data(output.archive, output.zeros.ptr, chunk);
                if (ret < 0) {
                    log.E("Error writing data for archive entry: {s}",
                        .{ar.archive_error_string(output.archive)});
                    return error.WriteArchiveFailed;
                }
                left -= chunk;
            }
            file.archive.pos += len;
        } else if (file.* == .sim) {
            log.D3("Sim output: added hole of {d} bytes", .{len});
            file.sim.pos += len;
        } else {
            return error.InvalidOutputType;
        }
    }

    pub fn finish(file: *File) !void {
        if (file.* == .fs) {
            // in case the file ended with non-dumpable pages, we need to truncate
            // to the expected size
            file.fs.file.setLength(file.fs.output.io, file.fs.file_pos) catch |err| {
                log.E("Failed to truncate file in finalize: {}", .{err});
                return error.FinalizeFileFailed;
            };
            file.fs.file.close(file.fs.output.io);
        } else if (file.* == .archive) {
            if (file.archive.length != file.archive.pos) {
                log.E("Archive entry length mismatch: expected {d} bytes, wrote {d} bytes",
                    .{file.archive.length, file.archive.pos});
                return error.ArchiveLengthMismatch;
            }
            ar.archive_entry_free(file.archive.entry);
        } else if (file.* == .sim) {
            // TODO free stuff
        } else {
            return error.InvalidOutputType;
        }
    }

    pub fn length(file: *File) usize {
        if (file.* == .sim) {
            return file.sim.pos;
        } else {
            @panic("length is only supported for sim files");
        }
    }
};
