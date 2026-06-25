const std = @import("std");

pub fn build(b: *std.Build) void {
    // only supported target is x86-64. Link statically to run everywhere
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .linux,
        .abi = .musl,
    });
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "qcore",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });

    // build payload.S into payload.bin
    const payload_run_cc = b.addSystemCommand(&[_][]const u8 {
        b.graph.zig_exe, "cc", "-target", "x86_64-linux-musl", "-fPIC", "-c"
    });
    payload_run_cc.addFileArg(b.path("src/payload.S"));
    payload_run_cc.addArg("-o");
    const payload_o = payload_run_cc.addOutputFileArg("payload.o");
    // These steps shell out to `zig` (cc/objcopy, and the parallel `zig cc`/`zig
    // ar` that `make` spawns below). Each nested `zig` inherits ZIG_PROGRESS and
    // writes binary progress IPC into the parent's pipe; with many running under
    // `make -j` the parent renders the interleaved bytes as terminal garbage.
    // Stop passing the progress fd down so these children stay silent.
    payload_run_cc.disable_zig_progress = true;

    const payload_run_objcopy = b.addSystemCommand(&[_][]const u8 {
        b.graph.zig_exe, "objcopy", "-O", "binary", "--only-section=.text"
    });
    payload_run_objcopy.addFileArg(payload_o);
    payload_run_objcopy.disable_zig_progress = true;
    const payload_bin = payload_run_objcopy.addOutputFileArg("payload.bin");
    exe.root_module.addAnonymousImport("payload", .{
        .root_source_file = payload_bin
    });

    // Build zstd and libarchive locally and link them statically.
    //
    // link against libmusl, so that they can be used with qcore.
    //
    // Each step redirects all of its (noisy) sub-build output to a log inside its
    // output dir and stays silent on success; the trap dumps that log to stderr
    // only on actual failure. Without this, autogen's `set -x` trace, configure's
    // pkg-config notices, and compiler warnings all hit stderr and make Zig
    // report the step as a "failed command" even when it succeeds.
    const cc = b.fmt("{s} cc -target x86_64-linux-musl", .{b.graph.zig_exe});
    const cflags = "-ffunction-sections -fdata-sections -g0 -O2";
    const quiet =
        \\log="$OUT/build.log"
        \\exec 3>&2
        \\trap 'rc=$?; if [ "$rc" -ne 0 ]; then cat "$log" >&3; fi' EXIT
        \\exec >"$log" 2>&1
    ;

    // zstd: build libzstd.a via its own lib/ Makefile, and stage the headers
    // libarchive's configure needs.
    const zstd_dep = b.dependency("zstd", .{});
    const zstd_build = b.addSystemCommand(&[_][]const u8{ "sh", "-eu", "-c", b.fmt(
        \\SRC="$1"; OUT="$2"
        \\{s}
        \\rm -rf "$OUT/src"; mkdir -p "$OUT/src" "$OUT/include"
        \\cp -a "$SRC"/. "$OUT/src/"
        \\make -C "$OUT/src/lib" -j"$(nproc)" libzstd.a CC="{s}" AR="{s} ar" RANLIB="{s} ranlib" CFLAGS="{s}"
        \\cp "$OUT/src/lib/libzstd.a" "$OUT/libzstd.a"
        \\cp "$OUT/src/lib/zstd.h" "$OUT/src/lib/zstd_errors.h" "$OUT/include/"
    , .{ quiet, cc, b.graph.zig_exe, b.graph.zig_exe, cflags }), "sh" });
    zstd_build.disable_zig_progress = true;
    zstd_build.addDirectoryArg(zstd_dep.path(""));
    const zstd_out = zstd_build.addOutputDirectoryArg("zstd-out");
    const zstd_lib = zstd_out.path(b, "libzstd.a");
    const zstd_include = zstd_out.path(b, "include");

    // libarchive: autotools build, with --with-zstd pointed at the zstd we just
    // built (positional args $3 = include dir, $4 = libdir). PKG_CONFIG_LIBDIR is
    // set to a bogus path so configure ignores any host (glibc) zstd and falls
    // back to the CPPFLAGS/LDFLAGS probe.
    const libarchive_dep = b.dependency("libarchive", .{});
    const libarchive_build = b.addSystemCommand(&[_][]const u8{ "sh", "-eu", "-c", b.fmt(
        \\SRC="$1"; OUT="$2"
        \\ZSTD_INC="$(cd "$3" && pwd)"; ZSTD_LIBDIR="$(cd "$4" && pwd)"
        \\{s}
        \\rm -rf "$OUT/src"; mkdir -p "$OUT/src"
        \\cp -a "$SRC"/. "$OUT/src/"
        \\cd "$OUT/src"
        \\/bin/sh build/autogen.sh
        \\CC="{s}" \
        \\CFLAGS="{s}" \
        \\CPPFLAGS="-I$ZSTD_INC" \
        \\LDFLAGS="-L$ZSTD_LIBDIR" \
        \\PKG_CONFIG_LIBDIR=/nonexistent \
        \\./configure --enable-static --disable-shared --disable-bsdtar --disable-bsdcpio --disable-bsdcat --without-xml2 --without-expat --without-openssl --without-nettle --without-bz2lib --without-lzma --without-zlib --without-lz4 --without-cng --without-iconv --with-zstd
        \\# Build only the library target; the bsd* frontends and test helpers are
        \\# not needed and their rules are the source of -j build flakiness.
        \\make -j"$(nproc)" libarchive.la
        \\cp .libs/libarchive.a "$OUT/libarchive.a"
    , .{ quiet, cc, cflags }), "sh" });
    libarchive_build.disable_zig_progress = true;
    libarchive_build.addDirectoryArg(libarchive_dep.path(""));
    const libarchive_out = libarchive_build.addOutputDirectoryArg("libarchive-out");
    libarchive_build.addDirectoryArg(zstd_include);
    libarchive_build.addDirectoryArg(zstd_out);

    exe.root_module.addObjectFile(libarchive_out.path(b, "libarchive.a"));
    exe.root_module.addIncludePath(libarchive_out.path(b, "src/libarchive"));
    exe.root_module.addObjectFile(zstd_lib);

    // Drop unused libarchive/zstd code: `-Wl,--gc-sections`. The static libs are
    // compiled with -ffunction-sections/-fdata-sections so this is effective.
    exe.link_gc_sections = true;

    b.installArtifact(exe);

    const run_step = b.step("run", "Run the app");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });

    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_exe_tests.step);
}
