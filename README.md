# qcore

qcore is a production-grade tool to grab a core from a running process with minimal disturbance.

It does so by stopping the process, injecting a fork into it, collecting some information and letting the process run again. The child is then used to construct the core dump. Finally, the target is grabbed again to inject a final wait to reap the child not to leave a zombie behind.

qcore also collects additional information about the process and network state. All information is either written to a directory or directly to a .tar.zst archive.

qcore is statically linked and can be used on any linux installation.

## Features
* minimal downtime for target (a few milliseconds up to a second for >10000 threads)
* sparse core files to reduce space on disk
* transparent to the target (apart from timing effects)
* additional collection of /proc files for fds and network
* netlink collection for extended statistics
* saves correlation between host pids and target pids as well as thread names
* optional bundling of binaries to allow standalone analysis
* statically linked, runs on any x86-64 linux
* small binary
* optional output directly into .tar.zst for minimal disk usage
* proper thread debugging even with containers

## Restrictions
* linux x86-64 only

## Standalone Debugging
qcore can optionally bundle the target binary and its dependencies into the output directory / archive. This allows to debug the core dump on any machine, independent of the OS flavor. It adds a README to the output that shows how to invoke gdb on it.

## How to Build

The build compiles zstd and libarchive from source to be able to link it
statically against libmusl. Required host tools:

* `zig` 0.16 from https://ziglang.org/download
* `make`, `autoconf`, `automake` and `libtool`
* `nproc`

Build steps:

* clone this repository
* run `zig build -Doptimize=ReleaseSafe` to build the binary

The binary will be placed in `zig-out/bin/qcore`. For minmal binary size build with `zig build -Doptimize=ReleaseSmall` instead. This currently yields a binary of less than 1MB.

## Binary Release
A stripped binary is available in the releases section of this repository. It is statically linked and runs on any linux x64 installation.
