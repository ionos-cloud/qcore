# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Curated release notes: the release workflow extracts the tagged version's
  section from `CHANGELOG.md` and uses it as the release body, falling back to
  auto-generated notes when no matching section exists.

### Fixed

- Fix unprivileged dumps, which failed since 0.9.1 when entering the target
  netns: skip `setns` when qcore shares the target's netns, and omit the
  network state when it cannot be entered.
- Read the target's fd limit from `/proc/<pid>/limits`, so root no longer
  needs `CAP_SYS_RESOURCE` to dump another user's process.
- Detect all errors of the injected `mmap`.
- Print errno values instead of the errno address.
- Stop logging a mislabeled auxv error for failed reads of `/proc` files.

## [0.9.1] - 2026-07-24

### Added

- GitHub CI for build and releases.

### Changed

- Reworked usage output: options up top, explanation at the bottom.
- Changed return code to an optional error value.
- Prefer OOM-killing the dump clone.
- Use named constants for syscall and ELF values.
- Move embedded output README out of the src root.
- Set version to match the git tag.
- Suppress build noise for external libraries.
- Build and README cleanups.

### Fixed

- Fix memory corruption from `PTRACE_GETEVENTMSG`.
- Fix usage of `alarm`.
- Fix two error paths that could leave the clone behind.
- Run cleanup after bundle failure.
- Remove output file(s) on failure.
- Bound `PT_DYNAMIC` size and address read from target memory.
- Bound `phoff` before locating program headers.
- Cap link map chain length in symbol resolution.
- Check `setns` return value when entering the target netns.
- Free resolved path of relative symlinks.
- Own the symlink map entries, free `checked_path`.
- Check status for null before reading signal masks.
- Close `/proc` dir handles on the success path.
- Dump all present pages when pagemap PFNs are hidden.
- Check inet diag payload against the right struct.
- Reject smaps detail lines without a map entry.
- Avoid underflow on empty cmdline in prpsinfo.

## [0.9.0] - 2026-07-24

### Added

- Initial public release: grab a core from a running process with minimal
  disturbance, with optional bundling of binaries for standalone debugging.
