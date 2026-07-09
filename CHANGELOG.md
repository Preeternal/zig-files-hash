# Releases

## v0.0.7 — C ABI v4: POSIX fd hashing and opt-in mmap

### Highlights

- C ABI version bumped to `ZFH_API_VERSION = 4`.
- Added POSIX `zfh_context_fd_hash` for hashing an already-open file descriptor.
- Added `ZFH_OPTION_USE_MMAP` for opt-in mmap hashing through
  `zfh_context_file_hash`.

### Compatibility notes

- `ZFH_OPTION_USE_MMAP` does not change the layout of `zfh_options`.
- The fd API reads from the current descriptor position and never closes it.
- mmap remains disabled by default and is not used by the fd API.

## v0.0.6 - Windows MSVC static C ABI link fix

Patch release for Windows C ABI static library consumers.

### Highlights

- C ABI version remains `ZFH_API_VERSION = 3`.
- Windows C ABI static `.lib` builds now bundle Zig compiler-rt.
- Fixes MSVC consumers failing to link unresolved Zig/LLVM runtime helper symbols such as `__divti3`.

### Compatibility notes

- No Zig API changes.
- No C ABI signature changes.
- Non-Windows static library artifacts keep their previous compiler-rt bundling behavior.
- C consumers using C ABI v3 do not need binding changes.

---

## v0.0.5 - C ABI build fixes

Patch release for C ABI consumers and mobile prebuilt builds.

### Highlights

- C ABI version remains `ZFH_API_VERSION = 3`.
- C ABI artifacts now disable Zig stack tracing at the C ABI root. This avoids
  pulling stack trace/self-info code into release prebuilts and fixes iOS
  `ReleaseFast` link failures caused by unavailable dyld symbols.
- C API generator builds for the host target even when the requested library
  target is Android/iOS or another cross target. This keeps `zig build c-api-*`
  usable during cross-compilation because the generator binary is executed on
  the build machine.
- Package version bumped to `0.0.5`.

### Compatibility notes

- No Zig API changes.
- No C ABI signature changes.
- C consumers that already migrated to C ABI v3 do not need binding changes.

---

## v0.0.4 - Zig 0.16 and C ABI v3

Migration release for Zig 0.16 and the new request/context/cancellation model.

### Highlights

- Minimum Zig version raised to `0.16.0`.
- File hashing now accepts explicit `std.Io`.
- Added `Context` as a reusable `std.Io` wrapper for one-shot file hashing:
  - `Context.init`
  - `Context.fileHash`
  - `Context.fileHashInDir`
- Added `HashRequest` with:
  - `hash_options`
  - `operation`
- Added cooperative cancellation through `Operation`.
- Added high-level cancellable streaming API:
  - `HashStream.init`
  - `HashStream.update`
  - `HashStream.digestLength`
  - `HashStream.final`
  - `HashStream.finalResult`
- `HashStream` now rejects `update`, `final`, and `finalResult` after
  finalization with `error.InvalidState`.
- `stringHash`, `fileHash`, and `fileHashInDir` now use `HashRequest`.
- `RuntimeHasher` remains public as a lower-level hasher without request/cancel handling.

### C ABI v3

- ABI version bumped: `ZFH_API_VERSION = 3`.
- C enums and mappings are generated from `tools/c_api`.
- Added generated header:
  - `zig_files_hash_c_api_generated.h`
- Added `zfh_request` to carry options and optional operation state.
- Added explicit C context API for file hashing:
  - `zfh_context_create`
  - `zfh_context_destroy`
  - `zfh_context_file_hash`
- Removed the old path-only `zfh_file_hash` entry point from the public C ABI.
- Added in-place operation state API:
  - `zfh_operation_state_size`
  - `zfh_operation_state_align`
  - `zfh_operation_init_inplace`
  - `zfh_operation_cancel`
- `zfh_hasher_init_inplace` now accepts `const zfh_request*` instead of
  `const zfh_options*`.
- C streaming state now wraps Zig `HashStream`, so `zfh_hasher_update` and
  `zfh_hasher_final` can return `ZFH_OPERATION_CANCELED`.
- Unknown `zfh_options.flags` bits are rejected as `ZFH_INVALID_ARGUMENT`.
- Error `ZFH_BUFFER_TOO_SMALL` was renamed to `ZFH_OUTPUT_BUFFER_TOO_SMALL`.

### Compatibility notes

- This is a breaking release for both Zig API and C ABI consumers.
- C consumers should regenerate bindings against
  `src/zig_files_hash_c_api.h` and `src/zig_files_hash_c_api_generated.h`.
- Callers that already own file reading should prefer C streaming APIs.
- Callers that want path-based file hashing from C should create a `zfh_context`.

---

## v0.0.3 - Runtime Hasher and C ABI Streaming

Third public release of `zig-files-hash`, focused on chunked/streaming hashing.

### Highlights

- Added public runtime hasher API in Zig:
  - `RuntimeHasher.init(alg, options)`
  - `RuntimeHasher.update(chunk)`
  - `RuntimeHasher.digestLength()`
  - `RuntimeHasher.final(out)`
  - `RuntimeHasher.finalResult()` + `digest.slice()` helper flow
- `dispatch` now uses `RuntimeHasher` as the shared hashing path.
- Kept public helper `digestLength(alg)` for non-streaming consumers.
- Added test coverage for `RuntimeHasher.digestLength`.

### C ABI v2

- ABI version bumped: `ZFH_API_VERSION = 2`.
- Streaming C ABI now uses caller-provided state buffer (inplace, no heap allocations).
- Added streaming C functions:
  - `zfh_hasher_state_size`
  - `zfh_hasher_state_align`
  - `zfh_hasher_init_inplace`
  - `zfh_hasher_update`
  - `zfh_hasher_final`
- `zfh_digest_length` now resolves via Zig public `digestLength(alg)` to keep one
  source of truth for digest sizes.
- Added C ABI streaming tests (chunked success, key-required mapping,
  buffer-too-small on final, invalid state checks).
- Defined post-final behavior for streaming state:
  repeated `zfh_hasher_final` and `zfh_hasher_update` after final return
  `ZFH_INVALID_ARGUMENT`.

### Compatibility notes

- Zig API remains allocation-free:
  - `stringHash` / `fileHash` unchanged for existing usage
  - streaming is additive via `RuntimeHasher`
- C API consumers should regenerate bindings against
  `src/zig_files_hash_c_api.h` (`ZFH_API_VERSION = 2`).
- Minimum Zig version remains `0.15.2`.

---

## v0.0.2 - C ABI, Header, and Build Steps

Second public release of `zig-files-hash`, focused on interoperability and packaging.

### Highlights

- Added C ABI module: `src/c_api.zig`.
- Added public C header: `src/zig_files_hash_c_api.h`.
- Added C ABI build steps:
  - `zig build c-api-static`
  - `zig build c-api-shared`
  - `zig build c-api-header`
  - `zig build c-api`
- Added C API tests to the project test flow.
- Added public Zig helper: `digestLength(alg: HashAlgorithm) usize`.

### C ABI details

- Full C API is documented in `src/zig_files_hash_c_api.h`.
- C ABI contract: caller owns buffers, functions write raw digest bytes, no heap allocations,
  and `written_len`/`out_len` indicate actual output size.
- `XXH3-64` output bytes are serialized in canonical big-endian order.
- `zfh_string_hash` and `zfh_file_hash` return stable `zfh_error` codes.
- `zfh_digest_length` now follows the same error model:
  - signature: `zfh_error zfh_digest_length(zfh_algorithm alg, size_t* out_len_ptr)`
  - invalid algorithm now returns `ZFH_INVALID_ALGORITHM` (instead of length sentinel values).

### Compatibility notes

- Zig API remains allocation-free and source-compatible for existing `stringHash` / `fileHash` usage.
- C ABI is new in this release and is intended as the integration boundary for RN/Node/native consumers.
- Minimum Zig version: `0.15.2` (tested in CI).

### Install

```bash
zig fetch --save https://github.com/Preeternal/zig-files-hash/archive/refs/tags/v0.0.2.tar.gz
```

### Stability

Pre-1.0 release: API may still evolve in future versions.

---

## v0.0.1 — First Public Release

Initial public release of `zig-files-hash`.

This version provides a small, allocation-free hashing core with a unified runtime API for strings and files.

### Highlights

- Unified public API:
  - `stringHash(alg, data, options, out) !usize`
  - `fileHash(alg, path, options, out) !usize`
- Allocation-free design: caller provides output buffer.
- Cross-platform test workflow (`ubuntu`, `macos`, `windows`) in CI.
- Zig version pinned in CI (`0.15.2`).

### Supported algorithms

- `SHA-224`
- `SHA-256`
- `SHA-384`
- `SHA-512`
- `SHA-512/224`
- `SHA-512/256`
- `MD5`
- `SHA-1`
- `XXH3-64` (optional seed)
- `BLAKE3` (optional keyed mode)
- `HMAC-SHA-224`
- `HMAC-SHA-256`
- `HMAC-SHA-384`
- `HMAC-SHA-512`
- `HMAC-MD5`
- `HMAC-SHA-1`

### Notes

- API returns raw digest bytes via caller-provided `out` buffer.
- `XXH3-64` output bytes are serialized in canonical big-endian order.
- Error model includes:
  - `error.BufferTooSmall`
  - `error.KeyRequired`
  - `error.InvalidKeyLength`
  - plus filesystem/OS errors for `fileHash`.

### Install

```bash
zig fetch --save https://github.com/Preeternal/zig-files-hash/archive/refs/tags/v0.0.1.tar.gz
```

### Stability

Pre-1.0 release: API may change in future versions.
