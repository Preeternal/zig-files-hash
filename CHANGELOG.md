# Releases

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
