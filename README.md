# zig-files-hash

Small hashing library in Zig with a runtime algorithm enum, explicit Zig 0.16
I/O, cancellable hash requests, and an optional C ABI.

## Status

- Pre-1.0 API may change.
- Minimum Zig version: `0.16.0` (`build.zig.zon`).
- Current C ABI version: `ZFH_API_VERSION = 4`.

## Features

- Unified algorithm selection via `HashAlgorithm`
- Hashing for in-memory data and files
- Explicit `std.Io` for file operations
- High-level streaming API via `HashStream`
- Low-level algorithm state via `RuntimeHasher`
- Caller-managed output buffers
- Optional C ABI for native/FFI integrations
- Cooperative cancellation through `Operation`
- Keyed/seeded modes where applicable
- Optional mmap fast path for stable regular files

## Installation

Add dependency to your Zig project:

```bash
zig fetch --save https://github.com/Preeternal/zig-files-hash/archive/refs/tags/v<VERSION>.tar.gz
```

Then wire module import in your `build.zig`:

```zig
const zfh_dep = b.dependency("zig_files_hash", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("zig_files_hash", zfh_dep.module("zig_files_hash"));
```

## Zig API

```zig
pub const HashAlgorithm
pub const HashOptions
pub const HashRequest
pub const Operation
pub const HashStream
pub const RuntimeHasher
pub const Context
pub const Error
pub const max_digest_length

pub fn digestLength(alg: HashAlgorithm) usize
```

Recommended API choice:

- Use `HashStream` when data already arrives in chunks, when the caller owns the
  file reading pipeline, or when integration code needs cancellation between
  chunks.
- Use `Context.fileHash` / `Context.fileHashInDir` for simple one-shot file
  hashing in Zig code.
- Use `stringHash` for small in-memory inputs.
- Use `RuntimeHasher` only when you need the low-level algorithm state directly.

One-shot APIs:

```zig
pub fn stringHash(
    alg: HashAlgorithm,
    data: []const u8,
    out: []u8,
    request: ?HashRequest,
) !usize

pub fn fileHash(
    io: std.Io,
    alg: HashAlgorithm,
    path: []const u8,
    out: []u8,
    request: ?HashRequest,
) !usize

pub fn fileHashInDir(
    io: std.Io,
    alg: HashAlgorithm,
    dir: std.Io.Dir,
    sub_path: []const u8,
    out: []u8,
    request: ?HashRequest,
) !usize
```

`Context` stores a reusable `std.Io` value:

```zig
pub fn Context.init(io: std.Io) Context
pub fn Context.fileHash(...)
pub fn Context.fileHashInDir(...)
```

`Context.fileHash` resolves relative paths from `std.Io.Dir.cwd()`. Use
`Context.fileHashInDir` when the caller should choose the base directory
explicitly.

Streaming APIs:

```zig
pub fn HashStream.init(alg: HashAlgorithm, request: ?HashRequest) !HashStream
pub fn HashStream.update(self: *HashStream, chunk: []const u8) !void
pub fn HashStream.digestLength(self: *const HashStream) usize
pub fn HashStream.final(self: *HashStream, out: []u8) !usize
pub fn HashStream.finalResult(self: *HashStream) !RuntimeHasher.Digest
```

`RuntimeHasher` remains public as a lower-level primitive without request/cancel
handling:

```zig
pub fn RuntimeHasher.init(alg: HashAlgorithm, options: ?HashOptions) !RuntimeHasher
pub fn RuntimeHasher.update(self: *RuntimeHasher, chunk: []const u8) void
pub fn RuntimeHasher.digestLength(self: *const RuntimeHasher) usize
pub fn RuntimeHasher.final(self: *RuntimeHasher, out: []u8) !usize
pub fn RuntimeHasher.finalResult(self: *RuntimeHasher) RuntimeHasher.Digest
pub fn RuntimeHasher.Digest.slice(self: *const RuntimeHasher.Digest) []const u8
```

Return value is digest length in bytes. Digest bytes are written to `out[0..len]`.
`finalResult` returns an owned fixed-size digest wrapper; consume bytes via
`digest.slice()`.

### Algorithms

```zig
pub const HashAlgorithm = enum {
    @"SHA-224",
    @"SHA-256",
    @"SHA-384",
    @"SHA-512",
    @"SHA-512/224",
    @"SHA-512/256",
    MD5,
    @"SHA-1",
    @"XXH3-64",
    BLAKE3,
    @"HMAC-SHA-224",
    @"HMAC-SHA-256",
    @"HMAC-SHA-384",
    @"HMAC-SHA-512",
    @"HMAC-MD5",
    @"HMAC-SHA-1",
};
```

### Options, requests, and cancellation

```zig
pub const HashOptions = struct {
    seed: ?u64 = null,
    key: ?[]const u8 = null,
};

pub const HashRequest = struct {
    hash_options: ?HashOptions = null,
    operation: ?*const Operation = null,
    use_mmap: bool = false,
};
```

`hash_options` affects the digest

`operation` affects execution only and is used for cooperative cancellation.

`use_mmap` only changes file I/O for `fileHash` / `fileHashInDir`. It is off by
default; enable it only for stable regular files after benchmarking your
workload and accepting mmap-specific risks. Local benchmarks ranged from
slightly slower to about 20% faster, usually only a few percent.

```zig
var op = zfh.Operation.init();

var stream = try zfh.HashStream.init(.BLAKE3, .{
    .operation = &op,
});

op.cancel();
try stream.update("data"); // returns error.OperationCanceled
```

The `Operation` object must outlive every `HashRequest` / `HashStream` that
stores a pointer to it.

### Errors

```zig
pub const Error = error{
    KeyRequired,
    InvalidKeyLength,
    OutputBufferTooSmall,
    OperationCanceled,
    InvalidState,
};
```

Rules:

- `HMAC-*`: `key` is required, otherwise `error.KeyRequired`
- `BLAKE3`: keyed mode requires `key.len == 32`, otherwise `error.InvalidKeyLength`
- `XXH3-64`: optional `seed`
- SHA/MD5 algorithms ignore options
- If `out` is too small: `error.OutputBufferTooSmall`
- If `operation` was canceled: `error.OperationCanceled`
- If a `HashStream` is used after finalization: `error.InvalidState`

`fileHash` / `fileHashInDir` return library errors plus filesystem/OS errors
from opening and reading files. The exact filesystem error set is
platform-dependent.

## Output format

- API returns raw digest bytes, not hex string.
- Print hex with `{x}` in Zig or your own hex encoder in C.
- `XXH3-64` bytes are written in canonical big-endian order.
- `XXH3-64` is non-cryptographic (fast checksum/hash, not for security).

## Usage

### Hash string

```zig
const std = @import("std");
const zfh = @import("zig_files_hash");

pub fn main() !void {
    var out: [zfh.max_digest_length]u8 = undefined;
    const len = try zfh.stringHash(.@"SHA-256", "hello world", out[0..], null);
    std.debug.print("SHA-256 = {x}\n", .{out[0..len]});
}
```

### Hash file

```zig
const std = @import("std");
const zfh = @import("zig_files_hash");

pub fn main(init: std.process.Init) !void {
    const context = zfh.Context.init(init.io);
    const path: []const u8 = "file.bin";
    var out: [zfh.max_digest_length]u8 = undefined;

    const len = try context.fileHash(.BLAKE3, path, out[0..], .{
        .hash_options = .{
            .key = "0123456789abcdef0123456789abcdef",
        },
    });

    std.debug.print("BLAKE3 = {x}\n", .{out[0..len]});
}
```

### Hash file in opened directory

```zig
const std = @import("std");
const zfh = @import("zig_files_hash");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const context = zfh.Context.init(io);
    var out: [zfh.max_digest_length]u8 = undefined;

    var dir = try std.Io.Dir.cwd().openDir(io, "fixtures", .{});
    defer dir.close(io);

    const len = try context.fileHashInDir(.@"SHA-256", dir, "sample.bin", out[0..], null);
    std.debug.print("SHA-256 = {x}\n", .{out[0..len]});
}
```

### Streaming hash

```zig
const std = @import("std");
const zfh = @import("zig_files_hash");

pub fn main() !void {
    var out: [zfh.max_digest_length]u8 = undefined;

    var stream = try zfh.HashStream.init(.@"SHA-256", null);
    try stream.update("hello ");
    try stream.update("world");

    const len = try stream.final(out[0..]);
    std.debug.print("SHA-256 = {x}\n", .{out[0..len]});
}
```

### Streaming hash with cancellation

```zig
const zfh = @import("zig_files_hash");

pub fn example() !void {
    var op = zfh.Operation.init();
    var stream = try zfh.HashStream.init(.BLAKE3, .{ .operation = &op });

    op.cancel();
    try stream.update("chunk"); // error.OperationCanceled
}
```

## C ABI

The C ABI lives in `src/c_api.zig`, with headers:

- `src/zig_files_hash_c_api.h`
- `src/zig_files_hash_c_api_generated.h`

Build artifacts:

```bash
zig build c-api-static   # .a / .lib
zig build c-api-shared   # .dylib / .so / .dll
zig build c-api-header   # installs headers to zig-out/include
zig build c-api          # all of the above
```

Installed outputs:

- `zig-out/lib/libzig_files_hash_c_api_static.a` (or `.lib`)
- `zig-out/lib/libzig_files_hash_c_api.dylib` / `.so` / `.dll`
- `zig-out/include/zig_files_hash_c_api.h`
- `zig-out/include/zig_files_hash_c_api_generated.h`

For native integrations that already read files in chunks, prefer the streaming
hasher functions (`zfh_hasher_init_inplace`, `zfh_hasher_update`,
`zfh_hasher_final`). Use `zfh_context_file_hash` as a convenience one-shot API
when C is responsible for opening and reading the file.

Main C functions:

```c
size_t zfh_max_digest_length(void);
uint32_t zfh_api_version(void);
zfh_error zfh_digest_length(zfh_algorithm alg, size_t *out_len_ptr);
const char *zfh_error_message(zfh_error code);

zfh_error zfh_string_hash(...);

zfh_error zfh_context_create(zfh_context **out_ctx);
zfh_error zfh_context_destroy(zfh_context *ctx);
zfh_error zfh_context_file_hash(...);
zfh_error zfh_fd_hash(...); /* POSIX only */

size_t zfh_operation_state_size(void);
size_t zfh_operation_state_align(void);
zfh_error zfh_operation_init_inplace(void *operation_ptr, size_t operation_len);
zfh_error zfh_operation_cancel(void *operation_ptr, size_t operation_len);

size_t zfh_hasher_state_size(void);
size_t zfh_hasher_state_align(void);
zfh_error zfh_hasher_init_inplace(...);
zfh_error zfh_hasher_update(...);
zfh_error zfh_hasher_final(...);
```

`zfh_api_version()` returns the same value as `ZFH_API_VERSION`.

### C request

Options and cancellation are passed through `zfh_request`:

```c
typedef struct zfh_options {
    uint32_t struct_size;
    uint32_t flags;
    uint64_t seed;
    const uint8_t *key_ptr;
    size_t key_len;
} zfh_options;

typedef struct zfh_request {
    uint32_t struct_size;
    const zfh_options *options_ptr;
    void *operation_ptr;
    size_t operation_len;
} zfh_request;
```

Use flags:

- `ZFH_OPTION_HAS_SEED`
- `ZFH_OPTION_HAS_KEY`
- `ZFH_OPTION_USE_MMAP` (only for `zfh_context_file_hash`)

Set `struct_size` with `ZFH_OPTIONS_STRUCT_SIZE` and
`ZFH_REQUEST_STRUCT_SIZE`. If no options or cancellation are needed, pass
`NULL` for `request_ptr`. Unknown option flags are rejected with
`ZFH_INVALID_ARGUMENT`.

### C operation

Operation state is caller-provided memory:

```c
size_t op_size = zfh_operation_state_size();
size_t op_align = zfh_operation_state_align();
```

Allocate a buffer with at least `op_size` bytes and `op_align` alignment, then:

```c
zfh_operation_init_inplace(op_ptr, op_size);

zfh_request req = {
    .struct_size = ZFH_REQUEST_STRUCT_SIZE,
    .options_ptr = NULL,
    .operation_ptr = op_ptr,
    .operation_len = op_size,
};

zfh_operation_cancel(op_ptr, op_size);
```

`zfh_string_hash`, `zfh_context_file_hash`, `zfh_fd_hash`, `zfh_hasher_update`, and
`zfh_hasher_final` can return `ZFH_OPERATION_CANCELED` when the operation is
canceled.

### C file hashing

File hashing in C uses an explicit context:

```c
zfh_context *ctx = NULL;
zfh_context_create(&ctx);

zfh_context_file_hash(
    ctx,
    ZFH_ALG_SHA_256,
    path_ptr,
    path_len,
    request_ptr,
    out_ptr,
    out_len,
    &written_len
);

zfh_context_destroy(ctx);
```

`path_ptr` is byte data with explicit `path_len`; null-termination is not
required.

Set `ZFH_OPTION_USE_MMAP` in `zfh_options.flags` to opt into mmap for this path
API. It is disabled by default and should be used only for stable regular files
after benchmarking the workload. The option is ignored by
`zfh_fd_hash`, which always reads from the current fd position.

### C file-descriptor hashing

On POSIX platforms, callers that already own an open descriptor can avoid
duplicating the read loop in C or a wrapper:

```c
zfh_fd_hash(
    ZFH_ALG_SHA_256,
    fd,
    request_ptr,
    out_ptr,
    out_len,
    &written_len
);
```

The function reads from the descriptor's current position, does not close it,
and hashes the input in chunks. `zfh_fd_hash` does not use mmap.

### C streaming contract

- Query state requirements with `zfh_hasher_state_size` and `zfh_hasher_state_align`.
- Caller provides an aligned state buffer (`state_ptr`, `state_len`) to `zfh_hasher_init_inplace`.
- `zfh_hasher_init_inplace` takes `const zfh_request *request_ptr`.
- Call `zfh_hasher_update` any number of times with chunked data.
- Call `zfh_hasher_final` once to write digest bytes.
- After successful `zfh_hasher_final`, further `zfh_hasher_update`/`zfh_hasher_final`
  calls on the same state return `ZFH_INVALID_ARGUMENT`.
- If the request operation is canceled, `zfh_hasher_update` / `zfh_hasher_final`
  return `ZFH_OPERATION_CANCELED`.

### C error model

- `ZFH_OK`
- `ZFH_INVALID_ARGUMENT`
- `ZFH_INVALID_ALGORITHM`
- `ZFH_KEY_REQUIRED`
- `ZFH_INVALID_KEY_LENGTH`
- `ZFH_OUTPUT_BUFFER_TOO_SMALL`
- `ZFH_OPERATION_CANCELED`
- `ZFH_INVALID_STATE`
- `ZFH_FILE_NOT_FOUND`
- `ZFH_ACCESS_DENIED`
- `ZFH_INVALID_PATH`
- `ZFH_IO_ERROR`
- `ZFH_UNKNOWN_ERROR`

Output length pointers are set to `0` on error.

## Build and test

```bash
zig build
zig build test
```

## Notes

- `getDemoOptionsArray` exists for local demo/testing flows; treat it as a non-stable helper.
- On AArch64, `SHA-224` / `SHA-256` and related HMAC variants can be much faster with CPU `sha2` extensions.
- For portable builds, keep generic targets. For controlled hardware or benchmarks, compare with `-Dcpu=baseline+sha2`.

## License

MIT. See [LICENSE](LICENSE).
