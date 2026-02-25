# zig-files-hash

Small, allocation-free hashing library in Zig with a unified runtime API and an optional C ABI.

## Status

- Pre-1.0 API may change.
- Minimum Zig version: `0.15.2` (`build.zig.zon`).

## Features

- Unified runtime API via `HashAlgorithm`
- Hashing for in-memory data and files
- Streaming API via `RuntimeHasher` (`init`/`update`/`final`)
- Allocation-free core API (caller-managed output buffer)
- Optional C ABI for native/FFI integrations
- Keyed/seeded modes where applicable

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
pub const Error
pub const max_digest_length
pub const RuntimeHasher

pub fn digestLength(alg: HashAlgorithm) usize

pub fn stringHash(
    alg: HashAlgorithm,
    data: []const u8,
    options: ?HashOptions,
    out: []u8,
) !usize

pub fn fileHash(
    alg: HashAlgorithm,
    path: []const u8,
    options: ?HashOptions,
    out: []u8,
) !usize

pub fn fileHashInDir(
    alg: HashAlgorithm,
    dir: std.fs.Dir,
    sub_path: []const u8,
    options: ?HashOptions,
    out: []u8,
) !usize

pub fn RuntimeHasher.init(alg: HashAlgorithm, options: ?HashOptions) !RuntimeHasher
pub fn RuntimeHasher.update(self: *RuntimeHasher, chunk: []const u8) void
pub fn RuntimeHasher.digestLength(self: *const RuntimeHasher) usize
pub fn RuntimeHasher.final(self: *RuntimeHasher, out: []u8) !usize
pub fn RuntimeHasher.finalResult(self: *RuntimeHasher) RuntimeHasher.Digest
pub fn RuntimeHasher.Digest.slice(self: *const RuntimeHasher.Digest) []const u8
```

Return value is digest length in bytes. Digest bytes are written to `out[0..len]`.
For streaming, `RuntimeHasher.final` uses the same output-buffer contract.
`RuntimeHasher.finalResult` is a Zig-side convenience helper; consume bytes via
`digest.slice()`.

`fileHashInDir` is an advanced Zig helper: `sub_path` is resolved relative to
the provided `std.fs.Dir` instead of `cwd`.

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

### Options and errors

```zig
pub const HashOptions = struct {
    seed: ?u64 = null,
    key: ?[]const u8 = null,
};

pub const Error = error{
    KeyRequired,
    InvalidKeyLength,
    BufferTooSmall,
};
```

Rules:

- `HMAC-*`: `key` is required, otherwise `error.KeyRequired`
- `BLAKE3`: keyed mode requires `key.len == 32`, otherwise `error.InvalidKeyLength`
- `XXH3-64`: optional `seed`
- SHA/MD5 algorithms ignore options
- If `out` is too small: `error.BufferTooSmall`

`stringHash` returns only library errors above.

`fileHash` returns library errors plus filesystem/OS errors from opening and reading files (for example: `error.FileNotFound`, `error.AccessDenied`, `error.IsDir`, `error.NotDir`, `error.NameTooLong`, `error.Unexpected`; exact set is platform-dependent).

## C ABI

The C ABI lives in `src/c_api.zig`, with header `src/zig_files_hash_c_api.h`.
Current ABI version: `ZFH_API_VERSION = 2`.

Build artifacts:

```bash
zig build c-api-static   # .a / .lib
zig build c-api-shared   # .dylib / .so / .dll
zig build c-api-header   # installs header to zig-out/include
zig build c-api          # all of the above
```

Installed outputs:

- `zig-out/lib/libzig_files_hash_c_api_static.a` (or `.lib`)
- `zig-out/lib/libzig_files_hash_c_api.dylib` / `.so` / `.dll`
- `zig-out/include/zig_files_hash_c_api.h`

Main C functions:

```c
size_t zfh_max_digest_length(void);
uint32_t zfh_api_version(void);
zfh_error zfh_digest_length(zfh_algorithm alg, size_t *out_len_ptr);
const char *zfh_error_message(zfh_error code);
zfh_error zfh_string_hash(...);
zfh_error zfh_file_hash(...);
size_t zfh_hasher_state_size(void);
size_t zfh_hasher_state_align(void);
zfh_error zfh_hasher_init_inplace(...);
zfh_error zfh_hasher_update(...);
zfh_error zfh_hasher_final(...);
```

`zfh_api_version()` returns the same value as `ZFH_API_VERSION`.

C options:

```c
typedef struct zfh_options {
    uint32_t struct_size; // set to sizeof(zfh_options)
    uint32_t flags;
    uint64_t seed;
    const uint8_t *key_ptr;
    size_t key_len;
} zfh_options;
```

Use flags:

- `ZFH_OPTION_HAS_SEED`
- `ZFH_OPTION_HAS_KEY`

If no options are needed, pass `NULL` for `options_ptr`.
If options are provided, set `struct_size = sizeof(zfh_options)` (or `ZFH_OPTIONS_STRUCT_SIZE`).
If `ZFH_OPTION_HAS_KEY` is set with `key_len == 0`, an empty key is passed through.
This is valid for HMAC algorithms. For `BLAKE3` keyed mode, empty key returns `ZFH_INVALID_KEY_LENGTH`.
For `zfh_digest_length` / `zfh_string_hash` / `zfh_file_hash` / `zfh_hasher_final`,
output length pointers are set to `0` on error.
`zfh_file_hash` takes `path_ptr + path_len`; null-terminated C strings are not required.

Streaming contract:

- Query state requirements with `zfh_hasher_state_size` and `zfh_hasher_state_align`.
- Caller provides an aligned state buffer (`state_ptr`, `state_len`) to `zfh_hasher_init_inplace`.
- Call `zfh_hasher_update` any number of times with chunked data.
- Call `zfh_hasher_final` once to write digest bytes.
- After successful `zfh_hasher_final`, further `zfh_hasher_update`/`zfh_hasher_final`
  calls on the same state return `ZFH_INVALID_ARGUMENT`.
- No heap allocations are performed inside this streaming path.

C error model:

- `ZFH_OK`
- `ZFH_INVALID_ARGUMENT`
- `ZFH_INVALID_ALGORITHM`
- `ZFH_BUFFER_TOO_SMALL`
- `ZFH_KEY_REQUIRED`
- `ZFH_INVALID_KEY_LENGTH`
- `ZFH_FILE_NOT_FOUND`
- `ZFH_ACCESS_DENIED`
- `ZFH_INVALID_PATH`
- `ZFH_IO_ERROR`
- `ZFH_UNKNOWN_ERROR`

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
    const len = try zfh.stringHash(.@"SHA-256", "hello world", null, out[0..]);
    std.debug.print("SHA-256 = {x}\n", .{out[0..len]});
}
```

### Hash file (BLAKE3 keyed)

```zig
const std = @import("std");
const zfh = @import("zig_files_hash");
const HashAlgorithm = zfh.HashAlgorithm;

pub fn main() !void {
    const path: []const u8 = "file.bin";
    var out: [zfh.max_digest_length]u8 = undefined;
    const options = zfh.HashOptions{
        .key = "0123456789abcdef0123456789abcdef",
    };

    const len = try zfh.fileHash(HashAlgorithm.BLAKE3, path, options, out[0..]);
    std.debug.print("BLAKE3 = {x}\n", .{out[0..len]});
}
```

### Hash file in opened directory (`fileHashInDir`)

```zig
const std = @import("std");
const zfh = @import("zig_files_hash");

pub fn main() !void {
    var out: [zfh.max_digest_length]u8 = undefined;

    var dir = try std.fs.cwd().openDir("fixtures", .{});
    defer dir.close();

    const len = try zfh.fileHashInDir(.@"SHA-256", dir, "sample.bin", null, out[0..]);
    std.debug.print("SHA-256 = {x}\n", .{out[0..len]});
}
```

### Streaming hash (chunked input)

```zig
const std = @import("std");
const zfh = @import("zig_files_hash");

pub fn main() !void {
    // Option A: final(out)
    var out: [zfh.max_digest_length]u8 = undefined;
    {
        var hasher = try zfh.RuntimeHasher.init(.@"SHA-256", null);
        hasher.update("hello ");
        hasher.update("world");
        const len = try hasher.final(out[0..]);
        std.debug.print("SHA-256 = {x}\n", .{out[0..len]});
    }

    // Option B: finalResult() + slice()
    {
        var hasher = try zfh.RuntimeHasher.init(.@"SHA-256", null);
        hasher.update("hello ");
        hasher.update("world");
        const digest = hasher.finalResult();
        std.debug.print("SHA-256 = {x}\n", .{digest.slice()});
    }
}
```

## Build and test

```bash
zig build
zig build test
```

## Notes

- `getDemoOptionsArray` exists for local demo/testing flows; treat it as non-stable helper.

## License

MIT. See [LICENSE](LICENSE).
