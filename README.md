# zig-files-hash

Small hashing library in Zig with one runtime API for multiple algorithms.

## Status

- Pre-1.0 API may change.
- Minimum Zig version: `0.15.2` (`build.zig.zon`).

## Features

- Unified runtime API via `HashAlgorithm`
- Hashing for in-memory data and files
- Allocation-free core API (caller provides output buffer)
- Keyed/seeded modes where applicable
- Cross-platform Zig build

## Public API

```zig
pub const HashAlgorithm
pub const HashOptions
pub const Error
pub const max_digest_length

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
```

Return value is digest length in bytes. Digest bytes are written to `out[0..len]`.

## Algorithms

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

## Options and Errors

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

## Output Format

- API returns raw digest bytes, not hex string.
- Print hex with `{x}`.
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
    const digest = out[0..len];

    std.debug.print("SHA-256 = {x}\n", .{digest});
}
```

### Hash file (BLAKE3 keyed)

```zig
const std = @import("std");
const zfh = @import("zig_files_hash");

pub fn main() !void {
    var out: [zfh.max_digest_length]u8 = undefined;
    const options = zfh.HashOptions{
        .key = "0123456789abcdef0123456789abcdef",
    };

    const len = try zfh.fileHash(.BLAKE3, "file.bin", options, out[0..]);
    std.debug.print("BLAKE3 = {x}\n", .{out[0..len]});
}
```

## Build and Test

```bash
zig build
zig build test
```

## Notes

- `getDemoOptionsArray` exists for local demo/testing flows; treat it as non-stable helper.

## License

MIT

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
