const std = @import("std");
const builtin_mode = @import("builtin").mode;
// const zig_files_hash = @import("zig_files_hash");

pub fn main() !void {
    // Prints to stderr, ignoring potential errors.
    // std.debug.print("All your {s} are belong to us.\n", .{"codebase"});
    // try zig_files_hash.bufferedPrint();
    // const stdout = std.fs.File.stdout();
    // try stdout.writeAll("Ok\n");

    std.debug.print("Running in {s} mode\n", .{@tagName(builtin_mode)});

    if (builtin_mode == .Debug) { // TODO: comment this condition before building release and use page_allocator for all modes
        var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
        defer std.debug.assert(gpa.deinit() == .ok);

        try run(gpa.allocator());
    } else {
        try run(std.heap.page_allocator);
    }
}

fn run(al: std.mem.Allocator) !void {
    var args_iterator = try std.process.argsWithAllocator(al);
    defer args_iterator.deinit();

    _ = args_iterator.next(); // skip argv[0]
    const path = args_iterator.next() orelse {
        std.debug.print("Usage: zig build run -- <arg>\n", .{});
        return;
    };

    std.debug.print("First argument: {s}\n", .{path});

    try calculateHashForEverything(path);

    var out_buf: [64]u8 = undefined;
    const size = try fileHashPub(HashAlgorithm.BLAKE3, path, null, out_buf[0..]);
    std.debug.print("BLAKE3 (public API) = {x}\n", .{out_buf[0..size]});
}

fn getAlgorithmName(comptime H: type) []const u8 {
    if (@hasDecl(H, "name")) return H.name;
    return @typeName(H);
}

fn calculateHashForEverything(path: [:0]const u8) !void {
    inline for (Algorithms) |H| {
        if (H == Blake3) {
            // 1) unkeyed
            const h1 = try fileHash(Blake3, path, null);
            std.debug.print("BLAKE3 = {x}\n", .{h1});

            // 2) keyed
            const opts = HashOptions{ .key = "0123456789abcdef0123456789abcdef" };
            const h2 = try fileHash(Blake3, path, opts);
            std.debug.print("BLAKE3-KEYED = {x}\n", .{h2});

            continue;
        }
        const options = getOptionsForTests(H, null);
        const h = try fileHash(H, path, options);
        std.debug.print("{s} = {x}\n", .{ getAlgorithmName(H), h });
    }
}

// export type THashAlgorithm =
//     | 'MD5'
//     | 'SHA-1'
//     | 'SHA-224'
//     | 'SHA-256'
//     | 'SHA-384'
//     | 'SHA-512'
//     | 'XXH3-64'
//     | 'XXH3-128'
//     | 'BLAKE3';
// const Hasher = union(enum) { Xxh3_64: Xxh3_64 };

// const HashMode = enum { hash, hmac, keyed };

const Algorithms = .{
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512_224,
    Sha512_256,
    MD5,
    Sha1,
    Xxh3_64,
    Blake3,
    HmacSha224,
    HmacSha256,
    HmacSha384,
    HmacSha512,
    HmacMd5,
    HmacSha1,
};

const HashAlgorithm = enum {
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

const HashOptions = struct {
    // mode: HashMode = .hash,
    seed: ?u64 = null,
    // Blake3 key size 32 ([32]u8),
    // Sha2_32 key size varies depending on variant ([?]u8)
    key: ?[]const u8 = null,
    // key_encoding: ?KeyEncoding = null,
};

const Error = error{
    KeyRequired,
    InvalidKeyLength,
    BufferTooSmall,
};

fn fileHashInDir(comptime H: type, dir: std.fs.Dir, sub_path: []const u8, options: ?HashOptions) !H.Digest {
    var file = try dir.openFile(sub_path, .{});
    defer file.close();
    var buf: [64 * 1024]u8 = undefined;
    var hasher = try H.init(options);

    while (true) {
        const n = try file.read(buf[0..]);
        if (n == 0) {
            return hasher.final();
        }

        const chunk = buf[0..n];
        hasher.update(chunk);
    }
}

pub fn fileHashPub(al: HashAlgorithm, path: []const u8, options: ?HashOptions, out: []u8) !usize {
    switch (al) {
        .@"SHA-224" => {
            const result = try fileHash(Sha224, path, options);
            if (out.len < result.len) {
                return Error.BufferTooSmall;
            }
            @memcpy(out[0..result.len], result[0..]);
            return result.len;
        },
        .@"SHA-256" => {
            const result = try fileHash(Sha256, path, options);
            if (out.len < result.len) {
                return Error.BufferTooSmall;
            }
            @memcpy(out[0..result.len], result[0..]);
            return result.len;
        },
        .@"SHA-384" => {
            const result = try fileHash(Sha384, path, options);
            if (out.len < result.len) {
                return Error.BufferTooSmall;
            }
            @memcpy(out[0..result.len], result[0..]);
            return result.len;
        },
        .@"SHA-512" => {
            const result = try fileHash(Sha512, path, options);
            if (out.len < result.len) {
                return Error.BufferTooSmall;
            }
            @memcpy(out[0..result.len], result[0..]);
            return result.len;
        },
        .@"SHA-512/224" => {
            const result = try fileHash(Sha512_224, path, options);
            if (out.len < result.len) {
                return Error.BufferTooSmall;
            }
            @memcpy(out[0..result.len], result[0..]);
            return result.len;
        },
        .@"SHA-512/256" => {
            const result = try fileHash(Sha512_256, path, options);
            if (out.len < result.len) {
                return Error.BufferTooSmall;
            }
            @memcpy(out[0..result.len], result[0..]);
            return result.len;
        },
        .MD5 => {
            const result = try fileHash(MD5, path, options);
            if (out.len < result.len) {
                return Error.BufferTooSmall;
            }
            @memcpy(out[0..result.len], result[0..]);
            return result.len;
        },
        .@"SHA-1" => {
            const result = try fileHash(Sha1, path, options);
            if (out.len < result.len) {
                return Error.BufferTooSmall;
            }
            @memcpy(out[0..result.len], result[0..]);
            return result.len;
        },
        .@"XXH3-64" => {
            const result = try fileHash(Xxh3_64, path, options);
            const size = @sizeOf(u64); // @sizeOf(@TypeOf(result));
            if (out.len < size) { // if (out.len < @sizeOf(@TypeOf(result))) {
                return Error.BufferTooSmall;
            }
            const result_bytes = std.mem.asBytes(&result);
            @memcpy(out[0..size], result_bytes[0..]);
            return size;
        },
        .BLAKE3 => {
            const result = try fileHash(Blake3, path, options);
            if (out.len < result.len) {
                return Error.BufferTooSmall;
            }
            @memcpy(out[0..result.len], result[0..]);
            return result.len;
        },
        .@"HMAC-SHA-224" => {
            const result = try fileHash(HmacSha224, path, options);
            if (out.len < result.len) {
                return Error.BufferTooSmall;
            }
            @memcpy(out[0..result.len], result[0..]);
            return result.len;
        },
        .@"HMAC-SHA-256" => {
            const result = try fileHash(HmacSha256, path, options);
            if (out.len < result.len) {
                return Error.BufferTooSmall;
            }
            @memcpy(out[0..result.len], result[0..]);
            return result.len;
        },
        .@"HMAC-SHA-384" => {
            const result = try fileHash(HmacSha384, path, options);
            if (out.len < result.len) {
                return Error.BufferTooSmall;
            }
            @memcpy(out[0..result.len], result[0..]);
            return result.len;
        },
        .@"HMAC-SHA-512" => {
            const result = try fileHash(HmacSha512, path, options);
            if (out.len < result.len) {
                return Error.BufferTooSmall;
            }
            @memcpy(out[0..result.len], result[0..]);
            return result.len;
        },
        .@"HMAC-MD5" => {
            const result = try fileHash(HmacMd5, path, options);
            if (out.len < result.len) {
                return Error.BufferTooSmall;
            }
            @memcpy(out[0..result.len], result[0..]);
            return result.len;
        },
        .@"HMAC-SHA-1" => {
            const result = try fileHash(HmacSha1, path, options);
            if (out.len < result.len) {
                return Error.BufferTooSmall;
            }
            @memcpy(out[0..result.len], result[0..]);
            return result.len;
        },
    }
}

fn fileHash(comptime H: type, path: []const u8, options: ?HashOptions) !H.Digest {
    return fileHashInDir(H, std.fs.cwd(), path, options);
}

fn stringHash(comptime H: type, data: []const u8, options: ?HashOptions) !H.Digest {
    var hasher = try H.init(options);
    hasher.update(data);
    return hasher.final();
}

fn Sha2_32(comptime Bits: u16) type {
    return struct {
        const Self = @This();

        pub const name = switch (Bits) {
            224 => "SHA-224",
            256 => "SHA-256",
            else => unreachable,
        };

        const Inner = switch (Bits) {
            224 => std.crypto.hash.sha2.Sha224,
            256 => std.crypto.hash.sha2.Sha256,
            else => @compileError("Bits must be 224/256"),
        };

        inner: Inner,

        pub fn init(options: ?HashOptions) !Self {
            _ = options;
            return .{ .inner = Inner.init(.{}) };
        }

        pub fn update(self: *Self, data: []const u8) void {
            self.inner.update(data);
        }

        pub const digest_length = Bits / 8;

        pub const Digest = [digest_length]u8;

        pub fn final(self: *Self) Digest {
            var out: [digest_length]u8 = undefined;
            self.inner.final(&out);
            return out;
        }
    };
}

const Sha224 = Sha2_32(224);
const Sha256 = Sha2_32(256);

fn Sha2_64(comptime Bits: u16) type {
    return struct {
        const Self = @This();

        pub const name = switch (Bits) {
            384 => "SHA-384",
            512 => "SHA-512",
            224 => "SHA-512/224",
            256 => "SHA-512/256",
            else => unreachable,
        };

        const Inner = switch (Bits) {
            384 => std.crypto.hash.sha2.Sha384,
            512 => std.crypto.hash.sha2.Sha512,
            224 => std.crypto.hash.sha2.Sha512_224,
            256 => std.crypto.hash.sha2.Sha512_256,
            else => @compileError("Bits must be 384/512/224/256"),
        };

        inner: Inner,

        pub fn init(options: ?HashOptions) !Self {
            _ = options;
            return .{ .inner = Inner.init(.{}) };
        }

        pub fn update(self: *Self, data: []const u8) void {
            self.inner.update(data);
        }

        pub const digest_length = Bits / 8;

        pub const Digest = [digest_length]u8;

        pub fn final(self: *Self) Digest {
            var out: [digest_length]u8 = undefined;
            self.inner.final(&out);
            return out;
        }
    };
}

const Sha384 = Sha2_64(384);
const Sha512 = Sha2_64(512);
const Sha512_224 = Sha2_64(224);
const Sha512_256 = Sha2_64(256);

const Sha1 = struct {
    pub const name = "SHA-1";

    inner: std.crypto.hash.Sha1,

    pub fn init(options: ?HashOptions) !Sha1 {
        _ = options;
        return .{ .inner = std.crypto.hash.Sha1.init(.{}) };
    }

    pub fn update(self: *Sha1, data: []const u8) void {
        self.inner.update(data);
    }

    pub const Digest = [20]u8;

    pub fn final(self: *Sha1) Digest {
        var out: Digest = undefined;
        self.inner.final(&out);
        return out;
    }
};

fn Hmac(comptime H: type) type {
    return struct {
        const Self = @This();

        pub const name = switch (H) {
            std.crypto.auth.hmac.sha2.HmacSha224 => "HMAC-SHA-224",
            std.crypto.auth.hmac.sha2.HmacSha256 => "HMAC-SHA-256",
            std.crypto.auth.hmac.sha2.HmacSha384 => "HMAC-SHA-384",
            std.crypto.auth.hmac.sha2.HmacSha512 => "HMAC-SHA-512",
            std.crypto.auth.hmac.HmacMd5 => "HMAC-MD5",
            std.crypto.auth.hmac.HmacSha1 => "HMAC-SHA-1",
            else => unreachable,
        };

        const Inner = H;

        inner: Inner,

        pub fn init(options: ?HashOptions) !Self {
            if (options) |o| {
                if (o.key) |k| {
                    return .{ .inner = Inner.init(k) };
                }
            }
            return Error.KeyRequired;
        }

        pub fn update(self: *Self, data: []const u8) void {
            self.inner.update(data);
        }

        pub const Digest = [H.mac_length]u8;

        pub fn final(self: *Self) Digest {
            var out: Digest = undefined;
            self.inner.final(&out);
            return out;
        }
    };
}

const HmacSha224 = Hmac(std.crypto.auth.hmac.sha2.HmacSha224);
const HmacSha256 = Hmac(std.crypto.auth.hmac.sha2.HmacSha256);
const HmacSha384 = Hmac(std.crypto.auth.hmac.sha2.HmacSha384);
const HmacSha512 = Hmac(std.crypto.auth.hmac.sha2.HmacSha512);
const HmacMd5 = Hmac(std.crypto.auth.hmac.HmacMd5);
const HmacSha1 = Hmac(std.crypto.auth.hmac.HmacSha1);

const MD5 = struct {
    pub const name = "MD5";

    inner: std.crypto.hash.Md5,

    pub fn init(options: ?HashOptions) !MD5 {
        _ = options;
        return .{ .inner = std.crypto.hash.Md5.init(.{}) };
    }

    pub fn update(self: *MD5, data: []const u8) void {
        self.inner.update(data);
    }

    pub const Digest = [16]u8;

    pub fn final(self: *MD5) Digest {
        var out: Digest = undefined;
        self.inner.final(&out);
        return out;
    }
};

const Xxh3_64 = struct {
    pub const name = "XXH3-64";

    inner: std.hash.XxHash3,

    pub fn init(options: ?HashOptions) !Xxh3_64 {
        const seed: u64 = (options orelse HashOptions{}).seed orelse 0;
        return .{ .inner = std.hash.XxHash3.init(seed) };
    }

    pub fn update(self: *Xxh3_64, data: []const u8) void {
        self.inner.update(data);
    }

    pub const Digest = u64;

    pub fn final(self: *Xxh3_64) Digest {
        return self.inner.final();
    }
};

const Blake3 = struct {
    const Self = @This();

    pub const name = "BLAKE3";

    inner: std.crypto.hash.Blake3,

    pub fn init(options: ?HashOptions) !Self {
        var opt: std.crypto.hash.Blake3.Options = .{};
        if (options) |o| {
            if (o.key) |k| {
                if (k.len != 32) {
                    return Error.InvalidKeyLength;
                }
                var tmp: [32]u8 = undefined;
                std.mem.copyForwards(u8, tmp[0..], k[0..32]);
                opt.key = tmp;
            }
        }

        return .{ .inner = std.crypto.hash.Blake3.init(opt) };
    }

    pub fn update(self: *Self, data: []const u8) void {
        self.inner.update(data);
    }

    pub const Digest = [32]u8;

    pub fn final(self: *const Self) Digest {
        var out: [32]u8 = undefined;
        self.inner.final(out[0..]);
        return out;
    }
};

fn getOptionsForTests(comptime H: type, is_keyed_blake3: ?bool) ?HashOptions {
    if (is_keyed_blake3) |keyed| {
        if (keyed and H == Blake3) {
            return HashOptions{ .key = "0123456789abcdef0123456789abcdef" };
        }
    }
    return switch (H) {
        HmacSha224, HmacSha256, HmacSha384, HmacSha512, HmacMd5, HmacSha1 => .{
            .key = "my_secret_key",
        },
        else => null,
    };
}

fn expectDeterministicStringHash(comptime H: type, is_keyed_blake3: ?bool) !void {
    const options = getOptionsForTests(H, is_keyed_blake3);
    const data = "Hello, world!";
    const hash1 = try stringHash(H, data, options);
    const hash2 = try stringHash(H, data, options);
    try std.testing.expectEqual(hash1, hash2);
}

test "deterministic string hash" {
    inline for (Algorithms) |H| {
        try expectDeterministicStringHash(H, null);
        if (H == Blake3) {
            try expectDeterministicStringHash(H, true);
        }
    }
}

fn expectFileHashDeterminismAndConsistency(comptime H: type, is_keyed_blake3: ?bool) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const sub_path = "test.bin";
    const data = "Hello, world!";

    {
        const file = try tmp.dir.createFile(sub_path, .{
            .truncate = true,
        });
        defer file.close();
        try file.writeAll(data);
    }

    const options = getOptionsForTests(H, is_keyed_blake3);

    const hash1 = try fileHashInDir(H, tmp.dir, sub_path, options);
    const hash2 = try fileHashInDir(H, tmp.dir, sub_path, options);

    try std.testing.expectEqual(hash1, hash2);

    const hash3 = try stringHash(H, data, options);
    try std.testing.expectEqual(hash1, hash3);
}

test "file hash determinism and consistency with string hash" {
    inline for (Algorithms) |H| {
        try expectFileHashDeterminismAndConsistency(H, null);
        if (H == Blake3) {
            try expectFileHashDeterminismAndConsistency(H, true);
        }
    }
}

test "Blake3 rejects key with invalid length" {
    const options = HashOptions{ .key = "short_key" };
    try std.testing.expectError(Error.InvalidKeyLength, Blake3.init(options));
}

test "key is required for HMAC algorithms" {
    inline for (Algorithms) |H| {
        switch (H) {
            HmacSha224, HmacSha256, HmacSha384, HmacSha512, HmacMd5, HmacSha1 => {
                try std.testing.expectError(Error.KeyRequired, H.init(null));
            },
            else => continue,
        }
    }
}

test "different input produces different hash" {
    const data1 = "Hello, world!";
    const data2 = "Hello, world?";
    inline for (Algorithms) |H| {
        const options = getOptionsForTests(H, null);
        const hash1 = try stringHash(H, data1, options);
        const hash2 = try stringHash(H, data2, options);
        if (H == Xxh3_64) {
            try std.testing.expect(hash1 != hash2);
        } else {
            try std.testing.expect(!std.mem.eql(u8, hash1[0..], hash2[0..]));
        }
    }
}

test "different options produce different hash" {
    const data = "Hello, world!";
    inline for (Algorithms) |H| {
        switch (H) {
            Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256, MD5, Sha1 => {
                // no options, skip
                continue;
            },
            Blake3 => {
                // test keyed vs unkeyed
                const options1 = getOptionsForTests(H, null);
                const options2 = getOptionsForTests(H, true);

                const hash1 = try stringHash(H, data, options1);
                const hash2 = try stringHash(H, data, options2);
                try std.testing.expect(!std.mem.eql(u8, hash1[0..], hash2[0..]));
                continue;
            },
            Xxh3_64 => {
                // test different seeds
                const options1 = getOptionsForTests(H, null);
                const options2 = HashOptions{ .seed = 12345 };

                const hash1 = try stringHash(H, data, options1);
                const hash2 = try stringHash(H, data, options2);
                try std.testing.expect(hash1 != hash2);
                continue;
            },
            else => {
                // for HMAC algorithms test different keys
                const options1 = getOptionsForTests(H, null);
                const options2 = HashOptions{ .key = "different_key" };

                const hash1 = try stringHash(H, data, options1);
                const hash2 = try stringHash(H, data, options2);
                try std.testing.expect(!std.mem.eql(u8, hash1[0..], hash2[0..]));
                continue;
            },
        }
    }
}

test "empty input produces deterministic hash" {
    const empty: []const u8 = "";
    inline for (Algorithms) |H| {
        const options = getOptionsForTests(H, null);
        const hash1 = try stringHash(H, empty, options);
        const hash2 = try stringHash(H, empty, options);
        // Only check determinism for empty input (no known-good hash comparison).
        try std.testing.expectEqual(hash1, hash2);
    }
}

test "multi-chunk file (>64KB) hash matches string hash" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const sub_path = "test.bin";
    var data: [70 * 1024]u8 = undefined;
    for (&data, 0..) |*b, i| {
        b.* = @as(u8, @intCast(i % 256));
    }

    {
        const file = try tmp.dir.createFile(sub_path, .{
            .truncate = true,
        });
        defer file.close();
        try file.writeAll(data[0..]);
    }
    inline for (Algorithms) |H| {
        const options = getOptionsForTests(H, null);
        const hash1 = try fileHashInDir(H, tmp.dir, sub_path, options);
        const hash2 = try stringHash(H, data[0..], options);
        try std.testing.expectEqual(hash1, hash2);

        if (H == Blake3) {
            const options_keyed = getOptionsForTests(H, true);
            const hash_keyed_1 = try fileHashInDir(H, tmp.dir, sub_path, options_keyed);
            const hash_keyed_2 = try stringHash(H, data[0..], options_keyed);
            try std.testing.expectEqual(hash_keyed_1, hash_keyed_2);
        }
    }
}

// test "simple test" {
//     const gpa = std.testing.allocator;
//     var list: std.ArrayList(i32) = .empty;
//     defer list.deinit(gpa); // Try commenting this out and see if zig detects the memory leak!
//     try list.append(gpa, 42);
//     try std.testing.expectEqual(@as(i32, 42), list.pop());
// }

// test "fuzz example" {
//     const Context = struct {
//         fn testOne(context: @This(), input: []const u8) anyerror!void {
//             _ = context;
//             // Try passing `--fuzz` to `zig build test` and see if it manages to fail this test case!
//             try std.testing.expect(!std.mem.eql(u8, "canyoufindme", input));
//         }
//     };
//     try std.testing.fuzz(Context{}, Context.testOne, .{});
// }
