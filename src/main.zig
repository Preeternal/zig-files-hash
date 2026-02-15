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

    var out_buf: [max_digest_length]u8 = undefined;
    const size = try fileHashPub(HashAlgorithm.BLAKE3, path, null, out_buf[0..]);
    std.debug.print("BLAKE3 (public API file input) = {x}\n", .{out_buf[0..size]});

    const size2 = try stringHashPub(HashAlgorithm.BLAKE3, "Hello, world!", null, out_buf[0..]);
    std.debug.print("BLAKE3 (public API string input) = {x}\n", .{out_buf[0..size2]});
}

fn calculateHashForEverything(path: [:0]const u8) !void {
    inline for (AlgorithmSpecs) |spec| {
        const H = spec.H;
        const options_array = getOptionsArrayForTests(H);
        for (options_array, 0..) |options, i| {
            const h: H.Digest = try fileHash(H, path, options);
            const suffix = if (H == Blake3 and i == 1) "-KEYED" else "";
            std.debug.print("{s}{s} = {x}\n", .{ spec.H.name, suffix, h });
        }
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

const AlgorithmSpec = struct {
    tag: HashAlgorithm,
    H: type,
};

const AlgorithmSpecs = [_]AlgorithmSpec{
    .{ .tag = .@"SHA-224", .H = Sha224 },
    .{ .tag = .@"SHA-256", .H = Sha256 },
    .{ .tag = .@"SHA-384", .H = Sha384 },
    .{ .tag = .@"SHA-512", .H = Sha512 },
    .{ .tag = .@"SHA-512/224", .H = Sha512_224 },
    .{ .tag = .@"SHA-512/256", .H = Sha512_256 },
    .{ .tag = .MD5, .H = MD5 },
    .{ .tag = .@"SHA-1", .H = Sha1 },
    .{ .tag = .@"XXH3-64", .H = Xxh3_64 },
    .{ .tag = .BLAKE3, .H = Blake3 },
    .{ .tag = .@"HMAC-SHA-224", .H = HmacSha224 },
    .{ .tag = .@"HMAC-SHA-256", .H = HmacSha256 },
    .{ .tag = .@"HMAC-SHA-384", .H = HmacSha384 },
    .{ .tag = .@"HMAC-SHA-512", .H = HmacSha512 },
    .{ .tag = .@"HMAC-MD5", .H = HmacMd5 },
    .{ .tag = .@"HMAC-SHA-1", .H = HmacSha1 },
};

comptime {
    const enum_fields = @typeInfo(HashAlgorithm).@"enum".fields;
    if (AlgorithmSpecs.len != enum_fields.len) {
        @compileError("AlgorithmSpecs.len must match HashAlgorithm enum size");
    }
}

comptime {
    const enum_fields = @typeInfo(HashAlgorithm).@"enum".fields;

    var seen: [enum_fields.len]bool = .{false} ** enum_fields.len;

    for (AlgorithmSpecs) |spec| {
        const idx = @intFromEnum(@as(HashAlgorithm, spec.tag));
        if (seen[idx]) {
            @compileError("Duplicate tag in AlgorithmSpecs: " ++ @tagName(spec.tag));
        }
        seen[idx] = true;
    }

    for (seen, 0..) |ok, i| {
        if (!ok) {
            @compileError("Missing spec for HashAlgorithm: " ++ enum_fields[i].name);
        }
    }
}

fn digestLengthBytes(comptime H: type) usize {
    const Digest = H.Digest;
    return switch (@typeInfo(Digest)) {
        .array => |a| a.len,
        else => @sizeOf(Digest),
    };
}

pub const max_digest_length = blk: {
    var max = 0;
    for (AlgorithmSpecs) |spec| {
        const len = digestLengthBytes(spec.H);
        if (len > max) {
            max = len;
        }
    }
    break :blk max;
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

fn writeFileHash(H: type, path: []const u8, options: ?HashOptions, out: []u8) !usize {
    const result = try fileHash(H, path, options);
    const result_bytes = std.mem.asBytes(&result);
    if (out.len < result_bytes.len) {
        return Error.BufferTooSmall;
    }
    @memcpy(out[0..result_bytes.len], result_bytes);
    return result_bytes.len;
}

pub fn fileHashPub(al: HashAlgorithm, path: []const u8, options: ?HashOptions, out: []u8) !usize {
    // std.debug.print("Calculating {s} hash for {s}\n", .{ @tagName(al), path });
    inline for (AlgorithmSpecs) |spec| {
        if (al == spec.tag) {
            return writeFileHash(spec.H, path, options, out);
        }
    }
    unreachable;
}

fn writeStringHash(H: type, data: []const u8, options: ?HashOptions, out: []u8) !usize {
    const result = try stringHash(H, data, options);
    const result_bytes = std.mem.asBytes(&result);
    if (out.len < result_bytes.len) {
        return Error.BufferTooSmall;
    }
    @memcpy(out[0..result_bytes.len], result_bytes);
    return result_bytes.len;
}

pub fn stringHashPub(al: HashAlgorithm, data: []const u8, options: ?HashOptions, out: []u8) !usize {
    // std.debug.print("Calculating {s} hash for string input\n", .{ @tagName(al) });
    inline for (AlgorithmSpecs) |spec| {
        if (al == spec.tag) {
            return writeStringHash(spec.H, data, options, out);
        }
    }
    unreachable;
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

fn getOptionsArrayForTests(comptime H: type) []const ?HashOptions {
    return switch (H) {
        Blake3 => &[2]?HashOptions{
            null,
            .{ .key = "0123456789abcdef0123456789abcdef" },
        },
        HmacSha224, HmacSha256, HmacSha384, HmacSha512, HmacMd5, HmacSha1 => &[1]?HashOptions{
            .{ .key = "my_secret_key" },
        },
        else => &[1]?HashOptions{null},
    };
}

fn expectDeterministicStringHash(comptime H: type) !void {
    const options_array = getOptionsArrayForTests(H);
    for (options_array) |options| {
        const data = "Hello, world!";
        const hash1 = try stringHash(H, data, options);
        const hash2 = try stringHash(H, data, options);
        try std.testing.expectEqual(hash1, hash2);
    }
}

test "deterministic string hash" {
    inline for (AlgorithmSpecs) |spec| {
        const H = spec.H;
        try expectDeterministicStringHash(H);
    }
}

fn expectFileHashDeterminismAndConsistency(comptime H: type) !void {
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

    const options_array = getOptionsArrayForTests(H);
    for (options_array) |options| {
        const hash1 = try fileHashInDir(H, tmp.dir, sub_path, options);
        const hash2 = try fileHashInDir(H, tmp.dir, sub_path, options);

        try std.testing.expectEqual(hash1, hash2);

        const hash3 = try stringHash(H, data, options);
        try std.testing.expectEqual(hash1, hash3);
    }
}

test "file hash determinism and consistency with string hash" {
    inline for (AlgorithmSpecs) |spec| {
        const H = spec.H;
        try expectFileHashDeterminismAndConsistency(H);
    }
}

test "Blake3 rejects key with invalid length" {
    const options = HashOptions{ .key = "short_key" };
    try std.testing.expectError(Error.InvalidKeyLength, Blake3.init(options));
}

test "key is required for HMAC algorithms" {
    inline for (AlgorithmSpecs) |spec| {
        const H = spec.H;
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
    inline for (AlgorithmSpecs) |spec| {
        const H = spec.H;
        const options_array = getOptionsArrayForTests(H);
        for (options_array) |options| {
            const hash1 = try stringHash(H, data1, options);
            const hash2 = try stringHash(H, data2, options);
            if (H == Xxh3_64) {
                try std.testing.expect(hash1 != hash2);
            } else {
                try std.testing.expect(!std.mem.eql(u8, hash1[0..], hash2[0..]));
            }
        }
    }
}

test "different options produce different hash" {
    const data = "Hello, world!";
    inline for (AlgorithmSpecs) |spec| {
        const H = spec.H;
        switch (H) {
            Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256, MD5, Sha1 => {
                // no options, skip
                continue;
            },
            Blake3 => {
                // test keyed vs unkeyed
                const options1 = HashOptions{ .key = "0123456789abcdef0123456789abcdef" };
                const options2 = null;

                const hash1 = try stringHash(H, data, options1);
                const hash2 = try stringHash(H, data, options2);
                try std.testing.expect(!std.mem.eql(u8, hash1[0..], hash2[0..]));
                continue;
            },
            Xxh3_64 => {
                // test with vs without seed
                const options1 = HashOptions{ .seed = 12345 };
                const options2 = null;

                const hash1 = try stringHash(H, data, options1);
                const hash2 = try stringHash(H, data, options2);
                try std.testing.expect(hash1 != hash2);
                continue;
            },
            else => {
                // for HMAC algorithms test different keys
                const options1 = HashOptions{ .key = "some_key" };
                const options2 = HashOptions{ .key = "another_key" };

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
    inline for (AlgorithmSpecs) |spec| {
        const H = spec.H;
        const options_array = getOptionsArrayForTests(H);
        for (options_array) |options| {
            const hash1 = try stringHash(H, empty, options);
            const hash2 = try stringHash(H, empty, options);
            // Only check determinism for empty input (no known-good hash comparison).
            try std.testing.expectEqual(hash1, hash2);
        }
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
    inline for (AlgorithmSpecs) |spec| {
        const H = spec.H;
        const options_array = getOptionsArrayForTests(H);
        for (options_array) |options| {
            const hash1 = try fileHashInDir(H, tmp.dir, sub_path, options);
            const hash2 = try stringHash(H, data[0..], options);
            try std.testing.expectEqual(hash1, hash2);
        }
    }
}

test "Public API produces same hash as direct API" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const data = "Hello, world!";
    const file_name = "test.bin";

    {
        const file = try tmp.dir.createFile(file_name, .{
            .truncate = true,
        });
        defer file.close();
        try file.writeAll(data);
    }

    inline for (AlgorithmSpecs) |spec| {
        const H = spec.H;
        const T = spec.tag;
        const options_array = getOptionsArrayForTests(H);
        for (options_array) |options| {
            var out_buf: [max_digest_length]u8 = undefined;
            var path_buf: [std.fs.max_path_bytes]u8 = undefined;

            const digest_file = try fileHashInDir(H, tmp.dir, file_name, options);
            const expected_bytes_file = std.mem.asBytes(&digest_file);
            const real_path = try tmp.dir.realpath(file_name, &path_buf);
            const size_file = try fileHashPub(T, real_path, options, out_buf[0..]);
            const public_bytes_file = out_buf[0..size_file];
            try std.testing.expectEqualSlices(u8, expected_bytes_file, public_bytes_file);

            const digest_str = try stringHash(H, data, options);
            const expected_bytes_str = std.mem.asBytes(&digest_str);
            const size_str = try stringHashPub(T, data, options, out_buf[0..]);
            const public_bytes_str = out_buf[0..size_str];
            try std.testing.expectEqualSlices(u8, expected_bytes_str, public_bytes_str);
        }
    }
}

test "SHA-256 NIST FIPS 180-4 (Secure Hash Standard)" {
    const abc = "abc";
    const expected_hex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const abc_hash = try stringHash(Sha256, abc, null);
    try std.testing.expectFmt(expected_hex, "{x}", .{abc_hash});

    const empty_str = "";
    const expected_empty_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const empty_hash = try stringHash(Sha256, empty_str, null);
    try std.testing.expectFmt(expected_empty_hex, "{x}", .{empty_hash});
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
