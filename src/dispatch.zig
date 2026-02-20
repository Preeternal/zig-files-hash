const std = @import("std");
const algorithms = @import("algorithms.zig");

const HashAlgorithm = algorithms.HashAlgorithm;
const AlgorithmSpecs = algorithms.AlgorithmSpecs;

const HashOptions = algorithms.HashOptions;
const Error = algorithms.Error;
const max_digest_length = algorithms.max_digest_length;

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
    const result = try fileHashImpl(H, path, options);
    if (out.len < result.len) {
        return Error.BufferTooSmall;
    }
    @memcpy(out[0..result.len], result[0..]);
    return result.len;
}

pub fn fileHash(alg: HashAlgorithm, path: []const u8, options: ?HashOptions, out: []u8) !usize {
    // std.debug.print("Calculating {s} hash for {s}\n", .{ @tagName(alg), path });
    inline for (AlgorithmSpecs) |spec| {
        if (alg == spec.tag) {
            return writeFileHash(spec.H, path, options, out);
        }
    }
    unreachable;
}

fn writeStringHash(H: type, data: []const u8, options: ?HashOptions, out: []u8) !usize {
    const result = try stringHashImpl(H, data, options);
    if (out.len < result.len) {
        return Error.BufferTooSmall;
    }
    @memcpy(out[0..result.len], result[0..]);
    return result.len;
}

pub fn stringHash(alg: HashAlgorithm, data: []const u8, options: ?HashOptions, out: []u8) !usize {
    // std.debug.print("Calculating {s} hash for string input\n", .{ @tagName(alg) });
    inline for (AlgorithmSpecs) |spec| {
        if (alg == spec.tag) {
            return writeStringHash(spec.H, data, options, out);
        }
    }
    unreachable;
}

fn fileHashImpl(comptime H: type, path: []const u8, options: ?HashOptions) !H.Digest {
    return fileHashInDir(H, std.fs.cwd(), path, options);
}

fn stringHashImpl(comptime H: type, data: []const u8, options: ?HashOptions) !H.Digest {
    var hasher = try H.init(options);
    hasher.update(data);
    return hasher.final();
}

pub fn getDemoOptionsArray(alg: HashAlgorithm) []const ?HashOptions {
    return switch (alg) {
        HashAlgorithm.BLAKE3 => &[2]?HashOptions{
            null,
            .{ .key = "0123456789abcdef0123456789abcdef" },
        },
        HashAlgorithm.@"HMAC-SHA-224", //
        HashAlgorithm.@"HMAC-SHA-256",
        HashAlgorithm.@"HMAC-SHA-384",
        HashAlgorithm.@"HMAC-SHA-512",
        HashAlgorithm.@"HMAC-MD5",
        HashAlgorithm.@"HMAC-SHA-1",
        => &[1]?HashOptions{
            .{ .key = "my_secret_key" },
        },
        HashAlgorithm.@"XXH3-64" => &[2]?HashOptions{
            null,
            .{ .seed = 12345 },
        },
        else => &[1]?HashOptions{null},
    };
}

fn expectDeterministicStringHash(alg: HashAlgorithm) !void {
    const options_array = getDemoOptionsArray(alg);
    for (options_array) |options| {
        const data = "Hello, world!";

        var out_buf1: [max_digest_length]u8 = undefined;
        const size1 = try stringHash(alg, data, options, out_buf1[0..]);
        const hash1 = out_buf1[0..size1];

        var out_buf2: [max_digest_length]u8 = undefined;
        const size2 = try stringHash(alg, data, options, out_buf2[0..]);
        const hash2 = out_buf2[0..size2];

        try std.testing.expectEqualSlices(u8, hash1, hash2);
    }
}

test "deterministic string hash" {
    inline for (AlgorithmSpecs) |spec| {
        const alg = spec.tag;
        try expectDeterministicStringHash(alg);
    }
}

fn expectFileHashDeterminismAndConsistency(alg: HashAlgorithm) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const file_name = "test.bin";
    const data = "Hello, world!";

    {
        const file = try tmp.dir.createFile(file_name, .{
            .truncate = true,
        });
        defer file.close();
        try file.writeAll(data);
    }

    const options_array = getDemoOptionsArray(alg);
    for (options_array) |options| {
        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const real_path = try tmp.dir.realpath(file_name, &path_buf);

        var out_buf1: [max_digest_length]u8 = undefined;
        const size_file1 = try fileHash(alg, real_path, options, out_buf1[0..]);
        const hash1 = out_buf1[0..size_file1];

        var out_buf2: [max_digest_length]u8 = undefined;
        const size_file2 = try fileHash(alg, real_path, options, out_buf2[0..]);
        const hash2 = out_buf2[0..size_file2];

        try std.testing.expectEqualSlices(u8, hash1, hash2);

        var out_buf3: [max_digest_length]u8 = undefined;
        const size_string = try stringHash(alg, data, options, out_buf3[0..]);
        const hash3 = out_buf3[0..size_string];

        try std.testing.expectEqualSlices(u8, hash1, hash3);
    }
}

test "file hash determinism and consistency with string hash" {
    inline for (AlgorithmSpecs) |spec| {
        const alg = spec.tag;
        try expectFileHashDeterminismAndConsistency(alg);
    }
}

test "different input produces different hash" {
    const data1 = "Hello, world!";
    const data2 = "Hello, world?";
    inline for (AlgorithmSpecs) |spec| {
        const alg = spec.tag;
        const options_array = getDemoOptionsArray(alg);
        for (options_array) |options| {
            var out_buf1: [max_digest_length]u8 = undefined;
            const size1 = try stringHash(alg, data1, options, out_buf1[0..]);
            const hash1 = out_buf1[0..size1];

            var out_buf2: [max_digest_length]u8 = undefined;
            const size2 = try stringHash(alg, data2, options, out_buf2[0..]);
            const hash2 = out_buf2[0..size2];

            try std.testing.expect(!std.mem.eql(u8, hash1, hash2));
        }
    }
}

test "different options produce different hash" {
    const data = "Hello, world!";
    inline for (AlgorithmSpecs) |spec| {
        const alg = spec.tag;
        switch (alg) {
            HashAlgorithm.@"SHA-224", //
            HashAlgorithm.@"SHA-256",
            HashAlgorithm.@"SHA-384",
            HashAlgorithm.@"SHA-512",
            HashAlgorithm.@"SHA-512/224",
            HashAlgorithm.@"SHA-512/256",
            HashAlgorithm.MD5,
            HashAlgorithm.@"SHA-1",
            => {
                // no options, skip
                continue;
            },
            HashAlgorithm.BLAKE3 => {
                // test keyed vs unkeyed
                const options1 = HashOptions{ .key = "0123456789abcdef0123456789abcdef" };
                const options2 = null;

                var out_buf1: [max_digest_length]u8 = undefined;
                const size1 = try stringHash(alg, data, options1, out_buf1[0..]);
                const hash1 = out_buf1[0..size1];

                var out_buf2: [max_digest_length]u8 = undefined;
                const size2 = try stringHash(alg, data, options2, out_buf2[0..]);
                const hash2 = out_buf2[0..size2];

                try std.testing.expect(!std.mem.eql(u8, hash1[0..], hash2[0..]));
                continue;
            },
            HashAlgorithm.@"XXH3-64" => {
                // test with vs without seed
                const options1 = HashOptions{ .seed = 12345 };
                const options2 = null;

                var out_buf1: [max_digest_length]u8 = undefined;

                const size1 = try stringHash(alg, data, options1, out_buf1[0..]);
                const hash1 = out_buf1[0..size1];

                var out_buf2: [max_digest_length]u8 = undefined;
                const size2 = try stringHash(alg, data, options2, out_buf2[0..]);
                const hash2 = out_buf2[0..size2];

                try std.testing.expect(!std.mem.eql(u8, hash1[0..], hash2[0..]));
                continue;
            },
            else => {
                // for HMAC algorithms test different keys
                const options1 = HashOptions{ .key = "some_key" };
                const options2 = HashOptions{ .key = "another_key" };

                var out_buf1: [max_digest_length]u8 = undefined;

                const size1 = try stringHash(alg, data, options1, out_buf1[0..]);
                const hash1 = out_buf1[0..size1];

                var out_buf2: [max_digest_length]u8 = undefined;
                const size2 = try stringHash(alg, data, options2, out_buf2[0..]);
                const hash2 = out_buf2[0..size2];

                try std.testing.expect(!std.mem.eql(u8, hash1[0..], hash2[0..]));
                continue;
            },
        }
    }
}

test "empty input produces deterministic hash" {
    const empty: []const u8 = "";
    inline for (AlgorithmSpecs) |spec| {
        const alg = spec.tag;
        const options_array = getDemoOptionsArray(alg);
        for (options_array) |options| {
            var out_buf1: [max_digest_length]u8 = undefined;

            const size1 = try stringHash(alg, empty, options, out_buf1[0..]);
            const hash1 = out_buf1[0..size1];

            var out_buf2: [max_digest_length]u8 = undefined;
            const size2 = try stringHash(alg, empty, options, out_buf2[0..]);
            const hash2 = out_buf2[0..size2];

            // Only check determinism for empty input (no known-good hash comparison).
            try std.testing.expectEqualSlices(u8, hash1, hash2);
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
        const alg = spec.tag;
        const H = spec.H;
        const options_array = getDemoOptionsArray(alg);
        for (options_array) |options| {
            const hash1 = try fileHashInDir(H, tmp.dir, sub_path, options);
            const hash2 = try stringHashImpl(H, data[0..], options);
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
        const alg = spec.tag;
        const options_array = getDemoOptionsArray(alg);
        for (options_array) |options| {
            const digest_file = try fileHashInDir(H, tmp.dir, file_name, options);
            const expected_bytes_file = std.mem.asBytes(&digest_file);

            var out_buf_file: [max_digest_length]u8 = undefined;
            var path_buf: [std.fs.max_path_bytes]u8 = undefined;
            const real_path = try tmp.dir.realpath(file_name, &path_buf);
            const size_file = try fileHash(alg, real_path, options, out_buf_file[0..]);
            const public_bytes_file = out_buf_file[0..size_file];

            try std.testing.expectEqualSlices(u8, expected_bytes_file, public_bytes_file);

            const digest_str = try stringHashImpl(H, data, options);
            const expected_bytes_str = std.mem.asBytes(&digest_str);
            var out_buf_str: [max_digest_length]u8 = undefined;
            const size_str = try stringHash(alg, data, options, out_buf_str[0..]);
            const public_bytes_str = out_buf_str[0..size_str];
            try std.testing.expectEqualSlices(u8, expected_bytes_str, public_bytes_str);
        }
    }
}

test "SHA-256 NIST FIPS 180-4" {
    var out_buf: [max_digest_length]u8 = undefined;

    const abc = "abc";
    const expected_hex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    const abc_size = try stringHash(HashAlgorithm.@"SHA-256", abc, null, out_buf[0..]);
    const abc_hash = out_buf[0..abc_size];
    try std.testing.expectFmt(expected_hex, "{x}", .{abc_hash});

    const empty_str = "";
    const expected_empty_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    const empty_size = try stringHash(HashAlgorithm.@"SHA-256", empty_str, null, out_buf[0..]);
    const empty_hash = out_buf[0..empty_size];
    try std.testing.expectFmt(expected_empty_hex, "{x}", .{empty_hash});
}

test "Blake3 test vector" {
    var out_buf: [max_digest_length]u8 = undefined;

    const empty_str = "";
    const expected_hex_xof = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a26f5487789e8f660afe6c99ef9e0c52b92e7393024a80459cf91f476f9ffdbda7001c22e159b402631f277ca96f2defdf1078282314e763699a31c5363165421cce14d";
    const expected_hex = expected_hex_xof[0 .. std.crypto.hash.Blake3.digest_length * 2];

    const size = try stringHash(HashAlgorithm.BLAKE3, empty_str, null, out_buf[0..]);
    const hash = out_buf[0..size];
    try std.testing.expectFmt(expected_hex, "{x}", .{hash});
}

test "XXH3-64 test vector" {
    var out_buf: [max_digest_length]u8 = undefined;

    const data = "Hello, world!";
    const expected_hex = "f3c34bf11915e869";

    const size = try stringHash(HashAlgorithm.@"XXH3-64", data, null, out_buf[0..]);
    const hash = out_buf[0..size];
    try std.testing.expectFmt(expected_hex, "{x}", .{hash});
}

test "RFC 4231 HMAC SHA-256 test vector" {
    var out_buf: [max_digest_length]u8 = undefined;

    const key = "Jefe";
    const data = "what do ya want for nothing?";
    const expected_hex = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
    const size = try stringHash(HashAlgorithm.@"HMAC-SHA-256", data, .{ .key = key }, out_buf[0..]);
    const hash = out_buf[0..size];
    try std.testing.expectFmt(expected_hex, "{x}", .{hash});
}

test "random stress test" {
    var prng = std.Random.DefaultPrng.init(0xdeadbeef);
    var random = prng.random();

    var buf: [4096]u8 = undefined;

    for (0..1000) |_| {
        const len = random.intRangeAtMost(usize, 0, buf.len);
        random.bytes(buf[0..len]);

        inline for (AlgorithmSpecs) |spec| {
            const H = spec.H;
            const alg = spec.tag;
            const options_array = getDemoOptionsArray(alg);

            for (options_array) |options| {
                const h1 = try stringHashImpl(H, buf[0..len], options);
                const h2 = try stringHashImpl(H, buf[0..len], options);

                try std.testing.expectEqual(h1, h2);
            }
        }
    }
}

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
