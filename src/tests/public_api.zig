const std = @import("std");
const api = @import("../root.zig");

const HashAlgorithm = api.HashAlgorithm;
const HashOptions = api.HashOptions;
const Error = api.Error;
const fileHash = api.fileHash;
const stringHash = api.stringHash;
const max_digest_length = api.max_digest_length;

fn expectedDigestLen(alg: HashAlgorithm) usize {
    return switch (alg) {
        .@"SHA-224" => 224 / 8,
        .@"SHA-256" => 256 / 8,
        .@"SHA-384" => 384 / 8,
        .@"SHA-512" => 512 / 8,
        .@"SHA-512/224" => 224 / 8,
        .@"SHA-512/256" => 256 / 8,
        .MD5 => std.crypto.hash.Md5.digest_length,
        .@"SHA-1" => std.crypto.hash.Sha1.digest_length,
        .@"XXH3-64" => 8,
        .BLAKE3 => std.crypto.hash.Blake3.digest_length,
        .@"HMAC-SHA-224" => std.crypto.auth.hmac.sha2.HmacSha224.mac_length,
        .@"HMAC-SHA-256" => std.crypto.auth.hmac.sha2.HmacSha256.mac_length,
        .@"HMAC-SHA-384" => std.crypto.auth.hmac.sha2.HmacSha384.mac_length,
        .@"HMAC-SHA-512" => std.crypto.auth.hmac.sha2.HmacSha512.mac_length,
        .@"HMAC-MD5" => std.crypto.auth.hmac.HmacMd5.mac_length,
        .@"HMAC-SHA-1" => std.crypto.auth.hmac.HmacSha1.mac_length,
    };
}

test "public API stringHash returns expected sizes" {
    const data = "abc";

    const cases = [_]struct {
        alg: HashAlgorithm,
        options: ?HashOptions,
    }{
        .{ .alg = .@"SHA-256", .options = null },
        .{ .alg = .@"XXH3-64", .options = null },
        .{ .alg = .BLAKE3, .options = null },
        .{ .alg = .@"HMAC-SHA-256", .options = .{ .key = "my_secret_key" } },
    };

    for (cases) |c| {
        var out: [max_digest_length]u8 = undefined;
        const size = try stringHash(c.alg, data, c.options, out[0..]);
        try std.testing.expectEqual(expectedDigestLen(c.alg), size);
    }
}

test "public API fileHash matches stringHash bytes" {
    const data = "Hello, world!";

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const file_name = "api_test.bin";

    {
        const file = try tmp.dir.createFile(file_name, .{ .truncate = true });
        defer file.close();
        try file.writeAll(data);
    }

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const real_path = try tmp.dir.realpath(file_name, &path_buf);

    const cases = [_]struct {
        alg: HashAlgorithm,
        options: ?HashOptions,
    }{
        .{ .alg = .@"SHA-256", .options = null },
        .{ .alg = .@"XXH3-64", .options = .{ .seed = 12345 } },
        .{ .alg = .BLAKE3, .options = .{ .key = "0123456789abcdef0123456789abcdef" } },
        .{ .alg = .@"HMAC-SHA-256", .options = .{ .key = "my_secret_key" } },
    };

    for (cases) |c| {
        var file_out: [max_digest_length]u8 = undefined;
        var string_out: [max_digest_length]u8 = undefined;

        const file_size = try fileHash(c.alg, real_path, c.options, file_out[0..]);
        const string_size = try stringHash(c.alg, data, c.options, string_out[0..]);

        try std.testing.expectEqual(file_size, string_size);
        try std.testing.expectEqual(expectedDigestLen(c.alg), file_size);
        try std.testing.expectEqualSlices(u8, file_out[0..file_size], string_out[0..string_size]);
    }
}

test "public API returns BufferTooSmall" {
    var out: [8]u8 = undefined;
    try std.testing.expectError(
        Error.BufferTooSmall,
        stringHash(.@"SHA-512", "abc", null, out[0..]),
    );
}

test "public API returns KeyRequired for HMAC" {
    var out: [max_digest_length]u8 = undefined;
    try std.testing.expectError(
        Error.KeyRequired,
        stringHash(.@"HMAC-SHA-256", "abc", null, out[0..]),
    );
}

test "public API returns InvalidKeyLength for BLAKE3 keyed mode" {
    var out: [max_digest_length]u8 = undefined;
    try std.testing.expectError(
        Error.InvalidKeyLength,
        stringHash(.BLAKE3, "abc", .{ .key = "short" }, out[0..]),
    );
}
