const std = @import("std");

pub const HashOptions = struct {
    // mode: HashMode = .hash,
    seed: ?u64 = null,
    // Blake3 key size 32 ([32]u8),
    // Sha2_32 key size varies depending on variant ([?]u8)
    key: ?[]const u8 = null,
    // key_encoding: ?KeyEncoding = null,
};

pub const Error = error{
    KeyRequired,
    InvalidKeyLength,
    BufferTooSmall,
};

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

const AlgorithmSpec = struct {
    tag: HashAlgorithm,
    H: type,
};

pub const AlgorithmSpecs = [_]AlgorithmSpec{
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

pub fn digestLength(alg: HashAlgorithm) usize {
    inline for (AlgorithmSpecs) |spec| {
        if (alg == spec.tag) {
            return digestLengthBytes(spec.H);
        }
    }
    unreachable;
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

    const digest_length = std.crypto.hash.Sha1.digest_length; // 20;

    pub const Digest = [digest_length]u8;

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

    const digest_length = std.crypto.hash.Md5.digest_length; // 16;

    pub const Digest = [digest_length]u8;

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

    pub const Digest = [8]u8;

    pub fn final(self: *Xxh3_64) Digest {
        var out: Digest = undefined;
        const result = self.inner.final();
        std.mem.writeInt(u64, &out, result, .big);
        return out;
    }
};

const Blake3 = struct {
    const Self = @This();

    pub const name = "BLAKE3";

    const Inner = std.crypto.hash.Blake3;

    inner: Inner,

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

    const digest_length = Inner.digest_length;

    pub const Digest = [digest_length]u8;

    pub fn final(self: *const Self) Digest {
        var out: Digest = undefined;
        self.inner.final(out[0..]);
        return out;
    }
};

test "Blake3 rejects key with invalid length" {
    const options = HashOptions{ .key = "short_key" };
    try std.testing.expectError(Error.InvalidKeyLength, Blake3.init(options));
}
