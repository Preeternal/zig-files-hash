const std = @import("std");

pub const HashOptions = struct {
    seed: ?u64 = null,
    key: ?[]const u8 = null,
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

pub const RuntimeHasher = union(HashAlgorithm) {
    @"SHA-224": Sha224,
    @"SHA-256": Sha256,
    @"SHA-384": Sha384,
    @"SHA-512": Sha512,
    @"SHA-512/224": Sha512_224,
    @"SHA-512/256": Sha512_256,
    MD5: MD5,
    @"SHA-1": Sha1,
    @"XXH3-64": Xxh3_64,
    BLAKE3: Blake3,
    @"HMAC-SHA-224": HmacSha224,
    @"HMAC-SHA-256": HmacSha256,
    @"HMAC-SHA-384": HmacSha384,
    @"HMAC-SHA-512": HmacSha512,
    @"HMAC-MD5": HmacMd5,
    @"HMAC-SHA-1": HmacSha1,

    pub fn init(alg: HashAlgorithm, options: ?HashOptions) !RuntimeHasher {
        const fields = @typeInfo(RuntimeHasher).@"union".fields;

        inline for (fields) |field| {
            const tag = @field(HashAlgorithm, field.name);

            if (alg == tag) {
                const H = field.type;
                const hasher = try H.init(options);
                return @unionInit(RuntimeHasher, field.name, hasher);
            }
        }

        unreachable;
    }

    pub fn update(self: *RuntimeHasher, chunk: []const u8) void {
        switch (self.*) {
            inline else => |*h| h.update(chunk),
        }
    }

    pub fn digestLength(self: *const RuntimeHasher) usize {
        return switch (self.*) {
            inline else => |*h| digestLengthBytes(@TypeOf(h.*)),
        };
    }

    pub fn final(self: *RuntimeHasher, out: []u8) !usize {
        switch (self.*) {
            inline else => |*h| {
                const result = h.final();
                if (out.len < result.len) return Error.BufferTooSmall;
                @memcpy(out[0..result.len], result[0..]);
                return result.len;
            },
        }
    }

    pub const Digest = struct {
        len: u8,
        bytes: [max_digest_length]u8,

        pub fn slice(self: *const Digest) []const u8 {
            return self.bytes[0..self.len];
        }
    };

    pub fn finalResult(self: *RuntimeHasher) Digest {
        switch (self.*) {
            inline else => |*h| {
                const result = h.final();
                var digest: Digest = .{ .len = @intCast(result.len), .bytes = undefined };
                @memcpy(digest.bytes[0..result.len], result[0..]);
                return digest;
            },
        }
    }
};

const hash_algorithm_enum_fields = @typeInfo(HashAlgorithm).@"enum".fields;
pub const runtime_hasher_union_fields = @typeInfo(RuntimeHasher).@"union".fields;

comptime {
    if (hash_algorithm_enum_fields.len != runtime_hasher_union_fields.len) {
        @compileError("RuntimeHasher variants must match HashAlgorithm enum size");
    }
}

comptime {
    var seen: [hash_algorithm_enum_fields.len]bool = .{false} ** hash_algorithm_enum_fields.len;

    for (runtime_hasher_union_fields) |field| {
        const tag = @field(HashAlgorithm, field.name);
        const idx = @intFromEnum(tag);

        if (seen[idx]) {
            @compileError("Duplicate tag in RuntimeHasher: " ++ field.name);
        }

        seen[idx] = true;
    }

    for (seen, 0..) |ok, i| {
        if (!ok) {
            @compileError("Missing RuntimeHasher variant for HashAlgorithm: " ++ hash_algorithm_enum_fields[i].name);
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
    var max: usize = 0;

    for (runtime_hasher_union_fields) |field| {
        const H = field.type;
        const len = digestLengthBytes(H);
        if (len > max) {
            max = len;
        }
    }

    break :blk max;
};

comptime {
    if (max_digest_length > std.math.maxInt(u8)) {
        @compileError("RuntimeHasher.Digest.len is u8; max_digest_length must fit into u8");
    }
}

pub fn digestLength(alg: HashAlgorithm) usize {
    inline for (runtime_hasher_union_fields) |field| {
        const H = field.type;
        const tag = @field(HashAlgorithm, field.name);
        if (alg == tag) {
            return digestLengthBytes(H);
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
    inline for (runtime_hasher_union_fields) |field| {
        const H = field.type;
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

test "RuntimeHasher.digestLength matches digest size for each algorithm" {
    inline for (runtime_hasher_union_fields) |field| {
        const H = field.type;
        const alg = @field(HashAlgorithm, field.name);
        const expected_len = digestLengthBytes(H);

        const options: ?HashOptions = switch (H) {
            HmacSha224, HmacSha256, HmacSha384, HmacSha512, HmacMd5, HmacSha1 => .{
                .key = "my_secret_key",
            },
            else => null,
        };

        var hasher = try RuntimeHasher.init(alg, options);
        try std.testing.expectEqual(expected_len, hasher.digestLength());
    }
}
