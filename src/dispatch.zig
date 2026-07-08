const std = @import("std");
const algorithms = @import("algorithms.zig");
const builtin = @import("builtin");

const native_os = builtin.os.tag;

const HashAlgorithm = algorithms.HashAlgorithm;
const RuntimeHasher = algorithms.RuntimeHasher;

const runtime_hasher_union_fields = algorithms.runtime_hasher_union_fields;

const HashOptions = algorithms.HashOptions;
const Error = algorithms.Error;
const max_digest_length = algorithms.max_digest_length;

pub const Operation = struct {
    canceled: std.atomic.Value(bool),

    const order = std.builtin.AtomicOrder.monotonic;

    pub fn init() Operation {
        return .{ .canceled = .init(false) };
    }
    pub fn cancel(self: *Operation) void {
        self.canceled.store(true, order);
    }
    pub fn isCanceled(self: *const Operation) bool {
        return self.canceled.load(order);
    }
    pub fn checkCanceled(self: *const Operation) !void {
        if (self.isCanceled()) {
            return Error.OperationCanceled;
        }
    }
};

pub fn checkOperationCanceled(operation: ?*const Operation) !void {
    if (operation) |o| {
        try o.checkCanceled();
    }
}

pub const HashRequest = struct { hash_options: ?HashOptions = null, operation: ?*const Operation = null };

pub const HashStream = struct {
    hasher: RuntimeHasher,
    operation: ?*const Operation,
    finalized: bool,

    pub fn init(alg: HashAlgorithm, request: ?HashRequest) !HashStream {
        const r = request orelse HashRequest{};
        try checkOperationCanceled(r.operation);
        const hasher = try RuntimeHasher.init(alg, r.hash_options);
        return .{ .hasher = hasher, .operation = r.operation, .finalized = false };
    }
    pub fn update(self: *HashStream, chunk: []const u8) !void {
        if (self.finalized) return Error.InvalidState;
        try checkOperationCanceled(self.operation);
        self.hasher.update(chunk);
    }
    pub fn digestLength(self: *const HashStream) usize {
        return self.hasher.digestLength();
    }
    pub fn final(self: *HashStream, out: []u8) !usize {
        if (self.finalized) return Error.InvalidState;
        try checkOperationCanceled(self.operation);
        if (out.len < self.digestLength()) return Error.OutputBufferTooSmall;
        self.finalized = true;
        return self.hasher.final(out);
    }
    pub fn finalResult(self: *HashStream) !RuntimeHasher.Digest {
        if (self.finalized) return Error.InvalidState;
        try checkOperationCanceled(self.operation);
        self.finalized = true;
        return self.hasher.finalResult();
    }
};

pub const Context = struct {
    io: std.Io,
    pub fn init(io: std.Io) Context {
        return .{ .io = io };
    }

    fn mmapHash(io: std.Io, file: std.Io.File, stream: *HashStream) !bool {
        const stat = file.stat(io) catch return false;
        if (stat.kind == .file and stat.size > 0 and native_os != .windows) {
            const fd = file.handle;
            const data = std.posix.mmap(null, //
                stat.size, //
                .{ .READ = true }, //
                .{ .TYPE = .PRIVATE }, //
                fd, 0) //
                catch return false;
            defer std.posix.munmap(data);
            try stream.update(data);
            return true;
        } else {
            return false;
        }
    }

    pub fn fileHashInDir(self: *const Context, alg: HashAlgorithm, dir: std.Io.Dir, sub_path: []const u8, out: []u8, request: ?HashRequest) !usize {
        const io = self.io;
        var file = try dir.openFile(io, sub_path, .{});
        defer file.close(io);

        var stream = try HashStream.init(alg, request);

        const mapped = try mmapHash(io, file, &stream);

        if (!mapped) {
            var buf: [64 * 1024]u8 = undefined;
            var file_reader = file.reader(io, &.{});
            while (true) {
                const n = try file_reader.interface.readSliceShort(buf[0..]);
                if (n == 0) break;

                const chunk = buf[0..n];
                try stream.update(chunk);
            }
        }

        return stream.final(out);
    }

    pub fn fileHash(self: *const Context, alg: HashAlgorithm, path: []const u8, out: []u8, request: ?HashRequest) !usize {
        return self.fileHashInDir(alg, std.Io.Dir.cwd(), path, out, request);
    }
};

pub fn fileHashInDir(io: std.Io, alg: HashAlgorithm, dir: std.Io.Dir, sub_path: []const u8, out: []u8, request: ?HashRequest) !usize {
    return Context.init(io).fileHashInDir(alg, dir, sub_path, out, request);
}

pub fn fileHash(io: std.Io, alg: HashAlgorithm, path: []const u8, out: []u8, request: ?HashRequest) !usize {
    return fileHashInDir(io, alg, std.Io.Dir.cwd(), path, out, request);
}

pub fn fdHash(
    alg: HashAlgorithm,
    fd: std.posix.fd_t,
    out: []u8,
    request: ?HashRequest,
) !usize {
    const read = std.posix.read;
    var stream = try HashStream.init(alg, request);
    var buf: [64 * 1024]u8 = undefined;
    while (true) {
        const n = try read(fd, buf[0..]);
        if (n == 0) break;
        const chunk = buf[0..n];
        try stream.update(chunk);
    }

    return stream.final(out);
}

pub fn stringHash(alg: HashAlgorithm, data: []const u8, out: []u8, request: ?HashRequest) !usize {
    var stream = try HashStream.init(alg, request);
    try stream.update(data);
    return stream.final(out);
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
        const size1 = try stringHash(alg, data, out_buf1[0..], .{ .hash_options = options });
        const hash1 = out_buf1[0..size1];

        var out_buf2: [max_digest_length]u8 = undefined;
        const size2 = try stringHash(alg, data, out_buf2[0..], .{ .hash_options = options });
        const hash2 = out_buf2[0..size2];

        try std.testing.expectEqualSlices(u8, hash1, hash2);
    }
}

test "deterministic string hash" {
    inline for (runtime_hasher_union_fields) |field| {
        const alg = @field(HashAlgorithm, field.name);
        try expectDeterministicStringHash(alg);
    }
}

fn expectFileHashDeterminismAndConsistency(alg: HashAlgorithm) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const file_name = "test.bin";
    const data = "Hello, world!";
    const io = std.testing.io;

    {
        const file = try tmp.dir.createFile(io, file_name, .{
            .truncate = true,
        });
        defer file.close(io);
        try file.writeStreamingAll(io, data);
    }

    const options_array = getDemoOptionsArray(alg);
    for (options_array) |options| {
        var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const real_path_size = try tmp.dir.realPathFile(io, file_name, &path_buf);
        const real_path = path_buf[0..real_path_size];

        var out_buf1: [max_digest_length]u8 = undefined;
        const size_file1 = try fileHash(io, alg, real_path, out_buf1[0..], .{
            .hash_options = options,
        });
        const hash1 = out_buf1[0..size_file1];

        var out_buf2: [max_digest_length]u8 = undefined;
        const size_file2 = try fileHash(io, alg, real_path, out_buf2[0..], .{
            .hash_options = options,
        });
        const hash2 = out_buf2[0..size_file2];

        try std.testing.expectEqualSlices(u8, hash1, hash2);

        var out_buf3: [max_digest_length]u8 = undefined;
        const size_string = try stringHash(alg, data, out_buf3[0..], .{ .hash_options = options });
        const hash3 = out_buf3[0..size_string];

        try std.testing.expectEqualSlices(u8, hash1, hash3);
    }
}

test "file hash determinism and consistency with string hash" {
    inline for (runtime_hasher_union_fields) |field| {
        const alg = @field(HashAlgorithm, field.name);
        try expectFileHashDeterminismAndConsistency(alg);
    }
}

test "different input produces different hash" {
    const data1 = "Hello, world!";
    const data2 = "Hello, world?";
    inline for (runtime_hasher_union_fields) |field| {
        const alg = @field(HashAlgorithm, field.name);
        const options_array = getDemoOptionsArray(alg);
        for (options_array) |options| {
            var out_buf1: [max_digest_length]u8 = undefined;
            const size1 = try stringHash(alg, data1, out_buf1[0..], .{ .hash_options = options });
            const hash1 = out_buf1[0..size1];

            var out_buf2: [max_digest_length]u8 = undefined;
            const size2 = try stringHash(alg, data2, out_buf2[0..], .{ .hash_options = options });
            const hash2 = out_buf2[0..size2];

            try std.testing.expect(!std.mem.eql(u8, hash1, hash2));
        }
    }
}

test "different options produce different hash" {
    const data = "Hello, world!";
    inline for (runtime_hasher_union_fields) |field| {
        const alg = @field(HashAlgorithm, field.name);
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
                const size1 = try stringHash(alg, data, out_buf1[0..], .{ .hash_options = options1 });
                const hash1 = out_buf1[0..size1];

                var out_buf2: [max_digest_length]u8 = undefined;
                const size2 = try stringHash(alg, data, out_buf2[0..], .{ .hash_options = options2 });
                const hash2 = out_buf2[0..size2];

                try std.testing.expect(!std.mem.eql(u8, hash1[0..], hash2[0..]));
                continue;
            },
            HashAlgorithm.@"XXH3-64" => {
                // test with vs without seed
                const options1 = HashOptions{ .seed = 12345 };
                const options2 = null;

                var out_buf1: [max_digest_length]u8 = undefined;

                const size1 = try stringHash(alg, data, out_buf1[0..], .{ .hash_options = options1 });
                const hash1 = out_buf1[0..size1];

                var out_buf2: [max_digest_length]u8 = undefined;
                const size2 = try stringHash(alg, data, out_buf2[0..], .{ .hash_options = options2 });
                const hash2 = out_buf2[0..size2];

                try std.testing.expect(!std.mem.eql(u8, hash1[0..], hash2[0..]));
                continue;
            },
            else => {
                // for HMAC algorithms test different keys
                const options1 = HashOptions{ .key = "some_key" };
                const options2 = HashOptions{ .key = "another_key" };

                var out_buf1: [max_digest_length]u8 = undefined;

                const size1 = try stringHash(alg, data, out_buf1[0..], .{ .hash_options = options1 });
                const hash1 = out_buf1[0..size1];

                var out_buf2: [max_digest_length]u8 = undefined;
                const size2 = try stringHash(alg, data, out_buf2[0..], .{ .hash_options = options2 });
                const hash2 = out_buf2[0..size2];

                try std.testing.expect(!std.mem.eql(u8, hash1[0..], hash2[0..]));
                continue;
            },
        }
    }
}

test "empty input produces deterministic hash" {
    const empty: []const u8 = "";
    inline for (runtime_hasher_union_fields) |field| {
        const alg = @field(HashAlgorithm, field.name);
        const options_array = getDemoOptionsArray(alg);
        for (options_array) |options| {
            var out_buf1: [max_digest_length]u8 = undefined;

            const size1 = try stringHash(alg, empty, out_buf1[0..], .{ .hash_options = options });
            const hash1 = out_buf1[0..size1];

            var out_buf2: [max_digest_length]u8 = undefined;
            const size2 = try stringHash(alg, empty, out_buf2[0..], .{ .hash_options = options });
            const hash2 = out_buf2[0..size2];

            // Only check determinism for empty input (no known-good hash comparison).
            try std.testing.expectEqualSlices(u8, hash1, hash2);
        }
    }
}

test "multi-chunk file (>64KB) hash matches string hash" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const sub_path = "test.bin";
    var data: [70 * 1024]u8 = undefined;
    for (&data, 0..) |*b, i| {
        b.* = @as(u8, @intCast(i % 256));
    }

    {
        const file = try tmp.dir.createFile(io, sub_path, .{
            .truncate = true,
        });
        defer file.close(io);
        try file.writeStreamingAll(io, data[0..]);
    }
    inline for (runtime_hasher_union_fields) |field| {
        const alg = @field(HashAlgorithm, field.name);
        const options_array = getDemoOptionsArray(alg);
        for (options_array) |options| {
            var out_buf_file: [max_digest_length]u8 = undefined;
            const out_len_file = try fileHashInDir(io, alg, tmp.dir, sub_path, out_buf_file[0..], .{
                .hash_options = options,
            });
            const hash1 = out_buf_file[0..out_len_file];
            var out_buf_str: [max_digest_length]u8 = undefined;
            const out_len_str = try stringHash(alg, data[0..], out_buf_str[0..], .{ .hash_options = options });
            const hash2 = out_buf_str[0..out_len_str];
            try std.testing.expectEqualSlices(u8, hash1, hash2);
        }
    }
}

test "Public API produces same hash as direct API" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const data = "Hello, world!";
    const file_name = "test.bin";

    {
        const file = try tmp.dir.createFile(io, file_name, .{
            .truncate = true,
        });
        defer file.close(io);
        try file.writeStreamingAll(io, data);
    }

    inline for (runtime_hasher_union_fields) |field| {
        const alg = @field(HashAlgorithm, field.name);
        const options_array = getDemoOptionsArray(alg);
        for (options_array) |options| {
            var out_buf_dir_file: [max_digest_length]u8 = undefined;
            const size_dir_file = try fileHashInDir(io, alg, tmp.dir, file_name, out_buf_dir_file[0..], .{
                .hash_options = options,
            });
            const dir_bytes = out_buf_dir_file[0..size_dir_file];

            var out_buf_file: [max_digest_length]u8 = undefined;
            var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
            const real_path_size = try tmp.dir.realPathFile(io, file_name, &path_buf);
            const real_path = path_buf[0..real_path_size];
            const size_file = try fileHash(io, alg, real_path, out_buf_file[0..], .{
                .hash_options = options,
            });
            const public_bytes_file = out_buf_file[0..size_file];

            try std.testing.expectEqualSlices(u8, dir_bytes, public_bytes_file);

            var file = try tmp.dir.openFile(io, file_name, .{});
            defer file.close(io);

            var stream = try HashStream.init(alg, .{ .hash_options = options });
            var buf: [64 * 1024]u8 = undefined;
            var file_reader = file.reader(io, &.{});
            while (true) {
                const n = try file_reader.interface.readSliceShort(buf[0..]);
                if (n == 0) break;

                const chunk = buf[0..n];
                try stream.update(chunk);
            }

            const digest = try stream.finalResult();
            const bytes = digest.slice();
            try std.testing.expectEqualSlices(u8, dir_bytes, bytes);
        }
    }
}

test "SHA-256 NIST FIPS 180-4" {
    var out_buf: [max_digest_length]u8 = undefined;

    const abc = "abc";
    const expected_hex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    const abc_size = try stringHash(HashAlgorithm.@"SHA-256", abc, out_buf[0..], null);
    const abc_hash = out_buf[0..abc_size];
    try std.testing.expectFmt(expected_hex, "{x}", .{abc_hash});

    const empty_str = "";
    const expected_empty_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    const empty_size = try stringHash(HashAlgorithm.@"SHA-256", empty_str, out_buf[0..], null);
    const empty_hash = out_buf[0..empty_size];
    try std.testing.expectFmt(expected_empty_hex, "{x}", .{empty_hash});
}

test "Blake3 test vector" {
    var out_buf: [max_digest_length]u8 = undefined;

    const empty_str = "";
    const expected_hex_xof = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a26f5487789e8f660afe6c99ef9e0c52b92e7393024a80459cf91f476f9ffdbda7001c22e159b402631f277ca96f2defdf1078282314e763699a31c5363165421cce14d";
    const expected_hex = expected_hex_xof[0 .. std.crypto.hash.Blake3.digest_length * 2];

    const size = try stringHash(HashAlgorithm.BLAKE3, empty_str, out_buf[0..], null);
    const hash = out_buf[0..size];
    try std.testing.expectFmt(expected_hex, "{x}", .{hash});
}

test "XXH3-64 test vector" {
    var out_buf: [max_digest_length]u8 = undefined;

    const data = "Hello, world!";
    const expected_hex = "f3c34bf11915e869";

    const size = try stringHash(HashAlgorithm.@"XXH3-64", data, out_buf[0..], null);
    const hash = out_buf[0..size];
    try std.testing.expectFmt(expected_hex, "{x}", .{hash});
}

test "RFC 4231 HMAC SHA-256 test vector" {
    var out_buf: [max_digest_length]u8 = undefined;

    const key = "Jefe";
    const data = "what do ya want for nothing?";
    const expected_hex = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
    const size = try stringHash(HashAlgorithm.@"HMAC-SHA-256", data, out_buf[0..], .{ .hash_options = .{ .key = key } });
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

        inline for (runtime_hasher_union_fields) |field| {
            const alg = @field(HashAlgorithm, field.name);
            const options_array = getDemoOptionsArray(alg);

            for (options_array) |options| {
                var out_buf1: [max_digest_length]u8 = undefined;
                const size1 = try stringHash(alg, buf[0..len], out_buf1[0..], .{ .hash_options = options });
                const h1 = out_buf1[0..size1];

                var out_buf2: [max_digest_length]u8 = undefined;
                const size2 = try stringHash(alg, buf[0..len], out_buf2[0..], .{ .hash_options = options });
                const h2 = out_buf2[0..size2];

                try std.testing.expectEqualSlices(u8, h1, h2);
            }
        }
    }
}

test "HashStream rejects update and final after final" {
    var out_buf: [max_digest_length]u8 = undefined;
    var stream = try HashStream.init(HashAlgorithm.@"SHA-256", null);

    try stream.update("abc");
    const size = try stream.final(out_buf[0..]);
    try std.testing.expectEqual(@as(usize, 32), size);

    try std.testing.expectError(Error.InvalidState, stream.update("def"));
    try std.testing.expectError(Error.InvalidState, stream.final(out_buf[0..]));
    try std.testing.expectError(Error.InvalidState, stream.finalResult());
}

test "HashStream can retry final after OutputBufferTooSmall" {
    var small_out: [8]u8 = undefined;
    var out_buf: [max_digest_length]u8 = undefined;
    var stream = try HashStream.init(HashAlgorithm.@"SHA-256", null);

    try stream.update("abc");
    try std.testing.expectError(Error.OutputBufferTooSmall, stream.final(small_out[0..]));

    const size = try stream.final(out_buf[0..]);
    try std.testing.expectEqual(@as(usize, 32), size);
    try std.testing.expectFmt("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "{x}", .{out_buf[0..size]});
}

test "fileHash returns OperationCanceled when operation is already canceled" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const data = "Hello, world!";
    const file_name = "test.bin";

    {
        const file = try tmp.dir.createFile(io, file_name, .{
            .truncate = true,
        });
        defer file.close(io);
        try file.writeStreamingAll(io, data);
    }

    const context = Context.init(io);
    var operation = Operation.init();

    var out_buf: [max_digest_length]u8 = undefined;
    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const real_path_size = try tmp.dir.realPathFile(io, file_name, &path_buf);
    const real_path = path_buf[0..real_path_size];
    operation.cancel();
    const size_file = context.fileHash(HashAlgorithm.@"SHA-256", real_path, out_buf[0..], .{
        .operation = &operation,
    });
    try std.testing.expectError(Error.OperationCanceled, size_file);
}

test "BLAKE3 fdHash matches fileHash" {
    if (native_os == .windows) {
        // POSIX fd API is not supported on Windows
        return;
    }

    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const data = "Hello, world!";
    const file_name = "test.bin";

    {
        const file = try tmp.dir.createFile(io, file_name, .{
            .truncate = true,
        });
        defer file.close(io);
        try file.writeStreamingAll(io, data);
    }

    var file = try tmp.dir.openFile(io, file_name, .{});
    defer file.close(io);

    var stream = try HashStream.init(HashAlgorithm.BLAKE3, null);
    var buf: [64 * 1024]u8 = undefined;
    var reader = file.reader(io, &.{});
    while (true) {
        const n = try reader.interface.readSliceShort(buf[0..]);
        if (n == 0) break;

        const chunk = buf[0..n];
        try stream.update(chunk);
    }

    const digest = try stream.finalResult();
    const bytes = digest.slice();

    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const real_path_size = try tmp.dir.realPathFile(io, file_name, &path_buf);
    const real_path = path_buf[0..real_path_size];

    const openat = std.posix.openat;
    const dir_fd = std.posix.AT.FDCWD;
    const flags = std.posix.O{ .ACCMODE = .RDONLY };
    const fd = try openat(dir_fd, real_path, flags, 0);
    defer _ = std.posix.system.close(fd);

    var out_buf_fd: [max_digest_length]u8 = undefined;

    const fd_size = try fdHash(HashAlgorithm.BLAKE3, fd, out_buf_fd[0..], null);
    const fd_bytes = out_buf_fd[0..fd_size];

    try std.testing.expectEqualSlices(u8, bytes, fd_bytes);
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
