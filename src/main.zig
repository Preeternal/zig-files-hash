const std = @import("std");
// const zig_files_hash = @import("zig_files_hash");

pub fn main() !void {
    // Prints to stderr, ignoring potential errors.
    // std.debug.print("All your {s} are belong to us.\n", .{"codebase"});
    // try zig_files_hash.bufferedPrint();
    // const stdout = std.fs.File.stdout();
    // try stdout.writeAll("Ok\n");

    const al = std.heap.page_allocator;
    var args_iterator = try std.process.argsWithAllocator(al);
    defer args_iterator.deinit();
    _ = args_iterator.next(); // skip 0 arg (program name)
    const path = args_iterator.next() orelse {
        std.debug.print("Usage: zig build run -- <arg>\n", .{});
        return;
    };
    std.debug.print("First argument: {s}\n", .{path});
    const h = try fileHash(Xxh3_64, path, null);
    std.debug.print("Xxh3_64 = {x}\n", .{h});

    const h2 = try fileHash(Blake3, path, null);
    const hex = std.fmt.bytesToHex(h2, .lower); // или .upper
    std.debug.print("Blake3 = {s}\n", .{hex[0..]});

    const sha224 = try fileHash(Sha224, path, null);
    const sha224_hex = std.fmt.bytesToHex(sha224, .lower);
    std.debug.print("SHA-224 = {s}\n", .{sha224_hex[0..]});

    const sha256 = try fileHash(Sha256, path, null);
    const sha256_hex = std.fmt.bytesToHex(sha256, .lower);
    std.debug.print("SHA-256 = {s}\n", .{sha256_hex[0..]});

    var arr = [_]u8{ 10, 20, 30, 40, 50 };

    const slice1 = arr[1..4];
    const slice2 = arr[0..];
    slice1[0] = 99;

    var a: u8 = 0;
    a += 1;

    const slice3 = arr[a..4];

    std.debug.print("arr    = {any}\n", .{arr});
    std.debug.print("slice1 = {any}\n", .{slice1});
    std.debug.print("slice2 = {any}\n", .{slice2});
    std.debug.print("slice3 = {any}\n", .{slice3});

    const s = "abc";
    std.debug.print("xxh3('abc') = {x}\n", .{xxh3_64_bytes(s)});

    var dh = DumbHasher.init();

    dh.update("ab");
    dh.update("c");

    const result = dh.final();
    std.debug.print("sum = {}\n", .{result});
}

fn xxh3_64_file(path: []const u8) !u64 {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    std.debug.print("File {any}\n", .{file});
    var buf: [64 * 1024]u8 = undefined;
    var hasher = Xxh3_64.init(null);
    while (true) {
        std.debug.print("prev buf len {any}\n", .{buf.len});
        const n = try file.read(buf[0..]);
        if (n == 0) {
            return hasher.final();
        }

        const chunk = buf[0..n];
        hasher.update(chunk);
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

const HashMode = enum { hash, hmac, keyed };

const HashOptions = struct {
    mode: HashMode = .hash,
    seed: ?u64 = null,
    key: ?[32]u8 = null,
    // key_encoding: ?KeyEncoding = null,
};

fn fileHash(comptime H: type, path: []const u8, options: ?HashOptions) !H.Digest {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    var buf: [64 * 1024]u8 = undefined;
    const opt = options;
    var hasher = H.init(opt);

    std.debug.print("Digest type = {any}\n", .{H.Digest});

    std.debug.print("Digest size = {d}\n", .{@sizeOf(H.Digest)});

    while (true) {
        std.debug.print("prev buf len {any}\n", .{buf.len});
        const n = try file.read(buf[0..]);
        if (n == 0) {
            return hasher.final();
        }

        const chunk = buf[0..n];
        hasher.update(chunk);
    }
}

fn Sha2_32(comptime Bits: u16) type {
    return struct {
        const Self = @This();

        const Inner = if (Bits == 256) std.crypto.hash.sha2.Sha256 else std.crypto.hash.sha2.Sha224;

        inner: Inner,

        pub fn init(options: ?HashOptions) Self {
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

const Xxh3_64 = struct {
    inner: std.hash.XxHash3,

    pub fn init(options: ?HashOptions) Xxh3_64 {
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
    inner: std.crypto.hash.Blake3,

    pub fn init(options: ?HashOptions) Blake3 {
        var opt: std.crypto.hash.Blake3.Options = .{};
        opt.key = if (options) |o| o.key else null;
        return .{ .inner = std.crypto.hash.Blake3.init(opt) };
    }

    pub fn update(self: *Blake3, data: []const u8) void {
        self.inner.update(data);
    }

    pub const Digest = [32]u8;

    pub fn final(self: *const Blake3) Digest {
        var out: [32]u8 = undefined;
        self.inner.final(out[0..]);
        return out;
    }
};

fn xxh3_64_bytes(data: []const u8) u64 {
    var h = Xxh3_64.init(null);
    h.update(data);
    return h.final();
}

const DumbHasher = struct {
    sum: u64,

    pub fn init() DumbHasher {
        return .{ .sum = 0 };
    }

    pub fn update(self: *DumbHasher, data: []const u8) void {
        for (data) |b| {
            self.sum += b;
        }
    }

    pub fn final(self: *const DumbHasher) u64 {
        return self.sum;
    }
};

test "simple test" {
    const gpa = std.testing.allocator;
    var list: std.ArrayList(i32) = .empty;
    defer list.deinit(gpa); // Try commenting this out and see if zig detects the memory leak!
    try list.append(gpa, 42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}

test "fuzz example" {
    const Context = struct {
        fn testOne(context: @This(), input: []const u8) anyerror!void {
            _ = context;
            // Try passing `--fuzz` to `zig build test` and see if it manages to fail this test case!
            try std.testing.expect(!std.mem.eql(u8, "canyoufindme", input));
        }
    };
    try std.testing.fuzz(Context{}, Context.testOne, .{});
}
