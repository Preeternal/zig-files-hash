const std = @import("std");
const builtin_mode = @import("builtin").mode;
const zig_files_hash = @import("zig_files_hash");

const HashAlgorithm = zig_files_hash.HashAlgorithm;
const max_digest_length = zig_files_hash.max_digest_length;
const fileHash = zig_files_hash.fileHash;
const stringHash = zig_files_hash.stringHash;
const getDemoOptionsArray = zig_files_hash.getDemoOptionsArray;

pub fn main() !void {
    std.debug.print("Running in {s} mode\n", .{@tagName(builtin_mode)});

    if (builtin_mode == .Debug) {
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

    try demoAllAlgorithms(path);

    var out_buf: [max_digest_length]u8 = undefined;
    const size = try fileHash(HashAlgorithm.BLAKE3, path, null, out_buf[0..]);
    std.debug.print("BLAKE3 (public API file input) = {x}\n", .{out_buf[0..size]});

    const size2 = try stringHash(HashAlgorithm.BLAKE3, "Hello, world!", null, out_buf[0..]);
    std.debug.print("BLAKE3 (public API string input) = {x}\n", .{out_buf[0..size2]});
}

pub fn demoAllAlgorithms(path: []const u8) !void {
    inline for (@typeInfo(HashAlgorithm).@"enum".fields) |field| {
        const alg: HashAlgorithm = @enumFromInt(field.value);
        const options_array = getDemoOptionsArray(alg);
        for (options_array, 0..) |options, i| {
            var out_buf: [max_digest_length]u8 = undefined;
            const size = try fileHash(alg, path, options, out_buf[0..]);
            const hash_slice = out_buf[0..size];
            const suffix = if (alg == HashAlgorithm.BLAKE3 and i == 1) "-KEYED" else if (alg == HashAlgorithm.@"XXH3-64" and i == 1) "-SEEDED" else "";
            std.debug.print("{s}{s} = {x}\n", .{ @tagName(alg), suffix, hash_slice });
        }
    }
}
