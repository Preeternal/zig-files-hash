const std = @import("std");
const builtin_mode = @import("builtin").mode;
const zig_files_hash = @import("zig_files_hash");

const HashAlgorithm = zig_files_hash.HashAlgorithm;
const max_digest_length = zig_files_hash.max_digest_length;
const fileHash = zig_files_hash.fileHash;
const stringHash = zig_files_hash.stringHash;
const fdHash = zig_files_hash.fdHash;
const Context = zig_files_hash.Context;
const Operation = zig_files_hash.Operation;
const getDemoOptionsArray = zig_files_hash.getDemoOptionsArray;

pub fn main(init: std.process.Init) !void {
    std.debug.print("Running in {s} mode\n", .{@tagName(builtin_mode)});

    if (builtin_mode == .Debug) {
        var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
        defer _ = debug_allocator.deinit();

        try run(debug_allocator.allocator(), init);
    } else {
        try run(std.heap.page_allocator, init);
    }
}

fn run(al: std.mem.Allocator, init: std.process.Init) !void {
    var args_iterator = try init.minimal.args.iterateAllocator(al);
    defer args_iterator.deinit();

    _ = args_iterator.next(); // skip argv[0]
    const path = args_iterator.next() orelse {
        std.debug.print("Usage: zig build run -- <arg>\n", .{});
        return;
    };

    std.debug.print("First argument: {s}\n", .{path});
    const io = init.io;

    try demoAllAlgorithms(io, path);

    var out_buf: [max_digest_length]u8 = undefined;

    const size = try fileHash(io, HashAlgorithm.BLAKE3, path, out_buf[0..], null);
    std.debug.print("BLAKE3 (public API file input) = {x}\n", .{out_buf[0..size]});

    const openat = std.posix.openat;
    const dir_fd = std.posix.AT.FDCWD;
    const flags = std.posix.O{ .ACCMODE = .RDONLY };
    const fd = try openat(dir_fd, path, flags, 0);
    defer _ = std.c.close(fd);

    var out_buf_fd: [max_digest_length]u8 = undefined;

    const fd_size = try fdHash(HashAlgorithm.BLAKE3, fd, out_buf_fd[0..], null);
    std.debug.print("BLAKE3 (public API FD input) = {x}\n", .{out_buf_fd[0..fd_size]});

    const size2 = try stringHash(HashAlgorithm.BLAKE3, "Hello, world!", out_buf[0..], null);
    std.debug.print("BLAKE3 (public API string input) = {x}\n", .{out_buf[0..size2]});
}

pub fn demoAllAlgorithms(io: std.Io, path: []const u8) !void {
    inline for (@typeInfo(HashAlgorithm).@"enum".fields) |field| {
        const alg: HashAlgorithm = @enumFromInt(field.value);
        const options_array = getDemoOptionsArray(alg);
        const context = Context.init(io);
        for (options_array, 0..) |options, i| {
            var out_buf: [max_digest_length]u8 = undefined;
            var operation = Operation.init();
            const size = try context.fileHash(alg, path, out_buf[0..], .{ .hash_options = options, .operation = &operation });
            const hash_slice = out_buf[0..size];
            const suffix = if (alg == HashAlgorithm.BLAKE3 and i == 1) "-KEYED" else if (alg == HashAlgorithm.@"XXH3-64" and i == 1) "-SEEDED" else "";
            std.debug.print("{s}{s} = {x}\n", .{ @tagName(alg), suffix, hash_slice });
        }
    }
}
