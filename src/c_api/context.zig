const std = @import("std");
const builtin = @import("builtin");
const zfh = @import("../root.zig");
const common = @import("common.zig");
const request = @import("request.zig");
const types = @import("types.zig");

const HashAlgorithm = zfh.HashAlgorithm;
const HashRequest = zfh.HashRequest;
const zfh_algorithm = types.zfh_algorithm;
const zfh_error = types.zfh_error;
const zfh_options = types.zfh_options;
const zfh_request = types.zfh_request;

pub const zfh_context = opaque {};

const CContext = struct {
    const Self = @This();
    threaded: std.Io.Threaded,

    pub fn init(al: std.mem.Allocator) Self {
        return .{ .threaded = .init(al, .{}) };
    }

    pub fn fileHash(self: *CContext, alg: HashAlgorithm, path: []const u8, out: []u8, parsed_request: ?HashRequest) !usize {
        return zfh.fileHash(self.threaded.io(), alg, path, out, parsed_request);
    }
};

pub fn create(ctx_ptr_ptr: ?*?*zfh_context) zfh_error {
    const out_ctx = ctx_ptr_ptr orelse return .invalid_argument;
    out_ctx.* = null;
    const al = std.heap.smp_allocator;
    const context = al.create(CContext) catch return .io_error;
    context.* = CContext.init(al);
    out_ctx.* = @ptrCast(context);
    return .ok;
}

pub fn destroy(ctx_ptr: ?*zfh_context) zfh_error {
    const ctx = ctx_ptr orelse return .invalid_argument;
    const context: *CContext = @ptrCast(@alignCast(ctx));
    context.threaded.deinit();
    const al = std.heap.smp_allocator;
    al.destroy(context);
    return .ok;
}

pub fn fileHash(
    ctx_ptr: ?*zfh_context,
    alg: zfh_algorithm,
    path_ptr: ?[*]const u8,
    path_len: usize,
    request_ptr: ?*const zfh_request,
    out_ptr: ?[*]u8,
    out_len: usize,
    written_len_ptr: ?*usize,
) zfh_error {
    const ctx = ctx_ptr orelse return .invalid_argument;
    const context: *CContext = @ptrCast(@alignCast(ctx));
    const written_len = written_len_ptr orelse return .invalid_argument;
    written_len.* = 0;

    const z_alg = common.toHashAlgorithm(alg) orelse return .invalid_algorithm;
    if (path_len == 0) return .invalid_path;
    const path = blk: {
        const ptr = path_ptr orelse return .invalid_argument;
        break :blk ptr[0..path_len];
    };
    const out = blk: {
        const ptr = out_ptr orelse return .invalid_argument;
        break :blk ptr[0..out_len];
    };

    const parsed_request = request.parseRequest(request_ptr) catch return .invalid_argument;

    const written = context.fileHash(z_alg, path, out, parsed_request) catch |err| return common.mapError(err);
    written_len.* = written;
    return .ok;
}

pub fn fdHash(
    alg: zfh_algorithm,
    fd: c_int,
    request_ptr: ?*const zfh_request,
    out_ptr: ?[*]u8,
    out_len: usize,
    written_len_ptr: ?*usize,
) zfh_error {
    const written_len = written_len_ptr orelse return .invalid_argument;
    written_len.* = 0;

    if (builtin.os.tag == .windows or fd < 0) return .invalid_argument;

    const z_alg = common.toHashAlgorithm(alg) orelse return .invalid_algorithm;
    const out = blk: {
        const ptr = out_ptr orelse return .invalid_argument;
        break :blk ptr[0..out_len];
    };

    const parsed_request = request.parseRequest(request_ptr) catch return .invalid_argument;
    const written = zfh.fdHash(z_alg, @intCast(fd), out, parsed_request) catch |err| return common.mapError(err);
    written_len.* = written;
    return .ok;
}

test "c_api context: lifecycle" {
    var ctx_ptr: ?*zfh_context = null;

    try std.testing.expectEqual(zfh_error.ok, create(&ctx_ptr));
    try std.testing.expect(ctx_ptr != null);

    try std.testing.expectEqual(zfh_error.ok, destroy(ctx_ptr));
    ctx_ptr = null;
}

test "c_api context: file not found mapping" {
    const path = "definitely_missing_file_123456789.bin";
    var out: [zfh.max_digest_length]u8 = undefined;
    var written: usize = 0;
    var ctx_ptr: ?*zfh_context = null;
    try std.testing.expectEqual(zfh_error.ok, create(&ctx_ptr));
    defer if (ctx_ptr) |ctx| {
        _ = destroy(ctx);
    };

    const rc = fileHash(ctx_ptr, .sha_256, path.ptr, path.len, null, out[0..].ptr, out.len, &written);
    try std.testing.expectEqual(zfh_error.file_not_found, rc);
}

test "c_api context: file hash supports mmap option" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const data = "C ABI mmap test data";
    const file_name = "mmap-test.bin";
    {
        const file = try tmp.dir.createFile(io, file_name, .{ .truncate = true });
        defer file.close(io);
        try file.writeStreamingAll(io, data);
    }

    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPathFile(io, file_name, &path_buf);
    const path = path_buf[0..path_len];

    var ctx_ptr: ?*zfh_context = null;
    try std.testing.expectEqual(zfh_error.ok, create(&ctx_ptr));
    defer if (ctx_ptr) |ctx| {
        _ = destroy(ctx);
    };

    var options = zfh_options{
        .struct_size = @sizeOf(zfh_options),
        .flags = types.ZFH_OPTION_USE_MMAP,
    };
    var c_request = zfh_request{
        .struct_size = @sizeOf(zfh_request),
        .options_ptr = &options,
    };
    var out_mmap: [zfh.max_digest_length]u8 = undefined;
    var mmap_written: usize = 0;
    const mmap_rc = fileHash(ctx_ptr, .sha_256, path.ptr, path.len, &c_request, out_mmap[0..].ptr, out_mmap.len, &mmap_written);
    try std.testing.expectEqual(zfh_error.ok, mmap_rc);

    var out_read: [zfh.max_digest_length]u8 = undefined;
    var read_written: usize = 0;
    const read_rc = fileHash(ctx_ptr, .sha_256, path.ptr, path.len, null, out_read[0..].ptr, out_read.len, &read_written);
    try std.testing.expectEqual(zfh_error.ok, read_rc);
    try std.testing.expectEqual(read_written, mmap_written);
    try std.testing.expectEqualSlices(u8, out_read[0..read_written], out_mmap[0..mmap_written]);
}

test "c_api fd hash matches path hash" {
    if (builtin.os.tag == .windows) return;

    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const data = "C ABI fd test data";
    const file_name = "fd-test.bin";
    {
        const file = try tmp.dir.createFile(io, file_name, .{ .truncate = true });
        defer file.close(io);
        try file.writeStreamingAll(io, data);
    }

    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPathFile(io, file_name, &path_buf);
    const path = path_buf[0..path_len];
    const fd = try std.posix.openat(std.posix.AT.FDCWD, path, .{ .ACCMODE = .RDONLY }, 0);
    defer _ = std.posix.system.close(fd);

    var out_fd: [zfh.max_digest_length]u8 = undefined;
    var fd_written: usize = 0;
    const fd_rc = fdHash(.sha_256, @intCast(fd), null, out_fd[0..].ptr, out_fd.len, &fd_written);
    try std.testing.expectEqual(zfh_error.ok, fd_rc);

    var out_path: [zfh.max_digest_length]u8 = undefined;
    var path_written: usize = 0;
    var ctx_ptr: ?*zfh_context = null;
    try std.testing.expectEqual(zfh_error.ok, create(&ctx_ptr));
    defer if (ctx_ptr) |ctx| {
        _ = destroy(ctx);
    };
    const path_rc = fileHash(ctx_ptr, .sha_256, path.ptr, path.len, null, out_path[0..].ptr, out_path.len, &path_written);
    try std.testing.expectEqual(zfh_error.ok, path_rc);
    try std.testing.expectEqual(path_written, fd_written);
    try std.testing.expectEqualSlices(u8, out_path[0..path_written], out_fd[0..fd_written]);
}
