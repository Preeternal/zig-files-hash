const std = @import("std");
const zfh = @import("../root.zig");
const common = @import("common.zig");
const request = @import("request.zig");
const types = @import("types.zig");

const HashAlgorithm = zfh.HashAlgorithm;
const HashRequest = zfh.HashRequest;
const zfh_algorithm = types.zfh_algorithm;
const zfh_error = types.zfh_error;
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
