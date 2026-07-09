const std = @import("std");

pub const std_options: std.Options = .{
    .allow_stack_tracing = false,
};

const zfh = @import("root.zig");
const common = @import("c_api/common.zig");
const context = @import("c_api/context.zig");
const hasher = @import("c_api/hasher.zig");
const operation = @import("c_api/operation.zig");
const request = @import("c_api/request.zig");
const types = @import("c_api/types.zig");

pub const ZFH_API_VERSION = types.ZFH_API_VERSION;
pub const zfh_error = types.zfh_error;
pub const zfh_algorithm = types.zfh_algorithm;
pub const ZFH_OPTION_HAS_SEED = types.ZFH_OPTION_HAS_SEED;
pub const ZFH_OPTION_HAS_KEY = types.ZFH_OPTION_HAS_KEY;
pub const ZFH_OPTION_USE_MMAP = types.ZFH_OPTION_USE_MMAP;
pub const zfh_options = types.zfh_options;
pub const zfh_request = types.zfh_request;
pub const zfh_context = context.zfh_context;

pub export fn zfh_max_digest_length() usize {
    return zfh.max_digest_length;
}

pub export fn zfh_api_version() u32 {
    return ZFH_API_VERSION;
}

pub export fn zfh_digest_length(
    alg: zfh_algorithm,
    out_len_ptr: ?*usize,
) zfh_error {
    const out_len = out_len_ptr orelse return .invalid_argument;
    out_len.* = 0;

    const z_alg = common.toHashAlgorithm(alg) orelse return .invalid_algorithm;
    out_len.* = zfh.digestLength(z_alg);
    return .ok;
}

pub export fn zfh_error_message(code: zfh_error) [*:0]const u8 {
    return common.errorMessage(code);
}

pub export fn zfh_string_hash(
    alg: zfh_algorithm,
    data_ptr: ?[*]const u8,
    data_len: usize,
    request_ptr: ?*const zfh_request,
    out_ptr: ?[*]u8,
    out_len: usize,
    written_len_ptr: ?*usize,
) zfh_error {
    const written_len = written_len_ptr orelse return .invalid_argument;
    written_len.* = 0;

    const z_alg = common.toHashAlgorithm(alg) orelse return .invalid_algorithm;
    const data: []const u8 = if (data_len == 0) "" else blk: {
        const ptr = data_ptr orelse return .invalid_argument;
        break :blk ptr[0..data_len];
    };
    const out = blk: {
        const ptr = out_ptr orelse return .invalid_argument;
        break :blk ptr[0..out_len];
    };

    const parsed_request = request.parseRequest(request_ptr) catch return .invalid_argument;

    const written = zfh.stringHash(z_alg, data, out, parsed_request) catch |err| return common.mapError(err);
    written_len.* = written;
    return .ok;
}

pub export fn zfh_context_create(ctx_ptr_ptr: ?*?*zfh_context) zfh_error {
    return context.create(ctx_ptr_ptr);
}

pub export fn zfh_context_destroy(ctx_ptr: ?*zfh_context) zfh_error {
    return context.destroy(ctx_ptr);
}

pub export fn zfh_operation_state_size() usize {
    return operation.stateSize();
}

pub export fn zfh_operation_state_align() usize {
    return operation.stateAlign();
}

pub export fn zfh_operation_init_inplace(
    operation_ptr: ?*anyopaque,
    operation_len: usize,
) zfh_error {
    return operation.initInplace(operation_ptr, operation_len);
}

pub export fn zfh_operation_cancel(
    operation_ptr: ?*anyopaque,
    operation_len: usize,
) zfh_error {
    return operation.cancel(operation_ptr, operation_len);
}

/// Convenience path-based file hashing API.
/// Suitable for callers that have a regular filesystem path and want the
/// library to perform file I/O.
///
/// Callers that already own file/stream reading or need platform-specific file
/// access should prefer the streaming hasher API:
/// `zfh_hasher_init_inplace`, `zfh_hasher_update`, `zfh_hasher_final`.
pub export fn zfh_context_file_hash(
    ctx_ptr: ?*zfh_context,
    alg: zfh_algorithm,
    path_ptr: ?[*]const u8,
    path_len: usize,
    request_ptr: ?*const zfh_request,
    out_ptr: ?[*]u8,
    out_len: usize,
    written_len_ptr: ?*usize,
) zfh_error {
    return context.fileHash(
        ctx_ptr,
        alg,
        path_ptr,
        path_len,
        request_ptr,
        out_ptr,
        out_len,
        written_len_ptr,
    );
}

/// Convenience file-descriptor hashing API for POSIX callers.
/// The descriptor is read from its current position and is never closed.
/// `ZFH_OPTION_USE_MMAP` is ignored for this API; mmap applies only to path
/// based file hashing.
pub export fn zfh_context_fd_hash(
    ctx_ptr: ?*zfh_context,
    alg: zfh_algorithm,
    fd: c_int,
    request_ptr: ?*const zfh_request,
    out_ptr: ?[*]u8,
    out_len: usize,
    written_len_ptr: ?*usize,
) zfh_error {
    return context.fdHash(
        ctx_ptr,
        alg,
        fd,
        request_ptr,
        out_ptr,
        out_len,
        written_len_ptr,
    );
}

pub export fn zfh_hasher_state_size() usize {
    return hasher.stateSize();
}

pub export fn zfh_hasher_state_align() usize {
    return hasher.stateAlign();
}

pub export fn zfh_hasher_init_inplace(
    alg: zfh_algorithm,
    request_ptr: ?*const zfh_request,
    state_ptr: ?*anyopaque,
    state_len: usize,
) zfh_error {
    return hasher.initInplace(alg, request_ptr, state_ptr, state_len);
}

pub export fn zfh_hasher_update(
    state_ptr: ?*anyopaque,
    state_len: usize,
    data_ptr: ?[*]const u8,
    data_len: usize,
) zfh_error {
    return hasher.update(state_ptr, state_len, data_ptr, data_len);
}

pub export fn zfh_hasher_final(
    state_ptr: ?*anyopaque,
    state_len: usize,
    out_ptr: ?[*]u8,
    out_len: usize,
    written_len_ptr: ?*usize,
) zfh_error {
    return hasher.final(state_ptr, state_len, out_ptr, out_len, written_len_ptr);
}

test "c_api: string hash success" {
    const input = "abc";
    var out: [zfh.max_digest_length]u8 = undefined;
    var written: usize = 0;

    const rc = zfh_string_hash(.sha_256, input.ptr, input.len, null, out[0..].ptr, out.len, &written);
    try std.testing.expectEqual(zfh_error.ok, rc);
    try std.testing.expectEqual(@as(usize, 32), written);
    try std.testing.expectFmt("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "{x}", .{out[0..written]});
}

test "c_api: string hash with canceled operation" {
    const input = "abc";
    var out: [zfh.max_digest_length]u8 = undefined;
    var written: usize = 123;
    var c_operation: operation.COperation = undefined;

    try std.testing.expectEqual(
        zfh_error.ok,
        zfh_operation_init_inplace(&c_operation, @sizeOf(operation.COperation)),
    );
    try std.testing.expectEqual(
        zfh_error.ok,
        zfh_operation_cancel(&c_operation, @sizeOf(operation.COperation)),
    );

    var c_request = zfh_request{
        .struct_size = @sizeOf(zfh_request),
        .operation_ptr = &c_operation,
        .operation_len = @sizeOf(operation.COperation),
    };

    const rc = zfh_string_hash(.sha_256, input.ptr, input.len, &c_request, out[0..].ptr, out.len, &written);
    try std.testing.expectEqual(zfh_error.operation_canceled, rc);
    try std.testing.expectEqual(@as(usize, 0), written);
}

test "c_api: digest length success" {
    var len: usize = 0;
    const rc = zfh_digest_length(.sha_256, &len);
    try std.testing.expectEqual(zfh_error.ok, rc);
    try std.testing.expectEqual(@as(usize, 32), len);
}

test "c_api: digest length invalid algorithm" {
    var len: usize = 123;
    const rc = zfh_digest_length(@enumFromInt(999), &len);
    try std.testing.expectEqual(zfh_error.invalid_algorithm, rc);
    try std.testing.expectEqual(@as(usize, 0), len);
}

test "c_api: invalid algorithm" {
    const input = "abc";
    var out: [zfh.max_digest_length]u8 = undefined;
    var written: usize = 0;

    const rc = zfh_string_hash(@enumFromInt(999), input.ptr, input.len, null, out[0..].ptr, out.len, &written);
    try std.testing.expectEqual(zfh_error.invalid_algorithm, rc);
    try std.testing.expectEqual(@as(usize, 0), written);
}

test "c_api: key required mapping" {
    const input = "abc";
    var out: [zfh.max_digest_length]u8 = undefined;
    var written: usize = 0;

    const rc = zfh_string_hash(.hmac_sha_256, input.ptr, input.len, null, out[0..].ptr, out.len, &written);
    try std.testing.expectEqual(zfh_error.key_required, rc);
}

test "c_api: empty key is valid for hmac" {
    const input = "abc";
    var out: [zfh.max_digest_length]u8 = undefined;
    var written: usize = 0;

    var options = zfh_options{
        .struct_size = @sizeOf(zfh_options),
        .flags = ZFH_OPTION_HAS_KEY,
        .key_ptr = null,
        .key_len = 0,
    };

    var c_request = zfh_request{
        .struct_size = @sizeOf(zfh_request),
        .options_ptr = &options,
        .operation_ptr = null,
    };

    const rc = zfh_string_hash(.hmac_sha_256, input.ptr, input.len, &c_request, out[0..].ptr, out.len, &written);
    try std.testing.expectEqual(zfh_error.ok, rc);

    var expected: [zfh.max_digest_length]u8 = undefined;
    const expected_written =
        try zfh.stringHash(.@"HMAC-SHA-256", input, expected[0..], .{ .hash_options = .{ .key = "" } });
    try std.testing.expectEqual(expected_written, written);
    try std.testing.expectEqualSlices(u8, expected[0..expected_written], out[0..written]);
}
