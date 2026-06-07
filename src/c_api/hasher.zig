const std = @import("std");
const zfh = @import("../root.zig");
const common = @import("common.zig");
const operation = @import("operation.zig");
const request = @import("request.zig");
const types = @import("types.zig");

const zfh_error = types.zfh_error;
const zfh_algorithm = types.zfh_algorithm;
const zfh_request = types.zfh_request;

const CHASHER_MAGIC: u32 = 0x5A464831; // "ZFH1"

pub const CHasher = struct {
    magic: u32,
    finalized: bool,
    stream: zfh.HashStream,
};

pub fn stateSize() usize {
    return @sizeOf(CHasher);
}

pub fn stateAlign() usize {
    return @alignOf(CHasher);
}

fn getStatePtr(state_ptr: ?*anyopaque, state_len: usize) !*CHasher {
    const raw_ptr = state_ptr orelse return error.InvalidState;
    if (state_len < @sizeOf(CHasher)) return error.InvalidState;
    if ((@intFromPtr(raw_ptr) % @alignOf(CHasher)) != 0) return error.InvalidState;
    return @ptrCast(@alignCast(raw_ptr));
}

fn getInitializedStatePtr(state_ptr: ?*anyopaque, state_len: usize) !*CHasher {
    const state = try getStatePtr(state_ptr, state_len);
    if (state.magic != CHASHER_MAGIC) return error.InvalidState;
    return state;
}

pub fn initInplace(
    alg: zfh_algorithm,
    request_ptr: ?*const zfh_request,
    state_ptr: ?*anyopaque,
    state_len: usize,
) zfh_error {
    const state = getStatePtr(state_ptr, state_len) catch return .invalid_argument;

    const z_alg = common.toHashAlgorithm(alg) orelse return .invalid_algorithm;
    const parsed_request = request.parseRequest(request_ptr) catch return .invalid_argument;
    const stream = zfh.HashStream.init(z_alg, parsed_request) catch |err| return common.mapError(err);

    state.* = .{
        .magic = CHASHER_MAGIC,
        .finalized = false,
        .stream = stream,
    };
    return .ok;
}

pub fn update(
    state_ptr: ?*anyopaque,
    state_len: usize,
    data_ptr: ?[*]const u8,
    data_len: usize,
) zfh_error {
    const chunk: []const u8 = if (data_len == 0) "" else blk: {
        const ptr = data_ptr orelse return .invalid_argument;
        break :blk ptr[0..data_len];
    };

    var state = getInitializedStatePtr(state_ptr, state_len) catch return .invalid_argument;
    if (state.finalized) return .invalid_argument;
    state.stream.update(chunk) catch |err| return common.mapError(err);
    return .ok;
}

pub fn final(
    state_ptr: ?*anyopaque,
    state_len: usize,
    out_ptr: ?[*]u8,
    out_len: usize,
    written_len_ptr: ?*usize,
) zfh_error {
    const written_len = written_len_ptr orelse return .invalid_argument;
    written_len.* = 0;

    const out = blk: {
        const ptr = out_ptr orelse return .invalid_argument;
        break :blk ptr[0..out_len];
    };

    var state = getInitializedStatePtr(state_ptr, state_len) catch return .invalid_argument;
    if (state.finalized) return .invalid_argument;
    const written = state.stream.final(out) catch |err| return common.mapError(err);
    state.finalized = true;
    written_len.* = written;
    return .ok;
}

test "c_api hasher: state requirements are non-zero" {
    try std.testing.expect(stateSize() > 0);
    try std.testing.expect(stateAlign() > 0);
}

test "c_api hasher: success with chunked updates" {
    const input = "abc";
    var out: [zfh.max_digest_length]u8 = undefined;
    var written: usize = 0;
    var state: CHasher = undefined;

    const init_rc = initInplace(.sha_256, null, &state, @sizeOf(CHasher));
    try std.testing.expectEqual(zfh_error.ok, init_rc);

    const update1_rc = update(&state, @sizeOf(CHasher), input.ptr, 1);
    try std.testing.expectEqual(zfh_error.ok, update1_rc);
    const update2_rc = update(&state, @sizeOf(CHasher), input.ptr + 1, input.len - 1);
    try std.testing.expectEqual(zfh_error.ok, update2_rc);

    const final_rc = final(&state, @sizeOf(CHasher), out[0..].ptr, out.len, &written);
    try std.testing.expectEqual(zfh_error.ok, final_rc);
    try std.testing.expectEqual(@as(usize, 32), written);
    try std.testing.expectFmt("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "{x}", .{out[0..written]});
}

test "c_api hasher: key required mapping" {
    var state: CHasher = undefined;

    const rc = initInplace(.hmac_sha_256, null, &state, @sizeOf(CHasher));
    try std.testing.expectEqual(zfh_error.key_required, rc);
}

test "c_api hasher: update returns operation canceled" {
    var state: CHasher = undefined;
    var c_operation: operation.COperation = undefined;
    try std.testing.expectEqual(
        zfh_error.ok,
        operation.initInplace(&c_operation, @sizeOf(operation.COperation)),
    );

    var c_request = zfh_request{
        .struct_size = @sizeOf(zfh_request),
        .operation_ptr = &c_operation,
        .operation_len = @sizeOf(operation.COperation),
    };

    const init_rc = initInplace(.sha_256, &c_request, &state, @sizeOf(CHasher));
    try std.testing.expectEqual(zfh_error.ok, init_rc);

    try std.testing.expectEqual(
        zfh_error.ok,
        operation.cancel(&c_operation, @sizeOf(operation.COperation)),
    );

    const update_rc = update(&state, @sizeOf(CHasher), "abc".ptr, 3);
    try std.testing.expectEqual(zfh_error.operation_canceled, update_rc);
}

test "c_api hasher: final returns operation canceled" {
    var state: CHasher = undefined;
    var out: [zfh.max_digest_length]u8 = undefined;
    var written: usize = 123;
    var c_operation: operation.COperation = undefined;
    try std.testing.expectEqual(
        zfh_error.ok,
        operation.initInplace(&c_operation, @sizeOf(operation.COperation)),
    );

    var c_request = zfh_request{
        .struct_size = @sizeOf(zfh_request),
        .operation_ptr = &c_operation,
        .operation_len = @sizeOf(operation.COperation),
    };

    const init_rc = initInplace(.sha_256, &c_request, &state, @sizeOf(CHasher));
    try std.testing.expectEqual(zfh_error.ok, init_rc);

    const update_rc = update(&state, @sizeOf(CHasher), "abc".ptr, 3);
    try std.testing.expectEqual(zfh_error.ok, update_rc);

    try std.testing.expectEqual(
        zfh_error.ok,
        operation.cancel(&c_operation, @sizeOf(operation.COperation)),
    );

    const final_rc = final(&state, @sizeOf(CHasher), out[0..].ptr, out.len, &written);
    try std.testing.expectEqual(zfh_error.operation_canceled, final_rc);
    try std.testing.expectEqual(@as(usize, 0), written);
}

test "c_api hasher: final buffer too small" {
    var state: CHasher = undefined;
    var out: [8]u8 = undefined;
    var written: usize = 0;

    const init_rc = initInplace(.sha_256, null, &state, @sizeOf(CHasher));
    try std.testing.expectEqual(zfh_error.ok, init_rc);

    const update_rc = update(&state, @sizeOf(CHasher), "abc".ptr, 3);
    try std.testing.expectEqual(zfh_error.ok, update_rc);

    const final_rc = final(&state, @sizeOf(CHasher), out[0..].ptr, out.len, &written);
    try std.testing.expectEqual(zfh_error.output_buffer_too_small, final_rc);
    try std.testing.expectEqual(@as(usize, 0), written);
}

test "c_api hasher: rejects repeated final" {
    var state: CHasher = undefined;
    var out: [zfh.max_digest_length]u8 = undefined;
    var written: usize = 0;

    const init_rc = initInplace(.sha_256, null, &state, @sizeOf(CHasher));
    try std.testing.expectEqual(zfh_error.ok, init_rc);

    const update_rc = update(&state, @sizeOf(CHasher), "abc".ptr, 3);
    try std.testing.expectEqual(zfh_error.ok, update_rc);

    const final1_rc = final(&state, @sizeOf(CHasher), out[0..].ptr, out.len, &written);
    try std.testing.expectEqual(zfh_error.ok, final1_rc);
    try std.testing.expect(written > 0);

    written = 123;
    const final2_rc = final(&state, @sizeOf(CHasher), out[0..].ptr, out.len, &written);
    try std.testing.expectEqual(zfh_error.invalid_argument, final2_rc);
    try std.testing.expectEqual(@as(usize, 0), written);
}

test "c_api hasher: rejects update after final" {
    var state: CHasher = undefined;
    var out: [zfh.max_digest_length]u8 = undefined;
    var written: usize = 0;

    const init_rc = initInplace(.sha_256, null, &state, @sizeOf(CHasher));
    try std.testing.expectEqual(zfh_error.ok, init_rc);

    const update1_rc = update(&state, @sizeOf(CHasher), "abc".ptr, 3);
    try std.testing.expectEqual(zfh_error.ok, update1_rc);

    const final_rc = final(&state, @sizeOf(CHasher), out[0..].ptr, out.len, &written);
    try std.testing.expectEqual(zfh_error.ok, final_rc);

    const update2_rc = update(&state, @sizeOf(CHasher), "x".ptr, 1);
    try std.testing.expectEqual(zfh_error.invalid_argument, update2_rc);
}

test "c_api hasher: invalid state size" {
    var raw_state: [@sizeOf(CHasher)]u8 align(@alignOf(CHasher)) = undefined;
    const rc = initInplace(.sha_256, null, raw_state[0..].ptr, @sizeOf(CHasher) - 1);
    try std.testing.expectEqual(zfh_error.invalid_argument, rc);
}

test "c_api hasher: update rejects uninitialized state" {
    var state: CHasher = undefined;
    state.magic = 0;
    const rc = update(&state, @sizeOf(CHasher), "abc".ptr, 3);
    try std.testing.expectEqual(zfh_error.invalid_argument, rc);
}
