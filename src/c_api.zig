const std = @import("std");
const zfh = @import("root.zig");

const HashAlgorithm = zfh.HashAlgorithm;
const HashOptions = zfh.HashOptions;
const Error = zfh.Error;

pub const ZFH_API_VERSION: u32 = 2;

pub const zfh_error = enum(c_int) {
    ok = 0,
    invalid_argument = 1,
    invalid_algorithm = 2,
    buffer_too_small = 3,
    key_required = 4,
    invalid_key_length = 5,
    file_not_found = 6,
    access_denied = 7,
    invalid_path = 8,
    io_error = 9,
    unknown_error = 10,
    _,
};

pub const zfh_algorithm = enum(c_int) {
    sha_224 = 0,
    sha_256 = 1,
    sha_384 = 2,
    sha_512 = 3,
    sha_512_224 = 4,
    sha_512_256 = 5,
    md5 = 6,
    sha_1 = 7,
    xxh3_64 = 8,
    blake3 = 9,
    hmac_sha_224 = 10,
    hmac_sha_256 = 11,
    hmac_sha_384 = 12,
    hmac_sha_512 = 13,
    hmac_md5 = 14,
    hmac_sha_1 = 15,
    _,
};

pub const zfh_options = extern struct {
    struct_size: u32 = @sizeOf(@This()),
    flags: u32 = 0,
    seed: u64 = 0,
    key_ptr: ?[*]const u8 = null,
    key_len: usize = 0,
};

pub const ZFH_OPTION_HAS_SEED: u32 = 1 << 0;
pub const ZFH_OPTION_HAS_KEY: u32 = 1 << 1;

const CHASHER_MAGIC: u32 = 0x5A464831; // "ZFH1"

const CHasher = struct {
    magic: u32,
    finalized: bool,
    hasher: zfh.RuntimeHasher,
};

fn toHashAlgorithm(alg: zfh_algorithm) ?HashAlgorithm {
    return switch (alg) {
        .sha_224 => .@"SHA-224",
        .sha_256 => .@"SHA-256",
        .sha_384 => .@"SHA-384",
        .sha_512 => .@"SHA-512",
        .sha_512_224 => .@"SHA-512/224",
        .sha_512_256 => .@"SHA-512/256",
        .md5 => .MD5,
        .sha_1 => .@"SHA-1",
        .xxh3_64 => .@"XXH3-64",
        .blake3 => .BLAKE3,
        .hmac_sha_224 => .@"HMAC-SHA-224",
        .hmac_sha_256 => .@"HMAC-SHA-256",
        .hmac_sha_384 => .@"HMAC-SHA-384",
        .hmac_sha_512 => .@"HMAC-SHA-512",
        .hmac_md5 => .@"HMAC-MD5",
        .hmac_sha_1 => .@"HMAC-SHA-1",
        else => null,
    };
}

fn parseOptions(options_ptr: ?*const zfh_options) !?HashOptions {
    const c_opts = options_ptr orelse return null;
    if (c_opts.struct_size < @as(u32, @intCast(@sizeOf(zfh_options)))) {
        return error.InvalidArgument;
    }

    var opts: HashOptions = .{};
    var has_any = false;

    if ((c_opts.flags & ZFH_OPTION_HAS_SEED) != 0) {
        opts.seed = c_opts.seed;
        has_any = true;
    }

    if ((c_opts.flags & ZFH_OPTION_HAS_KEY) != 0) {
        const key: []const u8 = if (c_opts.key_len == 0) "" else blk: {
            const key_ptr = c_opts.key_ptr orelse return error.InvalidArgument;
            break :blk key_ptr[0..c_opts.key_len];
        };

        opts.key = key;
        has_any = true;
    }

    return if (has_any) opts else null;
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

fn mapError(err: anyerror) zfh_error {
    if (err == Error.BufferTooSmall) return .buffer_too_small;
    if (err == Error.KeyRequired) return .key_required;
    if (err == Error.InvalidKeyLength) return .invalid_key_length;

    if (err == error.FileNotFound) return .file_not_found;
    if (err == error.AccessDenied) return .access_denied;
    if (err == error.IsDir or err == error.NotDir or err == error.NameTooLong) return .invalid_path;
    if (err == error.Unexpected) return .io_error;
    if (err == error.InputOutput) return .io_error;
    if (err == error.SystemResources) return .io_error;
    if (err == error.OperationAborted) return .io_error;
    if (err == error.BrokenPipe) return .io_error;

    return .unknown_error;
}

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

    const z_alg = toHashAlgorithm(alg) orelse return .invalid_algorithm;
    out_len.* = zfh.digestLength(z_alg);
    return .ok;
}

pub export fn zfh_error_message(code: zfh_error) [*:0]const u8 {
    return switch (code) {
        .ok => "ok",
        .invalid_argument => "invalid argument",
        .invalid_algorithm => "invalid algorithm",
        .buffer_too_small => "output buffer too small",
        .key_required => "key required",
        .invalid_key_length => "invalid key length",
        .file_not_found => "file not found",
        .access_denied => "access denied",
        .invalid_path => "invalid path",
        .io_error => "io error",
        .unknown_error => "unknown error",
        else => "unknown error",
    };
}

pub export fn zfh_string_hash(
    alg: zfh_algorithm,
    data_ptr: ?[*]const u8,
    data_len: usize,
    options_ptr: ?*const zfh_options,
    out_ptr: ?[*]u8,
    out_len: usize,
    written_len_ptr: ?*usize,
) zfh_error {
    const written_len = written_len_ptr orelse return .invalid_argument;
    written_len.* = 0;

    const z_alg = toHashAlgorithm(alg) orelse return .invalid_algorithm;
    const data: []const u8 = if (data_len == 0) "" else blk: {
        const ptr = data_ptr orelse return .invalid_argument;
        break :blk ptr[0..data_len];
    };
    const out = blk: {
        const ptr = out_ptr orelse return .invalid_argument;
        break :blk ptr[0..out_len];
    };
    const options = parseOptions(options_ptr) catch return .invalid_argument;

    const written = zfh.stringHash(z_alg, data, options, out) catch |err| return mapError(err);
    written_len.* = written;
    return .ok;
}

pub export fn zfh_file_hash(
    alg: zfh_algorithm,
    path_ptr: ?[*]const u8,
    path_len: usize,
    options_ptr: ?*const zfh_options,
    out_ptr: ?[*]u8,
    out_len: usize,
    written_len_ptr: ?*usize,
) zfh_error {
    const written_len = written_len_ptr orelse return .invalid_argument;
    written_len.* = 0;

    const z_alg = toHashAlgorithm(alg) orelse return .invalid_algorithm;
    if (path_len == 0) return .invalid_path;
    const path = blk: {
        const ptr = path_ptr orelse return .invalid_argument;
        break :blk ptr[0..path_len];
    };
    const out = blk: {
        const ptr = out_ptr orelse return .invalid_argument;
        break :blk ptr[0..out_len];
    };
    const options = parseOptions(options_ptr) catch return .invalid_argument;

    const written = zfh.fileHash(z_alg, path, options, out) catch |err| return mapError(err);
    written_len.* = written;
    return .ok;
}

pub export fn zfh_hasher_state_size() usize {
    return @sizeOf(CHasher);
}

pub export fn zfh_hasher_state_align() usize {
    return @alignOf(CHasher);
}

pub export fn zfh_hasher_init_inplace(
    alg: zfh_algorithm,
    options_ptr: ?*const zfh_options,
    state_ptr: ?*anyopaque,
    state_len: usize,
) zfh_error {
    const state = getStatePtr(state_ptr, state_len) catch return .invalid_argument;

    const z_alg = toHashAlgorithm(alg) orelse return .invalid_algorithm;
    const options = parseOptions(options_ptr) catch return .invalid_argument;
    const runtime_hasher = zfh.RuntimeHasher.init(z_alg, options) catch |err| return mapError(err);

    state.* = .{
        .magic = CHASHER_MAGIC,
        .finalized = false,
        .hasher = runtime_hasher,
    };
    return .ok;
}

pub export fn zfh_hasher_update(
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
    state.hasher.update(chunk);
    return .ok;
}

pub export fn zfh_hasher_final(
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
    const written = state.hasher.final(out) catch |err| return mapError(err);
    state.finalized = true;
    written_len.* = written;
    return .ok;
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

test "c_api: file not found mapping" {
    const path = "definitely_missing_file_123456789.bin";
    var out: [zfh.max_digest_length]u8 = undefined;
    var written: usize = 0;

    const rc = zfh_file_hash(.sha_256, path.ptr, path.len, null, out[0..].ptr, out.len, &written);
    try std.testing.expectEqual(zfh_error.file_not_found, rc);
}

test "c_api: invalid options struct size" {
    const input = "abc";
    var out: [zfh.max_digest_length]u8 = undefined;
    var written: usize = 0;
    var options = zfh_options{
        .struct_size = 0,
        .flags = ZFH_OPTION_HAS_SEED,
        .seed = 12345,
    };

    const rc = zfh_string_hash(.xxh3_64, input.ptr, input.len, &options, out[0..].ptr, out.len, &written);
    try std.testing.expectEqual(zfh_error.invalid_argument, rc);
    try std.testing.expectEqual(@as(usize, 0), written);
}

test "c_api: streaming hasher state requirements are non-zero" {
    try std.testing.expect(zfh_hasher_state_size() > 0);
    try std.testing.expect(zfh_hasher_state_align() > 0);
}

test "c_api: streaming hasher success with chunked updates" {
    const input = "abc";
    var out: [zfh.max_digest_length]u8 = undefined;
    var written: usize = 0;
    var state: CHasher = undefined;

    const init_rc = zfh_hasher_init_inplace(.sha_256, null, &state, @sizeOf(CHasher));
    try std.testing.expectEqual(zfh_error.ok, init_rc);

    const update1_rc = zfh_hasher_update(&state, @sizeOf(CHasher), input.ptr, 1);
    try std.testing.expectEqual(zfh_error.ok, update1_rc);
    const update2_rc = zfh_hasher_update(&state, @sizeOf(CHasher), input.ptr + 1, input.len - 1);
    try std.testing.expectEqual(zfh_error.ok, update2_rc);

    const final_rc = zfh_hasher_final(&state, @sizeOf(CHasher), out[0..].ptr, out.len, &written);
    try std.testing.expectEqual(zfh_error.ok, final_rc);
    try std.testing.expectEqual(@as(usize, 32), written);
    try std.testing.expectFmt("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "{x}", .{out[0..written]});
}

test "c_api: streaming hasher key required mapping" {
    var state: CHasher = undefined;

    const rc = zfh_hasher_init_inplace(.hmac_sha_256, null, &state, @sizeOf(CHasher));
    try std.testing.expectEqual(zfh_error.key_required, rc);
}

test "c_api: streaming hasher final buffer too small" {
    var state: CHasher = undefined;
    var out: [8]u8 = undefined;
    var written: usize = 0;

    const init_rc = zfh_hasher_init_inplace(.sha_256, null, &state, @sizeOf(CHasher));
    try std.testing.expectEqual(zfh_error.ok, init_rc);

    const update_rc = zfh_hasher_update(&state, @sizeOf(CHasher), "abc".ptr, 3);
    try std.testing.expectEqual(zfh_error.ok, update_rc);

    const final_rc = zfh_hasher_final(&state, @sizeOf(CHasher), out[0..].ptr, out.len, &written);
    try std.testing.expectEqual(zfh_error.buffer_too_small, final_rc);
    try std.testing.expectEqual(@as(usize, 0), written);
}

test "c_api: streaming hasher rejects repeated final" {
    var state: CHasher = undefined;
    var out: [zfh.max_digest_length]u8 = undefined;
    var written: usize = 0;

    const init_rc = zfh_hasher_init_inplace(.sha_256, null, &state, @sizeOf(CHasher));
    try std.testing.expectEqual(zfh_error.ok, init_rc);

    const update_rc = zfh_hasher_update(&state, @sizeOf(CHasher), "abc".ptr, 3);
    try std.testing.expectEqual(zfh_error.ok, update_rc);

    const final1_rc = zfh_hasher_final(&state, @sizeOf(CHasher), out[0..].ptr, out.len, &written);
    try std.testing.expectEqual(zfh_error.ok, final1_rc);
    try std.testing.expect(written > 0);

    written = 123;
    const final2_rc = zfh_hasher_final(&state, @sizeOf(CHasher), out[0..].ptr, out.len, &written);
    try std.testing.expectEqual(zfh_error.invalid_argument, final2_rc);
    try std.testing.expectEqual(@as(usize, 0), written);
}

test "c_api: streaming hasher rejects update after final" {
    var state: CHasher = undefined;
    var out: [zfh.max_digest_length]u8 = undefined;
    var written: usize = 0;

    const init_rc = zfh_hasher_init_inplace(.sha_256, null, &state, @sizeOf(CHasher));
    try std.testing.expectEqual(zfh_error.ok, init_rc);

    const update1_rc = zfh_hasher_update(&state, @sizeOf(CHasher), "abc".ptr, 3);
    try std.testing.expectEqual(zfh_error.ok, update1_rc);

    const final_rc = zfh_hasher_final(&state, @sizeOf(CHasher), out[0..].ptr, out.len, &written);
    try std.testing.expectEqual(zfh_error.ok, final_rc);

    const update2_rc = zfh_hasher_update(&state, @sizeOf(CHasher), "x".ptr, 1);
    try std.testing.expectEqual(zfh_error.invalid_argument, update2_rc);
}

test "c_api: streaming hasher invalid state size" {
    var raw_state: [@sizeOf(CHasher)]u8 align(@alignOf(CHasher)) = undefined;
    const rc = zfh_hasher_init_inplace(.sha_256, null, raw_state[0..].ptr, @sizeOf(CHasher) - 1);
    try std.testing.expectEqual(zfh_error.invalid_argument, rc);
}

test "c_api: streaming hasher update rejects uninitialized state" {
    var state: CHasher = undefined;
    state.magic = 0;
    const rc = zfh_hasher_update(&state, @sizeOf(CHasher), "abc".ptr, 3);
    try std.testing.expectEqual(zfh_error.invalid_argument, rc);
}
