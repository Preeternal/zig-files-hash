const std = @import("std");
const zfh = @import("../root.zig");
const operation = @import("operation.zig");
const types = @import("types.zig");

const HashOptions = zfh.HashOptions;
const HashRequest = zfh.HashRequest;
const Operation = zfh.Operation;
const zfh_options = types.zfh_options;
const zfh_request = types.zfh_request;

pub fn parseOptions(options_ptr: ?*const zfh_options) !?HashOptions {
    const c_opts = options_ptr orelse return null;
    if (c_opts.struct_size < @as(u32, @intCast(@sizeOf(zfh_options)))) {
        return error.InvalidArgument;
    }

    const known_flags = types.ZFH_OPTION_HAS_SEED | types.ZFH_OPTION_HAS_KEY;
    if ((c_opts.flags & ~known_flags) != 0) {
        return error.InvalidArgument;
    }

    var opts: HashOptions = .{};
    var has_any = false;

    if ((c_opts.flags & types.ZFH_OPTION_HAS_SEED) != 0) {
        opts.seed = c_opts.seed;
        has_any = true;
    }

    if ((c_opts.flags & types.ZFH_OPTION_HAS_KEY) != 0) {
        const key: []const u8 = if (c_opts.key_len == 0) "" else blk: {
            const key_ptr = c_opts.key_ptr orelse return error.InvalidArgument;
            break :blk key_ptr[0..c_opts.key_len];
        };

        opts.key = key;
        has_any = true;
    }

    return if (has_any) opts else null;
}

pub fn parseRequest(request_ptr: ?*const zfh_request) !?HashRequest {
    const c_request = request_ptr orelse return null;
    if (c_request.struct_size < @as(u32, @intCast(@sizeOf(zfh_request)))) {
        return error.InvalidArgument;
    }

    const parsed_operation: ?*const Operation = if (c_request.operation_ptr) |operation_ptr| blk: {
        const c_operation = try operation.getInitializedPtr(operation_ptr, c_request.operation_len);
        break :blk &c_operation.operation;
    } else blk: {
        if (c_request.operation_len != 0) return error.InvalidArgument;
        break :blk null;
    };

    return HashRequest{
        .hash_options = try parseOptions(c_request.options_ptr),
        .operation = parsed_operation,
    };
}

test "c_api request: parses null request" {
    try std.testing.expectEqual(@as(?HashRequest, null), try parseRequest(null));
}

test "c_api request: parses options" {
    var options = zfh_options{
        .struct_size = @sizeOf(zfh_options),
        .flags = types.ZFH_OPTION_HAS_SEED,
        .seed = 12345,
    };

    const parsed = (try parseOptions(&options)).?;
    try std.testing.expectEqual(@as(u64, 12345), parsed.seed.?);
}

test "c_api request: rejects invalid options struct size" {
    var options = zfh_options{
        .struct_size = 0,
        .flags = types.ZFH_OPTION_HAS_SEED,
        .seed = 12345,
    };

    try std.testing.expectError(error.InvalidArgument, parseOptions(&options));
}

test "c_api request: rejects unknown option flags" {
    var options = zfh_options{
        .struct_size = @sizeOf(zfh_options),
        .flags = 1 << 31,
    };

    try std.testing.expectError(error.InvalidArgument, parseOptions(&options));
}

test "c_api request: parses initialized operation" {
    var c_operation: operation.COperation = undefined;
    try std.testing.expectEqual(
        types.zfh_error.ok,
        operation.initInplace(&c_operation, @sizeOf(operation.COperation)),
    );
    try std.testing.expectEqual(
        types.zfh_error.ok,
        operation.cancel(&c_operation, @sizeOf(operation.COperation)),
    );

    var c_request = zfh_request{
        .struct_size = @sizeOf(zfh_request),
        .operation_ptr = &c_operation,
        .operation_len = @sizeOf(operation.COperation),
    };

    const parsed = (try parseRequest(&c_request)).?;
    try std.testing.expect(parsed.operation != null);
    try std.testing.expectError(zfh.Error.OperationCanceled, parsed.operation.?.checkCanceled());
}

test "c_api request: rejects uninitialized operation" {
    var c_operation = operation.COperation{
        .magic = 0,
        .operation = Operation.init(),
    };
    var c_request = zfh_request{
        .struct_size = @sizeOf(zfh_request),
        .operation_ptr = &c_operation,
        .operation_len = @sizeOf(operation.COperation),
    };

    try std.testing.expectError(error.InvalidState, parseRequest(&c_request));
}
