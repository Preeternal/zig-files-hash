const std = @import("std");
const zfh = @import("../root.zig");
const types = @import("types.zig");

const Operation = zfh.Operation;
const zfh_error = types.zfh_error;

const COPERATION_MAGIC: u32 = 0x5A464F31; // "ZFO1"

pub const COperation = struct {
    magic: u32,
    operation: Operation,
};

pub fn stateSize() usize {
    return @sizeOf(COperation);
}

pub fn stateAlign() usize {
    return @alignOf(COperation);
}

pub fn getPtr(operation_ptr: ?*anyopaque, operation_len: usize) !*COperation {
    const raw_ptr = operation_ptr orelse return error.InvalidState;
    if (operation_len < @sizeOf(COperation)) return error.InvalidState;
    if ((@intFromPtr(raw_ptr) % @alignOf(COperation)) != 0) return error.InvalidState;
    return @ptrCast(@alignCast(raw_ptr));
}

pub fn getInitializedPtr(operation_ptr: ?*anyopaque, operation_len: usize) !*COperation {
    const operation = try getPtr(operation_ptr, operation_len);
    if (operation.magic != COPERATION_MAGIC) return error.InvalidState;
    return operation;
}

pub fn initInplace(operation_ptr: ?*anyopaque, operation_len: usize) zfh_error {
    const operation = getPtr(operation_ptr, operation_len) catch return .invalid_argument;

    operation.* = .{
        .magic = COPERATION_MAGIC,
        .operation = Operation.init(),
    };
    return .ok;
}

pub fn cancel(operation_ptr: ?*anyopaque, operation_len: usize) zfh_error {
    const operation = getInitializedPtr(operation_ptr, operation_len) catch return .invalid_argument;
    operation.operation.cancel();
    return .ok;
}

test "c_api operation: state requirements are non-zero" {
    try std.testing.expect(stateSize() > 0);
    try std.testing.expect(stateAlign() > 0);
}

test "c_api operation: init and cancel" {
    var operation: COperation = undefined;

    try std.testing.expectEqual(zfh_error.ok, initInplace(&operation, @sizeOf(COperation)));
    try std.testing.expect(!operation.operation.isCanceled());

    try std.testing.expectEqual(zfh_error.ok, cancel(&operation, @sizeOf(COperation)));
    try std.testing.expect(operation.operation.isCanceled());
}

test "c_api operation: rejects invalid state" {
    var operation = COperation{
        .magic = 0,
        .operation = Operation.init(),
    };

    try std.testing.expectError(
        error.InvalidState,
        getInitializedPtr(&operation, @sizeOf(COperation)),
    );
}
