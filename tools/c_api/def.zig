//! Policy knobs for generated C ABI declarations.
//!
//! The generator derives algorithms from `zfh.HashAlgorithm` and library errors
//! from `zfh.Error`. Keep only non-library ABI policy here.

pub const api_version: u32 = 3;

pub const ExtraErrorDef = struct {
    zig_name: []const u8,
    c_name: []const u8,
    message: []const u8,
};

pub const error_prefix = [_]ExtraErrorDef{
    .{ .zig_name = "ok", .c_name = "ZFH_OK", .message = "ok" },
    .{ .zig_name = "invalid_argument", .c_name = "ZFH_INVALID_ARGUMENT", .message = "invalid argument" },
    .{ .zig_name = "invalid_algorithm", .c_name = "ZFH_INVALID_ALGORITHM", .message = "invalid algorithm" },
};

pub const error_suffix = [_]ExtraErrorDef{
    .{ .zig_name = "file_not_found", .c_name = "ZFH_FILE_NOT_FOUND", .message = "file not found" },
    .{ .zig_name = "access_denied", .c_name = "ZFH_ACCESS_DENIED", .message = "access denied" },
    .{ .zig_name = "invalid_path", .c_name = "ZFH_INVALID_PATH", .message = "invalid path" },
    .{ .zig_name = "io_error", .c_name = "ZFH_IO_ERROR", .message = "io error" },
    .{ .zig_name = "unknown_error", .c_name = "ZFH_UNKNOWN_ERROR", .message = "unknown error" },
};

pub const OptionFlagDef = struct {
    zig_name: []const u8,
    c_name: []const u8,
    expr: []const u8,
};

pub const option_flags = [_]OptionFlagDef{
    .{ .zig_name = "ZFH_OPTION_HAS_SEED", .c_name = "ZFH_OPTION_HAS_SEED", .expr = "1 << 0" },
    .{ .zig_name = "ZFH_OPTION_HAS_KEY", .c_name = "ZFH_OPTION_HAS_KEY", .expr = "1 << 1" },
};
