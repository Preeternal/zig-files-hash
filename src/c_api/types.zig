const generated = @import("../c_api_generated.zig");

pub const ZFH_API_VERSION = generated.ZFH_API_VERSION;
pub const zfh_error = generated.zfh_error;
pub const zfh_algorithm = generated.zfh_algorithm;
pub const ZFH_OPTION_HAS_SEED = generated.ZFH_OPTION_HAS_SEED;
pub const ZFH_OPTION_HAS_KEY = generated.ZFH_OPTION_HAS_KEY;
pub const ZFH_OPTION_USE_MMAP = generated.ZFH_OPTION_USE_MMAP;

pub const zfh_options = extern struct {
    struct_size: u32 = @sizeOf(@This()),
    flags: u32 = 0,
    seed: u64 = 0,
    key_ptr: ?[*]const u8 = null,
    key_len: usize = 0,
};

pub const zfh_request = extern struct {
    struct_size: u32 = @sizeOf(@This()), //
    options_ptr: ?*const zfh_options = null,
    operation_ptr: ?*anyopaque = null,
    operation_len: usize = 0,
};
