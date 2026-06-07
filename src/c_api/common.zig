const generated = @import("../c_api_generated.zig");
const zfh = @import("../root.zig");
const types = @import("types.zig");

pub fn toHashAlgorithm(alg: types.zfh_algorithm) ?zfh.HashAlgorithm {
    return generated.toHashAlgorithm(alg);
}

pub fn errorMessage(code: types.zfh_error) [*:0]const u8 {
    return generated.errorMessage(code);
}

pub fn mapError(err: anyerror) types.zfh_error {
    if (generated.mapLibraryError(err)) |mapped| return mapped;

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
