//! By convention, root.zig is the root source file when making a library.
const std = @import("std");
const algorithms = @import("algorithms.zig");
const dispatch = @import("dispatch.zig");

pub const HashAlgorithm = algorithms.HashAlgorithm;
pub const HashOptions = algorithms.HashOptions;
pub const Error = algorithms.Error;
pub const max_digest_length = algorithms.max_digest_length;
pub const digestLength = algorithms.digestLength;

pub const fileHash = dispatch.fileHash;
pub const stringHash = dispatch.stringHash;

pub const getDemoOptionsArray = dispatch.getDemoOptionsArray;
