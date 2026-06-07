const std = @import("std");
const render_header = @import("render_header.zig");
const render_zig = @import("render_zig.zig");

const generated_zig_path = "src/c_api_generated.zig";
const generated_header_path = "src/zig_files_hash_c_api_generated.h";

pub fn main() !void {
    const allocator = std.heap.smp_allocator;

    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var zig_source: std.Io.Writer.Allocating = .init(allocator);
    defer zig_source.deinit();
    try render_zig.render(&zig_source.writer);
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = generated_zig_path,
        .data = zig_source.written(),
    });

    var header_source: std.Io.Writer.Allocating = .init(allocator);
    defer header_source.deinit();
    try render_header.render(&header_source.writer);
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = generated_header_path,
        .data = header_source.written(),
    });
}
