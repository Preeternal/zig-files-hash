const std = @import("std");

pub const OutputCase = enum { lower, upper };
pub const BoundaryMode = enum { separators, camel };

pub fn writeSnake(w: *std.Io.Writer, name: []const u8, output_case: OutputCase, boundary_mode: BoundaryMode) !void {
    var wrote_any = false;
    var last_was_separator = false;
    var prev_was_lower_or_digit = false;

    for (name) |byte| {
        if (std.ascii.isAlphanumeric(byte)) {
            if (boundary_mode == .camel and std.ascii.isUpper(byte) and wrote_any and !last_was_separator and prev_was_lower_or_digit) {
                try w.writeByte('_');
            }

            const out = switch (output_case) {
                .lower => std.ascii.toLower(byte),
                .upper => std.ascii.toUpper(byte),
            };
            try w.writeByte(out);

            wrote_any = true;
            last_was_separator = false;
            prev_was_lower_or_digit = std.ascii.isLower(byte) or std.ascii.isDigit(byte);
        } else if (wrote_any and !last_was_separator) {
            try w.writeByte('_');
            last_was_separator = true;
            prev_was_lower_or_digit = false;
        }
    }
}

pub fn writeMessageFromCamel(w: *std.Io.Writer, name: []const u8) !void {
    var wrote_any = false;
    var last_was_separator = false;
    var prev_was_lower_or_digit = false;

    for (name) |byte| {
        if (std.ascii.isAlphanumeric(byte)) {
            if (std.ascii.isUpper(byte) and wrote_any and !last_was_separator and prev_was_lower_or_digit) {
                try w.writeByte(' ');
            }

            try w.writeByte(std.ascii.toLower(byte));

            wrote_any = true;
            last_was_separator = false;
            prev_was_lower_or_digit = std.ascii.isLower(byte) or std.ascii.isDigit(byte);
        } else if (wrote_any and !last_was_separator) {
            try w.writeByte(' ');
            last_was_separator = true;
            prev_was_lower_or_digit = false;
        }
    }
}
