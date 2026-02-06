const std = @import("std");

pub fn main() void {
    const user = User{
        .power = 9001,
        .name = "Пётр",
    };

    std.debug.print("{s} обладает силой {d}\n", .{ user.name, user.power });
    std.debug.print("Size of []const u8 = {d}\n", .{@sizeOf([]const u8)});
    std.debug.print("Size of u8 = {d}\n", .{@sizeOf(u8)});
    std.debug.print("Size of u64 = {d}\n", .{@sizeOf(u64)});
    std.debug.print("Len of Пётр = {d}\n", .{"Пётр".len});
    std.debug.print("sizeOf(User) = {d}\n", .{@sizeOf(User)});

    std.debug.print("bits u47 = {d}\n", .{@bitSizeOf(u47)});
    std.debug.print("size u47 = {d}\n", .{@sizeOf(u47)});
    std.debug.print("align u47 = {d}\n", .{@alignOf(u47)});

    const sum = add(8999, 2);
    std.debug.print("8999 + 2 = {d}\n", .{sum});

    // const a = [_]i32{ 1, 2, 3, 4, 5 };
    // const b = a[1..4];

    // std.debug.print("a  = {any}\n", .{a});
    // std.debug.print("b  = {any}\n", .{b});
    // std.debug.print("TypeOf(a)  = {s}\n", .{@typeName(@TypeOf(a))});
    // std.debug.print("TypeOf(b)  = {s}\n", .{@typeName(@TypeOf(b))});
    // std.debug.print("sizeOf(b)  = {d}\n", .{@sizeOf(@TypeOf(b))});
    // std.debug.print("b points to array len = {d}\n\n", .{b.*.len});

    // const a1 = [_]i32{ 1, 2, 3, 4, 5 };
    // var end: usize = 4;
    // end += 0; // keep `end` a runtime variable so the result stays a slice
    // const b1 = a1[1..end];

    // std.debug.print("a1 = {any}\n", .{a1});
    // std.debug.print("b1 = {any}\n", .{b1});
    // std.debug.print("TypeOf(b1) = {s}\n", .{@typeName(@TypeOf(b1))});
    // std.debug.print("sizeOf(b1) = {d}\n", .{@sizeOf(@TypeOf(b1))});
    // std.debug.print("b1.len     = {d}\n", .{b1.len});
    // // `b1.ptr` is a many-pointer (`[*]const i32`), while `&a1[1]` is a single-item pointer (`*const i32`).
    // // Easiest way to compare them is by comparing their addresses.
    // std.debug.print("b1.ptr==&a1[1] ? {any}\n", .{
    //     @intFromPtr(b1.ptr) == @intFromPtr(&a1[1]),
    // });

    // массив из трёх булевских значений с false на конце
    const aa = [3:false]bool{ false, true, false };

    std.debug.print("aa = {any}\n", .{aa});

    // эта строка более сложная, объясняться не будет
    std.debug.print("{any}\n", .{std.mem.asBytes(&aa).*});
}

pub const User = struct {
    power: u64 = 0,
    name: []const u8,
};

fn add(a: i64, b: i64) i64 {
    return a + b;
}

const some = 3;
var other = union(enum) {
    A: u8,
    B: u16,
}{ .A = 42 };

// test "sizes" {
//     _ = std.math.maxInt(u64);
//     // try std.testing.expect(@sizeOf(User) == 2);
//     // try std.testing.expect(@sizeOf(u64) == 8);
//     // try std.testing.expect(@sizeOf([]const u8) == 8);
// }
