// SPDX-License-Identifier: CC0-1.0

//! Internal plumbing: the integer mixers everything else is built from.
//!
//! A mixer stirs one integer into another. It is a bijection, so mixing never
//! loses information, and flipping any single input bit flips about half the
//! output bits - the property a hash needs and that `x * 31 + y` has not.
//!
//! `Murmur3` finishes with `fmix32` and `combine` uses `fmix64`, which is why
//! both live here rather than in either. Not exported from `root.zig`.

const std = @import("std");
const testing = std.testing;

/// The 32-bit golden ratio, `2^32 / phi` rounded to an odd number - odd so
/// that multiplication stays invertible.
pub const golden32: u32 = 0x9E3779B9;

/// The 64-bit one, `2^64 / phi`.
pub const golden64: u64 = 0x9E3779B97F4A7C15;

/// MurmurHash3's 32-bit finalizer: shift, multiply, shift, multiply, shift.
pub fn fmix32(value: u32) u32 {
    var h = value;
    h ^= h >> 16;
    h *%= 0x85EBCA6B;
    h ^= h >> 13;
    h *%= 0xC2B2AE35;
    h ^= h >> 16;
    return h;
}

/// MurmurHash3's 64-bit finalizer, the one SplitMix64 also ends on.
pub fn fmix64(value: u64) u64 {
    var h = value;
    h ^= h >> 33;
    h *%= 0xFF51AFD7ED558CCD;
    h ^= h >> 33;
    h *%= 0xC4CEB9FE1A85EC53;
    h ^= h >> 33;
    return h;
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

test "zero stays zero" {
    // Shifts and multiplies only, so zero is a fixed point. Anything hashing an
    // empty message starts somewhere else.
    try testing.expectEqual(@as(u32, 0), fmix32(0));
    try testing.expectEqual(@as(u64, 0), fmix64(0));
}

test "consecutive inputs land far apart" {
    // The point of a mixer: 0, 1, 2, 3 must not come out as neighbours.
    var seen: std.AutoHashMapUnmanaged(u64, void) = .empty;
    defer seen.deinit(testing.allocator);

    for (0..1000) |i| {
        const h = fmix64(i);
        // A bijection cannot repeat itself.
        try testing.expect(!seen.contains(h));
        try seen.put(testing.allocator, h, {});
        if (i != 0) {
            // Neighbouring inputs are nowhere near neighbouring outputs.
            try testing.expect(@max(h, fmix64(i - 1)) - @min(h, fmix64(i - 1)) > 1000);
        }
    }
}

test "one input bit flips about half the output bits" {
    var prng: std.Random.DefaultPrng = .init(0x5EED);
    const random = prng.random();

    var flipped: [64]usize = @splat(0);
    const rounds = 512;
    for (0..rounds) |_| {
        const value = random.int(u64);
        const base = fmix64(value);
        for (0..64) |bit| {
            const changed = fmix64(value ^ (@as(u64, 1) << @intCast(bit)));
            flipped[bit] += @popCount(base ^ changed);
        }
    }

    // 32 of 64 bits is the ideal; anything in this band is a healthy avalanche.
    for (flipped) |total| {
        const average = @as(f64, @floatFromInt(total)) / rounds;
        try testing.expect(average > 28.0 and average < 36.0);
    }
}

test "fmix32 avalanches too" {
    var prng: std.Random.DefaultPrng = .init(0x5EED);
    const random = prng.random();

    var total: usize = 0;
    const rounds = 512;
    for (0..rounds) |_| {
        const value = random.int(u32);
        const base = fmix32(value);
        for (0..32) |bit| {
            total += @popCount(base ^ fmix32(value ^ (@as(u32, 1) << @intCast(bit))));
        }
    }

    const average = @as(f64, @floatFromInt(total)) / (rounds * 32);
    try testing.expect(average > 14.0 and average < 18.0);
}
