// SPDX-License-Identifier: CC0-1.0

//! Hash combine: several hashes into one.
//!
//! Adding hashes makes `(1, 2)` and `(2, 1)` equal, xoring lets a value cancel
//! itself, and `31 * h + x` leaves the low bits where they were. So `step`
//! runs every value through a full 64-bit mixer and multiplies the state by
//! the golden ratio, which makes the result behave like a hash of the whole
//! tuple however weak the parts were.
//!
//!   `pair`, `all`, `Combiner`   order matters
//!   `unordered`, `Unordered`    order does not
//!
//! Everything here works in `u64`; widen a narrower hash on the way in.

const std = @import("std");
const testing = std.testing;

const mix = @import("mix.zig");

/// The state a combination starts from: the hash of nothing at all.
pub const empty: u64 = mix.golden64;

/// Mix `value` into `state`, and return the new state.
///
/// The result is already a finished hash - there is no separate finalize step
/// - so a running combination can be read at any point.
pub fn step(state: u64, value: u64) u64 {
    // The value is mixed first, so a weak input does not carry its structure
    // into the result; multiplying the state makes position matter.
    return mix.fmix64((state *% mix.golden64) ^ mix.fmix64(value));
}

/// Two hashes into one. Order matters: `pair(a, b)` is not `pair(b, a)`.
pub fn pair(a: u64, b: u64) u64 {
    return step(step(empty, a), b);
}

/// Any number of hashes into one, in the order given.
pub fn all(hashes: []const u64) u64 {
    var state = empty;
    for (hashes) |h| state = step(state, h);
    return state;
}

/// A running ordered combination, for when the values arrive over time or
/// come from different places.
///
/// ```zig
/// var c: combine.Combiner = .init();
/// c.add(hashing.hashBytes(name));
/// c.add(@as(u64, version));
/// for (tags) |tag| c.add(hashing.hashBytes(tag));
/// const digest = c.final();
/// ```
pub const Combiner = struct {
    state: u64,

    pub fn init() Combiner {
        return .{ .state = empty };
    }

    /// Start somewhere other than `empty`, so that two combinations of the
    /// same values under different seeds disagree.
    pub fn initSeed(seed: u64) Combiner {
        return .{ .state = seed };
    }

    pub fn add(self: *Combiner, value: u64) void {
        self.state = step(self.state, value);
    }

    pub fn addAll(self: *Combiner, values: []const u64) void {
        for (values) |value| self.add(value);
    }

    /// The combination so far. Every `add` leaves the state mixed, so this
    /// only reads it out - combining can carry on afterwards.
    pub fn final(self: Combiner) u64 {
        return self.state;
    }
};

/// An order-independent combination: a running total of mixed values.
///
/// Addition is commutative and associative, so members can arrive in any order
/// and `remove` undoes an `add` - which is what a changing set, or a directory
/// hash that has to be patched rather than recomputed, wants.
///
/// A multiset, not a set: adding the same value twice differs from adding it
/// once. Deduplicate first if that is what you meant.
pub const Unordered = struct {
    total: u64 = 0,
    count: u64 = 0,

    pub fn init() Unordered {
        return .{};
    }

    pub fn add(self: *Unordered, value: u64) void {
        // Mixed on the way in: sums of nearby numbers are nearby numbers.
        self.total +%= mix.fmix64(value);
        self.count +%= 1;
    }

    pub fn addAll(self: *Unordered, values: []const u64) void {
        for (values) |value| self.add(value);
    }

    /// Take a value back out. Removing what was never added is not an error:
    /// it leaves a state no sequence of adds would have produced.
    pub fn remove(self: *Unordered, value: u64) void {
        self.total -%= mix.fmix64(value);
        self.count -%= 1;
    }

    /// The combination so far. The count goes in here rather than the running
    /// total, so `remove` restores the state exactly and an empty set does not
    /// agree with a set holding one zero.
    pub fn final(self: Unordered) u64 {
        return mix.fmix64(empty ^ self.total ^ (self.count *% mix.golden64));
    }
};

/// Any number of hashes into one, ignoring their order.
pub fn unordered(hashes: []const u64) u64 {
    var u: Unordered = .init();
    u.addAll(hashes);
    return u.final();
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

test "order matters, and does not" {
    const a: u64 = 0x1111111111111111;
    const b: u64 = 0x2222222222222222;
    const c: u64 = 0x3333333333333333;

    try testing.expect(pair(a, b) != pair(b, a));
    try testing.expect(all(&.{ a, b, c }) != all(&.{ c, b, a }));

    try testing.expectEqual(unordered(&.{ a, b, c }), unordered(&.{ c, a, b }));
    try testing.expectEqual(unordered(&.{ a, b, c }), unordered(&.{ b, c, a }));

    // Even so, the two are not the same function.
    try testing.expect(all(&.{ a, b, c }) != unordered(&.{ a, b, c }));
}

test "the empty combination, and the one-value one" {
    try testing.expectEqual(empty, all(&.{}));
    try testing.expectEqual(step(empty, 7), all(&.{7}));
    try testing.expectEqual(all(&.{ 1, 2 }), pair(1, 2));

    // A hash of nothing should not be zero: zero is what uninitialised memory
    // and a forgotten call both look like.
    try testing.expect(all(&.{}) != 0);
    try testing.expect(unordered(&.{}) != 0);

    // An empty set and a set holding one zero are different sets.
    try testing.expect(unordered(&.{}) != unordered(&.{0}));
}

test "Combiner walks in step with all" {
    const values = [_]u64{ 5, 0, 0xFFFF_FFFF_FFFF_FFFF, 1 << 63, 42 };

    var c: Combiner = .init();
    c.addAll(&values);
    try testing.expectEqual(all(&values), c.final());

    // Reading it does not end it, and adding in pieces is adding.
    var piecewise: Combiner = .init();
    piecewise.add(values[0]);
    _ = piecewise.final();
    piecewise.addAll(values[1..]);
    try testing.expectEqual(all(&values), piecewise.final());

    // A seed moves everything.
    var seeded: Combiner = .initSeed(1);
    seeded.addAll(&values);
    try testing.expect(seeded.final() != all(&values));
}

test "Unordered takes values back out" {
    const values = [_]u64{ 11, 22, 33, 44 };

    var set: Unordered = .init();
    set.addAll(&values);
    const four = set.final();

    set.add(55);
    try testing.expect(set.final() != four);
    set.remove(55);
    try testing.expectEqual(four, set.final());

    // Removing something that was never there is allowed, and putting it back
    // restores the state - which is what makes an incremental index possible.
    set.remove(99);
    try testing.expect(set.final() != four);
    set.add(99);
    try testing.expectEqual(four, set.final());

    // It is a multiset: twice is not once.
    try testing.expect(unordered(&.{ 1, 1 }) != unordered(&.{1}));
}

test "weak inputs still come out spread" {
    // The case that catches naive combining: small integers, in order. If the
    // combination leaked its inputs, these would cluster.
    var seen: std.AutoHashMapUnmanaged(u64, void) = .empty;
    defer seen.deinit(testing.allocator);

    for (0..256) |i| {
        for (0..256) |j| {
            const combined = pair(i, j);
            try testing.expect(!seen.contains(combined));
            try seen.put(testing.allocator, combined, {});
        }
    }
    try testing.expectEqual(@as(usize, 256 * 256), seen.count());
}

test "a changed value changes the whole result" {
    var prng: std.Random.DefaultPrng = .init(0xCAFE);
    const random = prng.random();

    var total: usize = 0;
    const rounds = 256;
    for (0..rounds) |_| {
        const a = random.int(u64);
        const b = random.int(u64);
        const base = pair(a, b);
        for (0..64) |bit| {
            total += @popCount(base ^ pair(a, b ^ (@as(u64, 1) << @intCast(bit))));
        }
    }

    // 32 of 64 is the ideal. A combination that merely added or xored its
    // inputs would score one.
    const average = @as(f64, @floatFromInt(total)) / (rounds * 64);
    try testing.expect(average > 30.0 and average < 34.0);
}

test "frozen" {
    // The construction is part of the format the moment anything stores a
    // combined hash. These pin it.
    try testing.expectEqual(@as(u64, 0x9E3779B97F4A7C15), empty);
    try testing.expectEqual(@as(u64, 0xB18793696892B468), pair(1, 2));
    try testing.expectEqual(@as(u64, 0x1D3C257254114B29), all(&.{ 1, 2, 3 }));
    try testing.expectEqual(@as(u64, 0x31463BA4ACD51A67), unordered(&.{ 1, 2, 3 }));
}
