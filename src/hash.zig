// SPDX-License-Identifier: CC0-1.0

//! Non-cryptographic hashing: bytes in, one fixed-width number out.
//!
//! Three algorithms, none of them secret-keeping. They are for hash tables,
//! caches, dirty checks and content addressing - not for signatures, and not
//! for anything an attacker gets to choose the input of.
//!
//!   `Fnv1a32` / `Fnv1a64`  tiny and byte at a time, good on short keys
//!   `Murmur3`              the classic 32-bit workhorse
//!   `Xx64`                 fast on long input, 64 bits out
//!
//! All of them answer to the same calls, so swapping one for another is a
//! change of name and nothing else:
//!
//!   * `Digest`                   the type that comes out
//!   * `hash` / `hashSeed`        one shot, over a slice
//!   * `init` / `initSeed`        start a running hash
//!   * `update`                   feed it more bytes, any number of times
//!   * `final`                    read the digest out
//!
//! `final` takes the hasher by value, so reading a digest does not end the
//! hash. `updateValue` feeds a whole Zig value into any of them, and `Stream`
//! turns one into a `std.Io.Writer`. Nothing here allocates.

const std = @import("std");
const testing = std.testing;

const mix = @import("mix.zig");

// -------------------------------------------------------------------------
// FNV-1a
// -------------------------------------------------------------------------

/// FNV-1a, 32 bits. A xor and a multiply per byte, no table and no buffer, so
/// the hasher is four bytes of state. For short keys; on long input `Xx64` is
/// several times faster per byte.
pub const Fnv1a32 = Fnv1a(u32, 0x811C9DC5, 0x01000193);

/// FNV-1a, 64 bits. Worth the extra four bytes wherever 32 would start
/// colliding: a few tens of thousands of keys is already a coin flip there.
pub const Fnv1a64 = Fnv1a(u64, 0xCBF29CE484222325, 0x00000100000001B3);

fn Fnv1a(comptime T: type, comptime offset_basis: T, comptime prime: T) type {
    return struct {
        const Self = @This();

        /// What `final` and `hash` return.
        pub const Digest = T;

        state: T,

        /// A hasher over no bytes yet, starting from the FNV offset basis.
        pub fn init() Self {
            return .{ .state = offset_basis };
        }

        /// The same, starting from `seed`. Two hashers with different seeds
        /// disagree about everything - what a table wants on the day its keys
        /// turn out to collide.
        pub fn initSeed(seed: T) Self {
            return .{ .state = seed };
        }

        /// Feed in more bytes. Where the input is split across calls makes no
        /// difference: only the bytes and their order matter.
        pub fn update(self: *Self, bytes: []const u8) void {
            for (bytes) |byte| {
                self.state ^= byte;
                self.state *%= prime;
            }
        }

        /// The digest of everything fed in so far. Takes the hasher by value,
        /// so hashing can carry on afterwards.
        pub fn final(self: Self) Digest {
            return self.state;
        }

        /// One shot over a slice.
        pub fn hash(bytes: []const u8) Digest {
            var self: Self = .init();
            self.update(bytes);
            return self.final();
        }

        /// One shot, seeded.
        pub fn hashSeed(seed: T, bytes: []const u8) Digest {
            var self: Self = .initSeed(seed);
            self.update(bytes);
            return self.final();
        }
    };
}

// -------------------------------------------------------------------------
// MurmurHash3
// -------------------------------------------------------------------------

/// MurmurHash3, the 32-bit variant. Four bytes at a time through two
/// multiplies and a rotate, then `mix.fmix32` to spread the last block over
/// the whole word.
///
/// For when 32 bits is what the format wants: it distributes better than
/// FNV-1a on structured input - paths sharing a prefix, keys differing in one
/// character.
pub const Murmur3 = struct {
    const c1: u32 = 0xCC9E2D51;
    const c2: u32 = 0x1B873593;

    /// What `final` and `hash` return.
    pub const Digest = u32;

    state: u32,
    /// Bytes that have not filled a four-byte block yet.
    tail: [4]u8,
    tail_len: usize,
    /// Every byte ever fed in. Murmur folds the length into the digest, which
    /// is part of what keeps "ab" and "ab\x00" apart.
    total: usize,

    pub fn init() Murmur3 {
        return .initSeed(0);
    }

    pub fn initSeed(seed: u32) Murmur3 {
        return .{ .state = seed, .tail = undefined, .tail_len = 0, .total = 0 };
    }

    pub fn update(self: *Murmur3, bytes: []const u8) void {
        self.total +%= bytes.len;
        var rest = bytes;

        // Top up a part-filled block first, so that where the caller split the
        // input makes no difference to the digest.
        if (self.tail_len != 0) {
            const wanted = @min(4 - self.tail_len, rest.len);
            @memcpy(self.tail[self.tail_len..][0..wanted], rest[0..wanted]);
            self.tail_len += wanted;
            rest = rest[wanted..];
            if (self.tail_len < 4) return;
            self.block(std.mem.readInt(u32, &self.tail, .little));
            self.tail_len = 0;
        }

        while (rest.len >= 4) : (rest = rest[4..]) {
            self.block(std.mem.readInt(u32, rest[0..4], .little));
        }

        @memcpy(self.tail[0..rest.len], rest);
        self.tail_len = rest.len;
    }

    /// One full four-byte block.
    fn block(self: *Murmur3, value: u32) void {
        var k = value;
        k *%= c1;
        k = std.math.rotl(u32, k, 15);
        k *%= c2;

        self.state ^= k;
        self.state = std.math.rotl(u32, self.state, 13);
        self.state = self.state *% 5 +% 0xE6546B64;
    }

    pub fn final(self: Murmur3) Digest {
        var h = self.state;

        // The leftover bytes go through the block mixer but not the rotate,
        // which is what makes them a tail rather than a short block.
        if (self.tail_len != 0) {
            var k: u32 = 0;
            for (self.tail[0..self.tail_len], 0..) |byte, i| {
                k |= @as(u32, byte) << @intCast(8 * i);
            }
            k *%= c1;
            k = std.math.rotl(u32, k, 15);
            k *%= c2;
            h ^= k;
        }

        h ^= @as(u32, @truncate(self.total));
        return mix.fmix32(h);
    }

    pub fn hash(bytes: []const u8) Digest {
        return hashSeed(0, bytes);
    }

    pub fn hashSeed(seed: u32, bytes: []const u8) Digest {
        var self: Murmur3 = .initSeed(seed);
        self.update(bytes);
        return self.final();
    }
};

// -------------------------------------------------------------------------
// xxHash64
// -------------------------------------------------------------------------

/// xxHash64: four independent lanes, 32 bytes a round, merged at the end.
///
/// The default when there is nothing special about the input: fastest of the
/// three past a few dozen bytes, and wide enough that collisions stay a
/// curiosity - a million keys collide with probability about one in 37 million.
pub const Xx64 = struct {
    const prime1: u64 = 0x9E3779B185EBCA87;
    const prime2: u64 = 0xC2B2AE3D27D4EB4F;
    const prime3: u64 = 0x165667B19E3779F9;
    const prime4: u64 = 0x85EBCA77C2B2AE63;
    const prime5: u64 = 0x27D4EB2F165667C5;

    /// What `final` and `hash` return.
    pub const Digest = u64;

    /// The four lanes, each hashing every fourth eight-byte word.
    acc: [4]u64,
    seed: u64,
    /// Bytes that have not filled a 32-byte round yet.
    buf: [32]u8,
    buf_len: usize,
    total: usize,

    pub fn init() Xx64 {
        return .initSeed(0);
    }

    pub fn initSeed(seed: u64) Xx64 {
        return .{
            .acc = .{
                seed +% prime1 +% prime2,
                seed +% prime2,
                seed,
                seed -% prime1,
            },
            .seed = seed,
            .buf = undefined,
            .buf_len = 0,
            .total = 0,
        };
    }

    pub fn update(self: *Xx64, bytes: []const u8) void {
        self.total +%= bytes.len;
        var rest = bytes;

        if (self.buf_len != 0) {
            const wanted = @min(32 - self.buf_len, rest.len);
            @memcpy(self.buf[self.buf_len..][0..wanted], rest[0..wanted]);
            self.buf_len += wanted;
            rest = rest[wanted..];
            if (self.buf_len < 32) return;
            self.round(&self.buf);
            self.buf_len = 0;
        }

        while (rest.len >= 32) : (rest = rest[32..]) {
            self.round(rest[0..32]);
        }

        @memcpy(self.buf[0..rest.len], rest);
        self.buf_len = rest.len;
    }

    /// One 32-byte round: every lane takes its own eight-byte word.
    fn round(self: *Xx64, block: *const [32]u8) void {
        for (&self.acc, 0..) |*lane, i| {
            lane.* = accumulate(lane.*, std.mem.readInt(u64, block[i * 8 ..][0..8], .little));
        }
    }

    fn accumulate(acc: u64, input: u64) u64 {
        return std.math.rotl(u64, acc +% input *% prime2, 31) *% prime1;
    }

    fn mergeLane(acc: u64, lane: u64) u64 {
        return (acc ^ accumulate(0, lane)) *% prime1 +% prime4;
    }

    pub fn final(self: Xx64) Digest {
        var h: u64 = undefined;
        if (self.total >= 32) {
            // Four lanes into one word: rotated by different amounts so they
            // cannot cancel, then merged one at a time.
            h = std.math.rotl(u64, self.acc[0], 1) +%
                std.math.rotl(u64, self.acc[1], 7) +%
                std.math.rotl(u64, self.acc[2], 12) +%
                std.math.rotl(u64, self.acc[3], 18);
            for (self.acc) |lane| h = mergeLane(h, lane);
        } else {
            // Short input never filled a round, so the lanes were never used.
            h = self.seed +% prime5;
        }
        h +%= self.total;

        // The tail, in eight-, four- and one-byte steps.
        var rest: []const u8 = self.buf[0..self.buf_len];
        while (rest.len >= 8) : (rest = rest[8..]) {
            h ^= accumulate(0, std.mem.readInt(u64, rest[0..8], .little));
            h = std.math.rotl(u64, h, 27) *% prime1 +% prime4;
        }
        if (rest.len >= 4) {
            h ^= @as(u64, std.mem.readInt(u32, rest[0..4], .little)) *% prime1;
            h = std.math.rotl(u64, h, 23) *% prime2 +% prime3;
            rest = rest[4..];
        }
        for (rest) |byte| {
            h ^= @as(u64, byte) *% prime5;
            h = std.math.rotl(u64, h, 11) *% prime1;
        }

        return avalanche(h);
    }

    fn avalanche(value: u64) u64 {
        var h = value;
        h ^= h >> 33;
        h *%= prime2;
        h ^= h >> 29;
        h *%= prime3;
        h ^= h >> 32;
        return h;
    }

    pub fn hash(bytes: []const u8) Digest {
        return hashSeed(0, bytes);
    }

    pub fn hashSeed(seed: u64, bytes: []const u8) Digest {
        var self: Xx64 = .initSeed(seed);
        self.update(bytes);
        return self.final();
    }
};

// -------------------------------------------------------------------------
// Hashing values
// -------------------------------------------------------------------------

/// What a pointer contributes to a hash.
pub const Follow = enum {
    /// The address, not what is at it. Two equal strings in two places hash
    /// differently; this is identity, not equality.
    address,
    /// What it points at. Two equal strings hash the same wherever they live,
    /// which is what a table keyed by content needs.
    contents,
};

pub const ValueOptions = struct {
    follow: Follow = .contents,
};

/// Feed `value` into `hasher`, field by field.
///
/// Integers go in little-endian at their declared width, so a value hashes the
/// same on a big-endian machine. Padding is never hashed: fields are walked
/// rather than reinterpreted. Optionals contribute a tag byte, unions their
/// tag, and slices their length - so `.{ "ab", "c" }` and `.{ "a", "bc" }` do
/// not land on one digest.
///
/// Floats are hashed by bit pattern, the only stable choice, which means `0.0`
/// and `-0.0` differ. Types with no run-time content contribute nothing, and
/// anything with no defensible answer - a many-item pointer, an untagged union
/// - is a compile error rather than a guess.
pub fn updateValue(hasher: anytype, value: anytype, comptime options: ValueOptions) void {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .void, .null, .undefined => {},
        .bool => updateValue(hasher, @intFromBool(value), options),
        .comptime_int => updateValue(hasher, @as(i128, value), options),
        .comptime_float => updateValue(hasher, @as(f64, value), options),
        .int => |info| {
            if (info.bits == 0) return;
            const Narrow = std.meta.Int(.unsigned, info.bits);
            const width = comptime std.mem.alignForward(u16, info.bits, 8);
            const Wide = std.meta.Int(.unsigned, width);
            var buf: [@divExact(width, 8)]u8 = undefined;
            std.mem.writeInt(Wide, &buf, @as(Narrow, @bitCast(value)), .little);
            hasher.update(&buf);
        },
        .float => |info| updateValue(
            hasher,
            @as(std.meta.Int(.unsigned, info.bits), @bitCast(value)),
            options,
        ),
        .@"enum" => updateValue(hasher, @intFromEnum(value), options),
        .error_set => updateValue(hasher, @intFromError(value), options),
        .error_union => if (value) |payload| {
            updateValue(hasher, true, options);
            updateValue(hasher, payload, options);
        } else |err| {
            updateValue(hasher, false, options);
            updateValue(hasher, err, options);
        },
        .optional => if (value) |payload| {
            updateValue(hasher, true, options);
            updateValue(hasher, payload, options);
        } else {
            updateValue(hasher, false, options);
        },
        .array => for (value) |element| updateValue(hasher, element, options),
        .vector => |info| {
            inline for (0..info.len) |i| updateValue(hasher, value[i], options);
        },
        .@"struct" => |info| {
            // A packed struct is one integer wearing field names, so hash it
            // as that integer: one pass instead of one per field.
            if (info.backing_integer) |Backing| {
                updateValue(hasher, @as(Backing, @bitCast(value)), options);
            } else {
                inline for (info.fields) |field| {
                    updateValue(hasher, @field(value, field.name), options);
                }
            }
        },
        .@"union" => |info| {
            const Tag = info.tag_type orelse @compileError(
                "cannot hash the untagged union " ++ @typeName(T) ++
                    ": there is no way to tell which field is live",
            );
            updateValue(hasher, @as(Tag, value), options);
            switch (value) {
                inline else => |payload| updateValue(hasher, payload, options),
            }
        },
        .pointer => |info| switch (info.size) {
            .one => switch (options.follow) {
                .address => updateValue(hasher, @intFromPtr(value), options),
                .contents => updateValue(hasher, value.*, options),
            },
            .slice => switch (options.follow) {
                .address => {
                    updateValue(hasher, @intFromPtr(value.ptr), options);
                    updateValue(hasher, value.len, options);
                },
                .contents => {
                    // Length first, so a run of slices cannot be re-cut into
                    // a different run with the same digest.
                    updateValue(hasher, value.len, options);
                    if (info.child == u8) {
                        hasher.update(value);
                    } else {
                        for (value) |element| updateValue(hasher, element, options);
                    }
                },
            },
            .many, .c => switch (options.follow) {
                .address => updateValue(hasher, @intFromPtr(value), options),
                .contents => @compileError(
                    "cannot follow the many-item pointer " ++ @typeName(T) ++
                        ": it does not know its own length. Slice it first, or hash " ++
                        "it with .follow = .address",
                ),
            },
        },
        else => @compileError("cannot hash " ++ @typeName(T)),
    }
}

/// One shot: hash a whole value with `Algorithm`.
///
/// ```zig
/// const Point = struct { x: i32, y: i32 };
/// const h = hash.hashValue(hash.Xx64, Point{ .x = 3, .y = 4 }, .{});
/// ```
pub fn hashValue(
    comptime Algorithm: type,
    value: anytype,
    comptime options: ValueOptions,
) Algorithm.Digest {
    var hasher: Algorithm = .init();
    updateValue(&hasher, value, options);
    return hasher.final();
}

/// The same, from a seed.
pub fn hashValueSeed(
    comptime Algorithm: type,
    seed: Algorithm.Digest,
    value: anytype,
    comptime options: ValueOptions,
) Algorithm.Digest {
    var hasher: Algorithm = .initSeed(seed);
    updateValue(&hasher, value, options);
    return hasher.final();
}

// -------------------------------------------------------------------------
// Hashing a stream
// -------------------------------------------------------------------------

/// A `std.Io.Writer` that hashes everything written to it and keeps nothing.
///
/// Anything that writes to a stream can be hashed this way - a formatter, a
/// file copy, a compressor - with no buffer in between and no second pass:
///
/// ```zig
/// var stream: hash.Stream(hash.Xx64) = .init(.init());
/// try stream.writer().print("{d} {s}\n", .{ id, name });
/// const digest = stream.final();
/// ```
///
/// Works with any hasher of the right shape, `crc32.Ieee` included.
pub fn Stream(comptime Hasher: type) type {
    return struct {
        const Self = @This();

        pub const Digest = Hasher.Digest;

        hasher: Hasher,
        /// Reach it through `writer()` rather than touching it here.
        io_writer: std.Io.Writer,

        /// Wrap a hasher. It is copied in, so seed it before handing it over.
        pub fn init(hasher: Hasher) Self {
            return .{
                .hasher = hasher,
                // No buffer of its own: bytes go straight into the hasher.
                .io_writer = .{ .buffer = &.{}, .vtable = &writer_vtable },
            };
        }

        /// The writer to hand out. It borrows the stream, so do not move or
        /// copy the stream while the pointer is outstanding.
        pub fn writer(self: *Self) *std.Io.Writer {
            return &self.io_writer;
        }

        /// The digest of everything written so far. Writing may carry on.
        pub fn final(self: *const Self) Digest {
            return self.hasher.final();
        }

        const writer_vtable: std.Io.Writer.VTable = .{ .drain = drain };

        fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
            const self: *Self = @alignCast(@fieldParentPtr("io_writer", w));

            // The interface may have staged bytes of its own; those come first
            // and do not count towards the returned total.
            const buffered = w.buffer[0..w.end];
            if (buffered.len != 0) {
                self.hasher.update(buffered);
                w.end = 0;
            }
            if (data.len == 0) return 0;

            var consumed: usize = 0;
            for (data[0 .. data.len - 1]) |bytes| {
                self.hasher.update(bytes);
                consumed += bytes.len;
            }
            // The last slice stands for `splat` copies of itself.
            const pattern = data[data.len - 1];
            for (0..splat) |_| self.hasher.update(pattern);
            consumed += pattern.len * splat;
            return consumed;
        }
    };
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

test "known digests" {
    // Frozen. These are the published values for each algorithm, and they are
    // what a reader of a file written by this library will compute.
    try testing.expectEqual(@as(u32, 0x811C9DC5), Fnv1a32.hash(""));
    try testing.expectEqual(@as(u32, 0xE40C292C), Fnv1a32.hash("a"));
    try testing.expectEqual(@as(u32, 0x1A47E90B), Fnv1a32.hash("abc"));
    try testing.expectEqual(@as(u32, 0xBB86B11C), Fnv1a32.hash("123456789"));

    try testing.expectEqual(@as(u64, 0xCBF29CE484222325), Fnv1a64.hash(""));
    try testing.expectEqual(@as(u64, 0xAF63DC4C8601EC8C), Fnv1a64.hash("a"));
    try testing.expectEqual(@as(u64, 0xE71FA2190541574B), Fnv1a64.hash("abc"));
    try testing.expectEqual(@as(u64, 0x2DCBCCE86FCE9934), Fnv1a64.hash("message digest"));

    try testing.expectEqual(@as(u32, 0x00000000), Murmur3.hash(""));
    try testing.expectEqual(@as(u32, 0x3C2569B2), Murmur3.hash("a"));
    try testing.expectEqual(@as(u32, 0xB3DD93FA), Murmur3.hash("abc"));
    try testing.expectEqual(@as(u32, 0xB4FEF382), Murmur3.hash("123456789"));
    try testing.expectEqual(@as(u32, 0xA6BC0EC0), Murmur3.hashSeed(0x1234, "fluxion"));

    try testing.expectEqual(@as(u64, 0xEF46DB3751D8E999), Xx64.hash(""));
    try testing.expectEqual(@as(u64, 0xD24EC4F1A98C6E5B), Xx64.hash("a"));
    try testing.expectEqual(@as(u64, 0x44BC2CF5AD770999), Xx64.hash("abc"));
    try testing.expectEqual(@as(u64, 0x8CB841DB40E6AE83), Xx64.hash("123456789"));
    try testing.expectEqual(@as(u64, 0x7695D4A839645C48), Xx64.hashSeed(0xDEADBEEF, "fluxion"));

    // Longer than one 32-byte round, so xxHash64 uses all four lanes.
    const long = "0123456789012345678901234567890123456789012345678901234567890123456789";
    try testing.expectEqual(@as(u64, 0x4916A0F3F0E1C781), Xx64.hash(long));
    try testing.expectEqual(@as(u32, 0x4EEA03A8), Murmur3.hash(long));
}

test "every byte value" {
    var all: [256]u8 = undefined;
    for (&all, 0..) |*byte, i| byte.* = @intCast(i);

    try testing.expectEqual(@as(u64, 0x4242DC5249C33625), Fnv1a64.hash(&all));
    try testing.expectEqual(@as(u32, 0xE40A0E56), Murmur3.hash(&all));
    try testing.expectEqual(@as(u64, 0x1FACBE8406CD904B), Xx64.hash(&all));
}

test "where the input is split makes no difference" {
    var prng: std.Random.DefaultPrng = .init(0xF10D);
    const random = prng.random();

    var buf: [512]u8 = undefined;
    random.bytes(&buf);

    for (0..200) |_| {
        const len = random.uintAtMost(usize, buf.len);
        const input = buf[0..len];

        var fnv: Fnv1a64 = .init();
        var murmur: Murmur3 = .init();
        var xx: Xx64 = .init();

        var rest = input;
        while (rest.len != 0) {
            const take = @min(rest.len, random.uintLessThan(usize, 40) + 1);
            fnv.update(rest[0..take]);
            murmur.update(rest[0..take]);
            xx.update(rest[0..take]);
            rest = rest[take..];
        }

        try testing.expectEqual(Fnv1a64.hash(input), fnv.final());
        try testing.expectEqual(Murmur3.hash(input), murmur.final());
        try testing.expectEqual(Xx64.hash(input), xx.final());
    }
}

test "final does not end the hash" {
    var xx: Xx64 = .init();
    xx.update("fluxion");
    try testing.expectEqual(Xx64.hash("fluxion"), xx.final());

    // Reading the digest changed nothing, so the next one covers both halves.
    xx.update(" hash");
    try testing.expectEqual(Xx64.hash("fluxion hash"), xx.final());
}

test "seeds" {
    try testing.expectEqual(Murmur3.hash("fluxion"), Murmur3.hashSeed(0, "fluxion"));
    try testing.expectEqual(Xx64.hash("fluxion"), Xx64.hashSeed(0, "fluxion"));
    try testing.expect(Xx64.hash("fluxion") != Xx64.hashSeed(1, "fluxion"));
    try testing.expect(Murmur3.hash("fluxion") != Murmur3.hashSeed(1, "fluxion"));

    // FNV has no seed of its own: seeding it means starting the state
    // somewhere other than the offset basis.
    try testing.expectEqual(Fnv1a32.hash("fluxion"), Fnv1a32.hashSeed(0x811C9DC5, "fluxion"));
    try testing.expect(Fnv1a32.hash("fluxion") != Fnv1a32.hashSeed(0, "fluxion"));
}

test "an empty hasher is the starting state" {
    var fnv: Fnv1a32 = .init();
    try testing.expectEqual(@as(u32, 0x811C9DC5), fnv.final());
    var murmur: Murmur3 = .initSeed(7);
    try testing.expectEqual(Murmur3.hashSeed(7, ""), murmur.final());
    var xx: Xx64 = .init();
    try testing.expectEqual(Xx64.hash(""), xx.final());
}

test "values go in at their declared width, little end first" {
    // Three bytes for a u24, not four, and no padding anywhere near it.
    try testing.expectEqual(
        Xx64.hash(&[_]u8{ 0x01, 0x02, 0x03 }),
        hashValue(Xx64, @as(u24, 0x030201), .{}),
    );
    // A tuple of bytes is its bytes.
    try testing.expectEqual(
        Xx64.hash(&[_]u8{ 1, 2 }),
        hashValue(Xx64, .{ @as(u8, 1), @as(u8, 2) }, .{}),
    );
    // A negative number is its twos complement, at the same width.
    try testing.expectEqual(
        Xx64.hash(&[_]u8{ 0xFF, 0xFF }),
        hashValue(Xx64, @as(i16, -1), .{}),
    );
}

test "padding is not hashed" {
    const Padded = struct { flag: u8, count: u32 };

    var one: Padded = undefined;
    @memset(std.mem.asBytes(&one), 0xAA);
    one.flag = 1;
    one.count = 2;

    var two: Padded = undefined;
    @memset(std.mem.asBytes(&two), 0x55);
    two.flag = 1;
    two.count = 2;

    // Byte for byte these differ; field by field they do not.
    try testing.expect(!std.mem.eql(u8, std.mem.asBytes(&one), std.mem.asBytes(&two)));
    try testing.expectEqual(hashValue(Xx64, one, .{}), hashValue(Xx64, two, .{}));
}

test "values of every shape" {
    const Colour = enum { red, green, blue };
    const Shape = union(enum) { dot, line: u32, text: []const u8 };
    const Flags = packed struct { visible: bool, locked: bool, level: u6 };

    try testing.expect(hashValue(Xx64, Colour.red, .{}) != hashValue(Xx64, Colour.blue, .{}));
    try testing.expect(hashValue(Xx64, Shape.dot, .{}) != hashValue(Xx64, Shape{ .line = 0 }, .{}));
    try testing.expectEqual(
        hashValue(Xx64, Shape{ .text = "hi" }, .{}),
        hashValue(Xx64, Shape{ .text = "hi" }, .{}),
    );
    try testing.expect(
        hashValue(Xx64, Flags{ .visible = true, .locked = false, .level = 3 }, .{}) !=
            hashValue(Xx64, Flags{ .visible = true, .locked = true, .level = 3 }, .{}),
    );

    // An optional carries a tag, so absent and zero are different things.
    try testing.expect(hashValue(Xx64, @as(?u32, null), .{}) != hashValue(Xx64, @as(?u32, 0), .{}));

    // Arrays, vectors and error sets all have an answer.
    try testing.expectEqual(
        hashValue(Xx64, [3]u16{ 1, 2, 3 }, .{}),
        hashValue(Xx64, @Vector(3, u16){ 1, 2, 3 }, .{}),
    );
    const Error = error{ Full, Empty };
    try testing.expect(hashValue(Xx64, Error.Full, .{}) != hashValue(Xx64, Error.Empty, .{}));
}

test "slices carry their length" {
    // Otherwise these two would be the same three bytes in a row.
    const split: []const []const u8 = &.{ "ab", "c" };
    const other: []const []const u8 = &.{ "a", "bc" };
    try testing.expect(hashValue(Xx64, split, .{}) != hashValue(Xx64, other, .{}));
}

test "following a pointer, or not" {
    const text = "fluxion";
    var copy: [7]u8 = undefined;
    @memcpy(&copy, text);
    const same_bytes: []const u8 = &copy;

    // Same content, different address.
    try testing.expectEqual(
        hashValue(Xx64, @as([]const u8, text), .{}),
        hashValue(Xx64, same_bytes, .{}),
    );
    try testing.expect(hashValue(Xx64, @as([]const u8, text), .{ .follow = .address }) !=
        hashValue(Xx64, same_bytes, .{ .follow = .address }));
}

test "Stream hashes what is written through it" {
    var stream: Stream(Xx64) = .init(.init());
    const w = stream.writer();

    try w.writeAll("fluxion");
    try w.writeByte(' ');
    try w.print("{d}", .{42});
    try testing.expectEqual(Xx64.hash("fluxion 42"), stream.final());

    // The repeated-pattern path of the writer goes through the same hasher.
    var splat: Stream(Fnv1a64) = .init(.init());
    try splat.writer().splatByteAll('.', 5);
    try testing.expectEqual(Fnv1a64.hash("....."), splat.final());

    // Seeded, and read part way through.
    var seeded: Stream(Xx64) = .init(.initSeed(9));
    try seeded.writer().writeAll("half");
    try testing.expectEqual(Xx64.hashSeed(9, "half"), seeded.final());
    try seeded.writer().writeAll(" and half");
    try testing.expectEqual(Xx64.hashSeed(9, "half and half"), seeded.final());
}
