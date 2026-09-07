// SPDX-License-Identifier: CC0-1.0

//! CRC-32: the checksum in gzip, PNG, zip and Ethernet.
//!
//! A CRC is not a hash. It is the remainder of a polynomial division over
//! GF(2), which is a long way of saying it is linear - and that is the whole
//! point. Linearity is what lets `combine` take the checksums of two pieces
//! and produce the checksum of the two pieces joined, without looking at a
//! single byte again. It is also why a CRC must never be used where a hash is
//! wanted: given a checksum and a message, changing the message to keep the
//! checksum is arithmetic, not work. Use `hash` for tables, `crc32` for
//! transmission errors and bit rot.
//!
//!   `Ieee`         the one people mean by "CRC-32": gzip, PNG, zip
//!   `Castagnoli`   CRC-32C: iSCSI, ext4, and what SSE4.2 computes in hardware
//!   `Crc32`        any other reflected polynomial you have to interoperate with
//!
//! Each answers to the same calls as a hasher from `hash`, so `Stream` and the
//! rest work on them unchanged:
//!
//!   * `Digest`      always `u32`
//!   * `hash`        one shot, over a slice
//!   * `init`        start a running checksum
//!   * `initFrom`    or resume one from a digest computed earlier
//!   * `update`      feed it more bytes, any number of times
//!   * `final`       read the checksum out
//!   * `combine`     the checksum of two pieces, joined
//!
//! Nothing here allocates: the 1 KiB lookup table is built at compile time and
//! lives in the binary.

const std = @import("std");
const testing = std.testing;

/// The reflected form of each polynomial, which is how a table-driven CRC
/// spells it: bit-reversed, with the implicit high term dropped.
///
/// Non-exhaustive, so a polynomial that is not here can still be used:
/// `Crc32(@enumFromInt(0x...))`.
pub const Polynomial = enum(u32) {
    /// The CRC-32 of gzip, PNG, zip, Ethernet and everything else that just
    /// says "CRC-32". Normal form 0x04C11DB7.
    ieee = 0xEDB88320,
    /// CRC-32C, Castagnoli: better error detection than IEEE at every message
    /// length, and the one x86 has an instruction for. Normal form 0x1EDC6F41.
    castagnoli = 0x82F63B78,
    /// Koopman: chosen for short messages, where it catches more of what IEEE
    /// misses. Normal form 0x741B8CD7.
    koopman = 0xEB31D82E,
    _,
};

/// CRC-32 with the IEEE polynomial. The default, and what `checksum` uses.
pub const Ieee = Crc32(.ieee);

/// CRC-32C.
pub const Castagnoli = Crc32(.castagnoli);

/// One shot with the IEEE polynomial, for when the variant is not in question.
pub fn hash(bytes: []const u8) u32 {
    return Ieee.hash(bytes);
}

/// A table-driven CRC-32 over `polynomial`, in the reflected convention every
/// 32-bit CRC in the wild uses: input bits enter low end first, the register
/// starts at all ones, and the result is inverted on the way out.
pub fn Crc32(comptime polynomial: Polynomial) type {
    return struct {
        const Self = @This();

        /// What `final` and `hash` return.
        pub const Digest = u32;

        /// One byte's worth of division, precomputed. 256 entries because a
        /// byte selects the row; the alternative is eight shifts per byte.
        const table: [256]u32 = blk: {
            @setEvalBranchQuota(10_000);
            var t: [256]u32 = undefined;
            for (&t, 0..) |*slot, i| {
                var remainder: u32 = @intCast(i);
                for (0..8) |_| {
                    remainder = if (remainder & 1 != 0)
                        (remainder >> 1) ^ @intFromEnum(polynomial)
                    else
                        remainder >> 1;
                }
                slot.* = remainder;
            }
            break :blk t;
        };

        /// The register, held in its inverted form so that `update` is a plain
        /// table lookup and the inversion happens once, in `final`.
        state: u32,

        /// A checksum over no bytes yet.
        pub fn init() Self {
            return .{ .state = 0xFFFFFFFF };
        }

        /// Carry on from a digest computed earlier - by another process, or by
        /// this one before it stored the value and went away. Checksumming a
        /// file in two sessions gives the same answer as doing it in one:
        ///
        /// ```zig
        /// var crc: crc32.Ieee = .initFrom(stored);
        /// crc.update(new_bytes);
        /// ```
        ///
        /// A CRC has no seed in the sense a hash does - there is nothing to
        /// vary but the polynomial - so this is the only other way in.
        pub fn initFrom(digest: Digest) Self {
            return .{ .state = ~digest };
        }

        /// Feed in more bytes. Where the input is split across calls makes no
        /// difference to the result.
        pub fn update(self: *Self, bytes: []const u8) void {
            var state = self.state;
            for (bytes) |byte| {
                state = table[(state ^ byte) & 0xFF] ^ (state >> 8);
            }
            self.state = state;
        }

        /// The checksum of everything fed in so far. Takes the value, so
        /// checksumming can carry on afterwards.
        pub fn final(self: Self) Digest {
            return ~self.state;
        }

        /// One shot over a slice.
        pub fn hash(bytes: []const u8) Digest {
            var self: Self = .init();
            self.update(bytes);
            return self.final();
        }

        /// The checksum of `a ++ b`, from the checksum of each piece and the
        /// length of the second. Exact, not an estimate:
        ///
        /// ```zig
        /// Ieee.combine(Ieee.hash(a), Ieee.hash(b), b.len) == Ieee.hash(a ++ b)
        /// ```
        ///
        /// Useful when the pieces arrive out of order, are checksummed on
        /// different threads, or were checksummed years apart - appending to
        /// an archive need not re-read the archive.
        ///
        /// The work is proportional to the number of bits in `b_len`, not to
        /// `b_len` itself: pushing a checksum through `n` zero bytes is a
        /// linear map, so the map for `2n` zeros is the map for `n` applied
        /// twice, and repeated squaring gets to any length in about 32 steps.
        pub fn combine(a: Digest, b: Digest, b_len: usize) Digest {
            if (b_len == 0) return a;

            // The map for one zero bit. Row 0 is the polynomial - what a set
            // top bit feeds back - and the rest is the identity shifted once,
            // which is what the other bits do: move up one place.
            var odd: [32]u32 = undefined;
            odd[0] = @intFromEnum(polynomial);
            var bit: u32 = 1;
            for (odd[1..]) |*row| {
                row.* = bit;
                bit <<= 1;
            }

            var even: [32]u32 = undefined;
            square(&even, &odd); // two zero bits
            square(&odd, &even); // four

            var crc = a;
            var len = b_len;
            while (true) {
                // Each squaring doubles the run of zeros the map stands for:
                // eight bits, then sixteen, then thirty-two ... so the bits of
                // `len` select which of them to apply.
                square(&even, &odd);
                if (len & 1 != 0) crc = apply(&even, crc);
                len >>= 1;
                if (len == 0) break;

                square(&odd, &even);
                if (len & 1 != 0) crc = apply(&odd, crc);
                len >>= 1;
                if (len == 0) break;
            }

            // `a` pushed through the length of `b` now shares a register with
            // `b`'s own checksum, and over GF(2) addition is xor.
            return crc ^ b;
        }

        /// A 32x32 bit matrix over GF(2), one column per row entry, applied to
        /// `vector`: sum the rows the set bits select, where sum means xor.
        fn apply(matrix: *const [32]u32, vector: u32) u32 {
            var sum: u32 = 0;
            var rest = vector;
            var i: usize = 0;
            while (rest != 0) : ({
                rest >>= 1;
                i += 1;
            }) {
                if (rest & 1 != 0) sum ^= matrix[i];
            }
            return sum;
        }

        /// `out = matrix * matrix`: the map for twice as many zero bytes.
        fn square(out: *[32]u32, matrix: *const [32]u32) void {
            for (out, matrix) |*row, source| row.* = apply(matrix, source);
        }
    };
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

test "check values" {
    // "123456789" is the string every CRC catalogue publishes a value for.
    try testing.expectEqual(@as(u32, 0xCBF43926), Ieee.hash("123456789"));
    try testing.expectEqual(@as(u32, 0xE3069283), Castagnoli.hash("123456789"));
    try testing.expectEqual(@as(u32, 0x2D3DD0AE), Crc32(.koopman).hash("123456789"));

    try testing.expectEqual(@as(u32, 0xE8B7BE43), Ieee.hash("a"));
    try testing.expectEqual(@as(u32, 0x352441C2), Ieee.hash("abc"));
    try testing.expectEqual(@as(u32, 0x9AEC45D4), Ieee.hash("fluxion"));
    try testing.expectEqual(@as(u32, 0xCE0C5114), Ieee.hash("the quick brown fox jumps over the lazy dog"));
    try testing.expectEqual(@as(u32, 0xD97132AC), Castagnoli.hash("fluxion"));

    // The empty message. Both conditionings cancel, which is why it is zero
    // and why a zero checksum says nothing about whether anything arrived.
    try testing.expectEqual(@as(u32, 0), Ieee.hash(""));
    try testing.expectEqual(@as(u32, 0), Castagnoli.hash(""));

    var all: [256]u8 = undefined;
    for (&all, 0..) |*byte, i| byte.* = @intCast(i);
    try testing.expectEqual(@as(u32, 0x29058C73), Ieee.hash(&all));
    try testing.expectEqual(@as(u32, 0x9C44184B), Castagnoli.hash(&all));
}

test "the shorthand is the IEEE one" {
    try testing.expectEqual(Ieee.hash("fluxion"), hash("fluxion"));
}

test "where the input is split makes no difference" {
    const text = "the quick brown fox jumps over the lazy dog";
    for (0..text.len + 1) |cut| {
        var crc: Ieee = .init();
        crc.update(text[0..cut]);
        crc.update(text[cut..]);
        try testing.expectEqual(Ieee.hash(text), crc.final());
    }
}

test "a checksum can be put down and picked up again" {
    const text = "the quick brown fox jumps over the lazy dog";

    var first: Ieee = .init();
    first.update(text[0..10]);
    const stored = first.final(); // written to a file, sent over a wire

    var second: Ieee = .initFrom(stored);
    second.update(text[10..]);
    try testing.expectEqual(Ieee.hash(text), second.final());

    // And reading the digest did not end the first one either.
    first.update(text[10..]);
    try testing.expectEqual(Ieee.hash(text), first.final());
}

test "combine is exact" {
    var prng: std.Random.DefaultPrng = .init(0xC0FFEE);
    const random = prng.random();

    var buf: [2048]u8 = undefined;
    random.bytes(&buf);

    for (0..500) |_| {
        const len = random.uintAtMost(usize, buf.len);
        const message = buf[0..len];
        const cut = random.uintAtMost(usize, len);
        const head = message[0..cut];
        const tail = message[cut..];

        try testing.expectEqual(
            Ieee.hash(message),
            Ieee.combine(Ieee.hash(head), Ieee.hash(tail), tail.len),
        );
        try testing.expectEqual(
            Castagnoli.hash(message),
            Castagnoli.combine(Castagnoli.hash(head), Castagnoli.hash(tail), tail.len),
        );
    }
}

test "combine over many pieces" {
    const pieces = [_][]const u8{ "the quick ", "brown fox ", "jumps over ", "the lazy dog" };

    var joined = Ieee.hash(pieces[0]);
    for (pieces[1..]) |piece| joined = Ieee.combine(joined, Ieee.hash(piece), piece.len);
    try testing.expectEqual(Ieee.hash("the quick brown fox jumps over the lazy dog"), joined);

    // Nothing appended is nothing changed.
    try testing.expectEqual(joined, Ieee.combine(joined, Ieee.hash(""), 0));
}

test "one flipped bit changes the checksum" {
    // The whole point of a CRC. Every single-bit error in a message this short
    // lands on a different checksum.
    var message = "fluxion hash".*;
    const clean = Ieee.hash(&message);

    var seen: std.AutoHashMapUnmanaged(u32, void) = .empty;
    defer seen.deinit(testing.allocator);
    try seen.put(testing.allocator, clean, {});

    for (0..message.len) |byte| {
        for (0..8) |bit| {
            message[byte] ^= @as(u8, 1) << @intCast(bit);
            const damaged = Ieee.hash(&message);
            message[byte] ^= @as(u8, 1) << @intCast(bit);

            try testing.expect(!seen.contains(damaged));
            try seen.put(testing.allocator, damaged, {});
        }
    }
}

test "the polynomial is the whole difference" {
    // Same input, three polynomials, three unrelated answers.
    const text = "fluxion";
    try testing.expect(Ieee.hash(text) != Castagnoli.hash(text));
    try testing.expect(Ieee.hash(text) != Crc32(.koopman).hash(text));

    // A polynomial that is not in the enum is spelled out instead; this one
    // happens to be the IEEE polynomial written by hand.
    const Custom = Crc32(@enumFromInt(0xEDB88320));
    try testing.expectEqual(Ieee.hash(text), Custom.hash(text));
}
