// SPDX-License-Identifier: CC0-1.0

//! Fluxion Hash - turning bytes, values and other hashes into one number.
//!
//! Three pieces:
//!
//!   `hash`     non-cryptographic hashes: FNV-1a, MurmurHash3, xxHash64
//!   `crc32`    CRC-32 and CRC-32C, with checksums that can be joined
//!   `combine`  several hashes into one, in order or regardless of order
//!
//! Every hasher in the first two shares one shape, so swapping between them is
//! a change of name and nothing else:
//!
//!   `Digest`                the type that comes out
//!   `hash` / `hashSeed`     one shot, over a slice
//!   `init` / `initSeed`     start a running hash
//!   `update`                feed it more bytes, any number of times
//!   `final`                 read the digest out, and carry on if you like
//!
//! Nothing here allocates, and nothing here is cryptographic: these are for
//! hash tables, caches, dirty checks and transmission errors, not for
//! signatures or for anything an attacker chooses the input of.

const std = @import("std");
const testing = std.testing;

pub const hash = @import("hash.zig");
pub const crc32 = @import("crc32.zig");
pub const combine = @import("combine.zig");

/// FNV-1a, 32 bits: four bytes of state, a multiply per byte. See `hash`.
pub const Fnv1a32 = hash.Fnv1a32;

/// The 64-bit one. See `hash`.
pub const Fnv1a64 = hash.Fnv1a64;

/// MurmurHash3, 32 bits out. See `hash`.
pub const Murmur3 = hash.Murmur3;

/// xxHash64, the default for anything longer than a key. See `hash`.
pub const Xx64 = hash.Xx64;

/// CRC-32 as gzip, PNG and zip mean it. See `crc32`.
pub const Crc32 = crc32.Ieee;

/// CRC-32C, the Castagnoli polynomial. See `crc32`.
pub const Crc32c = crc32.Castagnoli;

/// A `std.Io.Writer` that hashes what goes through it. See `hash`.
pub const Stream = hash.Stream;

/// The algorithm the shorthands below use.
pub const Default = Xx64;

/// Shorthand for `Xx64.hash`, so call sites read `hashing.hashBytes(b)`.
pub fn hashBytes(bytes: []const u8) u64 {
    return Default.hash(bytes);
}

/// Shorthand for hashing a whole value with the default algorithm. See
/// `hash.updateValue` for what each kind of type contributes.
pub fn hashValue(value: anytype) u64 {
    return hash.hashValue(Default, value, .{});
}

/// Shorthand for `Crc32.hash`: the checksum, as opposed to the hash.
pub fn checksum(bytes: []const u8) u32 {
    return Crc32.hash(bytes);
}

test {
    // Pull each module in so `zig build test` runs its tests too.
    _ = hash;
    _ = crc32;
    _ = combine;
    _ = @import("mix.zig");
}

test "the pieces compose" {
    // A tiny index: three blobs, each with a content hash, and one checksum
    // over the lot.
    const blobs = [_][]const u8{ "the quick brown fox ", "jumps over ", "the lazy dog" };

    var ordered: combine.Combiner = .init();
    var any_order: combine.Unordered = .init();
    var whole: Crc32 = .init();
    for (blobs) |blob| {
        ordered.add(hashBytes(blob));
        any_order.add(hashBytes(blob));
        whole.update(blob);
    }

    // The checksum of the three joined, without joining them: each piece was
    // checksummed on its own, and the pieces were put together afterwards.
    var joined = checksum(blobs[0]);
    for (blobs[1..]) |blob| joined = Crc32.combine(joined, checksum(blob), blob.len);
    try testing.expectEqual(whole.final(), joined);
    try testing.expectEqual(checksum("the quick brown fox jumps over the lazy dog"), joined);

    // Reversed, the ordered combination moves and the unordered one does not.
    var backwards: combine.Combiner = .init();
    var backwards_any: combine.Unordered = .init();
    var i = blobs.len;
    while (i > 0) {
        i -= 1;
        backwards.add(hashBytes(blobs[i]));
        backwards_any.add(hashBytes(blobs[i]));
    }
    try testing.expect(ordered.final() != backwards.final());
    try testing.expectEqual(any_order.final(), backwards_any.final());
}

test "a record, hashed by value and by hand" {
    const Record = struct {
        name: []const u8,
        version: u16,
        tags: []const []const u8,
    };
    const record: Record = .{ .name = "fluxion", .version = 2, .tags = &.{ "zig", "hash" } };

    // Whole value at once, fields walked for you.
    const direct = hashValue(record);

    // Or field by field, which is what `hashValue` does underneath - and what
    // you would write by hand to leave a field out of the hash.
    const by_hand = combine.all(&.{
        hashBytes(record.name),
        record.version,
        combine.all(&.{ hashBytes(record.tags[0]), hashBytes(record.tags[1]) }),
    });

    // Two different constructions, so two different numbers; what matters is
    // that each is stable and that a change in any field moves it.
    try testing.expect(direct != by_hand);

    var changed = record;
    changed.version = 3;
    try testing.expect(hashValue(changed) != direct);
}

test "shorthands" {
    try testing.expectEqual(Xx64.hash("fluxion"), hashBytes("fluxion"));
    try testing.expectEqual(Crc32.hash("fluxion"), checksum("fluxion"));
    try testing.expectEqual(@as(u32, 0x9AEC45D4), checksum("fluxion"));
    try testing.expectEqual(hashValue(@as(u32, 7)), hashValue(@as(u32, 7)));
}
