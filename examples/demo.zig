// SPDX-License-Identifier: CC0-1.0

//! A tour of Fluxion Hash. Run it with `zig build example`.
//!
//! It indexes a handful of imaginary assets: hashes their contents, checksums
//! them in pieces, folds the pieces into one index hash, and then patches that
//! index without recomputing it.

const std = @import("std");
const Io = std.Io;
const hashing = @import("fluxion_hash");

const Asset = struct {
    name: []const u8,
    kind: enum { mesh, texture, sound },
    bytes: []const u8,
};

const assets = [_]Asset{
    .{ .name = "hull.mesh", .kind = .mesh, .bytes = "vertices, and a great many of them" },
    .{ .name = "hull.png", .kind = .texture, .bytes = "pixels, mostly grey" },
    .{ .name = "engine.wav", .kind = .sound, .bytes = "a low hum that loops" },
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();

    var stdout_buffer: [4096]u8 = undefined;
    var stdout: Io.File.Writer = .init(.stdout(), init.io, &stdout_buffer);
    const out = &stdout.interface;

    // --- one input, every algorithm --------------------------------------
    const text = "the quick brown fox jumps over the lazy dog";
    try out.print(
        \\--- {d} bytes through each of them ---
        \\fnv1a32   0x{X:0>8}
        \\fnv1a64   0x{X:0>16}
        \\murmur3   0x{X:0>8}
        \\xxhash64  0x{X:0>16}
        \\crc32     0x{X:0>8}  (a checksum, not a hash)
        \\
    , .{
        text.len,
        hashing.Fnv1a32.hash(text),
        hashing.Fnv1a64.hash(text),
        hashing.Murmur3.hash(text),
        hashing.Xx64.hash(text),
        hashing.Crc32.hash(text),
    });

    // --- checksums that join ---------------------------------------------
    // The file arrives in four pieces, each checksummed where it was made.
    const pieces = [_][]const u8{ "the quick ", "brown fox ", "jumps over ", "the lazy dog" };
    try out.writeAll("\n--- checksums that join ---\n");

    var joined = hashing.Crc32.hash(pieces[0]);
    try out.print("{s:<13} 0x{X:0>8}\n", .{ pieces[0], joined });
    for (pieces[1..]) |piece| {
        const piece_crc = hashing.Crc32.hash(piece);
        joined = hashing.Crc32.combine(joined, piece_crc, piece.len);
        try out.print("{s:<13} 0x{X:0>8}  joined so far 0x{X:0>8}\n", .{ piece, piece_crc, joined });
    }
    // Nothing was read twice, and the answer is the one the whole file gives.
    try out.print("whole file    0x{X:0>8}  {s}\n", .{
        hashing.checksum(text),
        if (joined == hashing.checksum(text)) "same" else "DIFFERENT",
    });

    // --- hashing values ---------------------------------------------------
    try out.writeAll("\n--- a record, hashed as a value ---\n");
    for (assets) |asset| {
        try out.print("{s:<12} {t:<8} 0x{X:0>16}\n", .{
            asset.name,
            asset.kind,
            hashing.hashValue(asset),
        });
    }

    // Fields are walked, so a change anywhere moves the digest - and padding,
    // which is not a field, moves nothing.
    var retextured = assets[1];
    retextured.bytes = "pixels, mostly blue";
    try out.print("{s:<12} {t:<8} 0x{X:0>16}  after one word changed\n", .{
        retextured.name,
        retextured.kind,
        hashing.hashValue(retextured),
    });

    // --- one number for the lot -------------------------------------------
    try out.writeAll("\n--- folding them into one index ---\n");

    var in_order: hashing.combine.Combiner = .init();
    var any_order: hashing.combine.Unordered = .init();
    for (assets) |asset| {
        in_order.add(hashing.hashValue(asset));
        any_order.add(hashing.hashValue(asset));
    }

    var reversed: hashing.combine.Combiner = .init();
    var reversed_any: hashing.combine.Unordered = .init();
    var i = assets.len;
    while (i > 0) {
        i -= 1;
        reversed.add(hashing.hashValue(assets[i]));
        reversed_any.add(hashing.hashValue(assets[i]));
    }

    try out.print(
        \\ordered    0x{X:0>16}   reversed 0x{X:0>16}
        \\unordered  0x{X:0>16}   reversed 0x{X:0>16}
        \\
    , .{ in_order.final(), reversed.final(), any_order.final(), reversed_any.final() });
    try out.writeAll(
        \\A list is a list, so the ordered fold moves when the list is reordered.
        \\A directory is a set, so the unordered one does not.
        \\
    );

    // --- patching the index -----------------------------------------------
    // One asset changed. Take the old hash out, put the new one in - the other
    // two are never touched.
    any_order.remove(hashing.hashValue(assets[1]));
    any_order.add(hashing.hashValue(retextured));

    var recomputed: hashing.combine.Unordered = .init();
    recomputed.add(hashing.hashValue(assets[0]));
    recomputed.add(hashing.hashValue(retextured));
    recomputed.add(hashing.hashValue(assets[2]));

    try out.print("\npatched    0x{X:0>16}\nrecomputed 0x{X:0>16}  {s}\n", .{
        any_order.final(),
        recomputed.final(),
        if (any_order.final() == recomputed.final()) "same" else "DIFFERENT",
    });

    // --- hashing on the way past -------------------------------------------
    // The manifest is hashed as it is written, with no copy of it in between.
    try out.writeAll("\n--- a manifest, hashed as it is written ---\n");

    var stream: hashing.Stream(hashing.Xx64) = .init(.init());
    var kept: Io.Writer.Allocating = .init(gpa);

    for (assets) |asset| {
        try stream.writer().print("{s} {t} {d}\n", .{ asset.name, asset.kind, asset.bytes.len });
        try kept.writer.print("{s} {t} {d}\n", .{ asset.name, asset.kind, asset.bytes.len });
    }
    const manifest = try kept.toOwnedSlice();

    try out.print("{s}", .{manifest});
    try out.print("streamed   0x{X:0>16}\nkept, then 0x{X:0>16}  {s}\n", .{
        stream.final(),
        hashing.hashBytes(manifest),
        if (stream.final() == hashing.hashBytes(manifest)) "same" else "DIFFERENT",
    });

    try out.flush();
}
