# Fluxion Hash

Bytes, values and other hashes, turned into one number. For Zig 0.16.

| Module | What it is |
| --- | --- |
| `hash` | FNV-1a, MurmurHash3 and xxHash64, one shot or streaming, plus whole-value hashing and a `std.Io.Writer` that hashes what goes past. |
| `crc32` | CRC-32 and CRC-32C, resumable from a stored digest, with checksums that can be joined without re-reading the bytes. |
| `combine` | Several hashes into one, in order or regardless of order, with the unordered form patchable in place. |

Every hasher in the first two modules shares one shape, so swapping between
them is a change of name and nothing else:

| Call | What it does |
| --- | --- |
| `Digest` | The type that comes out: `u32` or `u64`. |
| `hash` / `hashSeed` | One shot, over a slice. |
| `init` / `initSeed` | Start a running hash. |
| `update` | Feed it more bytes, any number of times. |
| `final` | Read the digest out — and carry on hashing afterwards. |

A CRC has no seed, because there is nothing to vary but the polynomial, so
`crc32` swaps `initSeed` for `initFrom`, which resumes from a digest computed
earlier.

Nothing here allocates. Nothing here is cryptographic: these are for hash
tables, caches, dirty checks and transmission errors, not for signatures and
not for anything an attacker chooses the input of.

## Install

```bash
zig fetch --save git+https://github.com/kisstp2006/fluxion-hash
```

Or, for a checkout next to your project, add to `build.zig.zon`:

```zig
.dependencies = .{
    .fluxion_hash = .{ .path = "../fluxion-hash" },
},
```

Either way, wire it up in `build.zig`:

```zig
const fluxion = b.dependency("fluxion_hash", .{
    .target = target,
    .optimize = optimize,
});
exe_mod.addImport("fluxion_hash", fluxion.module("fluxion_hash"));
```

```zig
const hashing = @import("fluxion_hash");
```

## Tour

### hash

Four hashers, one shape. Pick by what the input looks like and what the
output has to fit into:

```zig
hashing.Fnv1a32.hash("fluxion");   // 0x8E26B21C  short keys, four bytes of state
hashing.Fnv1a64.hash("fluxion");   // 0x19E10A1AB2E57A1C
hashing.Murmur3.hash("fluxion");   // 0x6A69C89C  32 bits, better spread than FNV
hashing.Xx64.hash("fluxion");      // 0xA2C76E8E6E458A3E  the default
```

Streaming is the same hash arriving in pieces. Where the input is split makes
no difference to the digest, and reading a digest does not end the hash:

```zig
var h: hashing.Xx64 = .init();
h.update("fluxion");
h.final();          // the hash of "fluxion"
h.update(" hash");
h.final();          // the hash of "fluxion hash"
```

Seeds give the same bytes a different answer, which is what a hash table wants
on the day its keys collide:

```zig
hashing.Xx64.hashSeed(0xDEADBEEF, "fluxion");
```

**Whole values.** `hashValue` walks a type field by field, so padding never
reaches the hash and the answer does not change with the machine:

```zig
const Asset = struct {
    name: []const u8,
    kind: enum { mesh, texture, sound },
    size: u32,
    tags: []const []const u8,
};

hashing.hashValue(asset);
```

Integers go in little-endian at their declared width — a `u24` is three bytes,
not four. Optionals contribute a tag, so `null` and `0` differ. Slices
contribute their length, so `.{ "ab", "c" }` and `.{ "a", "bc" }` differ.
Floats are hashed by their bit pattern, which is the only stable choice but
means `0.0` and `-0.0` differ. Pointers are followed by default; hash the
address instead when identity is what you meant:

```zig
hashing.hash.hashValue(hashing.Xx64, key, .{ .follow = .address });
```

A many-item pointer or an untagged union is a compile error rather than a
guess.

**Streams.** `Stream` turns any hasher into a `std.Io.Writer`, so bytes can be
hashed on their way somewhere else, with no buffer in between:

```zig
var stream: hashing.Stream(hashing.Xx64) = .init(.init());
for (assets) |asset| {
    try stream.writer().print("{s} {d}\n", .{ asset.name, asset.size });
}
const digest = stream.final();
```

### crc32

A CRC is not a hash. It is the remainder of a polynomial division, and it is
linear — which is why a checksum can be resumed and joined, and why it must
never be used where a hash is wanted: given a message and its checksum,
changing the message to keep the checksum is arithmetic, not work.

```zig
hashing.checksum("123456789");            // 0xCBF43926, the catalogue value
hashing.Crc32.hash("fluxion");            // IEEE: gzip, PNG, zip
hashing.Crc32c.hash("fluxion");           // Castagnoli: iSCSI, ext4
hashing.crc32.Crc32(.koopman).hash(text); // or any reflected polynomial
```

A running checksum can be put down and picked up again, so a file need not be
finished in one sitting:

```zig
var crc: hashing.Crc32 = .initFrom(stored_digest);
crc.update(the_rest);
```

And two checksums can be joined into the checksum of the two pieces
concatenated, exactly, without looking at a byte of either:

```zig
const whole = hashing.Crc32.combine(crc_a, crc_b, b.len);
// == hashing.Crc32.hash(a ++ b)
```

That is what makes appending to an archive cheap, and what lets four threads
checksum four chunks and agree on the answer afterwards. The work is
proportional to the number of bits in the length, not to the length: pushing a
checksum through a run of zero bytes is a linear map, the map for twice as many
zeros is that map applied twice, and repeated squaring reaches any length in
about 32 steps.

### combine

Three fields, three good hashes, and the record needs one number. Adding them
makes `(1, 2)` and `(2, 1)` equal. Xoring them lets a value cancel itself. The
`31 * h + x` of folklore leaves the low bits nearly where they were.

```zig
hashing.combine.pair(a, b);                 // two
hashing.combine.all(&.{ a, b, c });         // any number, in order
```

Order sometimes matters and sometimes does not, and the difference is worth
saying out loud:

```zig
var fields: hashing.combine.Combiner = .init();   // a struct, a list, a call
fields.add(hashing.hashBytes(name));
fields.add(version);

var members: hashing.combine.Unordered = .init(); // a set, a map, a directory
for (entries) |entry| members.add(hashing.hashValue(entry));
```

The unordered form can be patched. One entry changed, so take the old hash out
and put the new one in — the rest of the directory is never touched:

```zig
members.remove(old_hash);
members.add(new_hash);
members.final();    // exactly what recomputing from scratch would give
```

Everything here works in `u64`. Widen a narrower hash on the way in —
`@as(u64, crc)` — rather than combining in 32 bits and hoping.

## Everything together

```zig
// A file arrives in pieces, each checksummed where it was made.
var joined = hashing.checksum(pieces[0]);
for (pieces[1..]) |piece| {
    joined = hashing.Crc32.combine(joined, hashing.checksum(piece), piece.len);
}
// joined == hashing.checksum(whole_file), without reading it again.

// Each asset gets a content hash, and the index gets one number.
var index: hashing.combine.Unordered = .init();
for (assets) |asset| index.add(hashing.hashValue(asset));

// One asset changes: patch the index rather than rebuilding it.
index.remove(hashing.hashValue(old));
index.add(hashing.hashValue(new));
```

`zig build example` runs exactly this, on three imaginary assets, and prints
the numbers as it goes.

## Build

```bash
zig build test        # run the test suite
zig build example     # build and run the demo tour
zig build docs        # generate API docs into zig-out/docs
```

The digests are checked against the published vectors for each algorithm —
FNV-1a, MurmurHash3, xxHash64, and the `123456789` check values for CRC-32 and
CRC-32C — and the streaming paths are checked against the one-shot ones over
random input split at random points.

## Requirements

Zig 0.16.0.

## License

`SPDX-License-Identifier: CC0-1.0`

[CC0 1.0 Universal](LICENSE) — public domain dedication. Do whatever you like
with this, no attribution required.
