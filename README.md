# Fluxion Hash

Bytes, values and other hashes, turned into one number. For C3 0.8.

| Module | What it is |
| --- | --- |
| `fnv1a32`, `fnv1a64` | FNV-1a: tiny and byte at a time, good on short keys. |
| `murmur3` | MurmurHash3, the classic 32-bit workhorse. |
| `xx64` | xxHash64, fast on long input, 64 bits out. The default. |
| `crc32`, `crc32c` | CRC-32 and CRC-32C, resumable from a stored digest, with checksums that can be joined without re-reading the bytes. |
| `combine` | Several hashes into one, in order or regardless of order, with the unordered form patchable in place. |
| `stream` | An `OutStream` that hashes what goes past. |
| `hash` | The root: whole-value hashing, and shorthands that pick the default. |

Every hasher shares one shape, so swapping between them is a change of name
and nothing else:

| Call | What it does |
| --- | --- |
| `Digest` | The type that comes out: `uint` or `ulong`. |
| `hash` / `hash_seed` | One shot, over a slice: `xx64::hash(bytes)`. |
| `init` / `init_seed` | Start a running hash: `Xx64 h; h.init();`. |
| `update` | Feed it more bytes, any number of times. |
| `final` | Read the digest out - and carry on hashing afterwards. |

A CRC has no seed, because there is nothing to vary but the polynomial, so
`crc32` swaps `init_seed` for `init_from`, which resumes from a digest computed
earlier.

Nothing here allocates. Nothing here is cryptographic: these are for hash
tables, caches, dirty checks and transmission errors, not for signatures and
not for anything an attacker chooses the input of.

## Install

The library is the `fluxion_hash.c3l` directory in this repository. For a
checkout next to your project, add to `project.json`:

```json
"dependency-search-paths": ["../fluxion-hash"],
"dependencies": ["fluxion_hash"]
```

Then, in the code:

```c3
import fluxion::hash;
```

One import is the whole library: C3 imports a module's sub-modules with it,
so `xx64::hash`, `crc32::combine` and `Combiner` are all in scope from that
line.

## Tour

### The hashers

Four hashers, one shape. Pick by what the input looks like and what the
output has to fit into:

```c3
fnv1a32::hash("fluxion");   // 0x8E26B21C  short keys, four bytes of state
fnv1a64::hash("fluxion");   // 0x19E10A1AB2E57A1C
murmur3::hash("fluxion");   // 0x6A69C89C  32 bits, better spread than FNV
xx64::hash("fluxion");      // 0xA2C76E8E6E458A3E  the default
```

Streaming is the same hash arriving in pieces. Where the input is split makes
no difference to the digest, and reading a digest does not end the hash:

```c3
Xx64 h;
h.init();
h.update("fluxion");
h.final();          // the hash of "fluxion"
h.update(" hash");
h.final();          // the hash of "fluxion hash"
```

Seeds give the same bytes a different answer, which is what a hash table wants
on the day its keys collide:

```c3
xx64::hash_seed(0xDEADBEEF, "fluxion");
```

**Whole values.** `hash::hash_value` walks a type field by field at compile
time, so padding never reaches the hash and the answer does not change with
the machine:

```c3
struct Asset
{
    String name;
    Kind kind;
    uint size;
    String[] tags;
}

hash::hash_value(asset);
```

Integers go in little-endian at their declared width. Slices contribute their
length, so `{ "ab", "c" }` and `{ "a", "bc" }` differ. Floats are hashed by
their bit pattern, which is the only stable choice but means `0.0` and `-0.0`
differ. Enums contribute their ordinal, bitstructs and typedefs the value
underneath, and a fault its name. Pointers are followed by default; hash the
address instead when identity is what you meant:

```c3
hash::hash_value(key, ADDRESS);
hash::hash_value_with(Murmur3, key);      // a different algorithm
```

A union or a function pointer is a compile error rather than a guess.

**Streams.** `Stream` turns any hasher into an `OutStream`, so bytes can be
hashed on their way somewhere else, with no buffer in between:

```c3
Stream{Xx64} stream;
stream.init();
foreach (asset : assets)
{
    io::fprintf(&stream, "%s %d\n", asset.name, asset.size)!;
}
ulong digest = stream.final();
```

### crc32

A CRC is not a hash. It is the remainder of a polynomial division, and it is
linear - which is why a checksum can be resumed and joined, and why it must
never be used where a hash is wanted: given a message and its checksum,
changing the message to keep the checksum is arithmetic, not work.

```c3
hash::checksum("123456789");       // 0xCBF43926, the catalogue value
crc32::hash("fluxion");            // IEEE: gzip, PNG, zip
crc32c::hash("fluxion");           // Castagnoli: iSCSI, ext4
Crc{polynomial::KOOPMAN} koopman;  // or any reflected polynomial
```

A running checksum can be put down and picked up again, so a file need not be
finished in one sitting:

```c3
Crc32 crc;
crc.init_from(stored_digest);
crc.update(the_rest);
```

And two checksums can be joined into the checksum of the two pieces
concatenated, exactly, without looking at a byte of either:

```c3
uint whole = crc32::combine(crc_a, crc_b, b.len);
// == crc32::hash(a ++ b)
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

```c3
combine::pair(a, b);                 // two
combine::all({ a, b, c });           // any number, in order
```

Order sometimes matters and sometimes does not, and the difference is worth
saying out loud:

```c3
Combiner fields;                     // a struct, a list, a call
fields.init();
fields.add(hash::hash_bytes(name));
fields.add(version);

Unordered members;                   // a set, a map, a directory
members.init();
foreach (entry : entries) members.add(hash::hash_value(entry));
```

The unordered form can be patched. One entry changed, so take the old hash out
and put the new one in - the rest of the directory is never touched:

```c3
members.remove(old_hash);
members.add(new_hash);
members.final();    // exactly what recomputing from scratch would give
```

Everything here works in `ulong`. Widen a narrower hash on the way in -
`(ulong)crc` - rather than combining in 32 bits and hoping.

## Everything together

```c3
// A file arrives in pieces, each checksummed where it was made.
uint joined = hash::checksum(pieces[0]);
foreach (piece : pieces[1..])
{
    joined = crc32::combine(joined, hash::checksum(piece), piece.len);
}
// joined == hash::checksum(whole_file), without reading it again.

// Each asset gets a content hash, and the index gets one number.
Unordered index;
index.init();
foreach (asset : assets) index.add(hash::hash_value(asset));

// One asset changes: patch the index rather than rebuilding it.
index.remove(hash::hash_value(old));
index.add(hash::hash_value(new));
```

`c3c run demo` runs exactly this, on three imaginary assets, and prints the
numbers as it goes.

## Build

```bash
c3c test          # run the test suite
c3c run demo      # build and run the demo tour
```

The digests are checked against the published vectors for each algorithm -
FNV-1a, MurmurHash3, xxHash64, and the `123456789` check values for CRC-32 and
CRC-32C - and the streaming paths are checked against the one-shot ones over
random input split at random points.

Every multiply in this library wraps on purpose, which C3 defines and permits.
A project built with `"trap-on-wrap": true` will trap in it.

## Layout

```
fluxion_hash.c3l/manifest.json   what a consumer's build reads
src/                             the library, one module per file
examples/demo.c3                 the tour
project.json5                    this repository's own build: tests and the demo
```

The manifest points at `../src`, so the library is the same files whether it
is being built here or from a consumer's search path.

## Requirements

C3 0.8.3.

## License

`SPDX-License-Identifier: CC0-1.0`

[CC0 1.0 Universal](LICENSE) - public domain dedication. Do whatever you like
with this, no attribution required.
