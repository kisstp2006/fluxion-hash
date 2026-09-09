// SPDX-License-Identifier: CC0-1.0

// A `Stream` is an `OutStream` that hashes everything written to it and
// keeps nothing.
//
// Anything that writes to a stream can be hashed this way - a formatter, a
// file copy, a compressor - with no buffer in between and no second pass:
//
//     Stream{Xx64} stream;
//     stream.init();
//     io::fprintf(&stream, "%d %s\n", id, name)!;
//     ulong digest = stream.final();
//
// Works with any hasher of the right shape, `Crc32` included.
//
// `OutStream` is a C3 interface: a list of method signatures that a struct
// satisfies by declaring the type as `Stream (OutStream)` and marking each
// implementation `@dynamic`. Passing `&stream` where an `OutStream` is
// wanted then builds a fat pointer - the address and the type - and every
// `write` on it is a call through a table the compiler fills in. Zig did the
// same thing by hand, with a vtable struct and `@fieldParentPtr`; here the
// compiler owns the table and there is no parent pointer to get wrong.
module fluxion::hash::stream <Hasher>;
import std::io;

struct Stream (OutStream)
{
	Hasher hasher;
}

<*
 A stream over a fresh hasher.
*>
fn void Stream.init(&self)
{
	self.hasher.init();
}

<*
 A stream over a hasher already set up, so it can be seeded first:

     Xx64 seeded;
     seeded.init_seed(9);
     Stream{Xx64} stream;
     stream.init_from(seeded);

 The hasher is copied in, so what happens to `seeded` afterwards does not
 reach the stream.
*>
fn void Stream.init_from(&self, Hasher hasher)
{
	self.hasher = hasher;
}

<*
 The digest of everything written so far. Writing may carry on.

 A macro rather than a function so that the return type is whatever this
 hasher's `final` returns - the module never has to be told what `Digest`
 is, and each hasher stays free to answer in 32 or 64 bits.
*>
macro Stream.final(&self)
{
	return self.hasher.final();
}

// The two methods `OutStream` demands. Nothing here can fail, but the
// interface says the result may be missing - `sz?` is "a size, or a fault" -
// because a file or a socket can, and the signature has to fit them all.
fn sz? Stream.write(&self, char[] bytes) @dynamic
{
	self.hasher.update(bytes);
	return bytes.len;
}

fn void? Stream.write_byte(&self, char c) @dynamic
{
	char[1] one = { c };
	self.hasher.update(&one);
}
