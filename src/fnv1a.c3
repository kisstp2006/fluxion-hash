// SPDX-License-Identifier: CC0-1.0

// FNV-1a: a xor and a multiply per byte, no table and no buffer.
//
// This file is the first place the port meets a C3 generic, so it is worth
// saying how one is shaped. In Zig, `Fnv1a` was a function that took a type
// and two constants and returned a struct type. C3 has no functions that
// return types; instead a whole module section can be parameterised, and
// everything declared in it - the struct, its methods, the free functions -
// is stamped out together for each set of arguments. The parameters after
// the module name are the generic ones: a type, written like a type, and two
// constants, written like constants.
//
// Nobody writes `Fnv1a{uint, 0x811C9DC5, 0x01000193}` at a call site. The
// two instantiations anybody wants are named once, further down, in the
// `fnv1a32` and `fnv1a64` modules, and those are what `fluxion::hash` hands
// out.
module fluxion::hash::fnv1a <Digest, OFFSET, PRIME>;

<*
 FNV-1a over `Digest`, which is `uint` or `ulong`. The hasher is the state
 and nothing else: `Digest::size` bytes.
*>
struct Fnv1a
{
	Digest state;
}

<*
 A hasher over no bytes yet, starting from the FNV offset basis.

 C3 has no constructors and no static methods: a method must take the value
 it belongs to. So where Zig wrote `var h: Fnv1a32 = .init()`, C3 writes
 `Fnv1a32 h; h.init();` - the declaration zero-fills the struct, and `init`
 puts the real starting state in. Every hasher in this library begins that
 way, which is also how the standard library's own `Sha256` and `Crc32` do.
*>
fn void Fnv1a.init(&self)
{
	self.state = (Digest)OFFSET;
}

<*
 The same, starting from `seed`. Two hashers with different seeds disagree
 about everything - what a table wants on the day its keys turn out to
 collide.
*>
fn void Fnv1a.init_seed(&self, Digest seed)
{
	self.state = seed;
}

<*
 Feed in more bytes. Where the input is split across calls makes no
 difference: only the bytes and their order matter.
*>
fn void Fnv1a.update(&self, char[] bytes)
{
	foreach (byte : bytes)
	{
		self.state ^= byte;
		self.state *= (Digest)PRIME;
	}
}

<*
 The digest of everything fed in so far. `self` without the `&` means the
 method gets a copy, so reading the digest cannot disturb the hasher and
 hashing can carry on afterwards.
*>
fn Digest Fnv1a.final(self)
{
	return self.state;
}

<*
 One shot over a slice.
*>
fn Digest hash(char[] bytes)
{
	Fnv1a h;
	h.init();
	h.update(bytes);
	return h.final();
}

<*
 One shot, seeded.
*>
fn Digest hash_seed(Digest seed, char[] bytes)
{
	Fnv1a h;
	h.init_seed(seed);
	h.update(bytes);
	return h.final();
}

// -------------------------------------------------------------------------
// The two instantiations
// -------------------------------------------------------------------------
//
// A type alias of a generic instantiation is an ordinary type from then on:
// `Fnv1a32 h;` and methods on it work as they would on any struct. Functions
// are aliased the same way, one per name, so `fnv1a32::hash(bytes)` reads
// like the non-generic hashers do. An alias of a type must start with a
// capital and an alias of a function must not - that is the compiler's rule,
// not a house one.

// FNV-1a, 32 bits: four bytes of state, a multiply per byte. For short keys;
// on long input `xx64` is several times faster per byte.
module fluxion::hash::fnv1a32;
import fluxion::hash::fnv1a;

// What `final` and `hash` return.
alias Digest = uint;

alias Fnv1a32 = Fnv1a{uint, 0x811C9DC5, 0x01000193};
alias hash = fnv1a::hash{uint, 0x811C9DC5, 0x01000193};
alias hash_seed = fnv1a::hash_seed{uint, 0x811C9DC5, 0x01000193};

// FNV-1a, 64 bits. Worth the extra four bytes wherever 32 would start
// colliding: a few tens of thousands of keys is already a coin flip there.
module fluxion::hash::fnv1a64;
import fluxion::hash::fnv1a;

// What `final` and `hash` return.
alias Digest = ulong;

alias Fnv1a64 = Fnv1a{ulong, 0xCBF29CE484222325UL, 0x00000100000001B3};
alias hash = fnv1a::hash{ulong, 0xCBF29CE484222325UL, 0x00000100000001B3};
alias hash_seed = fnv1a::hash_seed{ulong, 0xCBF29CE484222325UL, 0x00000100000001B3};
