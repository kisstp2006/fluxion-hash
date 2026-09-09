// SPDX-License-Identifier: CC0-1.0

// MurmurHash3, the 32-bit variant. Four bytes at a time through two
// multiplies and a rotate, then `mix::fmix32` to spread the last block over
// the whole word.
//
// For when 32 bits is what the format wants: it distributes better than
// FNV-1a on structured input - paths sharing a prefix, keys differing in one
// character.
module fluxion::hash::murmur3;
import fluxion::hash::mix;

// What `final` and `hash` return.
alias Digest = uint;

const uint C1 @private = 0xCC9E2D51;
const uint C2 @private = 0x1B873593;

struct Murmur3
{
	uint state;
	// Bytes that have not filled a four-byte block yet.
	char[4] tail;
	sz tail_len;
	// Every byte ever fed in. Murmur folds the length into the digest, which
	// is part of what keeps "ab" and "ab\0" apart.
	sz total;
}

<*
 A hasher over no bytes yet.
*>
fn void Murmur3.init(&self)
{
	self.init_seed(0);
}

<*
 The same, from a seed.
*>
fn void Murmur3.init_seed(&self, uint seed)
{
	// A struct assignment from a literal replaces every field, so a hasher
	// that was already part-way through something starts clean.
	*self = { .state = seed };
}

<*
 Feed in more bytes. Where the input is split across calls makes no
 difference to the digest.
*>
fn void Murmur3.update(&self, char[] bytes)
{
	self.total += bytes.len;
	char[] rest = bytes;

	// Top up a part-filled block first, so that where the caller split the
	// input makes no difference to the digest.
	if (self.tail_len != 0)
	{
		sz wanted = min(4 - self.tail_len, rest.len);
		mem::copy(&self.tail[self.tail_len], rest.ptr, wanted);
		self.tail_len += wanted;
		rest = rest[wanted..];
		if (self.tail_len < 4) return;
		self.block(bitorder::load_le((uint*)&self.tail));
		self.tail_len = 0;
	}

	// `bitorder::load_le` reads an integer at byte alignment and in little-
	// endian order whatever the machine's own, so the digest is the same on
	// every target. A plain pointer cast and dereference would be neither.
	while (rest.len >= 4)
	{
		self.block(bitorder::load_le((uint*)rest.ptr));
		rest = rest[4..];
	}

	mem::copy(&self.tail, rest.ptr, rest.len);
	self.tail_len = rest.len;
}

// One full four-byte block.
fn void Murmur3.block(&self, uint value)
{
	uint k = value;
	k *= C1;
	k = k.rotl(15);
	k *= C2;

	self.state ^= k;
	self.state = self.state.rotl(13);
	self.state = self.state * 5 + 0xE6546B64;
}

<*
 The digest of everything fed in so far. Takes a copy, so hashing can carry
 on afterwards.
*>
fn Digest Murmur3.final(self)
{
	uint h = self.state;

	// The leftover bytes go through the block mixer but not the rotate,
	// which is what makes them a tail rather than a short block.
	if (self.tail_len != 0)
	{
		uint k = 0;
		for (sz i = 0; i < self.tail_len; i++)
		{
			k |= (uint)self.tail[i] << (8 * i);
		}
		k *= C1;
		k = k.rotl(15);
		k *= C2;
		h ^= k;
	}

	h ^= (uint)self.total;
	return mix::fmix32(h);
}

<*
 One shot over a slice.
*>
fn Digest hash(char[] bytes)
{
	return hash_seed(0, bytes);
}

<*
 One shot, seeded.
*>
fn Digest hash_seed(uint seed, char[] bytes)
{
	Murmur3 h;
	h.init_seed(seed);
	h.update(bytes);
	return h.final();
}
