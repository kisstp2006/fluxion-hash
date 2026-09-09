// SPDX-License-Identifier: CC0-1.0

// xxHash64: four independent lanes, 32 bytes a round, merged at the end.
//
// The default when there is nothing special about the input: fastest of the
// three past a few dozen bytes, and wide enough that collisions stay a
// curiosity - a million keys collide with probability about one in 37 million.
module fluxion::hash::xx64;

// What `final` and `hash` return.
alias Digest = ulong;

const ulong PRIME1 @private = 0x9E3779B185EBCA87UL;
const ulong PRIME2 @private = 0xC2B2AE3D27D4EB4FUL;
const ulong PRIME3 @private = 0x165667B19E3779F9UL;
const ulong PRIME4 @private = 0x85EBCA77C2B2AE63UL;
const ulong PRIME5 @private = 0x27D4EB2F165667C5UL;

struct Xx64
{
	// The four lanes, each hashing every fourth eight-byte word.
	ulong[4] acc;
	ulong seed;
	// Bytes that have not filled a 32-byte round yet.
	char[32] buf;
	sz buf_len;
	sz total;
}

<*
 A hasher over no bytes yet.
*>
fn void Xx64.init(&self)
{
	self.init_seed(0);
}

<*
 The same, from a seed.
*>
fn void Xx64.init_seed(&self, ulong seed)
{
	*self = {
		.acc = {
			seed + PRIME1 + PRIME2,
			seed + PRIME2,
			seed,
			seed - PRIME1,
		},
		.seed = seed,
	};
}

<*
 Feed in more bytes. Where the input is split across calls makes no
 difference to the digest.
*>
fn void Xx64.update(&self, char[] bytes)
{
	self.total += bytes.len;
	char[] rest = bytes;

	if (self.buf_len != 0)
	{
		sz wanted = min(32 - self.buf_len, rest.len);
		mem::copy(&self.buf[self.buf_len], rest.ptr, wanted);
		self.buf_len += wanted;
		rest = rest[wanted..];
		if (self.buf_len < 32) return;
		self.round(&self.buf);
		self.buf_len = 0;
	}

	while (rest.len >= 32)
	{
		self.round(rest[:32]);
		rest = rest[32..];
	}

	mem::copy(&self.buf, rest.ptr, rest.len);
	self.buf_len = rest.len;
}

// One 32-byte round: every lane takes its own eight-byte word.
fn void Xx64.round(&self, char[] block)
{
	foreach (i, &lane : self.acc)
	{
		*lane = accumulate(*lane, bitorder::load_le((ulong*)&block[i * 8]));
	}
}

fn ulong accumulate(ulong acc, ulong input) @private
{
	return (acc + input * PRIME2).rotl(31) * PRIME1;
}

fn ulong merge_lane(ulong acc, ulong lane) @private
{
	return (acc ^ accumulate(0, lane)) * PRIME1 + PRIME4;
}

<*
 The digest of everything fed in so far. Takes a copy, so hashing can carry
 on afterwards.
*>
fn Digest Xx64.final(self)
{
	ulong h;
	if (self.total >= 32)
	{
		// Four lanes into one word: rotated by different amounts so they
		// cannot cancel, then merged one at a time.
		h = self.acc[0].rotl(1) + self.acc[1].rotl(7) + self.acc[2].rotl(12) + self.acc[3].rotl(18);
		foreach (lane : self.acc) h = merge_lane(h, lane);
	}
	else
	{
		// Short input never filled a round, so the lanes were never used.
		h = self.seed + PRIME5;
	}
	h += (ulong)self.total;

	// The tail, in eight-, four- and one-byte steps.
	char[] rest = self.buf[:self.buf_len];
	while (rest.len >= 8)
	{
		h ^= accumulate(0, bitorder::load_le((ulong*)rest.ptr));
		h = h.rotl(27) * PRIME1 + PRIME4;
		rest = rest[8..];
	}
	if (rest.len >= 4)
	{
		h ^= (ulong)bitorder::load_le((uint*)rest.ptr) * PRIME1;
		h = h.rotl(23) * PRIME2 + PRIME3;
		rest = rest[4..];
	}
	foreach (byte : rest)
	{
		h ^= (ulong)byte * PRIME5;
		h = h.rotl(11) * PRIME1;
	}

	return avalanche(h);
}

fn ulong avalanche(ulong value) @private
{
	ulong h = value;
	h ^= h >> 33;
	h *= PRIME2;
	h ^= h >> 29;
	h *= PRIME3;
	h ^= h >> 32;
	return h;
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
fn Digest hash_seed(ulong seed, char[] bytes)
{
	Xx64 h;
	h.init_seed(seed);
	h.update(bytes);
	return h.final();
}
