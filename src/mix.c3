// SPDX-License-Identifier: CC0-1.0

// Internal plumbing: the integer mixers everything else is built from.
//
// A mixer stirs one integer into another. It is a bijection, so mixing never
// loses information, and flipping any single input bit flips about half the
// output bits - the property a hash needs and that `x * 31 + y` has not.
//
// `murmur3` finishes with `fmix32` and `combine` uses `fmix64`, which is why
// both live here rather than in either. C3 has no private modules, so this
// one is public by necessity; it is not part of the promised API.
//
// Every multiply in this file overflows on purpose. C3 defines integer
// overflow as two's-complement wrapping, signed or not, so there is no
// wrapping operator to spell it with - `*` is the wrapping multiply. The one
// thing to know is that a project can set `"trap-on-wrap": true` to hunt
// accidental overflow, and this library cannot be built under that setting.
module fluxion::hash::mix;

// The 32-bit golden ratio, `2^32 / phi` rounded to an odd number - odd so
// that multiplication stays invertible.
const uint GOLDEN32 = 0x9E3779B9;

// The 64-bit one, `2^64 / phi`.
const ulong GOLDEN64 = 0x9E3779B97F4A7C15UL;

<*
 MurmurHash3's 32-bit finalizer: shift, multiply, shift, multiply, shift.
*>
fn uint fmix32(uint value)
{
	uint h = value;
	h ^= h >> 16;
	h *= 0x85EBCA6B;
	h ^= h >> 13;
	h *= 0xC2B2AE35;
	h ^= h >> 16;
	return h;
}

<*
 MurmurHash3's 64-bit finalizer, the one SplitMix64 also ends on.
*>
fn ulong fmix64(ulong value)
{
	ulong h = value;
	h ^= h >> 33;
	h *= 0xFF51AFD7ED558CCDUL;
	h ^= h >> 33;
	h *= 0xC4CEB9FE1A85EC53UL;
	h ^= h >> 33;
	return h;
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------
//
// A test is any function marked `@test`; `c3c test` collects them from every
// source file it compiles, so they sit next to what they test, as the Zig
// ones did. `test::eq` and `test::ne` print both sides when they fail, and
// `test::@check` prints the expression.

import std::math::random;
import std::collections::set;

fn void test_zero_stays_zero() @test
{
	// Shifts and multiplies only, so zero is a fixed point. Anything hashing an
	// empty message starts somewhere else.
	test::eq(fmix32(0), 0U);
	test::eq(fmix64(0), 0UL);
}

fn void test_consecutive_inputs_land_far_apart() @test
{
	// The point of a mixer: 0, 1, 2, 3 must not come out as neighbours.
	HashSet{ulong} seen;
	seen.init(mem);
	defer seen.free();

	for (ulong i = 0; i < 1000; i++)
	{
		ulong h = fmix64(i);
		// A bijection cannot repeat itself.
		test::@check(!seen.contains(h));
		seen.add(h);
		if (i != 0)
		{
			// Neighbouring inputs are nowhere near neighbouring outputs.
			ulong previous = fmix64(i - 1);
			test::@check(max(h, previous) - min(h, previous) > 1000);
		}
	}
}

fn void test_one_input_bit_flips_about_half_the_output_bits() @test
{
	Sfc64Random prng;
	random::seed(&prng, 0x5EED);

	sz[64] flipped;
	const ROUNDS = 512;
	for (int round = 0; round < ROUNDS; round++)
	{
		ulong value = prng.next_long();
		ulong base = fmix64(value);
		for (int bit = 0; bit < 64; bit++)
		{
			ulong changed = fmix64(value ^ (1UL << bit));
			flipped[bit] += (base ^ changed).popcount();
		}
	}

	// 32 of 64 bits is the ideal; anything in this band is a healthy avalanche.
	foreach (total : flipped)
	{
		double average = (double)total / ROUNDS;
		test::@check(average > 28.0 && average < 36.0);
	}
}

fn void test_fmix32_avalanches_too() @test
{
	Sfc64Random prng;
	random::seed(&prng, 0x5EED);

	sz total = 0;
	const ROUNDS = 512;
	for (int round = 0; round < ROUNDS; round++)
	{
		uint value = prng.next_int();
		uint base = fmix32(value);
		for (int bit = 0; bit < 32; bit++)
		{
			total += (base ^ fmix32(value ^ (1U << bit))).popcount();
		}
	}

	double average = (double)total / (ROUNDS * 32);
	test::@check(average > 14.0 && average < 18.0);
}
