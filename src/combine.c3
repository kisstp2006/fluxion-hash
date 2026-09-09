// SPDX-License-Identifier: CC0-1.0

// Hash combine: several hashes into one.
//
// Adding hashes makes `(1, 2)` and `(2, 1)` equal, xoring lets a value cancel
// itself, and `31 * h + x` leaves the low bits where they were. So `step`
// runs every value through a full 64-bit mixer and multiplies the state by
// the golden ratio, which makes the result behave like a hash of the whole
// tuple however weak the parts were.
//
//   `pair`, `all`, `Combiner`   order matters
//   `unordered`, `Unordered`    order does not
//
// Everything here works in `ulong`; widen a narrower hash on the way in.
module fluxion::hash::combine;
import fluxion::hash::mix;

// The state a combination starts from: the hash of nothing at all.
const ulong EMPTY = mix::GOLDEN64;

<*
 Mix `value` into `state`, and return the new state.

 The result is already a finished hash - there is no separate finalize step -
 so a running combination can be read at any point.
*>
fn ulong step(ulong state, ulong value)
{
	// The value is mixed first, so a weak input does not carry its structure
	// into the result; multiplying the state makes position matter.
	return mix::fmix64((state * mix::GOLDEN64) ^ mix::fmix64(value));
}

<*
 Two hashes into one. Order matters: `pair(a, b)` is not `pair(b, a)`.
*>
fn ulong pair(ulong a, ulong b)
{
	return step(step(EMPTY, a), b);
}

<*
 Any number of hashes into one, in the order given.
*>
fn ulong all(ulong[] hashes)
{
	ulong state = EMPTY;
	foreach (h : hashes) state = step(state, h);
	return state;
}

<*
 A running ordered combination, for when the values arrive over time or come
 from different places.

     Combiner c;
     c.init();
     c.add(hash::hash_bytes(name));
     c.add(version);
     foreach (tag : tags) c.add(hash::hash_bytes(tag));
     ulong digest = c.final();
*>
struct Combiner
{
	ulong state;
}

fn void Combiner.init(&self)
{
	self.state = EMPTY;
}

<*
 Start somewhere other than `EMPTY`, so that two combinations of the same
 values under different seeds disagree.
*>
fn void Combiner.init_seed(&self, ulong seed)
{
	self.state = seed;
}

fn void Combiner.add(&self, ulong value)
{
	self.state = step(self.state, value);
}

fn void Combiner.add_all(&self, ulong[] values)
{
	foreach (value : values) self.add(value);
}

<*
 The combination so far. Every `add` leaves the state mixed, so this only
 reads it out - combining can carry on afterwards.
*>
fn ulong Combiner.final(self)
{
	return self.state;
}

<*
 An order-independent combination: a running total of mixed values.

 Addition is commutative and associative, so members can arrive in any order
 and `remove` undoes an `add` - which is what a changing set, or a directory
 hash that has to be patched rather than recomputed, wants.

 A multiset, not a set: adding the same value twice differs from adding it
 once. Deduplicate first if that is what you meant.
*>
struct Unordered
{
	ulong total;
	ulong count;
}

<*
 The zero-filled struct is already the empty combination, so a freshly
 declared `Unordered` works without this. It is here so that every hasher
 and combiner in the library starts the same way.
*>
fn void Unordered.init(&self)
{
	*self = {};
}

fn void Unordered.add(&self, ulong value)
{
	// Mixed on the way in: sums of nearby numbers are nearby numbers.
	self.total += mix::fmix64(value);
	self.count += 1;
}

fn void Unordered.add_all(&self, ulong[] values)
{
	foreach (value : values) self.add(value);
}

<*
 Take a value back out. Removing what was never added is not an error: it
 leaves a state no sequence of adds would have produced.
*>
fn void Unordered.remove(&self, ulong value)
{
	self.total -= mix::fmix64(value);
	self.count -= 1;
}

<*
 The combination so far. The count goes in here rather than the running
 total, so `remove` restores the state exactly and an empty set does not
 agree with a set holding one zero.
*>
fn ulong Unordered.final(self)
{
	return mix::fmix64(EMPTY ^ self.total ^ (self.count * mix::GOLDEN64));
}

<*
 Any number of hashes into one, ignoring their order.
*>
fn ulong unordered(ulong[] hashes)
{
	Unordered u;
	u.init();
	u.add_all(hashes);
	return u.final();
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

import std::math::random;
import std::collections::set;

fn void test_order_matters_and_does_not() @test
{
	const ulong A = 0x1111111111111111;
	const ulong B = 0x2222222222222222;
	const ulong C = 0x3333333333333333;

	test::ne(pair(A, B), pair(B, A));
	test::ne(all({ A, B, C }), all({ C, B, A }));

	test::eq(unordered({ A, B, C }), unordered({ C, A, B }));
	test::eq(unordered({ A, B, C }), unordered({ B, C, A }));

	// Even so, the two are not the same function.
	test::ne(all({ A, B, C }), unordered({ A, B, C }));
}

fn void test_the_empty_combination_and_the_one_value_one() @test
{
	test::eq(all((ulong[]){}), EMPTY);
	test::eq(all({ 7 }), step(EMPTY, 7));
	test::eq(pair(1, 2), all({ 1, 2 }));

	// A hash of nothing should not be zero: zero is what uninitialised memory
	// and a forgotten call both look like.
	test::ne(all((ulong[]){}), 0UL);
	test::ne(unordered((ulong[]){}), 0UL);

	// An empty set and a set holding one zero are different sets.
	test::ne(unordered((ulong[]){}), unordered({ 0 }));
}

fn void test_combiner_walks_in_step_with_all() @test
{
	ulong[] values = { 5, 0, 0xFFFF_FFFF_FFFF_FFFF, 1UL << 63, 42 };

	Combiner c;
	c.init();
	c.add_all(values);
	test::eq(c.final(), all(values));

	// Reading it does not end it, and adding in pieces is adding.
	Combiner piecewise;
	piecewise.init();
	piecewise.add(values[0]);
	piecewise.final();
	piecewise.add_all(values[1..]);
	test::eq(piecewise.final(), all(values));

	// A seed moves everything.
	Combiner seeded;
	seeded.init_seed(1);
	seeded.add_all(values);
	test::ne(seeded.final(), all(values));
}

fn void test_unordered_takes_values_back_out() @test
{
	ulong[] values = { 11, 22, 33, 44 };

	Unordered set;
	set.init();
	set.add_all(values);
	ulong four = set.final();

	set.add(55);
	test::ne(set.final(), four);
	set.remove(55);
	test::eq(set.final(), four);

	// Removing something that was never there is allowed, and putting it back
	// restores the state - which is what makes an incremental index possible.
	set.remove(99);
	test::ne(set.final(), four);
	set.add(99);
	test::eq(set.final(), four);

	// It is a multiset: twice is not once.
	test::ne(unordered({ 1, 1 }), unordered({ 1 }));
}

fn void test_weak_inputs_still_come_out_spread() @test
{
	// The case that catches naive combining: small integers, in order. If the
	// combination leaked its inputs, these would cluster.
	HashSet{ulong} seen;
	seen.init(mem);
	defer seen.free();

	for (ulong i = 0; i < 256; i++)
	{
		for (ulong j = 0; j < 256; j++)
		{
			ulong combined = pair(i, j);
			test::@check(!seen.contains(combined));
			seen.add(combined);
		}
	}
	test::eq(seen.len(), (sz)(256 * 256));
}

fn void test_a_changed_value_changes_the_whole_result() @test
{
	Sfc64Random prng;
	random::seed(&prng, 0xCAFE);

	sz total = 0;
	const ROUNDS = 256;
	for (int round = 0; round < ROUNDS; round++)
	{
		ulong a = prng.next_long();
		ulong b = prng.next_long();
		ulong base = pair(a, b);
		for (int bit = 0; bit < 64; bit++)
		{
			total += (base ^ pair(a, b ^ (1UL << bit))).popcount();
		}
	}

	// 32 of 64 is the ideal. A combination that merely added or xored its
	// inputs would score one.
	double average = (double)total / (ROUNDS * 64);
	test::@check(average > 30.0 && average < 34.0);
}

fn void test_frozen() @test
{
	// The construction is part of the format the moment anything stores a
	// combined hash. These pin it.
	test::eq(EMPTY, 0x9E3779B97F4A7C15UL);
	test::eq(pair(1, 2), 0xB18793696892B468UL);
	test::eq(all({ 1, 2, 3 }), 0x1D3C257254114B29UL);
	test::eq(unordered({ 1, 2, 3 }), 0x31463BA4ACD51A67UL);
}
