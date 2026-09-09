// SPDX-License-Identifier: CC0-1.0

// CRC-32: the checksum in gzip, PNG, zip and Ethernet.
//
// A CRC is not a hash: it is a polynomial remainder over GF(2), and therefore
// linear. That is what lets `combine` join the checksums of two pieces without
// re-reading a byte, and also why it must never stand in for a hash - given a
// checksum and a message, changing the message to keep the checksum is
// arithmetic, not work.
//
//   `crc32`      the one people mean by "CRC-32": gzip, PNG, zip
//   `crc32c`     CRC-32C: iSCSI, ext4, and what SSE4.2 computes in hardware
//   `Crc{POLY}`  any other reflected polynomial you have to interoperate with
//
// Each answers to the same calls as a hasher - `Digest`, `hash`, `init`,
// `update`, `final` - and adds `init_from`, to resume from a stored digest,
// and `combine`. Nothing allocates: the 1 KiB table is built at compile time.
//
// The generic parameter is the polynomial, a `uint` constant. A C3 generic
// module takes constants as readily as types, which is what lets one table
// builder and one `combine` serve every polynomial without a copy each.
module fluxion::hash::crc <POLYNOMIAL>;

// What `final` and `hash` return.
alias Digest = uint;

<*
 A table-driven CRC-32 over `POLYNOMIAL`, in the reflected convention every
 32-bit CRC in the wild uses: input bits enter low end first, the register
 starts at all ones, and the result is inverted on the way out.
*>
struct Crc
{
	// The register, held in its inverted form so that `update` is a plain
	// table lookup and the inversion happens once, in `final`.
	uint state;
}

// One byte's worth of division, precomputed. 256 entries because a byte
// selects the row; the alternative is eight shifts per byte.
//
// C3 folds a macro at compile time when everything in it is compile time:
// `$`-prefixed variables, `$for` loops, and nothing that would have to exist
// at run time. A plain `uint[256] t` local would break that - the compiler
// says so - which is why the scratch array is `$t`. The result is a genuine
// constant: it lives in read-only data, and there is no code that fills it.
macro uint[256] @table() @const @private
{
	var $t = (uint[256]){};
	$for var $i = 0; $i < 256; $i++:
		var $remainder = (uint)$i;
		$for var $bit = 0; $bit < 8; $bit++:
			$remainder = ($remainder & 1) ? ($remainder >> 1) ^ (uint)POLYNOMIAL : $remainder >> 1;
		$endfor
		$t[$i] = $remainder;
	$endfor
	return $t;
}

const uint[256] TABLE @private = @table();

<*
 A checksum over no bytes yet.
*>
fn void Crc.init(&self)
{
	self.state = 0xFFFFFFFF;
}

<*
 Carry on from a digest computed earlier, so checksumming a file in two
 sessions gives the same answer as doing it in one:

     Crc32 crc;
     crc.init_from(stored);
     crc.update(new_bytes);

 A CRC has no seed - there is nothing to vary but the polynomial - so this is
 the only other way in.
*>
fn void Crc.init_from(&self, Digest digest)
{
	self.state = ~digest;
}

<*
 Feed in more bytes. Where the input is split across calls makes no
 difference to the result.
*>
fn void Crc.update(&self, char[] bytes)
{
	uint state = self.state;
	foreach (byte : bytes)
	{
		state = TABLE[(state ^ byte) & 0xFF] ^ (state >> 8);
	}
	self.state = state;
}

<*
 The checksum of everything fed in so far. Takes a copy, so checksumming can
 carry on afterwards.
*>
fn Digest Crc.final(self)
{
	return ~self.state;
}

<*
 One shot over a slice.
*>
fn Digest hash(char[] bytes)
{
	Crc crc;
	crc.init();
	crc.update(bytes);
	return crc.final();
}

<*
 The checksum of `a ++ b`, from the checksum of each piece and the length of
 the second. Exact, not an estimate:

     crc32::combine(crc32::hash(a), crc32::hash(b), b.len) == crc32::hash(a ++ b)

 For pieces that arrive out of order, are checksummed on different threads,
 or were checksummed years apart - appending to an archive need not re-read
 it.

 The work is proportional to the bits in `b_len`, not to `b_len`: pushing a
 checksum through `n` zero bytes is a linear map, so repeated squaring
 reaches any length in about 32 steps.
*>
fn Digest combine(Digest a, Digest b, sz b_len)
{
	if (b_len == 0) return a;

	// The map for one zero bit: row 0 is the polynomial a set top bit feeds
	// back, the rest is the identity shifted once.
	uint[32] odd;
	odd[0] = (uint)POLYNOMIAL;
	uint bit = 1;
	foreach (&row : odd[1..])
	{
		*row = bit;
		bit <<= 1;
	}

	uint[32] even;
	square(&even, &odd); // two zero bits
	square(&odd, &even); // four

	uint crc = a;
	sz len = b_len;
	while (true)
	{
		// Each squaring doubles the run of zeros the map stands for, so the
		// bits of `len` select which of them to apply.
		square(&even, &odd);
		if (len & 1) crc = apply(&even, crc);
		len >>= 1;
		if (len == 0) break;

		square(&odd, &even);
		if (len & 1) crc = apply(&odd, crc);
		len >>= 1;
		if (len == 0) break;
	}

	// `a` pushed through the length of `b` now shares a register with `b`'s
	// own checksum, and over GF(2) addition is xor.
	return crc ^ b;
}

// A 32x32 bit matrix over GF(2), one column per row entry, applied to
// `vector`: sum the rows the set bits select, where sum means xor.
fn uint apply(uint[32]* matrix, uint vector) @private
{
	uint sum = 0;
	uint rest = vector;
	for (sz i = 0; rest != 0; rest >>= 1, i++)
	{
		if (rest & 1) sum ^= (*matrix)[i];
	}
	return sum;
}

// `out = matrix * matrix`: the map for twice as many zero bytes.
fn void square(uint[32]* out, uint[32]* matrix) @private
{
	foreach (i, &row : *out) *row = apply(matrix, (*matrix)[i]);
}

// -------------------------------------------------------------------------
// Polynomials
// -------------------------------------------------------------------------

// The reflected form of each polynomial, which is how a table-driven CRC
// spells it: bit-reversed, with the implicit high term dropped. A polynomial
// that is not here is spelled out: `Crc{0x...}`.
module fluxion::hash::polynomial;

// The CRC-32 of gzip, PNG, zip, Ethernet and everything else that just says
// "CRC-32". Normal form 0x04C11DB7.
const uint IEEE = 0xEDB88320;

// CRC-32C, Castagnoli: better error detection than IEEE at every message
// length, and the one x86 has an instruction for. Normal form 0x1EDC6F41.
const uint CASTAGNOLI = 0x82F63B78;

// Koopman: chosen for short messages, where it catches more of what IEEE
// misses. Normal form 0x741B8CD7.
const uint KOOPMAN = 0xEB31D82E;

// -------------------------------------------------------------------------
// The two instantiations
// -------------------------------------------------------------------------

// CRC-32 with the IEEE polynomial. The default, and what `hash::checksum`
// uses.
module fluxion::hash::crc32;
import fluxion::hash::crc, fluxion::hash::polynomial;

// What `final` and `hash` return.
alias Digest = uint;

alias Crc32 = Crc{polynomial::IEEE};
alias hash = crc::hash{polynomial::IEEE};
alias combine = crc::combine{polynomial::IEEE};

// CRC-32C.
module fluxion::hash::crc32c;
import fluxion::hash::crc, fluxion::hash::polynomial;

// What `final` and `hash` return.
alias Digest = uint;

alias Crc32c = Crc{polynomial::CASTAGNOLI};
alias hash = crc::hash{polynomial::CASTAGNOLI};
alias combine = crc::combine{polynomial::CASTAGNOLI};

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

module fluxion::hash::crc_test @test;
import fluxion::hash::crc, fluxion::hash::crc32, fluxion::hash::crc32c, fluxion::hash::polynomial;
import std::math::random;
import std::collections::set;

alias Koopman = Crc{polynomial::KOOPMAN};
alias koopman_hash = crc::hash{polynomial::KOOPMAN};

fn void test_check_values() @test
{
	// "123456789" is the string every CRC catalogue publishes a value for.
	test::eq(crc32::hash("123456789"), 0xCBF43926U);
	test::eq(crc32c::hash("123456789"), 0xE3069283U);
	test::eq(koopman_hash("123456789"), 0x2D3DD0AEU);

	test::eq(crc32::hash("a"), 0xE8B7BE43U);
	test::eq(crc32::hash("abc"), 0x352441C2U);
	test::eq(crc32::hash("fluxion"), 0x9AEC45D4U);
	test::eq(crc32::hash("the quick brown fox jumps over the lazy dog"), 0xCE0C5114U);
	test::eq(crc32c::hash("fluxion"), 0xD97132ACU);

	// The empty message. Both conditionings cancel, which is why it is zero
	// and why a zero checksum says nothing about whether anything arrived.
	test::eq(crc32::hash(""), 0U);
	test::eq(crc32c::hash(""), 0U);

	char[256] all;
	foreach (i, &byte : all) *byte = (char)i;
	test::eq(crc32::hash(&all), 0x29058C73U);
	test::eq(crc32c::hash(&all), 0x9C44184BU);
}

fn void test_where_the_input_is_split_makes_no_difference() @test
{
	String text = "the quick brown fox jumps over the lazy dog";
	for (sz cut = 0; cut <= text.len; cut++)
	{
		Crc32 crc;
		crc.init();
		crc.update(text[:cut]);
		crc.update(text[cut..]);
		test::eq(crc.final(), crc32::hash(text));
	}
}

fn void test_a_checksum_can_be_put_down_and_picked_up_again() @test
{
	String text = "the quick brown fox jumps over the lazy dog";

	Crc32 first;
	first.init();
	first.update(text[:10]);
	uint stored = first.final(); // written to a file, sent over a wire

	Crc32 second;
	second.init_from(stored);
	second.update(text[10..]);
	test::eq(second.final(), crc32::hash(text));

	// And reading the digest did not end the first one either.
	first.update(text[10..]);
	test::eq(first.final(), crc32::hash(text));
}

fn void test_combine_is_exact() @test
{
	Sfc64Random prng;
	random::seed(&prng, 0xC0FFEE);

	char[2048] buf;
	prng.next_bytes(&buf);

	for (int round = 0; round < 500; round++)
	{
		sz len = random::next(&prng, buf.len + 1);
		char[] message = buf[:len];
		sz cut = random::next(&prng, (int)len + 1);
		char[] head = message[:cut];
		char[] tail = message[cut..];

		test::eq(crc32::combine(crc32::hash(head), crc32::hash(tail), tail.len), crc32::hash(message));
		test::eq(crc32c::combine(crc32c::hash(head), crc32c::hash(tail), tail.len), crc32c::hash(message));
	}
}

fn void test_combine_over_many_pieces() @test
{
	String[] pieces = { "the quick ", "brown fox ", "jumps over ", "the lazy dog" };

	uint joined = crc32::hash(pieces[0]);
	foreach (piece : pieces[1..]) joined = crc32::combine(joined, crc32::hash(piece), piece.len);
	test::eq(joined, crc32::hash("the quick brown fox jumps over the lazy dog"));

	// Nothing appended is nothing changed.
	test::eq(crc32::combine(joined, crc32::hash(""), 0U), joined);
}

fn void test_one_flipped_bit_changes_the_checksum() @test
{
	// The whole point of a CRC. Every single-bit error in a message this short
	// lands on a different checksum.
	char[12] message = "fluxion hash";
	uint clean = crc32::hash(&message);

	HashSet{uint} seen;
	seen.init(mem);
	defer seen.free();
	seen.add(clean);

	foreach (i, &byte : message)
	{
		for (int bit = 0; bit < 8; bit++)
		{
			*byte ^= (char)(1 << bit);
			uint damaged = crc32::hash(&message);
			*byte ^= (char)(1 << bit);

			test::@check(!seen.contains(damaged));
			seen.add(damaged);
		}
	}
}

fn void test_the_polynomial_is_the_whole_difference() @test
{
	// Same input, three polynomials, three unrelated answers.
	String text = "fluxion";
	test::ne(crc32::hash(text), crc32c::hash(text));
	test::ne(crc32::hash(text), koopman_hash(text));

	// A polynomial that is not named is spelled out instead; this one happens
	// to be the IEEE polynomial written by hand.
	Crc{0xEDB88320} custom;
	custom.init();
	custom.update(text);
	test::eq(custom.final(), crc32::hash(text));
}
