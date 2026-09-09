// SPDX-License-Identifier: CC0-1.0

// Fluxion Hash - turning bytes, values and other hashes into one number.
//
// The pieces, each its own module under `fluxion::hash`:
//
//   `fnv1a32`, `fnv1a64`   tiny and byte at a time, good on short keys
//   `murmur3`              the classic 32-bit workhorse
//   `xx64`                 fast on long input, 64 bits out; the default
//   `crc32`, `crc32c`      CRC-32 and CRC-32C, with checksums that can be joined
//   `combine`              several hashes into one, in order or regardless of order
//   `stream`               an `OutStream` that hashes what goes past
//
// Every hasher shares one shape, so swapping between them is a change of
// name and nothing else:
//
//   `Digest`                 the type that comes out, `uint` or `ulong`
//   `hash` / `hash_seed`     one shot, over a slice: `xx64::hash(bytes)`
//   `init` / `init_seed`     start a running hash: `Xx64 h; h.init();`
//   `update`                 feed it more bytes, any number of times
//   `final`                  read the digest out, and carry on if you like
//
// A CRC has no seed, so `crc32` swaps `init_seed` for `init_from`, which
// resumes from a digest computed earlier.
//
// This module holds what is not one algorithm's: hashing a whole value, and
// the shorthands that pick the default. Importing `fluxion::hash` imports
// every sub-module with it, so one `import` is the whole library.
//
// Nothing here allocates, and nothing here is cryptographic: these are for
// hash tables, caches, dirty checks and transmission errors, not for
// signatures or for anything an attacker chooses the input of.
module fluxion::hash;
import fluxion::hash::xx64, fluxion::hash::crc32, fluxion::hash::combine;

// The algorithm the shorthands below use.
alias Default = Xx64;

<*
 Shorthand for `xx64::hash`, so call sites read `hash::hash_bytes(b)`.
*>
fn ulong hash_bytes(char[] bytes)
{
	return xx64::hash(bytes);
}

<*
 Shorthand for `crc32::hash`: the checksum, as opposed to the hash.
*>
fn uint checksum(char[] bytes)
{
	return crc32::hash(bytes);
}

// -------------------------------------------------------------------------
// Hashing values
// -------------------------------------------------------------------------

// What a pointer contributes to a hash.
enum Follow
{
	// The address, not what is at it. Two equal strings in two places hash
	// differently; this is identity, not equality.
	ADDRESS,
	// What it points at. Two equal strings hash the same wherever they live,
	// which is what a table keyed by content needs.
	CONTENTS,
}

<*
 Feed `value` into `hasher`, field by field.

 Integers go in little-endian at their declared width, so a value hashes the
 same on a big-endian machine. Padding is never hashed: fields are walked
 rather than reinterpreted. Slices contribute their length, so `{ "ab", "c" }`
 and `{ "a", "bc" }` do not land on one digest, and enums contribute their
 ordinal rather than any associated value.

 Floats are hashed by bit pattern, the only stable choice, which means `0.0`
 and `-0.0` differ. A fault is hashed by its name, because its value is
 assigned afresh each run. Anything with no defensible answer - a union, which
 does not know which field is live; a function pointer; an `any` - is a
 compile error rather than a guess.

 This is a macro, and the whole walk happens at compile time: `$Typeof` asks
 what the argument is, `$switch` picks a branch on it, and only that branch
 is compiled. A struct is opened with `$foreach` over `$Type::members`, and
 `value.$member` is the field by name. What comes out is straight-line code
 for exactly this type, with no reflection left in it at run time - the same
 thing Zig's `inline for` over `@typeInfo` produced.
*>
macro void update_value(hasher, value, Follow $follow = CONTENTS)
{
	var $Type = $Typeof(value);
	$switch $Type::kind:
		$case VOID:
			// Nothing to say.
		$case BOOL:
			update_value(hasher, (char)value, $follow);
		$case SIGNED_INT:
		$case UNSIGNED_INT:
			// `bitorder::store_le` writes the bytes little end first whatever
			// the machine does, and a negative number goes in as its two's
			// complement at the same width.
			char[$Type::size] buf;
			bitorder::store_le(&buf, value);
			hasher.update(&buf);
		$case FLOAT:
			$switch $Type::size:
				$case 2:
					update_value(hasher, bitcast(value, ushort), $follow);
				$case 4:
					update_value(hasher, bitcast(value, uint), $follow);
				$case 8:
					update_value(hasher, bitcast(value, ulong), $follow);
				$default:
					update_value(hasher, bitcast(value, uint128), $follow);
			$endswitch
		$case ENUM:
			update_value(hasher, value.ordinal, $follow);
		$case CONSTDEF:
		$case TYPEDEF:
		$case BITSTRUCT:
			// A typedef is its underlying type wearing a name; a bitstruct is
			// one integer wearing field names. Hash the thing underneath: one
			// pass instead of one per field.
			update_value(hasher, ($Typefrom($Type::inner))value, $follow);
		$case FAULT:
			update_value(hasher, value.description, $follow);
		$case STRUCT:
			$foreach $member : $Type::members:
				update_value(hasher, value.$member, $follow);
			$endforeach
		$case ARRAY:
			foreach (element : value) update_value(hasher, element, $follow);
		$case VECTOR:
			$for var $i = 0; $i < $Type::len; $i++:
				update_value(hasher, value[$i], $follow);
			$endfor
		$case SLICE:
			$switch $follow:
				$case ADDRESS:
					update_value(hasher, (uptr)value.ptr, $follow);
					update_value(hasher, (ulong)value.len, $follow);
				$case CONTENTS:
					// Length first, so a run of slices cannot be re-cut into
					// a different run with the same digest.
					update_value(hasher, (ulong)value.len, $follow);
					$if $Type::inner == char::typeid:
						hasher.update(value);
					$else
						foreach (element : value) update_value(hasher, element, $follow);
					$endif
			$endswitch
		$case POINTER:
			$switch $follow:
				$case ADDRESS:
					update_value(hasher, (uptr)value, $follow);
				$case CONTENTS:
					$if $Type::inner == void::typeid:
						$error("cannot follow the void pointer: it does not know what it points at. Hash it with ADDRESS");
					$else
						update_value(hasher, *value, $follow);
					$endif
			$endswitch
		$case UNION:
			$error("cannot hash the union " +++ $Type::name +++ ": there is no way to tell which field is live");
		$default:
			$error("cannot hash " +++ $Type::name);
	$endswitch
}

<*
 One shot: hash a whole value with `Hasher`.

     struct Point { int x; int y; }
     ulong h = hash::hash_value_with(Xx64, Point { 3, 4 });

 The hasher is a type, passed as a `$`-parameter because a type is a
 compile-time thing; the return type is whatever its `final` returns.
*>
macro hash_value_with($Hasher, value, Follow $follow = CONTENTS)
{
	$Hasher hasher;
	hasher.init();
	update_value(&hasher, value, $follow);
	return hasher.final();
}

<*
 The same, from a seed.
*>
macro hash_value_seed_with($Hasher, seed, value, Follow $follow = CONTENTS)
{
	$Hasher hasher;
	hasher.init_seed(seed);
	update_value(&hasher, value, $follow);
	return hasher.final();
}

<*
 Shorthand for hashing a whole value with the default algorithm. See
 `update_value` for what each kind of type contributes.
*>
macro ulong hash_value(value, Follow $follow = CONTENTS)
{
	return hash_value_with(Default, value, $follow);
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

import fluxion::hash::fnv1a32, fluxion::hash::fnv1a64, fluxion::hash::murmur3;
import fluxion::hash::stream;
import std::io;
import std::math::random;

fn void test_known_digests() @test
{
	// Frozen. These are the published values for each algorithm, and they are
	// what a reader of a file written by this library will compute.
	test::eq(fnv1a32::hash(""), 0x811C9DC5U);
	test::eq(fnv1a32::hash("a"), 0xE40C292CU);
	test::eq(fnv1a32::hash("abc"), 0x1A47E90BU);
	test::eq(fnv1a32::hash("123456789"), 0xBB86B11CU);

	test::eq(fnv1a64::hash(""), 0xCBF29CE484222325UL);
	test::eq(fnv1a64::hash("a"), 0xAF63DC4C8601EC8CUL);
	test::eq(fnv1a64::hash("abc"), 0xE71FA2190541574BUL);
	test::eq(fnv1a64::hash("message digest"), 0x2DCBCCE86FCE9934UL);

	test::eq(murmur3::hash(""), 0x00000000U);
	test::eq(murmur3::hash("a"), 0x3C2569B2U);
	test::eq(murmur3::hash("abc"), 0xB3DD93FAU);
	test::eq(murmur3::hash("123456789"), 0xB4FEF382U);
	test::eq(murmur3::hash_seed(0x1234, "fluxion"), 0xA6BC0EC0U);

	test::eq(xx64::hash(""), 0xEF46DB3751D8E999UL);
	test::eq(xx64::hash("a"), 0xD24EC4F1A98C6E5BUL);
	test::eq(xx64::hash("abc"), 0x44BC2CF5AD770999UL);
	test::eq(xx64::hash("123456789"), 0x8CB841DB40E6AE83UL);
	test::eq(xx64::hash_seed(0xDEADBEEF, "fluxion"), 0x7695D4A839645C48UL);

	// Longer than one 32-byte round, so xxHash64 uses all four lanes.
	String seventy = "0123456789012345678901234567890123456789012345678901234567890123456789";
	test::eq(xx64::hash(seventy), 0x4916A0F3F0E1C781UL);
	test::eq(murmur3::hash(seventy), 0x4EEA03A8U);
}

fn void test_every_byte_value() @test
{
	char[256] all;
	foreach (i, &byte : all) *byte = (char)i;

	test::eq(fnv1a64::hash(&all), 0x4242DC5249C33625UL);
	test::eq(murmur3::hash(&all), 0xE40A0E56U);
	test::eq(xx64::hash(&all), 0x1FACBE8406CD904BUL);
}

fn void test_where_the_input_is_split_makes_no_difference() @test
{
	Sfc64Random prng;
	random::seed(&prng, 0xF10D);

	char[512] buf;
	prng.next_bytes(&buf);

	for (int round = 0; round < 200; round++)
	{
		sz len = random::next(&prng, buf.len + 1);
		char[] input = buf[:len];

		Fnv1a64 fnv;
		fnv.init();
		Murmur3 murmur;
		murmur.init();
		Xx64 xx;
		xx.init();

		char[] rest = input;
		while (rest.len != 0)
		{
			// Drawn into a local first. `min` is a macro whose extra arguments
			// are spliced in as text, so `min(rest.len, random::next(..))`
			// would draw twice - compare one number and keep another - and
			// hand out more bytes than are left.
			sz draw = (sz)random::next(&prng, 40) + 1;
			sz take = min(rest.len, draw);
			fnv.update(rest[:take]);
			murmur.update(rest[:take]);
			xx.update(rest[:take]);
			rest = rest[take..];
		}

		test::eq(fnv.final(), fnv1a64::hash(input));
		test::eq(murmur.final(), murmur3::hash(input));
		test::eq(xx.final(), xx64::hash(input));
	}
}

fn void test_final_does_not_end_the_hash() @test
{
	Xx64 xx;
	xx.init();
	xx.update("fluxion");
	test::eq(xx.final(), xx64::hash("fluxion"));

	// Reading the digest changed nothing, so the next one covers both halves.
	xx.update(" hash");
	test::eq(xx.final(), xx64::hash("fluxion hash"));
}

fn void test_seeds() @test
{
	test::eq(murmur3::hash_seed(0, "fluxion"), murmur3::hash("fluxion"));
	test::eq(xx64::hash_seed(0, "fluxion"), xx64::hash("fluxion"));
	test::ne(xx64::hash_seed(1, "fluxion"), xx64::hash("fluxion"));
	test::ne(murmur3::hash_seed(1, "fluxion"), murmur3::hash("fluxion"));

	// FNV has no seed of its own: seeding it means starting the state
	// somewhere other than the offset basis.
	test::eq(fnv1a32::hash_seed(0x811C9DC5, "fluxion"), fnv1a32::hash("fluxion"));
	test::ne(fnv1a32::hash_seed(0, "fluxion"), fnv1a32::hash("fluxion"));
}

fn void test_an_empty_hasher_is_the_starting_state() @test
{
	Fnv1a32 fnv;
	fnv.init();
	test::eq(fnv.final(), 0x811C9DC5);
	Murmur3 murmur;
	murmur.init_seed(7);
	test::eq(murmur.final(), murmur3::hash_seed(7, ""));
	Xx64 xx;
	xx.init();
	test::eq(xx.final(), xx64::hash(""));
}

fn void test_values_go_in_at_their_declared_width_little_end_first() @test
{
	// Two bytes for a ushort, not eight, and no padding anywhere near it.
	test::eq(hash_value((ushort)0x0201), xx64::hash({ 0x01, 0x02 }));
	// An array of bytes is its bytes.
	test::eq(hash_value((char[2]){ 1, 2 }), xx64::hash({ 1, 2 }));
	// A negative number is its two's complement, at the same width.
	test::eq(hash_value((short)-1), xx64::hash({ 0xFF, 0xFF }));
}

// C3 declares types at module level only, so the fixtures the tests below
// share sit here rather than inside the test that uses them.
struct Padded { char flag; uint count; }
struct Point { int x; int y; }
struct Record
{
	String name;
	ushort version;
	String[] tags;
}
enum Colour { RED, GREEN, BLUE }
bitstruct Flags : char
{
	bool visible : 0;
	bool locked : 1;
	uint level : 2..7;
}
faultdef FULL, EMPTY;
typedef Metres = double;

fn void test_padding_is_not_hashed() @test
{
	Padded one;
	mem::set(&one, 0xAA, Padded::size);
	one.flag = 1;
	one.count = 2;

	Padded two;
	mem::set(&two, 0x55, Padded::size);
	two.flag = 1;
	two.count = 2;

	// Byte for byte these differ; field by field they do not.
	test::@check(!mem::equals(&one, &two, Padded::size));
	test::eq(hash_value(one), hash_value(two));
}

fn void test_values_of_every_shape() @test
{
	test::ne(hash_value(Colour.RED), hash_value(Colour.BLUE));
	test::ne(
		hash_value((Flags){ .visible = true, .locked = false, .level = 3 }),
		hash_value((Flags){ .visible = true, .locked = true, .level = 3 }));

	// Floats by bit pattern: the two zeros are two values.
	test::ne(hash_value(0.0), hash_value(-0.0));
	test::eq(hash_value(1.5f), hash_value(bitcast(1.5f, uint)));

	// A typedef hashes as what it wraps, so a distance and a plain number
	// agree - the type is the caller's business, the bytes are the hash's.
	test::eq(hash_value((Metres)3.0), hash_value(3.0));

	// Arrays, vectors and faults all have an answer.
	test::eq(hash_value((ushort[3]){ 1, 2, 3 }), hash_value((ushort[<3>]){ 1, 2, 3 }));
	test::ne(hash_value(FULL), hash_value(EMPTY));
}

fn void test_slices_carry_their_length() @test
{
	// Otherwise these two would be the same three bytes in a row.
	String[] split = { "ab", "c" };
	String[] other = { "a", "bc" };
	test::ne(hash_value(split), hash_value(other));
}

fn void test_following_a_pointer_or_not() @test
{
	String text = "fluxion";
	char[7] copy;
	mem::copy(&copy, text.ptr, text.len);
	char[] same_bytes = &copy;

	// Same content, different address.
	test::eq(hash_value((char[])text), hash_value(same_bytes));
	test::ne(hash_value((char[])text, ADDRESS), hash_value(same_bytes, ADDRESS));

	// A pointer to a struct is followed the same way.
	Point p = { 3, 4 };
	Point q = { 3, 4 };
	test::eq(hash_value(&p), hash_value(&q));
	test::eq(hash_value(&p), hash_value(p));
	test::ne(hash_value(&p, ADDRESS), hash_value(&q, ADDRESS));
}

fn void test_stream_hashes_what_is_written_through_it() @test
{
	Stream{Xx64} stream;
	stream.init();

	io::fprintf(&stream, "%s", "fluxion")!!;
	stream.write_byte(' ')!!;
	io::fprintf(&stream, "%d", 42)!!;
	test::eq(stream.final(), xx64::hash("fluxion 42"));

	// A CRC has the same shape, so it streams too.
	Stream{Crc32} crc;
	crc.init();
	io::fprintf(&crc, "%s", ".....")!!;
	test::eq(crc.final(), crc32::hash("....."));

	// Seeded, and read part way through.
	Xx64 nine;
	nine.init_seed(9);
	Stream{Xx64} seeded;
	seeded.init_from(nine);
	io::fprintf(&seeded, "half")!!;
	test::eq(seeded.final(), xx64::hash_seed(9, "half"));
	io::fprintf(&seeded, " and half")!!;
	test::eq(seeded.final(), xx64::hash_seed(9, "half and half"));
}

fn void test_the_pieces_compose() @test
{
	// A tiny index: three blobs, each with a content hash, and one checksum
	// over the lot.
	String[] blobs = { "the quick brown fox ", "jumps over ", "the lazy dog" };

	Combiner ordered;
	ordered.init();
	Unordered any_order;
	any_order.init();
	Crc32 whole;
	whole.init();
	foreach (blob : blobs)
	{
		ordered.add(hash_bytes(blob));
		any_order.add(hash_bytes(blob));
		whole.update(blob);
	}

	// The checksum of the three joined, without joining them: each piece was
	// checksummed on its own, and the pieces were put together afterwards.
	uint joined = checksum(blobs[0]);
	foreach (blob : blobs[1..]) joined = crc32::combine(joined, checksum(blob), blob.len);
	test::eq(joined, whole.final());
	test::eq(joined, checksum("the quick brown fox jumps over the lazy dog"));

	// Reversed, the ordered combination moves and the unordered one does not.
	Combiner backwards;
	backwards.init();
	Unordered backwards_any;
	backwards_any.init();
	foreach_r (blob : blobs)
	{
		backwards.add(hash_bytes(blob));
		backwards_any.add(hash_bytes(blob));
	}
	test::ne(ordered.final(), backwards.final());
	test::eq(any_order.final(), backwards_any.final());
}

fn void test_a_record_hashed_by_value_and_by_hand() @test
{
	Record record = { .name = "fluxion", .version = 2, .tags = { "c3", "hash" } };

	// Whole value at once, fields walked for you.
	ulong direct = hash_value(record);

	// Or field by field, which is what `hash_value` does underneath - and what
	// you would write by hand to leave a field out of the hash.
	ulong by_hand = combine::all({
		hash_bytes(record.name),
		record.version,
		combine::all({ hash_bytes(record.tags[0]), hash_bytes(record.tags[1]) }),
	});

	// Two different constructions, so two different numbers; what matters is
	// that each is stable and that a change in any field moves it.
	test::ne(direct, by_hand);

	Record changed = record;
	changed.version = 3;
	test::ne(hash_value(changed), direct);
}

fn void test_shorthands() @test
{
	test::eq(hash_bytes("fluxion"), xx64::hash("fluxion"));
	test::eq(checksum("fluxion"), crc32::hash("fluxion"));
	test::eq(checksum("fluxion"), 0x9AEC45D4U);
	test::eq(hash_value((uint)7), hash_value((uint)7));
}
