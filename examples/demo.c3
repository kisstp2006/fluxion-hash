// SPDX-License-Identifier: CC0-1.0

// A tour of Fluxion Hash. Run it with `c3c run demo`.
//
// It indexes a handful of imaginary assets: hashes their contents, checksums
// them in pieces, folds the pieces into one index hash, and then patches that
// index without recomputing it.
module demo;
import std::io;
import fluxion::hash;

enum Kind { MESH, TEXTURE, SOUND }

struct Asset
{
	String name;
	Kind kind;
	String bytes;
}

const Asset[3] ASSETS = {
	{ "hull.mesh", MESH, "vertices, and a great many of them" },
	{ "hull.png", TEXTURE, "pixels, mostly grey" },
	{ "engine.wav", SOUND, "a low hum that loops" },
};

fn void main()
{
	// --- one input, every algorithm --------------------------------------
	String text = "the quick brown fox jumps over the lazy dog";
	io::printfn("--- %d bytes through each of them ---", text.len);
	io::printfn("fnv1a32   0x%08X", fnv1a32::hash(text));
	io::printfn("fnv1a64   0x%016X", fnv1a64::hash(text));
	io::printfn("murmur3   0x%08X", murmur3::hash(text));
	io::printfn("xxhash64  0x%016X", xx64::hash(text));
	io::printfn("crc32     0x%08X  (a checksum, not a hash)", crc32::hash(text));

	// --- checksums that join ---------------------------------------------
	// The file arrives in four pieces, each checksummed where it was made.
	String[] pieces = { "the quick ", "brown fox ", "jumps over ", "the lazy dog" };
	io::printn("\n--- checksums that join ---");

	uint joined = crc32::hash(pieces[0]);
	io::printfn("%-13s 0x%08X", pieces[0], joined);
	foreach (piece : pieces[1..])
	{
		uint piece_crc = crc32::hash(piece);
		joined = crc32::combine(joined, piece_crc, piece.len);
		io::printfn("%-13s 0x%08X  joined so far 0x%08X", piece, piece_crc, joined);
	}
	// Nothing was read twice, and the answer is the one the whole file gives.
	io::printfn("whole file    0x%08X  %s", hash::checksum(text),
		joined == hash::checksum(text) ? "same" : "DIFFERENT");

	// --- hashing values ---------------------------------------------------
	io::printn("\n--- a record, hashed as a value ---");
	foreach (asset : ASSETS)
	{
		io::printfn("%-12s %-8s 0x%016X", asset.name, asset.kind, hash::hash_value(asset));
	}

	// Fields are walked, so a change anywhere moves the digest - and padding,
	// which is not a field, moves nothing.
	Asset retextured = ASSETS[1];
	retextured.bytes = "pixels, mostly blue";
	io::printfn("%-12s %-8s 0x%016X  after one word changed",
		retextured.name, retextured.kind, hash::hash_value(retextured));

	// --- one number for the lot -------------------------------------------
	io::printn("\n--- folding them into one index ---");

	Combiner in_order;
	in_order.init();
	Unordered any_order;
	any_order.init();
	foreach (asset : ASSETS)
	{
		in_order.add(hash::hash_value(asset));
		any_order.add(hash::hash_value(asset));
	}

	Combiner reversed;
	reversed.init();
	Unordered reversed_any;
	reversed_any.init();
	foreach_r (asset : ASSETS)
	{
		reversed.add(hash::hash_value(asset));
		reversed_any.add(hash::hash_value(asset));
	}

	io::printfn("ordered    0x%016X   reversed 0x%016X", in_order.final(), reversed.final());
	io::printfn("unordered  0x%016X   reversed 0x%016X", any_order.final(), reversed_any.final());
	io::printn("A list is a list, so the ordered fold moves when the list is reordered.");
	io::printn("A directory is a set, so the unordered one does not.");

	// --- patching the index -----------------------------------------------
	// One asset changed. Take the old hash out, put the new one in - the other
	// two are never touched.
	any_order.remove(hash::hash_value(ASSETS[1]));
	any_order.add(hash::hash_value(retextured));

	Unordered recomputed;
	recomputed.init();
	recomputed.add(hash::hash_value(ASSETS[0]));
	recomputed.add(hash::hash_value(retextured));
	recomputed.add(hash::hash_value(ASSETS[2]));

	io::printfn("\npatched    0x%016X\nrecomputed 0x%016X  %s", any_order.final(), recomputed.final(),
		any_order.final() == recomputed.final() ? "same" : "DIFFERENT");

	// --- hashing on the way past -------------------------------------------
	// The manifest is hashed as it is written, with no copy of it in between.
	io::printn("\n--- a manifest, hashed as it is written ---");

	Stream{Xx64} stream;
	stream.init();
	DString kept;
	kept.init(mem);
	defer kept.free();

	foreach (asset : ASSETS)
	{
		// `!!` says a failure here is a bug: a hashing stream cannot fail,
		// and the interface only says it might because a file could.
		io::fprintf(&stream, "%s %s %d\n", asset.name, asset.kind, asset.bytes.len)!!;
		kept.appendf("%s %s %d\n", asset.name, asset.kind, asset.bytes.len);
	}
	String manifest = kept.str_view();

	io::print(manifest);
	io::printfn("streamed   0x%016X\nkept, then 0x%016X  %s", stream.final(), hash::hash_bytes(manifest),
		stream.final() == hash::hash_bytes(manifest) ? "same" : "DIFFERENT");
}
