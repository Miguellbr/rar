import { Blake2sp } from '../lib/rar5/blake2.ts';

Deno.test('blake2sp: empty input matches the reference vector', () => {
	const h = new Blake2sp();
	const got = h.digest().toHex();
	// from the BLAKE2 reference KAT for BLAKE2sp.
	const want = 'dd0e891776933f43c7d032b08a917e25741f8aa9a12c12e1cac8801500f2ca4f';
	if (got !== want) {
		throw new Error(`empty: got ${got}, want ${want}`);
	}
});

Deno.test('blake2sp: streaming and one-shot produce the same digest', () => {
	const data = new Uint8Array(2048);
	for (let i = 0; i < data.length; i++) {
		data[i] = i & 0xff;
	}

	const oneShot = new Blake2sp();
	oneShot.update(data);
	const want = oneShot.digest().toHex();

	// feed one byte at a time — exercises the per-block partial-buffer path
	// and rotates through every leaf many times before crossing 64-byte and
	// 512-byte boundaries.
	const byByte = new Blake2sp();
	for (let i = 0; i < data.length; i++) {
		byByte.update(data.subarray(i, i + 1));
	}
	const gotByByte = byByte.digest().toHex();
	if (gotByByte !== want) {
		throw new Error(`by-byte: got ${gotByByte}, want ${want}`);
	}

	// chunk size deliberately not a divisor of either the leaf block (64)
	// or the stripe (512), so the dispatcher splits chunks across leaves.
	const chunked = new Blake2sp();
	for (let i = 0; i < data.length; i += 7) {
		chunked.update(data.subarray(i, Math.min(i + 7, data.length)));
	}
	const gotChunked = chunked.digest().toHex();
	if (gotChunked !== want) {
		throw new Error(`7-byte: got ${gotChunked}, want ${want}`);
	}
});

Deno.test('blake2sp: stripe-aligned inputs hash correctly', () => {
	// 512 bytes is exactly one full stripe — leaf 7 must receive its 64-byte
	// block and finalize as the rightmost node. one-shot vs 256+256.
	const data = new Uint8Array(512);
	for (let i = 0; i < data.length; i++) {
		data[i] = (i * 7 + 13) & 0xff;
	}

	const oneShot = new Blake2sp();
	oneShot.update(data);
	const want = oneShot.digest().toHex();

	const split = new Blake2sp();
	split.update(data.subarray(0, 256));
	split.update(data.subarray(256));
	const got = split.digest().toHex();

	if (got !== want) {
		throw new Error(`split: got ${got}, want ${want}`);
	}
});
