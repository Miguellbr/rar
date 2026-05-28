import { rar3DeriveKey } from '../lib/rar3/crypto.ts';
import { Sha1 } from '../lib/rar3/sha1.ts';

/**
 * @module
 *
 * KDF vectors for `rar3DeriveKey`. the three cases cover, in order: a short
 * salt where rarbug never triggers, a 28-character password whose 64-byte
 * seed sits exactly on the rarbug threshold (still no corruption), and a
 * 29-character password whose 66-byte seed crosses the threshold and
 * exercises the in-place corruption. expected outputs are copied verbatim
 * from rarfile's `tests/test_hashing.py::test_rar3_s2k`.
 */

const expectHex = (label: string, actual: Uint8Array, expected: string): void => {
	const got = actual.toHex();
	if (got !== expected) {
		throw new Error(`${label}: expected ${expected}, got ${got}`);
	}
};

Deno.test('rar3DeriveKey: short password ("password" / 3-byte salt) matches rarfile', () => {
	const { iv, key } = rar3DeriveKey('password', Uint8Array.fromHex('00ff00'));
	expectHex('key', key, 'a160cb31cb262e9231c0b6fc984fbb0d');
	expectHex('iv', iv, 'aa54a659fb0c359b30f353a6343fb11d');
});

Deno.test('rar3DeriveKey: 28-char password (64-byte seed, rarbug-threshold) matches rarfile', () => {
	const { iv, key } = rar3DeriveKey('p'.repeat(28), Uint8Array.fromHex('1122334455667788'));
	expectHex('key', key, 'ffff33ffaf31987c899ccc2f965a8927');
	expectHex('iv', iv, 'bdff6873721b247afa4f978448a5aeef');
});

Deno.test('rar3DeriveKey: 29-char password (66-byte seed, rarbug active) matches rarfile', () => {
	const { iv, key } = rar3DeriveKey('p'.repeat(29), Uint8Array.fromHex('1122334455667788'));
	expectHex('key', key, '306cafde28f1ea78c9427c3ec642c0db');
	expectHex('iv', iv, '173ecdf574c0bfe9e7c23bdfd96fa435');
});

Deno.test('Sha1.updateWithRar3Corruption: leaves short data unchanged', () => {
	const data = new Uint8Array(64);
	for (let idx = 0; idx < 64; idx++) {
		data[idx] = idx;
	}
	const original = data.slice();

	const sha = new Sha1();
	sha.updateWithRar3Corruption(data);

	for (let idx = 0; idx < 64; idx++) {
		if (data[idx] !== original[idx]) {
			throw new Error(`expected data unchanged at byte ${idx}, got 0x${data[idx].toString(16)}`);
		}
	}
});

Deno.test('Sha1.updateWithRar3Corruption: corrupts aligned blocks past 64 bytes', () => {
	// rarfile's _corrupt computes W[64..79] from the original block and
	// writes them back as 16 LE u32. for a 128-byte input fed with no prior
	// state (bufpos=0), dpos starts at 64, so the second 64-byte block is
	// rewritten while the first is left alone.
	const data = new Uint8Array(128);
	for (let idx = 0; idx < 128; idx++) {
		data[idx] = idx;
	}

	const sha = new Sha1();
	sha.updateWithRar3Corruption(data);

	// first half is untouched.
	for (let idx = 0; idx < 64; idx++) {
		if (data[idx] !== idx) {
			throw new Error(`first half byte ${idx} was modified to 0x${data[idx].toString(16)}`);
		}
	}
	// second half must differ from the identity input.
	let differs = false;
	for (let idx = 64; idx < 128; idx++) {
		if (data[idx] !== idx) {
			differs = true;
			break;
		}
	}
	if (!differs) {
		throw new Error('second half was not corrupted');
	}
});
