/**
 * @module
 *
 * AES-256 and the RAR5 password key-derivation function, built on Web Crypto.
 * the KDF is the standard PBKDF2-HMAC-SHA256 extended with two further chained
 * stretches that produce a tweak HMAC key and a password check value alongside
 * the AES key.
 */

import { textEncoder } from '../utils/buffer.ts';

/** the three values RAR5 derives from a password, salt, and iteration count. */
export interface DerivedKeys {
	/** 32-byte AES-256 encryption key */
	aesKey: Uint8Array<ArrayBuffer>;
	/** 32-byte HMAC-SHA256 key used to tweak checksums on encrypted entries */
	hmacKey: Uint8Array<ArrayBuffer>;
	/**
	 * 12-byte password check value: 8 XOR-folded bytes of the PBKDF2 output
	 * after `2^kdfCount + 32` iterations, plus the first four bytes of their
	 * SHA-256 as an integrity tail.
	 */
	checkValue: Uint8Array<ArrayBuffer>;
}

// XOR-accumulates `source` into `target` over `length` bytes.
const xorInto = (target: Uint8Array, source: Uint8Array, length: number): void => {
	for (let idx = 0; idx < length; idx++) {
		target[idx] ^= source[idx];
	}
};

// signs one HMAC-SHA256 round, returning the 32-byte result.
const hmacSha256 = async (
	key: CryptoKey,
	data: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> => {
	return new Uint8Array(await crypto.subtle.sign('HMAC', key, data));
};

/**
 * derives the RAR5 encryption material for a given password and encryption
 * record.
 *
 * the KDF runs PBKDF2-HMAC-SHA256 over `password` and `salt`, snapshotting
 * the running XOR-accumulator at three milestones: `2^kdfCount` iterations
 * gives the AES key, `2^kdfCount + 16` gives the tweak HMAC key, and
 * `2^kdfCount + 32` gives a 32-byte temp. that temp is XOR-folded into 8
 * bytes; appending the first four bytes of its SHA-256 yields the 12-byte
 * check value stored in the archive.
 *
 * @param password the user-supplied password
 * @param salt the 16-byte salt from the entry's encryption record
 * @param kdfCount binary log of the iteration count
 * @returns the AES key, tweak HMAC key, and 12-byte check value
 */
export const deriveKeys = async (
	password: string,
	salt: Uint8Array,
	kdfCount: number,
): Promise<DerivedKeys> => {
	const rounds = 1 << kdfCount;

	const passwordBytes = textEncoder.encode(password);
	const hmacKey = await crypto.subtle.importKey(
		'raw',
		passwordBytes,
		{ hash: 'SHA-256', name: 'HMAC' },
		false,
		['sign'],
	);

	// U_1 = HMAC(password, salt || INT_BE(1)).
	const seed = new Uint8Array(salt.length + 4);
	seed.set(salt);
	seed[salt.length + 3] = 1;

	let chain = await hmacSha256(hmacKey, seed);

	// accumulator holds PBKDF2's running XOR; we snapshot it at the three
	// milestone iteration counts.
	const acc = new Uint8Array(32);

	for (let idx = 0; idx < rounds; idx++) {
		xorInto(acc, chain, 32);
		chain = await hmacSha256(hmacKey, chain);
	}
	const aesKey = new Uint8Array(acc);

	for (let idx = 0; idx < 16; idx++) {
		xorInto(acc, chain, 32);
		chain = await hmacSha256(hmacKey, chain);
	}
	const tweakKey = new Uint8Array(acc);

	for (let idx = 0; idx < 16; idx++) {
		xorInto(acc, chain, 32);
		if (idx < 15) {
			chain = await hmacSha256(hmacKey, chain);
		}
	}

	// XOR-fold the final 32 bytes into 8.
	const check8 = new Uint8Array(8);
	for (let idx = 0; idx < 32; idx++) {
		check8[idx & 7] ^= acc[idx];
	}

	// append the first 4 bytes of SHA-256(check8) as the integrity tail.
	const checkSum = new Uint8Array(await crypto.subtle.digest('SHA-256', check8));

	const checkValue = new Uint8Array(12);
	checkValue.set(check8);
	checkValue.set(checkSum.subarray(0, 4), 8);

	return { aesKey, checkValue, hmacKey: tweakKey };
};

/**
 * imports a derived AES-256 key for use with {@link decryptAesCbc}.
 * @param keyBytes a 32-byte raw key
 * @returns a Web Crypto key handle
 */
export const importAesKey = (keyBytes: Uint8Array<ArrayBuffer>): Promise<CryptoKey> => {
	return crypto.subtle.importKey('raw', keyBytes, 'AES-CBC', false, ['decrypt', 'encrypt']);
};

// decrypts one CBC batch of `B` aligned bytes by appending a synthetic
// PKCS#7-padded block so Web Crypto, which only does padded AES-CBC, returns
// exactly `B` plaintext bytes. the synthetic block is `encrypt(empty)` keyed
// by the batch's last ciphertext block as IV — that always produces a block
// whose pre-stripping plaintext is `0x10` × 16, valid padding to strip.
const decryptCbcBatch = async (
	key: CryptoKey,
	iv: Uint8Array<ArrayBuffer>,
	batch: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> => {
	const lastBlock = batch.subarray(batch.length - 16);
	const paddingBlock = new Uint8Array(
		await crypto.subtle.encrypt({ iv: lastBlock, name: 'AES-CBC' }, key, new Uint8Array(0)),
	);

	const augmented = new Uint8Array(batch.length + 16);
	augmented.set(batch);
	augmented.set(paddingBlock, batch.length);

	return new Uint8Array(
		await crypto.subtle.decrypt({ iv, name: 'AES-CBC' }, key, augmented),
	);
};

/**
 * decrypts an AES-256-CBC ciphertext that has no PKCS#7 padding, as stored in
 * RAR5 file data areas.
 *
 * Web Crypto's `AES-CBC` always expects PKCS#7 padding on input, so we append
 * a synthetic, valid padding block (produced by encrypting an empty plaintext
 * under the last ciphertext block as IV) and rely on Web Crypto to strip it
 * after decryption.
 *
 * @param key the AES-256 key, imported by {@link importAesKey}
 * @param iv the 16-byte IV from the entry's encryption record
 * @param ciphertext the encrypted payload; must be a multiple of 16 bytes
 * @returns the decrypted bytes, the same length as `ciphertext`
 */
export const decryptAesCbc = async (
	key: CryptoKey,
	iv: Uint8Array<ArrayBuffer>,
	ciphertext: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> => {
	if (ciphertext.length === 0) {
		return new Uint8Array(0);
	}
	if ((ciphertext.length & 15) !== 0) {
		throw new Error(`encrypted data length ${ciphertext.length} is not a multiple of 16`);
	}

	return await decryptCbcBatch(key, iv, ciphertext);
};

// the maximum number of 16-byte cipher blocks that one streaming batch of
// {@link decryptAesCbcStream} hands to Web Crypto in one call. 4 KiB is a
// pragmatic balance: large enough that the per-call overhead is amortized,
// small enough that one batch fits comfortably in CPU cache.
const STREAM_BATCH_BYTES = 4096;

/**
 * decrypts an AES-256-CBC ciphertext stream incrementally, managing the CBC
 * IV chain manually so the full ciphertext never has to be buffered. each
 * emitted chunk is a multiple of 16 bytes, except potentially the final
 * empty close. as with {@link decryptAesCbc}, the input has no PKCS#7
 * padding and the output has the same total length as the input.
 *
 * @param key the AES-256 key, imported by {@link importAesKey}
 * @param iv the 16-byte IV from the entry's encryption record; consumed and
 * not retained
 * @param source ciphertext chunks in archive order; the total length must be
 * a multiple of 16 bytes
 * @returns a stream of plaintext chunks
 */
export const decryptAesCbcStream = (
	key: CryptoKey,
	iv: Uint8Array<ArrayBuffer>,
	source: ReadableStream<Uint8Array<ArrayBuffer>>,
): ReadableStream<Uint8Array<ArrayBuffer>> => {
	let chain = iv;
	// unconsumed ciphertext bytes carried over between pulls because they did
	// not form a complete 16-byte block or because the running batch had not
	// yet reached `STREAM_BATCH_BYTES`.
	let pending: Uint8Array<ArrayBuffer> = new Uint8Array(0);
	let sourceDone = false;
	const reader = source.getReader();

	const appendPending = (chunk: Uint8Array<ArrayBuffer>): void => {
		if (pending.length === 0) {
			pending = chunk;
			return;
		}
		const merged = new Uint8Array(pending.length + chunk.length);
		merged.set(pending);
		merged.set(chunk, pending.length);
		pending = merged;
	};

	return new ReadableStream<Uint8Array<ArrayBuffer>>({
		async pull(controller) {
			// gather enough buffered ciphertext for one decrypt call, unless the
			// source has signalled completion — in which case whatever is left
			// (and which must be 16-aligned at end-of-stream) is the final batch.
			while (!sourceDone && pending.length < STREAM_BATCH_BYTES) {
				const { done, value } = await reader.read();
				if (done) {
					sourceDone = true;
					break;
				}
				appendPending(value);
			}

			if (pending.length === 0) {
				controller.close();
				return;
			}

			const aligned = sourceDone ? pending.length : pending.length & ~15;
			if ((aligned & 15) !== 0) {
				throw new Error(
					`encrypted data length ${pending.length} is not a multiple of 16`,
				);
			}

			const batch = pending.subarray(0, aligned);
			const lastBlock = new Uint8Array(batch.subarray(aligned - 16));
			const plain = await decryptCbcBatch(key, chain, batch);
			chain = lastBlock;
			pending = pending.subarray(aligned);

			controller.enqueue(plain);
		},
		async cancel() {
			await reader.cancel();
		},
	});
};
