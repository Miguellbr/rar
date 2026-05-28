/**
 * @module
 *
 * AES-256 and the RAR5 password key-derivation function, built on Web Crypto.
 * the KDF is the standard PBKDF2-HMAC-SHA256 extended with two further chained
 * stretches that produce a tweak HMAC key and a password check value alongside
 * the AES key.
 */

import { InvalidPasswordError, MalformedArchiveError } from '../errors.ts';
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

/**
 * verifies a derived check value against the one stored in an entry's
 * encryption record. the stored value is 8 bytes of folded PBKDF2 output
 * plus the first 4 bytes of its SHA-256.
 *
 * @param stored the 12-byte check value taken from the archive
 * @param derived the 12-byte check value produced by {@link deriveKeys}
 * @throws if the values differ in length or content
 */
export const verifyCheckValue = (stored: Uint8Array, derived: Uint8Array): void => {
	if (stored.length !== derived.length) {
		throw new InvalidPasswordError(`password does not match: check value length differs`);
	}
	let diff = 0;
	for (let idx = 0; idx < stored.length; idx++) {
		diff |= stored[idx] ^ derived[idx];
	}
	if (diff !== 0) {
		throw new InvalidPasswordError(`password does not match: check value mismatch`);
	}
};

/**
 * a cache of keys derived for a given (password, salt, kdfCount) so that the
 * 32k-iteration KDF runs once per archive rather than once per encrypted
 * entry. the AES key handle is also cached so that Web Crypto only sees the
 * raw key bytes once.
 */
export class KeyCache {
	readonly #password: string;
	readonly #entries = new Map<string, Promise<{ derived: DerivedKeys; aes: CryptoKey }>>();

	constructor(password: string) {
		this.#password = password;
	}

	/**
	 * returns the AES key and derived material for a given salt and iteration
	 * count, deriving them on first access and replaying the cached result on
	 * later calls.
	 *
	 * @param salt the 16-byte salt from the entry's encryption record
	 * @param kdfCount binary log of the iteration count
	 */
	get(salt: Uint8Array, kdfCount: number): Promise<{ derived: DerivedKeys; aes: CryptoKey }> {
		const cacheKey = `${kdfCount}:${salt.toHex()}`;
		const existing = this.#entries.get(cacheKey);
		if (existing !== undefined) {
			return existing;
		}

		const computed = (async () => {
			const derived = await deriveKeys(this.#password, salt, kdfCount);
			const aes = await importAesKey(derived.aesKey);
			return { aes, derived };
		})();
		this.#entries.set(cacheKey, computed);
		return computed;
	}
}

/**
 * applies RAR5's `ConvertHashToMAC` transform to a CRC32, used to verify
 * encrypted entries with the TWEAKED checksum flag.
 *
 * RAR5 obscures an encrypted entry's CRC32 by HMAC-SHA256'ing its little-
 * endian byte form under the entry's derived tweak (HMAC) key and folding
 * the 32-byte digest down to 32 bits, four output bytes XOR'd into each
 * 8-bit lane. comparing the stored tweaked CRC against this transform of
 * the plaintext's natural CRC tells whether the decryption was correct.
 *
 * @param hmacKey the 32-byte tweak HMAC key from {@link deriveKeys}
 * @param plainCrc the natural CRC32 of the entry's plaintext
 * @returns the tweaked CRC32, as it appears in the archive header
 */
export const tweakCrc32 = async (
	hmacKey: Uint8Array<ArrayBuffer>,
	plainCrc: number,
): Promise<number> => {
	const rawCrc = new Uint8Array(4);
	rawCrc[0] = plainCrc & 0xff;
	rawCrc[1] = (plainCrc >>> 8) & 0xff;
	rawCrc[2] = (plainCrc >>> 16) & 0xff;
	rawCrc[3] = (plainCrc >>> 24) & 0xff;

	const key = await crypto.subtle.importKey(
		'raw',
		hmacKey,
		{ hash: 'SHA-256', name: 'HMAC' },
		false,
		['sign'],
	);
	const digest = new Uint8Array(await crypto.subtle.sign('HMAC', key, rawCrc));

	let tweaked = 0;
	for (let idx = 0; idx < 32; idx++) {
		tweaked ^= digest[idx] << ((idx & 3) * 8);
	}
	return tweaked >>> 0;
};

/**
 * transforms a plaintext BLAKE2sp-256 digest into the MAC stored in an
 * encrypted entry's header when the TWEAKED checksum flag is set: the 32-byte
 * HMAC-SHA256 of the digest under the entry's HMAC key.
 *
 * @param hmacKey the 32-byte tweak HMAC key from {@link deriveKeys}
 * @param plainDigest the BLAKE2sp-256 hash of the entry's plaintext
 * @returns the tweaked digest, as it appears in the archive header
 */
export const tweakBlake2sp = async (
	hmacKey: Uint8Array<ArrayBuffer>,
	plainDigest: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> => {
	const key = await crypto.subtle.importKey(
		'raw',
		hmacKey,
		{ hash: 'SHA-256', name: 'HMAC' },
		false,
		['sign'],
	);
	return new Uint8Array(await crypto.subtle.sign('HMAC', key, plainDigest));
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
		throw new MalformedArchiveError(
			`encrypted data length not a multiple of 16: ${ciphertext.length}`,
		);
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
	// the reader is acquired lazily on first pull so a caller that constructs
	// this stream and then drops it on an error path doesn't permanently lock
	// the source's reader.
	let reader: ReadableStreamDefaultReader<Uint8Array<ArrayBuffer>> | undefined;
	let cancelled = false;

	const appendPending = (chunk: Uint8Array<ArrayBuffer>): void => {
		if (pending.length === 0) {
			// copy rather than alias: a Reader that recycles its backing
			// buffer between read() calls would otherwise mutate `pending`
			// before the next decryptCbcBatch consumes it.
			pending = new Uint8Array(chunk.length);
			pending.set(chunk);
			return;
		}
		const merged = new Uint8Array(pending.length + chunk.length);
		merged.set(pending);
		merged.set(chunk, pending.length);
		pending = merged;
	};

	return new ReadableStream<Uint8Array<ArrayBuffer>>({
		async pull(controller) {
			if (reader === undefined) {
				if (cancelled) {
					controller.close();
					return;
				}
				reader = source.getReader();
			}

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
				throw new MalformedArchiveError(
					`encrypted data length not a multiple of 16: ${pending.length}`,
				);
			}

			const batch = pending.subarray(0, aligned);
			const lastBlock = new Uint8Array(batch.subarray(aligned - 16));
			const plain = await decryptCbcBatch(key, chain, batch);
			chain = lastBlock;
			pending = pending.subarray(aligned);

			controller.enqueue(plain);
		},
		async cancel(reason) {
			cancelled = true;
			await reader?.cancel(reason);
		},
	});
};
