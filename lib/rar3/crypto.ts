/**
 * @module
 *
 * RAR3 password-derived encryption: a 16-byte AES-128 key plus 16-byte IV
 * are derived from the user password and a per-entry 8-byte salt via
 * RARLAB's quirky SHA-1 KDF, then used for AES-128-CBC of file data (and
 * the CMT comment subblock when its PASSWORD flag is set).
 *
 * the AES streaming path itself is shared with RAR5 — web crypto handles
 * 128 and 256-bit AES-CBC keys through the same `importKey('AES-CBC', ...)`
 * call — so only the KDF is RAR3-specific here.
 */

import { decryptAesCbcStream, importAesKey } from '../rar5/crypto.ts';
import { Sha1 } from './sha1.ts';

/** AES-128 key and IV derived from a password and salt. */
export interface Rar3DerivedKey {
	/** 16-byte AES-128 key */
	key: Uint8Array<ArrayBuffer>;
	/** 16-byte AES-CBC IV */
	iv: Uint8Array<ArrayBuffer>;
}

// the maximum password length RAR honours; longer passwords are truncated.
const RAR_MAX_PASSWORD = 127;

/**
 * derives RAR3's AES-128 key and IV from a password and per-entry salt.
 *
 * follows rarfile's `rar3_s2k`: the password is re-encoded as UTF-16LE,
 * concatenated with the 8-byte salt to form `seed`, and then fed into a
 * SHA-1 hash in 0x40000 (16 * 0x4000) interleaved rounds. each outer
 * iteration's `digest()[19]` contributes one byte of the 16-byte IV; the
 * final digest's first 16 bytes — with each four-byte word byte-swapped
 * from big- to little-endian — is the AES key.
 *
 * @param password the user-supplied password
 * @param salt the 8-byte per-entry salt from the file header
 * @returns the 16-byte AES key and 16-byte CBC IV
 * @throws when the password is so long that the legacy "rarbug" SHA-1 quirk
 * would apply; the corpus we test against never trips this limit, and
 * porting the corruption is deferred until a fixture needs it
 */
export const rar3DeriveKey = (password: string, salt: Uint8Array): Rar3DerivedKey => {
	const truncated = password.length > RAR_MAX_PASSWORD ? password.slice(0, RAR_MAX_PASSWORD) : password;

	// UTF-16LE of the password — `String.charCodeAt` already returns the
	// code unit, so packing it as low+high gives the LE bytes.
	const wstr = new Uint8Array(truncated.length * 2);
	for (let idx = 0; idx < truncated.length; idx++) {
		const code = truncated.charCodeAt(idx);
		wstr[idx * 2 + 0] = code & 0xff;
		wstr[idx * 2 + 1] = (code >>> 8) & 0xff;
	}

	const seed = new Uint8Array(wstr.length + salt.length);
	seed.set(wstr);
	seed.set(salt, wstr.length);

	// the "rarbug" SHA-1 only kicks in when one update fills more than a
	// single 64-byte block. seed itself is the only such update, so for any
	// seed up to 64 bytes the running SHA-1 is unmodified standard SHA-1.
	if (seed.length > 64) {
		throw new Error(
			'rar3 password longer than 28 characters requires the legacy "rarbug" SHA-1 variant which is not yet implemented',
		);
	}

	const sha = new Sha1();
	const counter = new Uint8Array(3);
	const iv = new Uint8Array(16);

	for (let i = 0; i < 16; i++) {
		for (let j = 0; j < 0x4000; j++) {
			const k = i * 0x4000 + j;
			counter[0] = k & 0xff;
			counter[1] = (k >>> 8) & 0xff;
			counter[2] = (k >>> 16) & 0xff;

			sha.update(seed);
			sha.update(counter);

			if (j === 0) {
				iv[i] = sha.digest()[19];
			}
		}
	}

	// key = first 16 bytes of the final digest, with each 4-byte word
	// byte-swapped (big-endian → little-endian) per rarfile's `unpack(">LLLL")`
	// followed by `pack("<LLLL")`.
	const digest = sha.digest();
	const key = new Uint8Array(16);
	for (let word = 0; word < 4; word++) {
		key[word * 4 + 0] = digest[word * 4 + 3];
		key[word * 4 + 1] = digest[word * 4 + 2];
		key[word * 4 + 2] = digest[word * 4 + 1];
		key[word * 4 + 3] = digest[word * 4 + 0];
	}

	return { iv, key };
};

/**
 * builds an AES-128-CBC decryption stream for an encrypted RAR3 file body.
 * the ciphertext length must be a multiple of 16 bytes (the RAR3 encoder
 * pads the data area to the block size); the decrypted output is the same
 * length, with any trailing bytes past the entry's `unpackedSize` being
 * encoder padding the caller drops or feeds back into the LZSS decoder
 * along with the rest.
 *
 * @param password the user-supplied password
 * @param salt the 8-byte salt from the entry header
 * @param ciphertext a stream of ciphertext chunks in archive order
 * @returns a stream of plaintext chunks
 */
export const decryptRar3Stream = async (
	password: string,
	salt: Uint8Array,
	ciphertext: ReadableStream<Uint8Array<ArrayBuffer>>,
): Promise<ReadableStream<Uint8Array<ArrayBuffer>>> => {
	const { iv, key } = rar3DeriveKey(password, salt);
	const aes = await importAesKey(key);
	return decryptAesCbcStream(aes, iv, ciphertext);
};
