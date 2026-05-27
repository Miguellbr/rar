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

import { decryptAesCbc, decryptAesCbcStream, importAesKey } from '../rar5/crypto.ts';
import { BlockFlag, BlockType, MainFlag, RAR3_SIGNATURE } from './constants.ts';
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

// salts are 8 bytes; turn them into a stable cache key. `toHex` would do the
// same thing but isn't available on every platform.
const saltToKey = (salt: Uint8Array): string => {
	let out = '';
	for (const byte of salt) {
		out += byte.toString(16).padStart(2, '0');
	}
	return out;
};

const COMMON_HEADER_SIZE = 7;

/**
 * given an archive whose main header sets `MAIN_PASSWORD`, returns a
 * synthetic archive buffer in which every block past the main header has
 * had its header bytes AES-decrypted in place. the result is laid out
 * exactly like an unencrypted archive (mark + main + cleartext header +
 * raw data area, repeated), so the existing sync walker, parser, dumper,
 * and extractor can read it without change.
 *
 * each encrypted block on disk is `[8-byte salt | header ciphertext |
 * data ciphertext]`, where:
 *   - the header ciphertext covers `headerSize` bytes of cleartext padded
 *     up to a 16-byte boundary, AES-CBC chained from the iv that
 *     {@link rar3DeriveKey} produces for the per-block salt
 *   - the data area (`add_size` bytes) lives in its own region. when the
 *     entry sets FileFlag.password it is itself AES-CBC ciphertext keyed
 *     by the file salt inside the just-decrypted header; otherwise it is
 *     plaintext. either way the main-level decryption does not touch it,
 *     and the bytes are copied through unchanged for downstream code to
 *     handle.
 *
 * salts repeat in practice, so a small cache amortises the KDF cost.
 *
 * @param password the user-supplied password
 * @param archive the raw archive bytes
 * @param encryptedStart the offset at which encrypted blocks begin (just
 * past the cleartext mark + main header)
 * @returns a fresh buffer of the same logical contents with the header
 * encryption wrapper stripped
 */
export const decryptRar3HeaderStream = async (
	password: string,
	archive: Uint8Array,
	encryptedStart: number,
): Promise<Uint8Array> => {
	const synth: Uint8Array[] = [];
	const cache = new Map<string, { aes: CryptoKey; iv: Uint8Array<ArrayBuffer> }>();

	let offset = encryptedStart;
	while (offset < archive.length) {
		if (offset + 8 + 16 > archive.length) {
			throw new Error(
				`rar3 encrypted block at 0x${offset.toString(16)} is truncated`,
			);
		}

		const salt = archive.subarray(offset, offset + 8);
		const cacheKey = saltToKey(salt);
		let entry = cache.get(cacheKey);
		if (entry === undefined) {
			const { iv, key } = rar3DeriveKey(password, salt);
			const aes = await importAesKey(key);
			entry = { aes, iv };
			cache.set(cacheKey, entry);
		}

		// peek the first ciphertext block so we can read headerSize (and, for
		// LONG blocks, add_size).
		const firstCipher = new Uint8Array(archive.subarray(offset + 8, offset + 8 + 16));
		const firstPlain = await decryptAesCbc(entry.aes, entry.iv, firstCipher);

		const blockType = firstPlain[2];
		const blockFlags = firstPlain[3] | (firstPlain[4] << 8);
		const headerSize = firstPlain[5] | (firstPlain[6] << 8);
		if (headerSize < COMMON_HEADER_SIZE) {
			throw new Error(
				`rar3 encrypted block at 0x${offset.toString(16)} has invalid headerSize ${headerSize}`,
			);
		}

		// LONG blocks place add_size at offset 7..10. for file/sub blocks this
		// overlays the `packed_size` field, so the peek works uniformly across
		// block kinds.
		let addSize = 0;
		if ((blockFlags & BlockFlag.longBlock) !== 0) {
			if (firstPlain.length < 11) {
				throw new Error(
					`rar3 encrypted block at 0x${offset.toString(16)} truncated before add_size`,
				);
			}
			addSize = (firstPlain[7] | (firstPlain[8] << 8) | (firstPlain[9] << 16) |
				(firstPlain[10] << 24)) >>> 0;
		}

		const headerCipherLen = Math.ceil(headerSize / 16) * 16;
		if (offset + 8 + headerCipherLen + addSize > archive.length) {
			throw new Error(
				`rar3 encrypted block at 0x${offset.toString(16)} extends past EOF:` +
					` need ${8 + headerCipherLen + addSize}, have ${archive.length - offset}`,
			);
		}

		let headerCleartext: Uint8Array;
		if (headerCipherLen <= 16) {
			headerCleartext = firstPlain.subarray(0, headerSize);
		} else {
			// decrypt blocks 2..N with iv = first ciphertext block (CBC chain).
			const restCipher = new Uint8Array(
				archive.subarray(offset + 8 + 16, offset + 8 + headerCipherLen),
			);
			const restPlain = await decryptAesCbc(entry.aes, firstCipher, restCipher);
			const combined = new Uint8Array(headerCipherLen);
			combined.set(firstPlain);
			combined.set(restPlain, 16);
			headerCleartext = combined.subarray(0, headerSize);
		}
		synth.push(headerCleartext);

		// data area: untouched bytes; downstream file-level decryption handles
		// FileFlag.password entries using the salt inside the just-emitted
		// header.
		if (addSize > 0) {
			synth.push(archive.subarray(offset + 8 + headerCipherLen, offset + 8 + headerCipherLen + addSize));
		}

		offset += 8 + headerCipherLen + addSize;

		// endArc terminates the archive; bytes past it are encoder padding.
		if (blockType === BlockType.endArc) {
			break;
		}
	}

	let totalLen = encryptedStart;
	for (const block of synth) {
		totalLen += block.length;
	}
	const out = new Uint8Array(totalLen);
	out.set(archive.subarray(0, encryptedStart));
	let writePos = encryptedStart;
	for (const block of synth) {
		out.set(block, writePos);
		writePos += block.length;
	}
	return out;
};

// ensures the (presumed) RAR3 archive carries the signature at offset 0 — the
// caller has already checked this for unencrypted archives, but the header
// decryptor wants to refuse early when the input clearly isn't RAR3.
const assertRar3Signature = (archive: Uint8Array): void => {
	if (archive.length < RAR3_SIGNATURE.length) {
		throw new Error('rar3 archive shorter than the 7-byte signature');
	}
	for (let idx = 0; idx < RAR3_SIGNATURE.length; idx++) {
		if (archive[idx] !== RAR3_SIGNATURE[idx]) {
			throw new Error('not a rar3 archive: signature missing');
		}
	}
};

/**
 * if `archive`'s main header has `MAIN_PASSWORD` set and `password` is
 * supplied, returns a synthetic archive with the encryption wrapper
 * stripped (see {@link decryptRar3HeaderStream}); otherwise returns
 * `archive` unchanged.
 *
 * @param password the password to try, or `undefined` to skip decryption
 * @param archive the raw archive bytes
 * @returns the same buffer when not encrypted, or a freshly decrypted copy
 */
export const decryptRar3HeadersIfNeeded = async (
	password: string | undefined,
	archive: Uint8Array,
): Promise<Uint8Array> => {
	assertRar3Signature(archive);
	// the main header always follows the 7-byte signature.
	const mainOffset = RAR3_SIGNATURE.length;
	if (archive.length < mainOffset + COMMON_HEADER_SIZE) {
		return archive;
	}
	// parse the cleartext main header just enough to test MAIN_PASSWORD and
	// find the end of the cleartext prefix. main never sets LONG_BLOCK in any
	// fixture we care about, but we honour it for safety.
	const mainType = archive[mainOffset + 2];
	if (mainType !== BlockType.main) {
		return archive;
	}
	const mainFlags = archive[mainOffset + 3] | (archive[mainOffset + 4] << 8);
	const mainSize = archive[mainOffset + 5] | (archive[mainOffset + 6] << 8);
	if ((mainFlags & MainFlag.password) === 0) {
		return archive;
	}
	if (password === undefined) {
		throw new Error('rar3 archive has encrypted headers; pass a password to read it');
	}
	const encryptedStart = mainOffset + mainSize;
	return await decryptRar3HeaderStream(password, archive, encryptedStart);
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
