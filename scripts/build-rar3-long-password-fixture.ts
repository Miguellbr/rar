/**
 * @module
 *
 * one-shot builder for `tests/fixtures/rar3-long-password.rar`. constructs a
 * single-entry RAR3 archive whose body is AES-128-CBC encrypted with the
 * rarbug-flavoured KDF, using a 32-character password (66-byte seed) that
 * activates the in-place SHA-1 corruption. system `unrar` has been used as
 * an oracle to confirm the resulting archive decrypts to the expected
 * plaintext.
 *
 * run: `deno run -A scripts/build-rar3-long-password-fixture.ts`
 */

import { rar3DeriveKey } from '../lib/rar3/crypto.ts';
import { importAesKey } from '../lib/rar5/crypto.ts';
import { BlockFlag, BlockType, CompressMethod, FileFlag, HostOs } from '../lib/rar3/constants.ts';
import { crc32 } from '../lib/utils/crc32.ts';

const PASSWORD = 'the-rarbug-makes-this-key-funny!';
const SALT = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
const NAME = 'hello.txt';
const PLAINTEXT = new TextEncoder().encode('abcdefghijklmnopqrstuvwxyz012345');

// 2026-05-27 12:00:00 UTC, DOS-encoded: year-1980=46, month=5, day=27, hour=12.
const MTIME = ((46 << 25) | (5 << 21) | (27 << 16) | (12 << 11)) >>> 0;

const writeU16LE = (buf: Uint8Array, offset: number, value: number): void => {
	buf[offset + 0] = value & 0xff;
	buf[offset + 1] = (value >>> 8) & 0xff;
};

const writeU32LE = (buf: Uint8Array, offset: number, value: number): void => {
	buf[offset + 0] = value & 0xff;
	buf[offset + 1] = (value >>> 8) & 0xff;
	buf[offset + 2] = (value >>> 16) & 0xff;
	buf[offset + 3] = (value >>> 24) & 0xff;
};

const sealHeader = (header: Uint8Array, crcEnd: number): Uint8Array => {
	const crc = crc32(header.subarray(2, crcEnd)) & 0xffff;
	writeU16LE(header, 0, crc);
	return header;
};

const buildMainBlock = (): Uint8Array => {
	const header = new Uint8Array(13);
	header[2] = BlockType.main;
	writeU16LE(header, 3, 0x0000);
	writeU16LE(header, 5, 13);
	// 6 reserved bytes already zero.
	return sealHeader(header, 13);
};

const buildFileBlock = (ciphertextLength: number, plaintextCrc: number): Uint8Array => {
	const nameBytes = new TextEncoder().encode(NAME);
	const headerSize = 7 + 25 + nameBytes.length + SALT.length;
	const header = new Uint8Array(headerSize);

	header[2] = BlockType.file;
	const flags = BlockFlag.longBlock | FileFlag.password | FileFlag.salt;
	writeU16LE(header, 3, flags);
	writeU16LE(header, 5, headerSize);
	writeU32LE(header, 7, ciphertextLength); // packed_size — overlays add_size
	writeU32LE(header, 11, PLAINTEXT.length); // unpacked_size
	header[15] = HostOs.msdos;
	writeU32LE(header, 16, plaintextCrc);
	writeU32LE(header, 20, MTIME);
	header[24] = 29; // extract version
	header[25] = CompressMethod.stored;
	writeU16LE(header, 26, nameBytes.length);
	writeU32LE(header, 28, 0x00000020); // DOS archive attribute
	header.set(nameBytes, 32);
	header.set(SALT, 32 + nameBytes.length);

	return sealHeader(header, headerSize);
};

const buildEndArcBlock = (): Uint8Array => {
	const header = new Uint8Array(7);
	header[2] = BlockType.endArc;
	writeU16LE(header, 3, 0x0000);
	writeU16LE(header, 5, 7);
	return sealHeader(header, 7);
};

const encryptBody = async (): Promise<Uint8Array> => {
	const { iv, key } = rar3DeriveKey(PASSWORD, SALT);

	const aes = await importAesKey(key);

	// pad plaintext with PKCS#7 so web crypto encrypts cleanly, then drop the
	// trailing pad block. RAR3 ciphertext length matches the padded plaintext
	// length up to (but not past) the 16-byte boundary.
	const ct = new Uint8Array(
		await crypto.subtle.encrypt({ iv, name: 'AES-CBC' }, aes, PLAINTEXT),
	);
	const aligned = (PLAINTEXT.length + 15) & ~15;
	return ct.subarray(0, aligned);
};

const main = async (): Promise<void> => {
	const ciphertext = await encryptBody();
	const plaintextCrc = crc32(PLAINTEXT);

	const signature = new Uint8Array([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00]);
	const main = buildMainBlock();
	const file = buildFileBlock(ciphertext.length, plaintextCrc);
	const endArc = buildEndArcBlock();

	const total = signature.length + main.length + file.length + ciphertext.length + endArc.length;
	const archive = new Uint8Array(total);
	let pos = 0;
	for (const part of [signature, main, file, ciphertext, endArc]) {
		archive.set(part, pos);
		pos += part.length;
	}

	const outPath = new URL('../tests/fixtures/rar3-long-password.rar', import.meta.url);
	Deno.writeFileSync(outPath, archive);
	console.log(`wrote ${total}-byte fixture to ${outPath.pathname}`);
	console.log(`  password:  ${PASSWORD} (${PASSWORD.length} chars)`);
	console.log(`  name:      ${NAME}`);
	console.log(`  plaintext: ${PLAINTEXT.length} bytes, crc32 0x${plaintextCrc.toString(16)}`);
};

await main();
