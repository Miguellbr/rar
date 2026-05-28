import { crc32 } from '@mary/crc32';

import { decodeOldLzss15, decodeOldLzss20 } from '../lib/rar3/oldlzss.ts';

/**
 * @module
 *
 * regression tests for the RAR1.5/2.x LZSS decoders. each test pins a
 * compressed byte stream and the expected decompressed payload, sourced
 * from the vendored rarfile corpus. inputs validated against system unrar
 * via rarfile's `rar3_decompress` shell-out.
 */

const expectText = (
	out: Uint8Array | undefined,
	expected: string,
	expectedCrc: number,
	label: string,
): void => {
	if (out === undefined) {
		throw new Error(`${label}: decoder returned undefined`);
	}
	const actual = new TextDecoder().decode(out);
	if (actual !== expected) {
		throw new Error(
			`${label}: text mismatch, expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`,
		);
	}
	const crc = crc32(out) & 0xffff;
	if (crc !== expectedCrc) {
		throw new Error(
			`${label}: crc mismatch, expected 0x${expectedCrc.toString(16)}, got 0x${crc.toString(16)}`,
		);
	}
};

Deno.test('decodeOldLzss15: rarcomment fixture (16-byte archive comment)', () => {
	// the v15 oldComment subblock data area from rar15-comment.rar's MAIN
	// header: declen=16, expected text 'RARcomment -----', dataCrc=0xd0f2.
	const data = Uint8Array.fromHex('0f92e507a3f5feb48f4a0f5ded15e1344000');
	expectText(decodeOldLzss15(data, 16), 'RARcomment -----', 0xd0f2, 'v15 corpus');
});

Deno.test('decodeOldLzss15: empty input returns empty output', () => {
	const out = decodeOldLzss15(new Uint8Array(0), 0);
	if (out === undefined || out.length !== 0) {
		throw new Error(`expected empty Uint8Array, got ${out}`);
	}
});

Deno.test('decodeOldLzss20: rarcomment fixture (10-byte archive comment)', () => {
	// the v20 oldComment subblock data area from rar202-comment-nopsw.rar's
	// MAIN header: declen=10, expected text 'RARcomment', dataCrc=0x50ee.
	const data = Uint8Array.fromHex('10004c0000000000010a6da0a82b9f0795fe07aba381ada980');
	expectText(decodeOldLzss20(data, 10), 'RARcomment', 0x50ee, 'v20 corpus');
});

Deno.test('decodeOldLzss20: empty input returns empty output', () => {
	const out = decodeOldLzss20(new Uint8Array(0), 0);
	if (out === undefined || out.length !== 0) {
		throw new Error(`expected empty Uint8Array, got ${out}`);
	}
});
