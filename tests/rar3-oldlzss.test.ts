import { decodeOldLzss15, decodeOldLzss20 } from '../lib/rar3/oldlzss.ts';
import { crc32 } from '../lib/utils/crc32.ts';

/**
 * @module
 *
 * regression tests for the RAR1.5/2.x LZSS decoders. each test pins a
 * compressed byte stream and the expected decompressed payload, sourced
 * from the vendored rarfile corpus. inputs validated against system unrar
 * via rarfile's `rar3_decompress` shell-out.
 */

const fromHex = (hex: string): Uint8Array => {
	const trimmed = hex.replaceAll(/\s+/g, '');
	const out = new Uint8Array(trimmed.length / 2);
	for (let i = 0; i < out.length; i++) {
		out[i] = parseInt(trimmed.slice(i * 2, i * 2 + 2), 16);
	}
	return out;
};

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
	const data = fromHex('0f 92 e5 07 a3 f5 fe b4 8f 4a 0f 5d ed 15 e1 34 40 00');
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
	const data = fromHex('10 00 4c 00 00 00 00 00 01 0a 6d a0 a8 2b 9f 07 95 fe 07 ab a3 81 ad a9 80');
	expectText(decodeOldLzss20(data, 10), 'RARcomment', 0x50ee, 'v20 corpus');
});

Deno.test('decodeOldLzss20: empty input returns empty output', () => {
	const out = decodeOldLzss20(new Uint8Array(0), 0);
	if (out === undefined || out.length !== 0) {
		throw new Error(`expected empty Uint8Array, got ${out}`);
	}
});
