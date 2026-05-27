import { assertEquals } from 'jsr:@std/assert@1';

import { decodeOldLzss15 } from '../lib/rar3/oldlzss.ts';
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

Deno.test('decodeOldLzss15: rarcomment fixture (16-byte archive comment)', () => {
	// the v15 oldComment subblock data area from rar15-comment.rar's MAIN
	// header: declen=16, expected text 'RARcomment -----', dataCrc=0xd0f2.
	const data = fromHex('0f 92 e5 07 a3 f5 fe b4 8f 4a 0f 5d ed 15 e1 34 40 00');
	const out = decodeOldLzss15(data, 16);

	if (out === undefined) {
		throw new Error('decoder returned undefined');
	}
	assertEquals(new TextDecoder().decode(out), 'RARcomment -----');
	assertEquals(crc32(out) & 0xffff, 0xd0f2);
});

Deno.test('decodeOldLzss15: empty input returns empty output', () => {
	const out = decodeOldLzss15(new Uint8Array(0), 0);
	assertEquals(out, new Uint8Array(0));
});
