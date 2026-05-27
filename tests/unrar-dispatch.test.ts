import { InvalidSignatureError, TruncatedArchiveError } from '../lib/errors.ts';
import { fromUint8Array } from '../lib/reader/common.ts';
import { Rar3Entry, Rar5Entry, unrar } from '../lib/mod.ts';

/**
 * @module
 *
 * tests for the top-level {@link unrar} that auto-detects RAR5 vs RAR3 by
 * signature and dispatches to the format-specific extractor.
 */

const FIXTURES_DIR = new URL('./fixtures/rarfile/files/', import.meta.url);

Deno.test('unrar: rar5 archive yields Rar5Entry instances', async () => {
	const data = Deno.readFileSync(new URL('rar5-subdirs.rar', FIXTURES_DIR));
	const reader = fromUint8Array(data);

	let count = 0;
	for await (const entry of unrar(reader)) {
		count++;
		if (!(entry instanceof Rar5Entry)) {
			throw new Error(`expected Rar5Entry, got ${entry.constructor.name}`);
		}
	}
	if (count === 0) {
		throw new Error('expected at least one entry');
	}
});

Deno.test('unrar: rar3 archive yields Rar3Entry instances', async () => {
	const data = Deno.readFileSync(new URL('rar3-readonly-unix.rar', FIXTURES_DIR));
	const reader = fromUint8Array(data);

	let count = 0;
	for await (const entry of unrar(reader)) {
		count++;
		if (!(entry instanceof Rar3Entry)) {
			throw new Error(`expected Rar3Entry, got ${entry.constructor.name}`);
		}
	}
	if (count === 0) {
		throw new Error('expected at least one entry');
	}
});

Deno.test('unrar: non-RAR source throws', async () => {
	const reader = fromUint8Array(new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00]));

	let threw = false;
	try {
		for await (const _ of unrar(reader)) {
			// should never yield
		}
	} catch (error) {
		threw = true;
		if (!(error instanceof InvalidSignatureError)) {
			throw new Error(`unexpected error: ${error}`);
		}
	}
	if (!threw) {
		throw new Error('expected an InvalidSignatureError');
	}
});

Deno.test('unrar: source shorter than the RAR3 signature throws', async () => {
	const reader = fromUint8Array(new Uint8Array([0x52, 0x61, 0x72]));

	let threw = false;
	try {
		for await (const _ of unrar(reader)) {
			// should never yield
		}
	} catch (error) {
		threw = true;
		if (!(error instanceof TruncatedArchiveError)) {
			throw new Error(`unexpected error: ${error}`);
		}
	}
	if (!threw) {
		throw new Error('expected a TruncatedArchiveError');
	}
});
