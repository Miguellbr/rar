import { MissingPasswordError } from '../lib/errors.ts';
import { fromUint8Array } from '../lib/reader/common.ts';
import { walkRar3Archive } from '../lib/rar3/extract.ts';

/**
 * @module
 *
 * tests for the public RAR3 header walker. exercises the plain path, the
 * hpsw header-decryption path, and the missing-password failure mode.
 */

const FIXTURES_DIR = new URL('./fixtures/rarfile/files/', import.meta.url);

Deno.test('walkRar3Archive: yields file blocks without decompressing', async () => {
	const data = Deno.readFileSync(new URL('rar3-readonly-unix.rar', FIXTURES_DIR));
	const reader = fromUint8Array(data);

	const filenames: string[] = [];
	for await (const { block } of walkRar3Archive(reader)) {
		if (block.kind === 'file') {
			filenames.push(block.name);
		}
	}

	if (filenames.length === 0) {
		throw new Error('expected at least one file block');
	}
});

Deno.test('walkRar3Archive: decrypts hpsw headers when a password is supplied', async () => {
	const data = Deno.readFileSync(new URL('rar3-comment-hpsw.rar', FIXTURES_DIR));
	const reader = fromUint8Array(data);

	let sawFile = false;
	for await (const { block } of walkRar3Archive(reader, { password: 'password' })) {
		if (block.kind === 'file') {
			sawFile = true;
		}
	}

	if (!sawFile) {
		throw new Error('expected to see a file block after header decryption');
	}
});

Deno.test('walkRar3Archive: hpsw without a password throws MissingPasswordError', async () => {
	const data = Deno.readFileSync(new URL('rar3-comment-hpsw.rar', FIXTURES_DIR));
	const reader = fromUint8Array(data);

	let threw = false;
	try {
		for await (const _ of walkRar3Archive(reader)) {
			// should never yield
		}
	} catch (error) {
		threw = true;
		if (!(error instanceof MissingPasswordError)) {
			throw new Error(`unexpected error: ${error}`);
		}
	}
	if (!threw) {
		throw new Error('expected a MissingPasswordError');
	}
});
