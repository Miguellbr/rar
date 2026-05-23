import { fromUint8Array } from '../lib/reader/common.ts';
import { unrar } from '../lib/rar5/extract.ts';
import { crc32 } from '../lib/utils/crc32.ts';

/**
 * @module
 *
 * extraction tests for the RAR5 entry API. each stored entry of every fixture
 * is read back and checked against its recorded size and CRC32.
 */

const FIXTURES_DIR = new URL('./fixtures/rarfile/files/', import.meta.url);

// fixtures the per-file extractor pass cannot exercise: the misnamed RAR3
// file and the multi-volume parts which only round-trip when handed to
// unrar() together (covered separately below).
const SKIP = new Set([
	'rar5-readonly-win.rar',
	'rar5-vols.part1.rar',
	'rar5-vols.part2.rar',
	'rar5-vols.part3.rar',
]);

// the password rarfile's corpus uses for every password-protected fixture.
const CORPUS_PASSWORD = 'password';

const fixtures = [...Deno.readDirSync(FIXTURES_DIR)]
	.map((entry) => entry.name)
	.filter((name) => name.startsWith('rar5-') && name.endsWith('.rar'))
	.sort();

for (const name of fixtures) {
	Deno.test({
		name: `rar5 extract: ${name}`,
		ignore: SKIP.has(name),
		fn: async () => {
			const data = Deno.readFileSync(new URL(name, FIXTURES_DIR));
			const reader = fromUint8Array(data);
			const password = name.includes('-psw') || name.includes('-hpsw') ? CORPUS_PASSWORD : undefined;

			let entries = 0;
			let verified = 0;

			for await (const entry of unrar(reader, { password })) {
				entries++;

				// directories and links are not yet read back; everything else,
				// stored or compressed (solid or not, encrypted or not), is
				// verified by size.
				if (entry.isDirectory || entry.linkTarget !== undefined) {
					continue;
				}

				const bytes = await entry.bytes();

				if (bytes.length !== entry.size) {
					throw new Error(
						`${name}: ${entry.filename} read ${bytes.length} bytes, expected ${entry.size}`,
					);
				}

				// the TWEAKED flag XORs the stored CRC with a HMAC of the
				// plaintext, so a direct comparison is meaningful only for
				// non-encrypted entries.
				if (entry.crc32 !== undefined && !entry.isEncrypted) {
					const actual = crc32(bytes);
					if (actual !== entry.crc32) {
						throw new Error(
							`${name}: ${entry.filename} crc32 0x${actual.toString(16)},` +
								` expected 0x${entry.crc32.toString(16)}`,
						);
					}
				}

				verified++;
			}

			if (entries === 0) {
				throw new Error(`${name}: archive yielded no entries`);
			}
		},
	});
}

Deno.test('rar5 extract: rar5-psw stored and compressed entries decrypt to the same content', async () => {
	const data = Deno.readFileSync(new URL('rar5-psw.rar', FIXTURES_DIR));
	const reader = fromUint8Array(data);

	const byName = new Map<string, Uint8Array>();
	for await (const entry of unrar(reader, { password: CORPUS_PASSWORD })) {
		byName.set(entry.filename, await entry.bytes());
	}

	const stest1 = byName.get('stest1.txt');
	const stest2 = byName.get('stest2.txt');
	if (stest1 === undefined || stest2 === undefined) {
		throw new Error('expected both stest1.txt and stest2.txt');
	}
	if (stest1.length !== stest2.length) {
		throw new Error(`size mismatch: stest1=${stest1.length} stest2=${stest2.length}`);
	}
	for (let idx = 0; idx < stest1.length; idx++) {
		if (stest1[idx] !== stest2[idx]) {
			throw new Error(`byte ${idx} differs: stest1=${stest1[idx]} stest2=${stest2[idx]}`);
		}
	}
});

Deno.test('rar5 extract: rar5-psw rejects a wrong password', async () => {
	const data = Deno.readFileSync(new URL('rar5-psw.rar', FIXTURES_DIR));
	const reader = fromUint8Array(data);

	let threw = false;
	try {
		for await (const entry of unrar(reader, { password: 'wrong-password' })) {
			await entry.bytes();
		}
	} catch (error) {
		threw = true;
		if (!(error instanceof Error) || !error.message.includes('check value')) {
			throw new Error(`unexpected error: ${error}`);
		}
	}
	if (!threw) {
		throw new Error('expected a check-value error for the wrong password');
	}
});

Deno.test('rar5 extract: rar5-psw rejects a missing password', async () => {
	const data = Deno.readFileSync(new URL('rar5-psw.rar', FIXTURES_DIR));
	const reader = fromUint8Array(data);

	let threw = false;
	try {
		for await (const entry of unrar(reader)) {
			await entry.bytes();
		}
	} catch (error) {
		threw = true;
		if (!(error instanceof Error) || !error.message.includes('password is required')) {
			throw new Error(`unexpected error: ${error}`);
		}
	}
	if (!threw) {
		throw new Error('expected a missing-password error');
	}
});

Deno.test('rar5 extract: rar5-vols multi-volume set', async () => {
	const readers = ['rar5-vols.part1.rar', 'rar5-vols.part2.rar', 'rar5-vols.part3.rar'].map(
		(name) => fromUint8Array(Deno.readFileSync(new URL(name, FIXTURES_DIR))),
	);

	const seen: { name: string; size: number; split: boolean }[] = [];
	for await (const entry of unrar(readers)) {
		const bytes = await entry.bytes();

		if (bytes.length !== entry.size) {
			throw new Error(`${entry.filename} read ${bytes.length} bytes, expected ${entry.size}`);
		}
		if (entry.crc32 !== undefined && crc32(bytes) !== entry.crc32) {
			throw new Error(`${entry.filename} crc32 mismatch`);
		}

		seen.push({ name: entry.filename, size: entry.size, split: entry.isSplit });
	}

	const expected = [
		{ name: 'vols/bigfile.txt', size: 205000, split: true },
		{ name: 'vols/smallfile.txt', size: 2050, split: false },
	];
	if (JSON.stringify(seen) !== JSON.stringify(expected)) {
		throw new Error(`unexpected entries: ${JSON.stringify(seen)}`);
	}
});

Deno.test('rar5 extract: rar5-vols rejects a standalone middle volume', async () => {
	const reader = fromUint8Array(
		Deno.readFileSync(new URL('rar5-vols.part2.rar', FIXTURES_DIR)),
	);

	let threw = false;
	try {
		for await (const _ of unrar(reader)) {
			// the first file block in part2 has splitBefore set with no preceding head
		}
	} catch (error) {
		threw = true;
		if (!(error instanceof Error) || !error.message.includes('split continuation')) {
			throw new Error(`unexpected error: ${error}`);
		}
	}

	if (!threw) {
		throw new Error('expected a standalone middle volume to be rejected');
	}
});

Deno.test('rar5 extract: stored content round-trips', async () => {
	const data = Deno.readFileSync(new URL('rar5-subdirs.rar', FIXTURES_DIR));

	const byName = new Map<string, string>();
	for await (const entry of unrar(fromUint8Array(data))) {
		if (!entry.isDirectory) {
			byName.set(entry.filename, await entry.text());
		}
	}

	const file = byName.get('sub/dir1/file1.txt');
	if (file === undefined) {
		throw new Error('expected sub/dir1/file1.txt to be present');
	}
	if (file.length === 0) {
		throw new Error('expected sub/dir1/file1.txt to have content');
	}
});
