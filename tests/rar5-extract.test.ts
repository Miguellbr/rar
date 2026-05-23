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

// fixtures the RAR5 extractor cannot yet handle; see the corpus notes.
const SKIP = new Set([
	'rar5-hpsw.rar',
	'rar5-readonly-win.rar',
	'rar5-vols.part1.rar',
	'rar5-vols.part2.rar',
	'rar5-vols.part3.rar',
]);

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

			let entries = 0;
			let verified = 0;

			for await (const entry of unrar(reader)) {
				entries++;

				// directories, links, and encrypted data are not yet covered;
				// everything else, stored or compressed (solid or not), is verified.
				if (entry.isDirectory || entry.linkTarget !== undefined || entry.isEncrypted) {
					continue;
				}

				const bytes = await entry.bytes();

				if (bytes.length !== entry.size) {
					throw new Error(
						`${name}: ${entry.filename} read ${bytes.length} bytes, expected ${entry.size}`,
					);
				}

				if (entry.crc32 !== undefined) {
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
