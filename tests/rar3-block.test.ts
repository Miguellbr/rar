import { CompressMethod, HostOs } from '../lib/rar3/constants.ts';
import { walkBlocks } from '../lib/rar3/block.ts';

/**
 * @module
 *
 * smoke tests for the RAR3 block-walker. for each non-RAR5 fixture in the
 * vendored rarfile corpus, walk the headers and assert we get a reasonable
 * structure back (mark, at least one main, then a mix of file/sub/endArc).
 * decompression and dumprar-style rendering are tracked separately.
 */

const FIXTURES_DIR = new URL('./fixtures/rarfile/files/', import.meta.url);

// fixtures the walker cannot yet exercise; either they are actually RAR5 files
// despite the name, or they have encrypted block headers, which needs the
// RAR3 header decryption path we have not built.
const SKIP: Record<string, string> = {
	'ctime5.rar': 'actually a RAR5 archive (signature ends in 0x01); belongs to the RAR5 corpus',
	'rar3-comment-hpsw.rar': 'encrypted headers; needs RAR3 header decryption',
};

const fixtures = [...Deno.readDirSync(FIXTURES_DIR)]
	.map((entry) => entry.name)
	.filter((name) => /\.(rar|r00|r01)$/.test(name) && !name.startsWith('rar5-'))
	.sort();

for (const name of fixtures) {
	Deno.test({
		name: `rar3 walk: ${name}`,
		ignore: SKIP[name] !== undefined,
		fn: () => {
			const data = Deno.readFileSync(new URL(name, FIXTURES_DIR));

			const kinds: string[] = [];
			const files: string[] = [];

			for (const block of walkBlocks(data)) {
				kinds.push(block.kind);
				if (block.kind === 'file' || block.kind === 'sub') {
					files.push(block.name);
				}
			}

			if (kinds[0] !== 'mark') {
				throw new Error(`${name}: expected first block kind 'mark', got ${kinds[0]}`);
			}
			if (kinds[1] !== 'main') {
				throw new Error(`${name}: expected second block kind 'main', got ${kinds[1]}`);
			}
			// every walked fixture has at least one block beyond mark+main;
			// otherwise the archive is empty, which is not the case in the corpus.
			if (kinds.length < 3) {
				throw new Error(`${name}: only ${kinds.length} blocks parsed`);
			}
		},
	});
}

Deno.test('rar3 walk: rar3-comment-plain.rar exposes the expected file entries', () => {
	const data = Deno.readFileSync(new URL('rar3-comment-plain.rar', FIXTURES_DIR));

	const fileNames: string[] = [];
	for (const block of walkBlocks(data)) {
		if (block.kind === 'file') {
			fileNames.push(block.name);
			// the corpus' rar3-comment-plain entries are RAR3 normal-compressed
			// 8-byte texts on unix; spot-check.
			if (block.method !== CompressMethod.normal) {
				throw new Error(`expected normal compression for ${block.name}, got 0x${block.method.toString(16)}`);
			}
			if (block.hostOs !== HostOs.unix) {
				throw new Error(`expected unix host for ${block.name}, got ${block.hostOs}`);
			}
		}
	}

	const expected = ['file1.txt', 'file2.txt'];
	if (JSON.stringify(fileNames) !== JSON.stringify(expected)) {
		throw new Error(`unexpected file list: ${JSON.stringify(fileNames)}`);
	}
});
