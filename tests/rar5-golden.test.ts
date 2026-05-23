import { fromUint8Array } from '../lib/reader/common.ts';
import { dumpArchive } from '../lib/rar5/dump.ts';

/**
 * @module
 *
 * golden-dump regression tests for the RAR5 block parser. each `.rar` fixture
 * in the vendored rarfile corpus is dumped in dumprar's verbosity-1 format and
 * compared against its paired `.exp` file.
 */

const FIXTURES_DIR = new URL('./fixtures/rarfile/files/', import.meta.url);

// the password rarfile's corpus uses for every password-protected fixture.
const CORPUS_PASSWORD = 'password';

// fixtures that the RAR5 golden-dump harness cannot yet cover; see
// tests/fixtures/rarfile/README.md and the corpus notes.
const SKIP: Record<string, string> = {
	'rar5-readonly-win.rar': 'misnamed RAR3 archive; belongs to the future RAR3 path',
};

// fixtures whose dump is driven by passing the whole volume set rather than a
// single reader. for them, the corresponding `.exp` aggregates file metadata
// across volumes.
const VOLUME_SET: Record<string, readonly string[]> = {
	'rar5-vols.part1.rar': [
		'rar5-vols.part1.rar',
		'rar5-vols.part2.rar',
		'rar5-vols.part3.rar',
	],
};

// reports the first line that differs, with a little surrounding context.
const describeDiff = (actual: string, expected: string): string => {
	const a = actual.split('\n');
	const b = expected.split('\n');

	for (let idx = 0; idx < Math.max(a.length, b.length); idx++) {
		if (a[idx] !== b[idx]) {
			return `first difference at line ${idx + 1}:\n` +
				`  expected: ${JSON.stringify(b[idx])}\n` +
				`  actual:   ${JSON.stringify(a[idx])}`;
		}
	}

	return 'outputs differ in length only';
};

const fixtures = [...Deno.readDirSync(FIXTURES_DIR)]
	.map((entry) => entry.name)
	.filter((name) => name.startsWith('rar5-') && name.endsWith('.rar'))
	.sort();

for (const name of fixtures) {
	const skipReason = SKIP[name];

	Deno.test({
		name: `rar5 golden dump: ${name}`,
		ignore: skipReason !== undefined,
		fn: async () => {
			const expected = Deno.readTextFileSync(new URL(`${name}.exp`, FIXTURES_DIR));
			const password = name.includes('-hpsw') ? CORPUS_PASSWORD : undefined;

			const volumeSet = VOLUME_SET[name];
			const source = volumeSet !== undefined
				? volumeSet.map((vol) => fromUint8Array(Deno.readFileSync(new URL(vol, FIXTURES_DIR))))
				: fromUint8Array(Deno.readFileSync(new URL(name, FIXTURES_DIR)));

			const actual = await dumpArchive(source, `test/files/${name}`, { password });

			if (actual !== expected) {
				throw new Error(`golden dump mismatch for ${name}\n${describeDiff(actual, expected)}`);
			}
		},
	});
}
