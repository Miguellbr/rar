import { dumpArchive } from '../lib/rar3/dump.ts';

/**
 * @module
 *
 * golden-dump regression tests for the RAR3 block parser. each `.rar`
 * fixture in the vendored rarfile corpus is dumped in dumprar's verbosity-1
 * format and compared against its paired `.exp` file. fixtures that require
 * archive- or entry-level comments, multi-volume aggregation, or
 * encrypted-header handling are still skipped.
 */

const FIXTURES_DIR = new URL('./fixtures/rarfile/files/', import.meta.url);

const SKIP: Record<string, string> = {
	'ctime5.rar': 'actually a RAR5 archive (signature ends in 0x01); belongs to the RAR5 corpus',
	'rar15-comment-lock.rar': 'RAR1.5 archive-level comment; sub-block dump not yet rendered',
	'rar15-comment.rar': 'RAR1.5 archive-level comment; sub-block dump not yet rendered',
	'rar202-comment-nopsw.rar': 'RAR2.0.2 archive-level comment; sub-block dump not yet rendered',
	'rar202-comment-psw.rar': 'RAR2.0.2 encrypted archive comment; sub-block dump not yet rendered',
	'rar3-comment-hpsw.rar': 'encrypted headers; needs RAR3 header decryption',
	'rar3-comment-plain.rar': 'archive- and entry-level comments; sub-block dump not yet rendered',
	'rar3-comment-psw.rar': 'encrypted comment; sub-block dump not yet rendered',
	'rar3-old.r00': 'no golden file; rendered through rar3-old.rar as its first volume',
	'rar3-old.r01': 'no golden file; rendered through rar3-old.rar as its first volume',
};

// multi-volume sets identified by the first-volume filename. each entry names
// every continuation volume in archive order; the dumper aggregates split
// files across the whole list when given the first volume.
const VOLUME_SETS: Record<string, readonly string[]> = {
	'rar3-old.rar': ['rar3-old.r00', 'rar3-old.r01'],
	'rar3-vols.part1.rar': ['rar3-vols.part2.rar', 'rar3-vols.part3.rar'],
};

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
	.filter((name) => /\.(rar|r00|r01)$/.test(name) && !name.startsWith('rar5-'))
	.sort();

for (const name of fixtures) {
	const skipReason = SKIP[name];

	Deno.test({
		name: `rar3 golden dump: ${name}`,
		ignore: skipReason !== undefined,
		fn: () => {
			const continuations = VOLUME_SETS[name];
			const expected = Deno.readTextFileSync(new URL(`${name}.exp`, FIXTURES_DIR));

			let actual: string;
			if (continuations === undefined) {
				const data = Deno.readFileSync(new URL(name, FIXTURES_DIR));
				actual = dumpArchive(data, `test/files/${name}`);
			} else {
				const volumes = [
					Deno.readFileSync(new URL(name, FIXTURES_DIR)),
					...continuations.map((vol) => Deno.readFileSync(new URL(vol, FIXTURES_DIR))),
				];
				actual = dumpArchive(volumes, `test/files/${name}`);
			}

			if (actual !== expected) {
				throw new Error(`golden dump mismatch for ${name}\n${describeDiff(actual, expected)}`);
			}
		},
	});
}
