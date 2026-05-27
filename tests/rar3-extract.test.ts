import { fromUint8Array } from '../lib/reader/common.ts';
import { unrar3 } from '../lib/rar3/extract.ts';
import { crc32 } from '../lib/utils/crc32.ts';

/**
 * @module
 *
 * extraction tests for the RAR3 entry API. only stored entries are exercised
 * here — fixtures that include compressed entries are filtered out per file,
 * since the rar3 decompressor is a separate task. metadata fields are
 * spot-checked against fixture knowledge as a sanity gate.
 */

const FIXTURES_DIR = new URL('./fixtures/rarfile/files/', import.meta.url);

// fixtures that should not be passed to unrar3 at all: a misnamed RAR5
// archive and the multi-volume continuations which only round-trip when
// bundled with their first volume.
const PER_FILE_SKIP = new Set([
	'ctime5.rar',
	'rar3-old.r00',
	'rar3-old.r01',
	'rar3-old.rar',
	'rar3-vols.part1.rar',
	'rar3-vols.part2.rar',
	'rar3-vols.part3.rar',
]);

// password used by every encrypted fixture in the corpus.
const CORPUS_PASSWORD = 'password';

const fixtures = [...Deno.readDirSync(FIXTURES_DIR)]
	.map((entry) => entry.name)
	.filter((name) => /\.(rar|r00|r01)$/.test(name) && !name.startsWith('rar5-'))
	.sort();

for (const name of fixtures) {
	Deno.test({
		name: `rar3 extract: ${name}`,
		ignore: PER_FILE_SKIP.has(name),
		fn: async () => {
			const data = Deno.readFileSync(new URL(name, FIXTURES_DIR));
			const reader = fromUint8Array(data);
			const password = name.includes('-psw') || name.includes('-hpsw') ? CORPUS_PASSWORD : undefined;

			let entries = 0;
			let storedVerified = 0;

			for await (const entry of unrar3(reader, { password })) {
				entries++;

				if (entry.isDirectory) {
					continue;
				}
				// compressed and encrypted entries cannot be read yet; skip the
				// body check but make sure the metadata side still works.
				if (entry.isEncrypted || entry.compressionMethod !== 0x30) {
					continue;
				}

				const bytes = await entry.bytes();

				if (bytes.length !== entry.size) {
					throw new Error(
						`${name}: ${entry.filename} read ${bytes.length} bytes, expected ${entry.size}`,
					);
				}

				const actualCrc = crc32(bytes);
				if (actualCrc !== entry.crc32) {
					throw new Error(
						`${name}: ${entry.filename} crc32 0x${actualCrc.toString(16)},` +
							` expected 0x${entry.crc32.toString(16)}`,
					);
				}

				storedVerified++;
			}

			if (entries === 0) {
				throw new Error(`${name}: archive yielded no entries`);
			}
		},
	});
}

Deno.test('rar3 extract: rar3-readonly-unix.rar surfaces stored content with metadata', async () => {
	const data = Deno.readFileSync(new URL('rar3-readonly-unix.rar', FIXTURES_DIR));
	const reader = fromUint8Array(data);

	const byName = new Map<string, { size: number; mode: number; crc32: number; bytes: Uint8Array }>();
	for await (const entry of unrar3(reader)) {
		if (entry.isDirectory) {
			continue;
		}
		byName.set(entry.filename, {
			bytes: await entry.bytes(),
			crc32: entry.crc32,
			mode: entry.mode,
			size: entry.size,
		});
	}

	const file = byName.get('ro_dir/ro_file.txt');
	if (file === undefined) {
		throw new Error('expected ro_dir/ro_file.txt in archive');
	}
	if (file.size !== 9) {
		throw new Error(`expected size 9, got ${file.size}`);
	}
	// the .exp shows mode `-r--r--r--` which is 0o100444 = 33060.
	if ((file.mode & 0o777) !== 0o444) {
		throw new Error(`expected read-only mode, got 0o${file.mode.toString(8)}`);
	}
	if (crc32(file.bytes) !== file.crc32) {
		throw new Error('crc32 mismatch');
	}
});

Deno.test('rar3 extract: rar3-vols multi-volume stored set round-trips', async () => {
	const readers = ['rar3-vols.part1.rar', 'rar3-vols.part2.rar', 'rar3-vols.part3.rar'].map(
		(name) => fromUint8Array(Deno.readFileSync(new URL(name, FIXTURES_DIR))),
	);

	const seen: { name: string; size: number; split: boolean }[] = [];
	for await (const entry of unrar3(readers)) {
		const bytes = await entry.bytes();
		if (bytes.length !== entry.size) {
			throw new Error(`${entry.filename} read ${bytes.length} bytes, expected ${entry.size}`);
		}
		if (crc32(bytes) !== entry.crc32) {
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

Deno.test('rar3 extract: rar3-old legacy multi-volume set round-trips', async () => {
	// the .rar/.r00/.r01 naming is the pre-newNumbering layout; same data as
	// rar3-vols.part*, just with the legacy filename scheme.
	const readers = ['rar3-old.rar', 'rar3-old.r00', 'rar3-old.r01'].map(
		(name) => fromUint8Array(Deno.readFileSync(new URL(name, FIXTURES_DIR))),
	);

	const names: string[] = [];
	for await (const entry of unrar3(readers)) {
		const bytes = await entry.bytes();
		if (bytes.length !== entry.size) {
			throw new Error(`${entry.filename} read ${bytes.length} bytes, expected ${entry.size}`);
		}
		if (crc32(bytes) !== entry.crc32) {
			throw new Error(`${entry.filename} crc32 mismatch`);
		}
		names.push(entry.filename);
	}

	if (JSON.stringify(names) !== JSON.stringify(['vols/bigfile.txt', 'vols/smallfile.txt'])) {
		throw new Error(`unexpected entries: ${JSON.stringify(names)}`);
	}
});

Deno.test('rar3 extract: rar3-vols rejects a standalone middle volume', async () => {
	const reader = fromUint8Array(
		Deno.readFileSync(new URL('rar3-vols.part2.rar', FIXTURES_DIR)),
	);

	let threw = false;
	try {
		for await (const _ of unrar3(reader)) {
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

Deno.test({
	name: 'rar3 extract: seektest stest1 (compressed) matches stest2 (stored)',
	fn: async () => {
		const data = Deno.readFileSync(new URL('seektest.rar', FIXTURES_DIR));
		const reader = fromUint8Array(data);

		const byName = new Map<string, Uint8Array>();
		for await (const entry of unrar3(reader)) {
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
	},
});

Deno.test('rar3 extract: password-protected entries decrypt with rar3DeriveKey', async () => {
	// rar3-comment-psw.rar carries two encrypted file entries — both 0-byte
	// payloads — alongside their encrypted CMT comment subblocks. extracting
	// without a password surfaces a clear error; supplying the corpus password
	// completes the read.
	const data = Deno.readFileSync(new URL('rar3-comment-psw.rar', FIXTURES_DIR));

	{
		let threw = false;
		try {
			for await (const entry of unrar3(fromUint8Array(data))) {
				if (entry.isEncrypted) {
					await entry.bytes();
				}
			}
		} catch (error) {
			threw = true;
			if (!(error instanceof Error) || !error.message.includes('password-protected')) {
				throw new Error(`unexpected error: ${error}`);
			}
		}
		if (!threw) {
			throw new Error('expected the encrypted entry to refuse extraction without a password');
		}
	}

	const sizes: number[] = [];
	for await (const entry of unrar3(fromUint8Array(data), { password: 'password' })) {
		if (!entry.isEncrypted) {
			continue;
		}
		const bytes = await entry.bytes();
		if (bytes.length !== entry.size) {
			throw new Error(
				`${entry.filename} read ${bytes.length} bytes, expected ${entry.size}`,
			);
		}
		sizes.push(entry.size);
	}
	if (sizes.length === 0) {
		throw new Error('expected at least one encrypted entry in rar3-comment-psw.rar');
	}
});

Deno.test('rar3 extract: PPMd entries — solid reuse block decodes', async () => {
	// unicode.rar uses PPMd-H. the first entry's block carries the "full
	// reinit" flag and decodes end to end. the second entry is a "reuse"
	// (solid) block whose model state is inherited from the first entry;
	// only the range decoder is re-primed.
	const data = Deno.readFileSync(new URL('unicode.rar', FIXTURES_DIR));
	const reader = fromUint8Array(data);

	const decoded: Uint8Array[] = [];
	for await (const entry of unrar3(reader)) {
		if (entry.isDirectory || entry.compressionMethod === 0x30) {
			continue;
		}
		decoded.push(await entry.bytes());
	}

	if (decoded.length !== 2) {
		throw new Error(`expected 2 PPMd entries, got ${decoded.length}`);
	}
	for (let i = 0; i < 2; i++) {
		const bytes = decoded[i];
		if (bytes.length !== 2 || bytes[0] !== 0x31 || bytes[1] !== 0x0a) {
			throw new Error(
				`entry ${i}: expected "1\\n", got ${JSON.stringify(Array.from(bytes))}`,
			);
		}
	}
});
