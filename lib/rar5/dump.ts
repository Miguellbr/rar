import { textDecoder } from '../utils/buffer.ts';

import type { FileBlock, RarTime } from './block.ts';
import { isDirectory, isFile, isSymlink, walkBlocks } from './block.ts';
import { BlockFlag } from './constants.ts';

/**
 * @module
 *
 * reproduces the verbosity-1 output of rarfile's `dumprar.py` for RAR5
 * archives. the output is byte-compatible with the `.exp` golden files in the
 * vendored rarfile corpus, so the test suite can diff against them directly.
 */

// #region flag rendering

type FlagBits = readonly (readonly [number, string])[];

const BLOCK_FLAG_BITS: FlagBits = [
	[0x01, 'EXTRA'],
	[0x02, 'DATA'],
	[0x04, 'SKIP'],
	[0x08, 'SPLIT_BEFORE'],
	[0x10, 'SPLIT_AFTER'],
	[0x20, 'DEPENDS'],
	[0x40, 'KEEP'],
];

const FILE_FLAG_BITS: FlagBits = [
	[0x01, 'DIR'],
	[0x02, 'MTIME'],
	[0x04, 'CRC32'],
	[0x08, 'NOSIZE'],
];

const ENCRYPTION_FLAG_BITS: FlagBits = [
	[0x01, 'CHECKVAL'],
	[0x02, 'TWEAKED'],
];

const REDIRECTION_FLAG_BITS: FlagBits = [
	[0x01, 'DIR'],
];

const DOS_MODE_BITS: FlagBits = [
	[0x00000001, 'READONLY'],
	[0x00000002, 'HIDDEN'],
	[0x00000004, 'SYSTEM'],
	[0x00000008, 'VOLUME_ID'],
	[0x00000010, 'DIRECTORY'],
	[0x00000020, 'ARCHIVE'],
	[0x00000040, 'DEVICE'],
	[0x00000080, 'NORMAL'],
	[0x00000100, 'TEMPORARY'],
	[0x00000200, 'SPARSE_FILE'],
	[0x00000400, 'REPARSE_POINT'],
	[0x00000800, 'COMPRESSED'],
	[0x00001000, 'OFFLINE'],
	[0x00002000, 'NOT_CONTENT_INDEXED'],
	[0x00004000, 'ENCRYPTED'],
	[0x00008000, 'INTEGRITY_STREAM'],
	[0x00010000, 'VIRTUAL'],
	[0x00020000, 'NO_SCRUB_DATA'],
	[0x00040000, 'RECALL_ON_OPEN'],
	[0x00080000, 'PINNED'],
	[0x00100000, 'UNPINNED'],
	[0x00400000, 'RECALL_ON_DATA_ACCESS'],
	[0x20000000, 'STRICTLY_SEQUENTIAL'],
];

const REDIRECTION_TYPE_NAMES: Record<number, string> = {
	1: 'UNIX_SYMLINK',
	2: 'WINDOWS_SYMLINK',
	3: 'WINDOWS_JUNCTION',
	4: 'HARD_LINK',
	5: 'FILE_COPY',
};

const renderFlags = (value: number, bits: FlagBits): string => {
	const names: string[] = [];
	let known = 0;

	for (const [bit, name] of bits) {
		known |= bit;
		if (value & bit) {
			names.push(name);
		}
	}

	let unknown = value & ~known;
	for (let shift = 0; unknown !== 0; shift++) {
		if (unknown & 1) {
			names.push(`UNK_${(1 << shift >>> 0).toString(16).padStart(4, '0')}`);
		}
		unknown >>>= 1;
	}

	return names.length !== 0 ? names.join(',') : '-';
};

// #endregion

// #region mode rendering

const modeTriad = (value: number): string[] => {
	return [value & 4 ? 'r' : '-', value & 2 ? 'w' : '-', value & 1 ? 'x' : '-'];
};

const unixMode = (mode: number): string => {
	const perms = [...modeTriad(mode >> 6), ...modeTriad(mode >> 3), ...modeTriad(mode)];

	if (mode & 0x0800) {
		perms[2] = perms[2] === 'x' ? 's' : 'S';
	}
	if (mode & 0x0400) {
		perms[5] = perms[5] === 'x' ? 's' : 'S';
	}
	if (mode & 0x0200) {
		perms[8] = perms[8] === 'x' ? 't' : '-';
	}

	const kind = mode & 0xf000;
	switch (kind) {
		case 0x4000: {
			perms.unshift('d');
			break;
		}
		case 0xa000: {
			perms.unshift('l');
			break;
		}
		case 0x0000:
		case 0x8000: {
			perms.unshift('-');
			break;
		}
		default: {
			perms.unshift('?');
			perms.push(`(0x${kind.toString(16).padStart(4, '0')})`);
		}
	}

	return perms.join('');
};

// the host OS code is the raw RAR5 value: 0 for Windows, 1 for Unix.
const renderMode = (hostOs: number, mode: number): string => {
	return hostOs === 1 ? unixMode(mode) : renderFlags(mode, DOS_MODE_BITS);
};

// #endregion

// #region python-style value rendering

const escapeByte = (code: number, quote: number): string => {
	switch (code) {
		case 0x09: {
			return '\\t';
		}
		case 0x0a: {
			return '\\n';
		}
		case 0x0d: {
			return '\\r';
		}
		case 0x5c: {
			return '\\\\';
		}
	}

	if (code === quote) {
		return '\\' + String.fromCharCode(code);
	}
	if (code >= 0x20 && code < 0x7f) {
		return String.fromCharCode(code);
	}
	if (code < 0x100) {
		return `\\x${code.toString(16).padStart(2, '0')}`;
	}
	if (code < 0x10000) {
		return `\\u${code.toString(16).padStart(4, '0')}`;
	}

	return `\\U${code.toString(16).padStart(8, '0')}`;
};

// mirrors python's repr(): single quotes unless the value contains a single
// quote but no double quote.
const pickQuote = (hasSingle: boolean, hasDouble: boolean): number => {
	return hasSingle && !hasDouble ? 0x22 : 0x27;
};

/**
 * renders a string the way python's `repr()` would.
 * @param value the string to render
 * @returns the quoted, escaped representation
 */
export const pyStringRepr = (value: string): string => {
	const quote = pickQuote(value.includes("'"), value.includes('"'));

	let body = '';
	for (const char of value) {
		body += escapeByte(char.codePointAt(0)!, quote);
	}

	const q = String.fromCharCode(quote);
	return q + body + q;
};

/**
 * renders a byte string the way python's `repr(bytes)` would.
 * @param value the bytes to render
 * @returns the quoted, escaped representation with a `b` prefix
 */
export const pyBytesRepr = (value: Uint8Array): string => {
	const quote = pickQuote(value.includes(0x27), value.includes(0x22));

	let body = '';
	for (const code of value) {
		body += escapeByte(code, quote);
	}

	const q = String.fromCharCode(quote);
	return 'b' + q + body + q;
};

const pyOptionalBytes = (value: Uint8Array | undefined): string => {
	return value !== undefined ? pyBytesRepr(value) : 'None';
};

const pyOptionalInt = (value: number | undefined): string => {
	return value !== undefined ? String(value) : 'None';
};

// #endregion

// #region scalar formatting

const hex = (bytes: Uint8Array): string => {
	let out = '';
	for (const byte of bytes) {
		out += byte.toString(16).padStart(2, '0');
	}

	return out;
};

const pad2 = (value: number): string => String(value).padStart(2, '0');

// breaks a timestamp into its UTC calendar fields.
const calendar = (time: RarTime): [string, string] => {
	const date = new Date(time.seconds * 1000);

	const day = `${String(date.getUTCFullYear()).padStart(4, '0')}-` +
		`${pad2(date.getUTCMonth() + 1)}-${pad2(date.getUTCDate())}`;
	const clock = `${pad2(date.getUTCHours())}:${pad2(date.getUTCMinutes())}:${pad2(date.getUTCSeconds())}`;

	return [day, clock];
};

// matches how dumprar prints the `date_time` six-tuple.
const formatDateTime = (time: RarTime): string => {
	const [day, clock] = calendar(time);
	return `${day} ${clock}`;
};

// matches datetime.isoformat as extended by rarfile's nanosecond-aware subclass:
// a whole-microsecond value prints six fractional digits, anything finer prints
// nine, and a zero fraction is omitted entirely.
const formatIso = (time: RarTime): string => {
	const [day, clock] = calendar(time);

	let fraction = '';
	if (time.nanos !== 0) {
		fraction = time.nanos % 1000 === 0
			? '.' + String(time.nanos / 1000).padStart(6, '0')
			: '.' + String(time.nanos).padStart(9, '0');
	}

	return `${day}T${clock}${fraction}+00:00`;
};

// #endregion

// #region archive dump

const dumpFile = (block: FileBlock, lines: string[]): void => {
	const rftype = (isFile(block) ? 'F' : '-') +
		(isDirectory(block) ? 'D' : '-') +
		(isSymlink(block) ? 'L' : '-');

	lines.push(
		`R5_FILE: hdrlen=${block.headerSize} datlen=${block.dataSize}` +
			` hdr_extra=${block.blockExtraSize} is=${rftype}`,
	);
	lines.push(
		`  block_flags=0x${block.blockFlags.toString(16).padStart(4, '0')}:` +
			renderFlags(block.blockFlags, BLOCK_FLAG_BITS),
	);
	lines.push(`  name=${block.name}`);
	lines.push(
		`  file_flags=0x${block.fileFlags.toString(16).padStart(4, '0')}:` +
			renderFlags(block.fileFlags, FILE_FLAG_BITS),
	);

	const ci = block.compressionInfo;
	lines.push(
		`  cmp_algo=${ci & 0x3f} cmp_meth=${(ci >> 7) & 0x07} dict=${ci >> 10}` +
			` solid=${(ci & 0x40) > 0 ? 'True' : 'False'}`,
	);

	lines.push(
		`  os=${block.hostOs}:${block.hostOs === 1 ? 'UNIX' : 'WINDOWS'}` +
			` mode=${renderMode(block.hostOs, block.attributes)}` +
			` cmp=${block.dataSize} dec=${block.unpackedSize} vol=0`,
	);

	if (block.crc !== undefined) {
		lines.push(`  crc=0x${block.crc.toString(16).padStart(8, '0')} (${block.crc})`);
	}
	if (block.hash !== undefined) {
		lines.push(`  blake2sp=${hex(block.hash.value)}`);
	}
	if (block.mtime !== undefined) {
		lines.push(`  date_time=${formatDateTime(block.mtime)}`);
		lines.push(`  mtime=${formatIso(block.mtime)}`);
	}
	if (block.ctime !== undefined) {
		lines.push(`  ctime=${formatIso(block.ctime)}`);
	}
	if (block.atime !== undefined) {
		lines.push(`  atime=${formatIso(block.atime)}`);
	}

	if (block.encryption !== undefined) {
		const enc = block.encryption;
		const algoName = enc.algorithm === 0 ? 'AES256' : 'UnknownAlgo';

		lines.push(
			`  algo=${enc.algorithm}:${algoName}` +
				` enc_flags=${enc.flags.toString(16).padStart(4, '0')}:` +
				renderFlags(enc.flags, ENCRYPTION_FLAG_BITS) +
				` kdf_lg=${enc.kdfCount} kdf_count=${1 << enc.kdfCount}` +
				` salt=${hex(enc.salt)} iv=${hex(enc.iv)}` +
				` checkval=${enc.checkValue !== undefined ? hex(enc.checkValue) : '-'}`,
		);
	}

	if (block.redirection !== undefined) {
		const redir = block.redirection;
		const typeName = REDIRECTION_TYPE_NAMES[redir.type] ?? 'Unknown';

		lines.push(
			`  redir: type=${typeName}` +
				` flags=${redir.flags}:${renderFlags(redir.flags, REDIRECTION_FLAG_BITS)}` +
				` destination=${redir.target}`,
		);
	}

	if (block.owner !== undefined) {
		const owner = block.owner;
		lines.push(
			`  owner: name=${pyOptionalBytes(owner.userName)} group=${pyOptionalBytes(owner.groupName)}` +
				` uid=${pyOptionalInt(owner.userId)} gid=${pyOptionalInt(owner.groupId)}`,
		);
	}

	if (block.version !== undefined) {
		lines.push(`  version: flags=${block.version.flags} version=${block.version.version}`);
	}
};

/**
 * dumps a RAR5 archive in dumprar's verbosity-1 format.
 *
 * only file entries are dumped, in archive order, skipping superseded file
 * versions and the trailing parts of split files — matching how dumprar walks
 * an archive's name list.
 *
 * @param data the complete archive bytes
 * @param archivePath path label to print on the leading `Archive:` line
 * @returns the dump text, newline-terminated
 */
export const dumpArchive = (data: Uint8Array, archivePath: string): string => {
	const lines: string[] = [`Archive: ${archivePath}`];

	const files: FileBlock[] = [];
	let comment: string | undefined;

	for (const block of walkBlocks(data)) {
		if (block.kind === 'service' && block.name === 'CMT') {
			const split = block.blockFlags & (BlockFlag.splitBefore | BlockFlag.splitAfter);
			const method = (block.compressionInfo >> 7) & 0x07;

			if (!split && method === 0) {
				const raw = data.subarray(block.dataOffset, block.dataOffset + block.dataSize);
				const nul = raw.indexOf(0);
				comment = textDecoder.decode(nul === -1 ? raw : raw.subarray(0, nul));
			}
		} else if (block.kind === 'file') {
			// superseded versions and split continuations never reach the name list
			if (block.version === undefined && !(block.blockFlags & BlockFlag.splitBefore)) {
				files.push(block);
			}
		}
	}

	if (comment !== undefined) {
		lines.push(`  comment=${pyStringRepr(comment)}`);
	}

	for (const file of files) {
		dumpFile(file, lines);
	}

	return lines.join('\n') + '\n';
};

// #endregion
