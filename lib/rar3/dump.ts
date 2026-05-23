/**
 * @module
 *
 * reproduces the verbosity-1 output of rarfile's `dumprar.py` for RAR3
 * (RAR1.5 through RAR4) archives. the output is byte-compatible with the
 * `.exp` golden files in the vendored rarfile corpus, so the test suite can
 * diff against them directly.
 *
 * the RAR3 dump format differs from RAR5's: blocks use the `FILE:` prefix
 * rather than `R5_FILE:`, flags include the RAR3 file/block names, dictionary
 * size is encoded into the file-flag bits, and the host OS code uses a
 * different numbering. comments, multi-volume aggregation, and the
 * encrypted-header variants are not yet rendered.
 */

import type { DosTime, EndArcBlock, ExtTime, FileBlock, MainBlock } from './block.ts';
import { walkBlocks } from './block.ts';
import { EndArcFlag, FileFlag, HostOs, MainFlag } from './constants.ts';

// #region flag rendering

type FlagBits = readonly (readonly [number, string])[];

// dumprar's r3 `file_bits` order. note the bit at 0x4000 is rendered as
// "SKIP" (not "SKIP_IF_UNKNOWN") to match the python output verbatim.
const FILE_FLAG_BITS: FlagBits = [
	[0x0001, 'SPLIT_BEFORE'],
	[0x0002, 'SPLIT_AFTER'],
	[0x0004, 'PASSWORD'],
	[0x0008, 'COMMENT'],
	[0x0010, 'SOLID'],
	[0x0100, 'LARGE'],
	[0x0200, 'UNICODE'],
	[0x0400, 'SALT'],
	[0x0800, 'VERSION'],
	[0x1000, 'EXTTIME'],
	[0x2000, 'EXTFLAGS'],
	[0x4000, 'SKIP'],
	[0x8000, 'LONG'],
];

// dictionary-size labels for the 3-bit field 0x00e0; the all-ones combination
// (DIR) means the entry is a directory, not a dictionary size.
const DICT_LABELS: Record<number, string> = {
	0x0000: 'D64',
	0x0020: 'D128',
	0x0040: 'D256',
	0x0060: 'D512',
	0x0080: 'D1024',
	0x00a0: 'D2048',
	0x00c0: 'D4096',
	0x00e0: 'DIR',
};

// renders `value` as a comma-separated list of flag names, with bits not
// represented by a name surfaced as `UNK_HHHH`.
const renderFlagsBare = (value: number, bits: FlagBits): string => {
	const names: string[] = [];
	let known = 0;

	for (const [bit, name] of bits) {
		known |= bit;
		if ((value & bit) !== 0) {
			names.push(name);
		}
	}

	let unknown = value & ~known;
	for (let shift = 0; unknown !== 0; shift++) {
		if ((unknown & 1) !== 0) {
			names.push(`UNK_${(1 << shift >>> 0).toString(16).padStart(4, '0')}`);
		}
		unknown >>>= 1;
	}

	return names.length !== 0 ? names.join(',') : '-';
};

// the file-flag rendering enumerates non-dict flags in dumprar's order, then
// appends a single dictionary-size (or `DIR`) label as the final segment.
const renderFileFlags = (flags: number): string => {
	const dictBits = flags & FileFlag.dictMask;
	const dictLabel = DICT_LABELS[dictBits] ?? `UNK_DICT_${dictBits.toString(16)}`;

	const segments: string[] = [];
	for (const [bit, name] of FILE_FLAG_BITS) {
		if ((flags & bit) !== 0) {
			segments.push(name);
		}
	}
	segments.push(dictLabel);
	return segments.join(',');
};

// #endregion

// #region mode rendering

const DOS_MODE_BITS: FlagBits = [
	[0x00000001, 'READONLY'],
	[0x00000002, 'HIDDEN'],
	[0x00000004, 'SYSTEM'],
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
];

const modeTriad = (value: number): string[] => {
	return [value & 4 ? 'r' : '-', value & 2 ? 'w' : '-', value & 1 ? 'x' : '-'];
};

const unixMode = (mode: number): string => {
	const perms = [...modeTriad(mode >> 6), ...modeTriad(mode >> 3), ...modeTriad(mode)];

	if (mode & 0x0800) perms[2] = perms[2] === 'x' ? 's' : 'S';
	if (mode & 0x0400) perms[5] = perms[5] === 'x' ? 's' : 'S';
	if (mode & 0x0200) perms[8] = perms[8] === 'x' ? 't' : '-';

	const kind = mode & 0xf000;
	switch (kind) {
		case 0x4000:
			perms.unshift('d');
			break;
		case 0xa000:
			perms.unshift('l');
			break;
		case 0x0000:
		case 0x8000:
			perms.unshift('-');
			break;
		default:
			perms.unshift('?');
			perms.push(`(0x${kind.toString(16).padStart(4, '0')})`);
	}

	return perms.join('');
};

const renderMode = (hostOs: number, mode: number): string => {
	return hostOs === HostOs.unix ? unixMode(mode) : renderFlagsBare(mode, DOS_MODE_BITS);
};

// #endregion

// #region time formatting

const pad2 = (value: number): string => String(value).padStart(2, '0');

const formatDateTime = (time: DosTime): string => {
	return `${time.year}-${pad2(time.month)}-${pad2(time.day)} ` +
		`${pad2(time.hour)}:${pad2(time.minute)}:${pad2(time.second)}`;
};

// rarfile uses datetime.isoformat() on its NanoDateTime subclass: a fraction
// that is a whole number of microseconds prints six digits, anything finer
// prints all nine, and a zero fraction is omitted entirely. RAR3 timestamps
// are local time, so unlike the RAR5 dump there is no `+00:00` suffix.
const formatIso = (time: DosTime, nanos: number = 0): string => {
	const base = `${time.year}-${pad2(time.month)}-${pad2(time.day)}T` +
		`${pad2(time.hour)}:${pad2(time.minute)}:${pad2(time.second)}`;

	if (nanos === 0) {
		return base;
	}
	if (nanos % 1000 === 0) {
		return `${base}.${String(nanos / 1000).padStart(6, '0')}`;
	}
	return `${base}.${String(nanos).padStart(9, '0')}`;
};

const formatExtTime = (ext: ExtTime | undefined, fallback: DosTime): string => {
	if (ext === undefined) {
		return formatIso(fallback);
	}
	return formatIso(ext.time, ext.nanos);
};

// #endregion

// #region os and method rendering

const OS_NAMES: Record<number, string> = {
	0: 'DOS',
	1: 'OS2',
	2: 'WIN',
	3: 'UNIX',
	4: 'MAC',
	5: 'BEOS',
};

const isDirectory = (block: FileBlock): boolean => {
	return (block.fileFlags & FileFlag.dictMask) === FileFlag.directory;
};

const isSymlink = (block: FileBlock): boolean => {
	// only unix-host entries can encode a symlink, via the S_IFLNK (0xa000)
	// bits at the top of `mode`.
	return block.hostOs === HostOs.unix && (block.attributes & 0xf000) === 0xa000;
};

// rar archives keep windows-style backslashes in entry names; dumprar always
// renders them with forward slashes regardless of the host OS.
const normalizeName = (name: string): string => name.replaceAll('\\', '/');

// #endregion

// #region archive dump

// the per-file dump state carried across a multi-volume walk: the head's
// metadata lives in `head`, while the volume index and split-aware totals
// settle as later parts are seen.
interface AggregatedFile {
	head: FileBlock;
	compressedSize: number;
	crc: number;
	volume: number;
}

const dumpFile = (entry: AggregatedFile, lines: string[]): void => {
	const { compressedSize, crc, head, volume } = entry;
	const dir = isDirectory(head);
	const link = isSymlink(head);
	// rarfile prints `is=` as three characters: file, dir, link. unix
	// symlinks are detected through the host-mode S_IFLNK bits.
	const rftype = (link || dir ? '-' : 'F') + (dir ? 'D' : '-') + (link ? 'L' : '-');

	lines.push(`FILE: hdrlen=${head.headerSize} datlen=${head.dataSize} is=${rftype}`);
	lines.push(
		`  flags=0x${head.fileFlags.toString(16).padStart(4, '0')}:` +
			renderFileFlags(head.fileFlags),
	);

	const osName = OS_NAMES[head.hostOs] ?? `OS${head.hostOs}`;
	const methodDigit = head.method >= 0x30 && head.method <= 0x35 ? head.method - 0x30 : head.method;

	// dumprar adds `namecmp=N/M` for unicode names: N is the size of the
	// base bytes the name decodes from (everything before the optional NUL
	// in the raw name field), M is the on-disk name field length.
	let nameCmp = '';
	if ((head.fileFlags & FileFlag.unicode) !== 0) {
		const nul = head.rawName.indexOf(0);
		const baseLen = nul === -1 ? head.rawName.length : nul;
		nameCmp = ` namecmp=${baseLen}/${head.rawName.length}`;
	}

	lines.push(
		`  os=${head.hostOs}:${osName} ver=${head.extractVersion}` +
			` mode=${renderMode(head.hostOs, head.attributes)}` +
			` meth=${methodDigit}` +
			` cmp=${compressedSize} dec=${head.unpackedSize} vol=${volume}` +
			nameCmp,
	);

	// the extended-time record can bump the DOS mtime by 1 second so it
	// recovers the resolution DOS truncates; the dump uses the corrected
	// value for both the `date_time` and `mtime` lines.
	const baseTime = head.extMtime?.time ?? head.mtime;
	lines.push(
		`  crc=0x${crc.toString(16).padStart(8, '0')} (${crc})` +
			` date_time=${formatDateTime(baseTime)}`,
	);
	lines.push(`  name=${normalizeName(head.name)}${dir ? '/' : ''}`);
	if (head.extMtime !== undefined) {
		lines.push(`  mtime=${formatExtTime(head.extMtime, baseTime)}`);
	}
	if (head.ctime !== undefined) {
		lines.push(`  ctime=${formatIso(head.ctime.time, head.ctime.nanos)}`);
	}
	if (head.atime !== undefined) {
		lines.push(`  atime=${formatIso(head.atime.time, head.atime.nanos)}`);
	}
	if (head.arctime !== undefined) {
		lines.push(`  arctime=${formatIso(head.arctime.time, head.arctime.nanos)}`);
	}
};

// returns true when a single-volume buffer represents a continuation rather
// than the first volume of a multi-volume set, matching rarfile's check.
const isContinuationVolume = (main: MainBlock, firstFile: FileBlock | undefined): boolean => {
	if ((main.mainFlags & MainFlag.newNumbering) !== 0) {
		// modern .partN.rar volumes flag the first member with FIRSTVOLUME;
		// anything else without that flag must be a continuation.
		return (main.mainFlags & MainFlag.firstVolume) === 0;
	}
	// RAR1.5 - RAR2.x do not flag the first volume, so the only signal is that
	// the very first file in the volume continues from a previous part.
	return firstFile !== undefined && (firstFile.fileFlags & FileFlag.splitBefore) !== 0;
};

/**
 * dumps a RAR3 (RAR1.5 - RAR4) archive in dumprar's verbosity-1 format.
 *
 * pass a single buffer for a self-contained archive or an ordered list of
 * volume buffers to aggregate a split set. only file entries are dumped, in
 * archive order; superseded versions and the trailing parts of split files
 * fold into their head per dumprar. archive- and entry-level comments and
 * encrypted-header archives are not yet rendered.
 *
 * a single buffer that is actually a middle or trailing volume produces
 * dumprar's `--- ... is middle part of multi-vol archive` line so the test
 * suite sees the same output as upstream.
 *
 * @param data the complete archive bytes for one volume, or an ordered list
 * of every volume's bytes
 * @param archivePath path label to print on the leading `Archive:` line
 * @returns the dump text, newline-terminated
 */
export const dumpArchive = (
	data: Uint8Array | readonly Uint8Array[],
	archivePath: string,
): string => {
	const volumes: readonly Uint8Array[] = Array.isArray(data) ? data : [data as Uint8Array];
	const isSingleVolume = !Array.isArray(data);

	const lines: string[] = [`Archive: ${archivePath}`];

	// when only one volume is in hand, walk it once to find out whether it is
	// the first or a continuation; if it is a continuation, surface the same
	// error string dumprar prints and bail. the EndArc.volnr field (when
	// present) names the volume's zero-based index for the error message.
	if (isSingleVolume) {
		let main: MainBlock | undefined;
		let firstFile: FileBlock | undefined;
		let endArc: EndArcBlock | undefined;
		for (const block of walkBlocks(volumes[0])) {
			if (block.kind === 'main' && main === undefined) {
				main = block;
			} else if (block.kind === 'file' && firstFile === undefined) {
				firstFile = block;
			} else if (block.kind === 'endArc' && endArc === undefined) {
				endArc = block;
			}
		}
		if (main !== undefined && isContinuationVolume(main, firstFile)) {
			let current: number | undefined;
			if (endArc !== undefined && (endArc.endArcFlags & EndArcFlag.volNr) !== 0) {
				current = endArc.volumeNumber;
			}
			const currentText = current !== undefined ? String(current) : '?';
			lines.push(
				` --- ${archivePath} is middle part of multi-vol archive` +
					` (Need to start from first volume (current: ${currentText}))---`,
			);
			return lines.join('\n') + '\n';
		}
	}

	const entries: AggregatedFile[] = [];
	const entriesByName = new Map<string, AggregatedFile>();
	let openName: string | undefined;

	for (let vol = 0; vol < volumes.length; vol++) {
		for (const block of walkBlocks(volumes[vol])) {
			if (block.kind !== 'file') {
				continue;
			}
			if ((block.fileFlags & FileFlag.version) !== 0) {
				continue;
			}

			const splitBefore = (block.fileFlags & FileFlag.splitBefore) !== 0;
			const splitAfter = (block.fileFlags & FileFlag.splitAfter) !== 0;

			if (!splitBefore) {
				const entry: AggregatedFile = {
					compressedSize: block.dataSize,
					crc: block.crc,
					head: block,
					volume: vol,
				};
				entries.push(entry);
				entriesByName.set(block.name, entry);
				openName = splitAfter ? block.name : undefined;
				continue;
			}

			// a continuation extends the open split entry; mirror dumprar's
			// lenient skip when the names don't line up so a stray middle volume
			// in a list doesn't blow up the dump.
			if (openName === undefined || openName !== block.name) {
				continue;
			}
			const entry = entriesByName.get(openName);
			if (entry !== undefined) {
				entry.compressedSize += block.dataSize;
				entry.crc = block.crc;
			}
			if (!splitAfter) {
				openName = undefined;
			}
		}
	}

	for (const entry of entries) {
		dumpFile(entry, lines);
	}

	return lines.join('\n') + '\n';
};

// #endregion
