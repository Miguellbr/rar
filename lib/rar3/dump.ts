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
 * different numbering. RAR3-style CMT sub-block comments — including
 * password-encrypted CMTs when the caller supplies the password — and
 * RAR1.5/2.x oldComment subblocks (stored and compressed) are rendered as
 * `comment=...` lines.
 */

import { concat, decodeUtf8From, read } from '../utils/buffer.ts';
import { StreamReader } from '../utils/stream-reader.ts';

import type { DosTime, EndArcBlock, ExtTime, FileBlock, MainBlock, OldCommentSubBlock } from './block.ts';
import { walkBlocks } from './block.ts';
import { CompressMethod, EndArcFlag, FileFlag, HostOs, MainFlag } from './constants.ts';
import { decryptRar3HeadersIfNeeded, decryptRar3Stream } from './crypto.ts';
import { decodeOldLzss15, decodeOldLzss20 } from './oldlzss.ts';
import { Rar3Decoder } from './unpack.ts';

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
// settle as later parts are seen. an entry-level CMT subblock that follows
// the file folds its decoded text into `comment`.
interface AggregatedFile {
	head: FileBlock;
	compressedSize: number;
	crc: number;
	volume: number;
	comment?: string;
}

// formats a string the way python's `repr` would print it: wrapped in single
// quotes (or double quotes when the string contains a single quote but no
// double quote), with the standard `\`, `\n`, `\r`, `\t` and `\xHH` escapes.
// matches what rarfile's dumprar emits for `comment=...` lines.
const pythonRepr = (text: string): string => {
	const useDouble = text.includes("'") && !text.includes('"');
	const quote = useDouble ? '"' : "'";
	let out = quote;
	for (const ch of text) {
		const code = ch.codePointAt(0)!;
		if (ch === '\\') {
			out += '\\\\';
		} else if (ch === quote) {
			out += '\\' + quote;
		} else if (ch === '\n') {
			out += '\\n';
		} else if (ch === '\r') {
			out += '\\r';
		} else if (ch === '\t') {
			out += '\\t';
		} else if (code < 0x20 || code === 0x7f) {
			out += '\\x' + code.toString(16).padStart(2, '0');
		} else {
			out += ch;
		}
	}
	return out + quote;
};

// the dictionary size (in bytes) implied by a file/sub header's flag bits.
// the dict-mask carries a 3-bit code that the LZSS engine rounds up to the
// next power of two; the "directory" code degenerates to the smallest window.
const dictionarySizeFromFlags = (fileFlags: number): number => {
	const dict = fileFlags & FileFlag.dictMask;
	if (dict === FileFlag.directory) {
		return 64 * 1024;
	}
	return (64 * 1024) << (dict >> 5);
};

// wraps a Uint8Array in a single-chunk ReadableStream. the chunk is copied
// so a caller mutating the source buffer later cannot corrupt the queued
// chunk (the underlying archive Uint8Array typically outlives the stream).
const bufferToStream = (
	data: Uint8Array,
): ReadableStream<Uint8Array<ArrayBuffer>> => {
	return new ReadableStream<Uint8Array<ArrayBuffer>>({
		start(controller) {
			if (data.length > 0) {
				controller.enqueue(new Uint8Array(data));
			}
			controller.close();
		},
	});
};

// decodes a legacy oldComment subblock embedded inline in a MAIN or FILE
// header. stored (`meth=0x30`) data is returned verbatim. compressed
// variants are routed through the v15 or v20 LZSS decoder based on the
// `version` field. anything else returns `undefined` so the caller can omit
// the comment rather than abort the dump.
const decodeOldComment = (sub: OldCommentSubBlock): string | undefined => {
	let bytes: Uint8Array | undefined;
	if (sub.method === CompressMethod.stored) {
		if (sub.data.length < sub.decompressedSize) {
			return undefined;
		}
		bytes = sub.data.subarray(0, sub.decompressedSize);
	} else if (sub.version <= 15) {
		bytes = decodeOldLzss15(sub.data, sub.decompressedSize);
	} else if (sub.version <= 20 || sub.version === 26) {
		bytes = decodeOldLzss20(sub.data, sub.decompressedSize);
	}
	if (bytes === undefined) {
		return undefined;
	}

	try {
		return decodeUtf8From(bytes as Uint8Array<ArrayBuffer>);
	} catch {
		return undefined;
	}
};

// decodes the data area of a CMT sub-record into its plain-text form. handles
// stored, LZSS-compressed, and password-encrypted RAR3 (ver 29) CMTs. the
// RAR1.5/2.x LZSS variant, split CMTs, and CMTs missing the required salt
// are reported as `undefined` so the caller can omit the comment rather
// than abort the dump.
const decodeCmtPayload = async (
	head: FileBlock,
	data: Uint8Array,
	password: string | undefined,
): Promise<string | undefined> => {
	if ((head.fileFlags & (FileFlag.splitAfter | FileFlag.splitBefore)) !== 0) {
		return undefined;
	}
	if (head.extractVersion < 29) {
		return undefined;
	}

	const encrypted = (head.fileFlags & FileFlag.password) !== 0;
	if (encrypted && (password === undefined || head.salt === undefined)) {
		return undefined;
	}

	// resolve the ciphertext stream first: stored data and the LZSS branches
	// both need to pull from a plaintext stream once decryption is out of the
	// way. for plain entries this is the source data verbatim.
	let plaintextStream: ReadableStream<Uint8Array<ArrayBuffer>>;
	if (encrypted) {
		try {
			plaintextStream = await decryptRar3Stream(
				password!,
				head.salt!,
				bufferToStream(data),
			);
		} catch {
			return undefined;
		}
	} else {
		plaintextStream = bufferToStream(data);
	}

	let bytes: Uint8Array;
	if (head.method === CompressMethod.stored) {
		// stored: read up to `unpackedSize` bytes; any trailing AES padding
		// bytes are encoder noise.
		try {
			bytes = await read(plaintextStream, head.unpackedSize);
		} catch {
			return undefined;
		}
	} else {
		const decoder = new Rar3Decoder(dictionarySizeFromFlags(head.fileFlags));
		const chunks: Uint8Array[] = [];
		await using reader = new StreamReader(plaintextStream);
		try {
			await decoder.decode(reader, head.unpackedSize, (chunk) => {
				chunks.push(chunk);
			});
		} catch {
			return undefined;
		}
		bytes = chunks.length === 1 ? chunks[0] : concat(chunks, head.unpackedSize);
	}

	try {
		return decodeUtf8From(bytes as Uint8Array<ArrayBuffer>);
	} catch {
		return undefined;
	}
};

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
	if (entry.comment !== undefined) {
		lines.push(`  comment=${pythonRepr(entry.comment)}`);
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

/** options recognised by {@link dumpArchive}. */
export interface DumpOptions {
	/** password used to decrypt encrypted CMT subblocks */
	password?: string;
}

/**
 * dumps a RAR3 (RAR1.5 - RAR4) archive in dumprar's verbosity-1 format.
 *
 * pass a single buffer for a self-contained archive or an ordered list of
 * volume buffers to aggregate a split set. file entries dump in archive
 * order; superseded versions and the trailing parts of split files fold into
 * their head per dumprar. RAR3 CMT sub-block comments are surfaced as
 * `comment=...` lines, with encrypted comments decrypted on the fly when
 * `options.password` is supplied. RAR1.5/2.x oldComment subblocks decode
 * through the v15/v20 LZSS decoders in {@link decodeOldLzss15}/
 * {@link decodeOldLzss20}.
 *
 * a single buffer that is actually a middle or trailing volume produces
 * dumprar's `--- ... is middle part of multi-vol archive` line so the test
 * suite sees the same output as upstream.
 *
 * @param data the complete archive bytes for one volume, or an ordered list
 * of every volume's bytes
 * @param archivePath path label to print on the leading `Archive:` line
 * @param options optional settings such as a password for encrypted CMT
 * comment subblocks
 * @returns the dump text, newline-terminated
 */
export const dumpArchive = async (
	data: Uint8Array | readonly Uint8Array[],
	archivePath: string,
	options?: DumpOptions,
): Promise<string> => {
	const rawVolumes: readonly Uint8Array[] = Array.isArray(data) ? data : [data as Uint8Array];
	const isSingleVolume = !Array.isArray(data);

	// strip the AES wrapper from every volume whose main header has
	// MAIN_PASSWORD set, before any walker touches them. unencrypted volumes
	// pass through unchanged.
	const volumes: Uint8Array[] = [];
	for (const buffer of rawVolumes) {
		volumes.push(await decryptRar3HeadersIfNeeded(options?.password, buffer));
	}

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
	let archiveComment: string | undefined;

	for (let vol = 0; vol < volumes.length; vol++) {
		const buffer = volumes[vol];
		for (const block of walkBlocks(buffer)) {
			// CMT newSub blocks carry comments. SOLID = entry-level comment for
			// the previous file; otherwise an archive-level comment. an unknown
			// or unsupported encoding (encrypted, RAR1.5/2.x LZSS) returns
			// `undefined` so we silently skip rather than disrupt the dump.
			if (block.kind === 'sub' && block.name === 'CMT') {
				const payload = buffer.subarray(block.dataOffset, block.dataOffset + block.dataSize);
				const text = await decodeCmtPayload(block, payload, options?.password);
				if (text !== undefined) {
					if ((block.fileFlags & FileFlag.solid) !== 0) {
						const target = entries[entries.length - 1];
						if (target !== undefined) {
							target.comment = text;
						}
					} else {
						archiveComment = text;
					}
				}
				continue;
			}

			// RAR1.5/2.x carry the archive-level comment as an oldComment
			// subblock embedded inside the MAIN header. only the first volume's
			// MAIN counts, mirroring rarfile.
			if (block.kind === 'main') {
				if (vol === 0 && block.oldComment !== undefined && archiveComment === undefined) {
					const text = decodeOldComment(block.oldComment);
					if (text !== undefined) {
						archiveComment = text;
					}
				}
				continue;
			}

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
				// RAR1.5/2.x file-level comments live inline in the FILE header.
				if (block.oldComment !== undefined) {
					const text = decodeOldComment(block.oldComment);
					if (text !== undefined) {
						entry.comment = text;
					}
				}
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

	if (archiveComment !== undefined) {
		lines.push(`  comment=${pythonRepr(archiveComment)}`);
	}

	for (const entry of entries) {
		dumpFile(entry, lines);
	}

	return lines.join('\n') + '\n';
};

// #endregion
