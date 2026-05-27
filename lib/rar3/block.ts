/**
 * @module
 *
 * parser for the RAR1-4 ("RAR3") on-disk block format. each block opens with
 * a 7-byte common header (CRC16 + type + flags + headerSize), optionally
 * followed by a 4-byte `add_size` when the LONG_BLOCK flag is set, then a
 * type-specific payload. data follows immediately after the header bytes.
 */

import { crc32 } from '../utils/crc32.ts';
import { BlockFlag, BlockType, EndArcFlag, FileFlag, MainFlag, RAR3_SIGNATURE } from './constants.ts';

// #region cursor

// a small little-endian reader over a header buffer. RAR3 headers are short
// and rarely span more than a few dozen bytes, so a hand-rolled cursor reads
// cleanly without pulling in DataView.
class Cursor {
	readonly data: Uint8Array;
	pos: number;

	constructor(data: Uint8Array, pos: number = 0) {
		this.data = data;
		this.pos = pos;
	}

	get remaining(): number {
		return this.data.length - this.pos;
	}

	u8(): number {
		return this.data[this.pos++];
	}

	u16(): number {
		const value = this.data[this.pos] | (this.data[this.pos + 1] << 8);
		this.pos += 2;
		return value;
	}

	u32(): number {
		const value = (this.data[this.pos] |
			(this.data[this.pos + 1] << 8) |
			(this.data[this.pos + 2] << 16) |
			(this.data[this.pos + 3] << 24)) >>> 0;
		this.pos += 4;
		return value;
	}

	bytes(length: number): Uint8Array {
		const value = this.data.subarray(this.pos, this.pos + length);
		this.pos += length;
		return value;
	}

	skip(length: number): void {
		this.pos += length;
	}
}

// #endregion

// #region types

/** a DOS-format timestamp split into its 6 calendar fields. */
export interface DosTime {
	year: number;
	month: number;
	day: number;
	hour: number;
	minute: number;
	second: number;
}

/** fields common to every parsed RAR3 block. */
export interface BlockCommon {
	/** CRC16 stored in the header */
	headerCrc: number;
	/** total on-disk size of the header, including the CRC, type, flags, and size fields */
	headerSize: number;
	/** absolute offset of the block within the archive */
	headerOffset: number;
	/** absolute offset of the block's data area, immediately after the header */
	dataOffset: number;
	/** common header flag bits */
	blockFlags: number;
	/** size of the data area, or 0 when no data follows */
	dataSize: number;
}

/** the archive mark block — the 7-byte signature at the start of each volume. */
export interface MarkBlock extends BlockCommon {
	kind: 'mark';
}

/** the main archive header. */
export interface MainBlock extends BlockCommon {
	kind: 'main';
	/** archive flag bits, re-exposed as `mainFlags` for symmetry with `block.blockFlags` */
	mainFlags: number;
}

/** a single high-precision timestamp parsed from the extended-time record. */
export interface ExtTime {
	/** the base DOS time, possibly bumped by 1 second per the spec's +sec flag */
	time: DosTime;
	/** sub-second remainder in nanoseconds, in the range [0, 1e9) */
	nanos: number;
}

/** a file or sub-record entry. */
export interface FileBlock extends BlockCommon {
	kind: 'file' | 'sub';
	/** file flag bits */
	fileFlags: number;
	/** uncompressed size in bytes */
	unpackedSize: number;
	/** host OS code */
	hostOs: number;
	/** data CRC32 */
	crc: number;
	/** modification time, decoded from the DOS-format field */
	mtime: DosTime;
	/** modification time with sub-second precision, when the EXTTIME flag is set */
	extMtime?: ExtTime;
	/** creation time, when an extended-time record contributes one */
	ctime?: ExtTime;
	/** access time, when an extended-time record contributes one */
	atime?: ExtTime;
	/** archival time, when an extended-time record contributes one */
	arctime?: ExtTime;
	/** required minimum unpack version (20-29 for RAR2.0 through RAR4) */
	extractVersion: number;
	/** compression method code (0x30 stored, 0x33 normal, 0x35 best, etc.) */
	method: number;
	/** decoded entry name; non-unicode names are decoded as latin-1 */
	name: string;
	/** raw, undecoded name bytes */
	rawName: Uint8Array;
	/** OS-specific attributes */
	attributes: number;
	/** 8-byte per-file salt, when the SALT flag is set */
	salt?: Uint8Array;
}

/** the end-of-archive marker. */
export interface EndArcBlock extends BlockCommon {
	kind: 'endArc';
	endArcFlags: number;
	/** archive-wide data CRC, when {@link EndArcFlag.dataCrc} is set */
	dataCrc?: number;
	/** the volume number this marker closes, when {@link EndArcFlag.volNr} is set */
	volumeNumber?: number;
}

/** a block whose type byte is not yet handled by the parser. */
export interface UnknownBlock extends BlockCommon {
	kind: 'unknown';
	blockType: number;
}

/** any parsed RAR3 block. */
export type Rar3Block = EndArcBlock | FileBlock | MainBlock | MarkBlock | UnknownBlock;

// #endregion

// #region helpers

const decodeDosTime = (raw: number): DosTime => {
	return {
		day: (raw >>> 16) & 0x1f,
		hour: (raw >>> 11) & 0x1f,
		minute: (raw >>> 5) & 0x3f,
		month: (raw >>> 21) & 0x0f,
		second: (raw & 0x1f) * 2,
		year: ((raw >>> 25) & 0x7f) + 1980,
	};
};

// rarfile's UnicodeFilename decoder: RAR3 stores unicode names either as
// straight UTF-8 (UNICODE flag, no NUL) or as a NUL-separated base + a
// compressed-unicode tail that describes high-byte overrides for each
// character in the base. when the tail is unparseable we fall back to UTF-8
// of the base — matching rarfile's `_decode` fallback chain — and finally to
// latin-1 as a last resort so a totally malformed name still round-trips.
const decodeUnicodeName = (raw: Uint8Array): string => {
	const nul = raw.indexOf(0);
	if (nul === -1) {
		return safeUtf8Decode(raw);
	}

	const base = raw.subarray(0, nul);
	const tail = raw.subarray(nul + 1);
	const decoded = tail.length > 0 ? decodeUnicodeTail(base, tail) : undefined;
	return decoded ?? safeUtf8Decode(base);
};

// decodes `bytes` as UTF-8, falling back to latin-1 if the bytes contain a
// sequence the decoder rejects.
const safeUtf8Decode = (bytes: Uint8Array): string => {
	try {
		return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
	} catch {
		return latin1Decode(bytes);
	}
};

// decodes the compressed-unicode tail produced by RAR2.x/3.x; based on
// rarfile's UnicodeFilename. returns undefined if the tail is malformed.
const decodeUnicodeTail = (base: Uint8Array, tail: Uint8Array): string | undefined => {
	if (tail.length < 1) {
		return undefined;
	}

	const highByte = tail[0] << 8;
	let inPos = 1;
	let outPos = 0;
	let flagBits = 0;
	let flagByte = 0;

	// each emitted value is a UTF-16 code unit; the input encodes them as
	// (low, high) byte pairs, and the result is a UTF-16 little-endian string.
	const out: number[] = [];

	while (inPos < tail.length) {
		if (flagBits === 0) {
			flagByte = tail[inPos++];
			flagBits = 8;
		}
		flagBits -= 2;
		const cmd = (flagByte >>> flagBits) & 3;

		switch (cmd) {
			case 0: {
				// low byte from the tail, high byte is zero
				if (inPos >= tail.length) return undefined;
				out.push(tail[inPos++]);
				outPos++;
				break;
			}
			case 1: {
				// low byte from the tail, high byte is the shared `hi`
				if (inPos >= tail.length) return undefined;
				out.push(highByte | tail[inPos++]);
				outPos++;
				break;
			}
			case 2: {
				// full 16-bit value: low byte then high byte
				if (inPos + 1 >= tail.length) return undefined;
				out.push(tail[inPos] | (tail[inPos + 1] << 8));
				inPos += 2;
				outPos++;
				break;
			}
			case 3: {
				if (inPos >= tail.length) return undefined;
				const length = tail[inPos++];
				if (length & 0x80) {
					// run of `(length & 0x7f) + 2` code units copied from the base
					// name with a single correction byte added and `hi` overlaid.
					if (inPos >= tail.length) return undefined;
					const correction = tail[inPos++];
					for (let idx = 0; idx < (length & 0x7f) + 2; idx++) {
						if (outPos >= base.length) return undefined;
						out.push(highByte | ((base[outPos] + correction) & 0xff));
						outPos++;
					}
				} else {
					// run of `length + 2` code units copied from the base name
					// verbatim with high byte zero — used for ASCII spans.
					for (let idx = 0; idx < length + 2; idx++) {
						if (outPos >= base.length) return undefined;
						out.push(base[outPos]);
						outPos++;
					}
				}
				break;
			}
		}
	}

	// `out` is a sequence of UTF-16 code units; `fromCharCode` interprets each
	// argument as one such unit, so a surrogate pair encoded as two consecutive
	// code units becomes a single supplementary-plane character in the string.
	return String.fromCharCode(...out);
};

const latin1Decode = (bytes: Uint8Array): string => {
	let out = '';
	for (const byte of bytes) {
		out += String.fromCharCode(byte);
	}
	return out;
};

// #endregion

// #region block parsing

const COMMON_HEADER_SIZE = 7;

const parseFileLikeBlock = (
	kind: 'file' | 'sub',
	common: BlockCommon,
	cursor: Cursor,
): FileBlock => {
	const fileFlags = common.blockFlags;

	// the file-header's compress_size field overlays the common header's
	// add_size field — they are the same four on-disk bytes — so callers must
	// position `cursor` at the start of that shared field. the resulting value
	// also becomes the block's `dataSize`.
	let packedSize = cursor.u32();
	let unpackedSize = cursor.u32();
	const hostOs = cursor.u8();
	const crc = cursor.u32();
	const mtime = decodeDosTime(cursor.u32());
	const extractVersion = cursor.u8();
	const method = cursor.u8();
	const nameSize = cursor.u16();
	const attributes = cursor.u32();

	if ((fileFlags & FileFlag.large) !== 0) {
		// 64-bit sizes: the spec extends both fields with their high halves.
		// JavaScript numbers safely hold the lower 53 bits of the resulting
		// quantity, plenty for any real archive.
		const packedHigh = cursor.u32();
		const unpackedHigh = cursor.u32();
		packedSize += packedHigh * 0x100000000;
		unpackedSize += unpackedHigh * 0x100000000;
	}

	const rawName = cursor.bytes(nameSize);
	// names without the UNICODE flag are stored in either UTF-8 or the host
	// OS's 8-bit charset; rarfile tries UTF-8 first and falls back to the
	// default charset, and we do the same with latin-1 as the safety net.
	const name = (fileFlags & FileFlag.unicode) !== 0 ? decodeUnicodeName(rawName) : safeUtf8Decode(rawName);

	let salt: Uint8Array | undefined;
	if ((fileFlags & FileFlag.salt) !== 0) {
		salt = cursor.bytes(8);
	}

	const block: FileBlock = {
		...common,
		attributes,
		crc,
		dataSize: packedSize,
		extractVersion,
		fileFlags,
		hostOs,
		kind,
		method,
		mtime,
		name,
		rawName,
		salt,
		unpackedSize,
	};

	if ((fileFlags & FileFlag.extTime) !== 0 && cursor.remaining >= 2) {
		parseExtTime(block, cursor);
	}

	return block;
};

// parses the optional extended-time record that follows the name (and any
// per-file salt) when the EXTTIME flag is set. the record carries up to four
// timestamps — mtime, ctime, atime, arctime — each with sub-second precision
// and an optional whole-second correction.
const parseExtTime = (block: FileBlock, cursor: Cursor): void => {
	const flags = cursor.u16();

	const mtimeNibble = (flags >>> 12) & 0x0f;
	const ctimeNibble = (flags >>> 8) & 0x0f;
	const atimeNibble = (flags >>> 4) & 0x0f;
	const arctimeNibble = flags & 0x0f;

	const ext = parseXTime(mtimeNibble, cursor, block.mtime);
	if (ext !== undefined) {
		block.extMtime = ext;
	}
	const ctime = parseXTime(ctimeNibble, cursor);
	if (ctime !== undefined) {
		block.ctime = ctime;
	}
	const atime = parseXTime(atimeNibble, cursor);
	if (atime !== undefined) {
		block.atime = atime;
	}
	const arctime = parseXTime(arctimeNibble, cursor);
	if (arctime !== undefined) {
		block.arctime = arctime;
	}
};

// one extended timestamp nibble: bit 3 marks "present", bit 2 marks "+1
// second" (to recover the half-second DOS time loses), bits 1-0 are the
// count of fractional bytes (0-3), each contributing 8 bits of 100-ns ticks.
const parseXTime = (nibble: number, cursor: Cursor, base?: DosTime): ExtTime | undefined => {
	if ((nibble & 8) === 0) {
		return undefined;
	}

	let time = base;
	if (time === undefined) {
		if (cursor.remaining < 4) {
			return undefined;
		}
		time = decodeDosTime(cursor.u32());
	}

	const fracBytes = nibble & 3;
	if (cursor.remaining < fracBytes) {
		return undefined;
	}

	let rem = 0;
	for (let idx = 0; idx < fracBytes; idx++) {
		rem = (cursor.u8() << 16) | (rem >>> 8);
	}

	if ((nibble & 4) !== 0 && time.second < 59) {
		time = { ...time, second: time.second + 1 };
	}

	// each unit of `rem` is 100 ns, with the value packed so the high bytes
	// already represent the most significant fraction; multiply to nanoseconds.
	return { nanos: rem * 100, time };
};

const parseMainBlock = (common: BlockCommon): MainBlock => {
	return { ...common, kind: 'main', mainFlags: common.blockFlags };
};

const parseEndArcBlock = (common: BlockCommon, cursor: Cursor): EndArcBlock => {
	const endArcFlags = common.blockFlags;

	let dataCrc: number | undefined;
	if ((endArcFlags & EndArcFlag.dataCrc) !== 0 && cursor.remaining >= 4) {
		dataCrc = cursor.u32();
	}

	let volumeNumber: number | undefined;
	if ((endArcFlags & EndArcFlag.volNr) !== 0 && cursor.remaining >= 2) {
		volumeNumber = cursor.u16();
	}

	return { ...common, dataCrc, endArcFlags, kind: 'endArc', volumeNumber };
};

/**
 * parses one RAR3 block from a buffer big enough to hold its full header and
 * its `add_size` u32 (i.e. the bytes from `headerOffset` through the end of
 * the cleartext header).
 *
 * the 2-byte header CRC is verified after parsing. its coverage range varies
 * by block type: main and file headers exclude their trailing comment
 * sub-block area, sub and endArc cover the whole header. the legacy
 * oldSub (0x77) block additionally extends CRC coverage over its data area;
 * none of our fixtures carry one, so the verification is skipped there.
 *
 * @param header the complete header bytes
 * @param headerOffset absolute offset of the header within the archive
 * @returns the parsed block
 * @throws if the header is too small for the declared `headerSize`, or its
 * stored CRC does not match the bytes it covers
 */
export const parseBlock = (header: Uint8Array, headerOffset: number): Rar3Block => {
	if (header.length < COMMON_HEADER_SIZE) {
		throw new Error(`rar3 block header truncated: ${header.length} bytes`);
	}

	const cursor = new Cursor(header);
	const headerCrc = cursor.u16();
	const blockType = cursor.u8();
	const blockFlags = cursor.u16();
	const headerSize = cursor.u16();

	if (blockType === BlockType.mark) {
		// the 7-byte signature presents as a self-describing block; just stamp
		// it as the mark and let the walker advance past it.
		return {
			blockFlags,
			dataOffset: headerOffset + COMMON_HEADER_SIZE,
			dataSize: 0,
			headerCrc,
			headerOffset,
			headerSize: COMMON_HEADER_SIZE,
			kind: 'mark',
		};
	}

	if (header.length < headerSize) {
		throw new Error(
			`rar3 block header truncated: declared ${headerSize} bytes, have ${header.length}`,
		);
	}

	const longBlock = (blockFlags & BlockFlag.longBlock) !== 0;
	const isFileLike = blockType === BlockType.file || blockType === BlockType.sub;

	// for file/sub blocks the LONG_BLOCK add_size field shares its on-disk
	// bytes with the file-header's compress_size, so we don't advance past it
	// here — parseFileLikeBlock will read those four bytes itself. for every
	// other block kind that sets LONG_BLOCK, the add_size is a standalone
	// data-area length we consume up front.
	const dataSize = longBlock && !isFileLike ? cursor.u32() : 0;
	const dataOffset = headerOffset + headerSize;

	const common: BlockCommon = {
		blockFlags,
		dataOffset,
		dataSize,
		headerCrc,
		headerOffset,
		headerSize,
	};

	let block: Rar3Block;
	switch (blockType) {
		case BlockType.main: {
			block = parseMainBlock(common);
			break;
		}
		case BlockType.file: {
			block = parseFileLikeBlock('file', common, cursor);
			break;
		}
		case BlockType.sub: {
			block = parseFileLikeBlock('sub', common, cursor);
			break;
		}
		case BlockType.endArc: {
			block = parseEndArcBlock(common, cursor);
			break;
		}
		default: {
			block = { ...common, blockType, kind: 'unknown' };
		}
	}

	verifyHeaderCrc(header, blockType, blockFlags, longBlock, cursor.pos, headerSize, headerOffset);
	return block;
};

// computes how many bytes from the start of the header the CRC covers, then
// checks the stored CRC16 against `crc32(coverage) & 0xffff`. coverage rules
// follow rarfile's parser: MAIN goes through the fixed header (6 reserved
// bytes plus 1 for ENCRYPTVER) but excludes any trailing comment subblock;
// FILE/SUB stop at the end of the parsed file-header fields (which already
// excludes the optional comment subblock that follows when FileFlag.comment
// is set); other block kinds cover the entire declared header.
const verifyHeaderCrc = (
	header: Uint8Array,
	blockType: number,
	blockFlags: number,
	longBlock: boolean,
	cursorEnd: number,
	headerSize: number,
	headerOffset: number,
): void => {
	// the legacy oldSub block (RAR1.5) folds its data area into the CRC range
	// and we never see one in the corpus; skip the check rather than fail
	// loudly on a hypothetical archive that carries one.
	if (blockType === BlockType.oldSub) {
		return;
	}

	let crcEnd: number;
	if (blockType === BlockType.main) {
		crcEnd = COMMON_HEADER_SIZE + (longBlock ? 4 : 0) + 6;
		if ((blockFlags & MainFlag.encryptVer) !== 0) {
			crcEnd += 1;
		}
	} else if (blockType === BlockType.file) {
		// FILE crc_pos excludes the trailing comment subblock area, so it ends
		// where the parsed file-header fields stop (matching rarfile's
		// `_parse_file_header` return value).
		crcEnd = cursorEnd;
	} else {
		// SUB and the rest (endArc, unknown, legacy) cover the whole declared
		// header. SUB blocks carry per-record fields after the file-header
		// section (owner UID/GID, ACL bytes, etc.) that the generic file parse
		// doesn't enumerate; CRC always runs over the declared headerSize.
		crcEnd = headerSize;
	}

	const storedCrc = header[0] | (header[1] << 8);
	const actualCrc = crc32(header.subarray(2, crcEnd)) & 0xffff;
	if (actualCrc !== storedCrc) {
		throw new Error(
			`rar3 block at 0x${headerOffset.toString(16)} header CRC mismatch:` +
				` stored 0x${storedCrc.toString(16).padStart(4, '0')},` +
				` computed 0x${actualCrc.toString(16).padStart(4, '0')}` +
				` (type=0x${blockType.toString(16)}, range=2..${crcEnd})`,
		);
	}
};

// #endregion

// #region archive walking

/**
 * reports whether the given offset of `data` is the start of a RAR3 signature.
 * @param data archive bytes
 * @param offset position to inspect
 * @returns true when the next bytes match {@link RAR3_SIGNATURE}
 */
export const matchesSignature = (data: Uint8Array, offset: number): boolean => {
	for (let idx = 0; idx < RAR3_SIGNATURE.length; idx++) {
		if (data[offset + idx] !== RAR3_SIGNATURE[idx]) {
			return false;
		}
	}
	return true;
};

/**
 * locates the RAR3 signature within a buffer.
 *
 * the signature is searched for rather than assumed at offset 0, so archives
 * carrying a self-extracting stub are handled.
 *
 * @param data archive bytes
 * @returns the offset of the signature, or -1 if none is found
 */
export const findSignature = (data: Uint8Array): number => {
	for (let offset = 0, end = data.length - RAR3_SIGNATURE.length; offset <= end; offset++) {
		if (matchesSignature(data, offset)) {
			return offset;
		}
	}
	return -1;
};

/**
 * walks every block of a RAR3 archive held entirely in memory.
 *
 * the signature block is yielded first as a `kind: 'mark'` block, then each
 * following header until an end-of-archive marker or the buffer is exhausted.
 *
 * @param data the complete archive bytes
 * @returns an iterator over the parsed blocks
 * @throws if no signature is found or a block header fails CRC validation
 */
export function* walkBlocks(data: Uint8Array): Generator<Rar3Block> {
	const start = findSignature(data);
	if (start === -1) {
		throw new Error(`not a rar3 archive: signature not found`);
	}

	let offset = start;

	// peek `headerSize` enough bytes to slice the header; the LONG_BLOCK
	// add_size field, when present, sits inside the 11-byte window we cover by
	// reading the declared header size.
	while (offset + COMMON_HEADER_SIZE <= data.length) {
		// peek the declared header size, then slice that many bytes for the
		// parser; the file/sub-block overlay means headerSize is the full
		// on-disk header length for every kind we know about.
		const headerSize = data[offset + 5] | (data[offset + 6] << 8);
		if (headerSize < COMMON_HEADER_SIZE) {
			throw new Error(
				`rar3 block at 0x${offset.toString(16)} has invalid headerSize ${headerSize}`,
			);
		}
		if (offset + headerSize > data.length) {
			throw new Error(
				`rar3 archive truncated: block at 0x${offset.toString(16)} declares ` +
					`${headerSize} bytes, ${data.length - offset} available`,
			);
		}

		const block = parseBlock(data.subarray(offset, offset + headerSize), offset);
		yield block;

		if (block.kind === 'endArc') {
			break;
		}

		offset = block.dataOffset + block.dataSize;
	}
}

// #endregion

// re-export the most-used flag namespace so the parser is comfortable to
// import from a single module.
export { BlockFlag, BlockType, EndArcFlag, FileFlag, MainFlag } from './constants.ts';
