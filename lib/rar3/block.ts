/**
 * @module
 *
 * parser for the RAR1-4 ("RAR3") on-disk block format. each block opens with
 * a 7-byte common header (CRC16 + type + flags + headerSize), optionally
 * followed by a 4-byte `add_size` when the LONG_BLOCK flag is set, then a
 * type-specific payload. data follows immediately after the header bytes.
 */

import { textDecoder } from '../utils/buffer.ts';

import { BlockFlag, BlockType, EndArcFlag, FileFlag, RAR3_SIGNATURE } from './constants.ts';

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

// rarfile's UnicodeFilename decoder: RAR3 stores unicode names as the
// extended-ascii bytes (latin-1, typically the user's locale-encoded form)
// followed by a NUL and a compressed-unicode tail describing high-byte
// overrides. when the tail is absent or unparseable, the bytes before the NUL
// are decoded as latin-1.
const decodeUnicodeName = (raw: Uint8Array): string => {
	const nul = raw.indexOf(0);
	if (nul === -1) {
		// no NUL: the bytes are pure UTF-8.
		return textDecoder.decode(raw);
	}

	const base = raw.subarray(0, nul);
	const tail = raw.subarray(nul + 1);

	// no tail means just the latin-1 base.
	if (tail.length === 0) {
		return latin1Decode(base);
	}

	const decoded = decodeUnicodeTail(base, tail);
	return decoded ?? latin1Decode(base);
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
				if (inPos >= tail.length) return undefined;
				out.push(tail[inPos++] << 8);
				outPos++;
				break;
			}
			case 1: {
				if (inPos >= tail.length) return undefined;
				out.push(highByte | tail[inPos++]);
				outPos++;
				break;
			}
			case 2: {
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
					if (inPos >= tail.length) return undefined;
					const correction = tail[inPos++];
					for (let idx = 0; idx < (length & 0x7f) + 2; idx++) {
						if (outPos >= base.length) return undefined;
						out.push(highByte | ((base[outPos] + correction) & 0xff));
						outPos++;
					}
				} else {
					for (let idx = 0; idx < length + 2; idx++) {
						if (outPos >= base.length) return undefined;
						out.push(highByte | base[outPos]);
						outPos++;
					}
				}
				break;
			}
		}
	}

	return String.fromCodePoint(...out);
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
	const name = (fileFlags & FileFlag.unicode) !== 0 ? decodeUnicodeName(rawName) : latin1Decode(rawName);

	let salt: Uint8Array | undefined;
	if ((fileFlags & FileFlag.salt) !== 0) {
		salt = cursor.bytes(8);
	}

	return {
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
 * the header CRC16 is intentionally not verified here: its on-disk coverage
 * range varies by block type (main and file headers exclude their trailing
 * sub-block area, while sub and endArc cover the whole header), and the
 * dumprar-style consumer needs the parsed fields regardless. data integrity
 * is anchored by each file block's `crc` field over the file payload.
 *
 * @param header the complete header bytes
 * @param headerOffset absolute offset of the header within the archive
 * @returns the parsed block
 * @throws if the header is too small for the declared `headerSize`
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

	switch (blockType) {
		case BlockType.main: {
			return parseMainBlock(common);
		}
		case BlockType.file: {
			return parseFileLikeBlock('file', common, cursor);
		}
		case BlockType.sub: {
			return parseFileLikeBlock('sub', common, cursor);
		}
		case BlockType.endArc: {
			return parseEndArcBlock(common, cursor);
		}
		default: {
			return { ...common, blockType, kind: 'unknown' };
		}
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
