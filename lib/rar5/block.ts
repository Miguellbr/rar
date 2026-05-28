import { crc32 } from '@mary/crc32';

import { ChecksumMismatchError, InvalidSignatureError } from '../errors.ts';
import { textDecoder } from '../utils/buffer.ts';

import {
	BlockFlag,
	BlockType,
	COMPRESSION_SOLID,
	FileEncryptionFlag,
	FileExtraType,
	FileFlag,
	HashType,
	OwnerFlag,
	RAR5_SIGNATURE,
	RedirectionType,
	TimeFlag,
} from './constants.ts';
import { Cursor } from './cursor.ts';

// #region types

/** a unix-epoch timestamp with nanosecond precision. */
export interface RarTime {
	/** whole seconds since the unix epoch; may be negative for pre-1970 times */
	seconds: number;
	/** sub-second remainder in nanoseconds, in the range [0, 1e9) */
	nanos: number;
}

/** fields shared by every parsed RAR5 block. */
export interface BlockCommon {
	/** CRC32 stored in the header */
	headerCrc: number;
	/** total on-disk size of the header, including the CRC and size fields */
	headerSize: number;
	/** absolute offset of the block within the archive */
	headerOffset: number;
	/** absolute offset of the block's data area, immediately after the header */
	dataOffset: number;
	/** common header flag bits */
	blockFlags: number;
	/** size of the extra area, or 0 when absent */
	blockExtraSize: number;
	/** size of the data area, or 0 when absent */
	dataSize: number;
}

/** the main archive header. */
export interface MainBlock extends BlockCommon {
	kind: 'main';
	/** archive flag bits */
	mainFlags: number;
	/** volume number, present on every volume of a multi-volume set except the first */
	volumeNumber?: number;
}

/** encryption parameters attached to an individual file via an extra record. */
export interface FileEncryption {
	/** cipher code */
	algorithm: number;
	/** encryption flag bits */
	flags: number;
	/** binary log of the PBKDF2 iteration count */
	kdfCount: number;
	/** 16-byte key derivation salt */
	salt: Uint8Array;
	/** 16-byte cipher initialization vector */
	iv: Uint8Array;
	/** optional 12-byte password check value */
	checkValue?: Uint8Array;
}

/** a redirection record: symlink, junction, hard link, or file copy. */
export interface FileRedirection {
	/** redirection type code */
	type: number;
	/** redirection flag bits */
	flags: number;
	/** redirection target path */
	target: string;
}

/** unix ownership information attached to a file. */
export interface FileOwner {
	/** raw, undecoded user name bytes */
	userName?: Uint8Array;
	/** raw, undecoded group name bytes */
	groupName?: Uint8Array;
	userId?: number;
	groupId?: number;
}

/** a file header or a service header; the two share an identical layout. */
export interface FileBlock extends BlockCommon {
	kind: 'file' | 'service';
	/** file flag bits */
	fileFlags: number;
	/** uncompressed size of the entry */
	unpackedSize: number;
	/** OS-specific attributes; the unix st_mode or Windows attribute bits */
	attributes: number;
	/** raw compression information field */
	compressionInfo: number;
	/** host OS code */
	hostOs: number;
	/** decoded entry name, with path separators normalized to forward slashes */
	name: string;
	/** raw, undecoded name bytes */
	rawName: Uint8Array;
	/** data CRC32, when a hash or inline checksum is present */
	crc?: number;
	/** modification time, from the inline field or a time extra record */
	mtime?: RarTime;
	/** creation time, from a time extra record */
	ctime?: RarTime;
	/** access time, from a time extra record */
	atime?: RarTime;
	/** file hash, when a hash extra record is present */
	hash?: { type: number; value: Uint8Array };
	/** encryption parameters, when an encryption extra record is present */
	encryption?: FileEncryption;
	/** redirection, when a redirection extra record is present */
	redirection?: FileRedirection;
	/** unix ownership, when an owner extra record is present */
	owner?: FileOwner;
	/** file version, when a version extra record is present */
	version?: { flags: number; version: number };
}

/** the archive encryption header, which precedes encrypted block headers. */
export interface EncryptionBlock extends BlockCommon {
	kind: 'encryption';
	/** cipher code */
	algorithm: number;
	/** encryption flag bits */
	flags: number;
	/** binary log of the PBKDF2 iteration count */
	kdfCount: number;
	/** 16-byte key derivation salt */
	salt: Uint8Array;
	/** optional 12-byte password check value */
	checkValue?: Uint8Array;
}

/** the end of archive header. */
export interface EndArcBlock extends BlockCommon {
	kind: 'endArc';
	/** end of archive flag bits */
	endArcFlags: number;
}

/** a block whose type code is not recognized. */
export interface UnknownBlock extends BlockCommon {
	kind: 'unknown';
	/** the unrecognized block type code */
	blockType: number;
}

/** any parsed RAR5 block. */
export type Rar5Block = EncryptionBlock | EndArcBlock | FileBlock | MainBlock | UnknownBlock;

/** the compression information field, decoded into its components. */
export interface CompressionInfo {
	/** algorithm version */
	algorithm: number;
	/** whether the entry is part of a solid run */
	solid: boolean;
	/** compression method, 0 for stored */
	method: number;
	/** dictionary size exponent */
	dictionarySize: number;
}

// #endregion

// #region predicates

/**
 * reports whether a file block describes a directory.
 * @param block the block to inspect
 * @returns true for a directory entry
 */
export const isDirectory = (block: FileBlock): boolean => {
	return block.redirection === undefined && (block.fileFlags & FileFlag.directory) !== 0;
};

/**
 * reports whether a file block describes a symlink, junction, or similar link.
 * @param block the block to inspect
 * @returns true for a link entry
 */
export const isSymlink = (block: FileBlock): boolean => {
	const redir = block.redirection;
	return redir !== undefined && (
		redir.type === RedirectionType.unixSymlink ||
		redir.type === RedirectionType.windowsJunction ||
		redir.type === RedirectionType.windowsSymlink
	);
};

/**
 * reports whether a file block describes a regular file, as opposed to a
 * directory or a link.
 * @param block the block to inspect
 * @returns true for a regular file entry
 */
export const isFile = (block: FileBlock): boolean => {
	return !isDirectory(block) && !isSymlink(block);
};

/**
 * decodes the raw compression information field into its components.
 * @param raw the raw field value
 * @returns the decoded components
 */
export const decodeCompressionInfo = (raw: number): CompressionInfo => {
	return {
		algorithm: raw & 0x3f,
		solid: (raw & COMPRESSION_SOLID) !== 0,
		method: (raw >> 7) & 0x07,
		dictionarySize: raw >> 10,
	};
};

// #endregion

// #region timestamps

// 100-nanosecond ticks between the Windows epoch (1601) and the unix epoch.
const WINDOWS_EPOCH_TICKS = 116444736000000000n;
const TICKS_PER_SECOND = 10000000n;

const readWindowsTime = (cursor: Cursor): RarTime => {
	const low = BigInt(cursor.u32());
	const high = BigInt(cursor.u32());

	const ticks = ((high << 32n) | low) - WINDOWS_EPOCH_TICKS;

	let seconds = ticks / TICKS_PER_SECOND;
	let remainder = ticks % TICKS_PER_SECOND;

	// keep the remainder non-negative for pre-1970 timestamps
	if (remainder < 0n) {
		remainder += TICKS_PER_SECOND;
		seconds -= 1n;
	}

	return { seconds: Number(seconds), nanos: Number(remainder) * 100 };
};

const readUnixTime = (cursor: Cursor): RarTime => {
	return { seconds: cursor.u32(), nanos: 0 };
};

// #endregion

// #region extra records

const parseTimeRecord = (block: FileBlock, cursor: Cursor): void => {
	const flags = cursor.vint();
	const unix = (flags & TimeFlag.unixTime) !== 0;
	const read = unix ? readUnixTime : readWindowsTime;

	const mtime = flags & TimeFlag.hasMtime ? read(cursor) : undefined;
	const ctime = flags & TimeFlag.hasCtime ? read(cursor) : undefined;
	const atime = flags & TimeFlag.hasAtime ? read(cursor) : undefined;

	if (flags & TimeFlag.unixNanoseconds) {
		if (mtime !== undefined) {
			mtime.nanos = cursor.u32();
		}
		if (ctime !== undefined) {
			ctime.nanos = cursor.u32();
		}
		if (atime !== undefined) {
			atime.nanos = cursor.u32();
		}
	}

	if (mtime !== undefined) {
		block.mtime = mtime;
	}
	if (ctime !== undefined) {
		block.ctime = ctime;
	}
	if (atime !== undefined) {
		block.atime = atime;
	}
};

const parseEncryptionRecord = (block: FileBlock, cursor: Cursor): void => {
	const algorithm = cursor.vint();
	const flags = cursor.vint();
	const kdfCount = cursor.byte();
	const salt = cursor.bytes(16);
	const iv = cursor.bytes(16);
	const checkValue = flags & FileEncryptionFlag.hasCheckValue ? cursor.bytes(12) : undefined;

	block.encryption = { algorithm, checkValue, flags, iv, kdfCount, salt };
};

const parseHashRecord = (block: FileBlock, cursor: Cursor): void => {
	const type = cursor.vint();

	if (type === HashType.blake2sp) {
		const value = cursor.bytes(32);
		block.hash = { type, value };
	}
};

const parseRedirectionRecord = (block: FileBlock, cursor: Cursor): void => {
	const type = cursor.vint();
	const flags = cursor.vint();
	const target = textDecoder.decode(cursor.vstr());

	block.redirection = { flags, target, type };
};

const parseOwnerRecord = (block: FileBlock, cursor: Cursor): void => {
	const flags = cursor.vint();
	const owner: FileOwner = {};

	if (flags & OwnerFlag.hasUserName) {
		owner.userName = cursor.vstr();
	}
	if (flags & OwnerFlag.hasGroupName) {
		owner.groupName = cursor.vstr();
	}
	if (flags & OwnerFlag.hasUserId) {
		owner.userId = cursor.vint();
	}
	if (flags & OwnerFlag.hasGroupId) {
		owner.groupId = cursor.vint();
	}

	block.owner = owner;
};

const parseVersionRecord = (block: FileBlock, cursor: Cursor): void => {
	const flags = cursor.vint();
	const version = cursor.vint();

	block.version = { flags, version };
};

const parseExtraRecord = (block: FileBlock, record: Uint8Array): void => {
	const cursor = new Cursor(record);
	const type = cursor.vint();

	switch (type) {
		case FileExtraType.encryption: {
			parseEncryptionRecord(block, cursor);
			break;
		}
		case FileExtraType.hash: {
			parseHashRecord(block, cursor);
			break;
		}
		case FileExtraType.owner: {
			parseOwnerRecord(block, cursor);
			break;
		}
		case FileExtraType.redirection: {
			parseRedirectionRecord(block, cursor);
			break;
		}
		case FileExtraType.time: {
			parseTimeRecord(block, cursor);
			break;
		}
		case FileExtraType.version: {
			parseVersionRecord(block, cursor);
			break;
		}
	}
};

// #endregion

// #region block parsing

const parseFileBlock = (
	kind: 'file' | 'service',
	common: BlockCommon,
	cursor: Cursor,
): FileBlock => {
	const fileFlags = cursor.vint();
	const unpackedSize = cursor.vint();
	const attributes = cursor.vint();

	const block: FileBlock = {
		...common,
		attributes,
		compressionInfo: 0,
		fileFlags,
		hostOs: 0,
		kind,
		name: '',
		rawName: new Uint8Array(0),
		unpackedSize,
	};

	if (fileFlags & FileFlag.hasMtime) {
		block.mtime = readUnixTime(cursor);
	}
	if (fileFlags & FileFlag.hasCrc32) {
		block.crc = cursor.u32();
	}

	block.compressionInfo = cursor.vint();
	block.hostOs = cursor.vint();
	block.rawName = cursor.vstr();

	// path separators are normalized and a trailing slash, if any, is dropped;
	// directory entries get a single slash reattached below.
	const decodedName = textDecoder.decode(block.rawName).replaceAll('\\', '/').replace(/\/+$/, '');

	// the extra area is the tail of the header; one byte of trailing slack is
	// tolerated to match how RAR writes padded headers.
	if (common.blockExtraSize > 0) {
		while (cursor.remaining > 1) {
			const size = cursor.vint();
			if (size > cursor.remaining) {
				break;
			}

			parseExtraRecord(block, cursor.bytes(size));
		}
	}

	block.name = isDirectory(block) ? decodedName + '/' : decodedName;

	return block;
};

const parseMainBlock = (common: BlockCommon, cursor: Cursor): MainBlock => {
	const mainFlags = cursor.vint();
	const volumeNumber = mainFlags & 0x02 ? cursor.vint() : undefined;

	return { ...common, kind: 'main', mainFlags, volumeNumber };
};

const parseEncryptionBlock = (common: BlockCommon, cursor: Cursor): EncryptionBlock => {
	const algorithm = cursor.vint();
	const flags = cursor.vint();
	const kdfCount = cursor.byte();
	const salt = cursor.bytes(16);
	const checkValue = flags & 0x01 ? cursor.bytes(12) : undefined;

	return { ...common, algorithm, checkValue, flags, kdfCount, kind: 'encryption', salt };
};

const parseEndArcBlock = (common: BlockCommon, cursor: Cursor): EndArcBlock => {
	const endArcFlags = cursor.vint();

	return { ...common, endArcFlags, kind: 'endArc' };
};

/**
 * parses a single block from the bytes of its header.
 *
 * the header CRC is verified before the type-specific fields are read.
 *
 * @param header the complete header bytes, starting at the CRC field
 * @param headerOffset absolute offset of the header within the archive
 * @returns the parsed block
 * @throws if the header CRC does not match its contents
 */
export const parseBlock = (header: Uint8Array, headerOffset: number): Rar5Block => {
	// resolve the header size first, then bound all further reads to it so a
	// caller-supplied slice that overshoots the header cannot leak into parsing.
	const sizeCursor = new Cursor(header);
	const headerCrc = sizeCursor.u32();
	const headerSize = sizeCursor.vint() + sizeCursor.pos;

	const bounded = header.subarray(0, headerSize);

	const computedCrc = crc32(bounded.subarray(4));
	if (computedCrc !== headerCrc) {
		throw new ChecksumMismatchError(
			`header CRC mismatch: expected ${headerCrc}, got ${computedCrc}`,
		);
	}

	const cursor = new Cursor(bounded, sizeCursor.pos);
	const blockType = cursor.vint();
	const blockFlags = cursor.vint();

	const blockExtraSize = blockFlags & BlockFlag.extraData ? cursor.vint() : 0;
	const dataSize = blockFlags & BlockFlag.dataArea ? cursor.vint() : 0;

	const common: BlockCommon = {
		blockExtraSize,
		blockFlags,
		dataSize,
		dataOffset: headerOffset + headerSize,
		headerCrc,
		headerOffset,
		headerSize,
	};

	switch (blockType) {
		case BlockType.main: {
			return parseMainBlock(common, cursor);
		}
		case BlockType.file: {
			return parseFileBlock('file', common, cursor);
		}
		case BlockType.service: {
			return parseFileBlock('service', common, cursor);
		}
		case BlockType.encryption: {
			return parseEncryptionBlock(common, cursor);
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

const matchesSignature = (data: Uint8Array, offset: number): boolean => {
	for (let idx = 0; idx < RAR5_SIGNATURE.length; idx++) {
		if (data[offset + idx] !== RAR5_SIGNATURE[idx]) {
			return false;
		}
	}

	return true;
};

/**
 * locates the RAR5 signature within a buffer.
 *
 * the signature is searched for rather than assumed at offset 0, so archives
 * carrying a self-extracting stub are handled.
 *
 * @param data archive bytes
 * @returns the offset just past the signature, or -1 if no signature is found
 */
export const findSignature = (data: Uint8Array): number => {
	for (let offset = 0, end = data.length - RAR5_SIGNATURE.length; offset <= end; offset++) {
		if (matchesSignature(data, offset)) {
			return offset + RAR5_SIGNATURE.length;
		}
	}

	return -1;
};

/**
 * walks every block of a RAR5 archive held entirely in memory.
 *
 * iteration stops after the end of archive header, or when the buffer is
 * exhausted.
 *
 * @param data the complete archive bytes
 * @returns an iterator over the parsed blocks
 * @throws if no signature is found or a block header fails CRC validation
 */
export function* walkBlocks(data: Uint8Array): Generator<Rar5Block> {
	const start = findSignature(data);
	if (start === -1) {
		throw new InvalidSignatureError(`not a RAR5 archive: signature not found`);
	}

	let offset = start;

	while (offset + 4 < data.length) {
		// the header size is only known after the CRC and size vint are read, so
		// peek far enough to decode it before slicing the full header.
		const probe = new Cursor(data, offset);
		probe.skip(4);
		const headerSize = probe.vint() + (probe.pos - offset);

		const block = parseBlock(data.subarray(offset, offset + headerSize), offset);
		yield block;

		if (block.kind === 'endArc') {
			break;
		}

		offset = block.dataOffset + block.dataSize;
	}
}

// #endregion
