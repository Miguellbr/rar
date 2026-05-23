/**
 * @module
 *
 * symbolic names for the RAR3 (and earlier) on-disk format. RAR3 uses small
 * fixed-layout headers with little-endian integers, where RAR5 switched to a
 * length-prefixed vint design; the two share no constants.
 */

/** the 7-byte signature that opens every RAR1.5 - RAR4.x archive. */
export const RAR3_SIGNATURE = new Uint8Array([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00]) as Readonly<
	Uint8Array
>;

/** the type byte of each header block. the characters spell `rstuvwxyz{`. */
export const BlockType = {
	/** archive mark — opens every volume */
	mark: 0x72,
	/** main archive header */
	main: 0x73,
	/** file or directory entry */
	file: 0x74,
	/** legacy archive-level comment */
	oldComment: 0x75,
	/** legacy extra info */
	oldExtra: 0x76,
	/** legacy sub-record (per file) */
	oldSub: 0x77,
	/** legacy recovery record */
	oldRecovery: 0x78,
	/** legacy authenticity record */
	oldAuth: 0x79,
	/** modern sub-record (CMT, RR, etc.) */
	sub: 0x7a,
	/** end of archive marker */
	endArc: 0x7b,
} as const;

/** flags carried in every block header. */
export const BlockFlag = {
	/** set on blocks that hardlink-treat themselves as unknown when extracting */
	skipIfUnknown: 0x4000,
	/** an `add_size` u32 follows the fixed header, naming the data area size */
	longBlock: 0x8000,
} as const;

/** flags specific to the main archive header. */
export const MainFlag = {
	/** archive is a volume of a multi-volume set */
	volume: 0x0001,
	/** an archive comment record follows */
	comment: 0x0002,
	/** archive is locked (no further modifications) */
	lock: 0x0004,
	/** archive uses solid compression */
	solid: 0x0008,
	/** uses new-style volume numbering (.partN.rar instead of .r00, .r01) */
	newNumbering: 0x0010,
	/** archive has an authenticity record */
	auth: 0x0020,
	/** archive carries a recovery record */
	recovery: 0x0040,
	/** archive (including its headers) is encrypted */
	password: 0x0080,
	/** this is the first volume of the set */
	firstVolume: 0x0100,
	/** the next byte after the fixed main header carries the encryption version */
	encryptVer: 0x0200,
} as const;

/** flags specific to a file or sub block. */
export const FileFlag = {
	/** file data continues from the previous volume */
	splitBefore: 0x0001,
	/** file data continues into the next volume */
	splitAfter: 0x0002,
	/** file data is password-encrypted */
	password: 0x0004,
	/** a file-level comment follows */
	comment: 0x0008,
	/** file is part of the solid run */
	solid: 0x0010,
	/** mask covering the dictionary size bits below */
	dictMask: 0x00e0,
	/** 64 KiB dictionary */
	dict64: 0x0000,
	/** 128 KiB dictionary */
	dict128: 0x0020,
	/** 256 KiB dictionary */
	dict256: 0x0040,
	/** 512 KiB dictionary */
	dict512: 0x0060,
	/** 1 MiB dictionary */
	dict1024: 0x0080,
	/** 2 MiB dictionary */
	dict2048: 0x00a0,
	/** 4 MiB dictionary */
	dict4096: 0x00c0,
	/** the entry is a directory (dictionary bits all set) */
	directory: 0x00e0,
	/** 64-bit size fields follow */
	large: 0x0100,
	/** the name is unicode-encoded (utf-8 or rarfile's compressed form) */
	unicode: 0x0200,
	/** a per-file salt is stored before the name */
	salt: 0x0400,
	/** the file is a version-tagged copy */
	version: 0x0800,
	/** an extended-time record follows the name */
	extTime: 0x1000,
	/** extra flags are stored */
	extFlags: 0x2000,
} as const;

/** flags specific to the end-of-archive marker. */
export const EndArcFlag = {
	/** archive continues in another volume */
	nextVolume: 0x0001,
	/** an overall data CRC32 follows */
	dataCrc: 0x0002,
	/** reserved space follows */
	revSpace: 0x0004,
	/** the current volume number follows */
	volNr: 0x0008,
} as const;

/** host OS codes carried by file headers. */
export const HostOs = {
	msdos: 0,
	os2: 1,
	windows: 2,
	unix: 3,
	macOs: 4,
	beOs: 5,
} as const;

/** compression method codes carried by file headers. */
export const CompressMethod = {
	/** stored without compression */
	stored: 0x30,
	/** "fastest" */
	fastest: 0x31,
	/** "fast" */
	fast: 0x32,
	/** "normal" */
	normal: 0x33,
	/** "good" */
	good: 0x34,
	/** "best" */
	best: 0x35,
} as const;
