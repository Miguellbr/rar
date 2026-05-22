/**
 * the 8-byte signature that marks the start of a RAR 5.0 archive.
 */
export const RAR5_SIGNATURE: Uint8Array = new Uint8Array([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00]);

// #region block header

/** block type codes carried by the common header. */
export const BlockType = {
	encryption: 4,
	endArc: 5,
	file: 2,
	main: 1,
	service: 3,
} as const;

/** common header flag bits, shared by every block type. */
export const BlockFlag = {
	/** an extra area is present after the type-specific fields */
	extraData: 0x01,
	/** a data area follows the header */
	dataArea: 0x02,
	/** unknown-type blocks may be skipped using the header size alone */
	skipIfUnknown: 0x04,
	/** the data area continues from the previous volume */
	splitBefore: 0x08,
	/** the data area continues into the next volume */
	splitAfter: 0x10,
	/** the block depends on the preceding block */
	dependsPrev: 0x20,
	/** keep the block with its host file when the host is modified */
	keepWithParent: 0x40,
} as const;

// #endregion

// #region main header

/** archive flags carried by the main header. */
export const MainFlag = {
	/** archive is one volume of a multi-volume set */
	volume: 0x01,
	/** a volume number field is present (set on every volume except the first) */
	hasVolumeNumber: 0x02,
	/** archive is solid */
	solid: 0x04,
	/** archive carries a recovery record */
	recovery: 0x08,
	/** archive is locked */
	locked: 0x10,
} as const;

// #endregion

// #region file / service header

/** file flags carried by file and service headers. */
export const FileFlag = {
	/** entry is a directory */
	directory: 0x01,
	/** an inline unix mtime field is present */
	hasMtime: 0x02,
	/** an inline data CRC32 field is present */
	hasCrc32: 0x04,
	/** the unpacked size is unknown */
	unknownUnpackedSize: 0x08,
} as const;

/** host OS codes carried by file and service headers. */
export const HostOs = {
	unix: 1,
	windows: 0,
} as const;

/** solid bit within the compression information field. */
export const COMPRESSION_SOLID = 0x40;

/** extra record type codes found in file and service headers. */
export const FileExtraType = {
	encryption: 1,
	hash: 2,
	owner: 6,
	redirection: 5,
	serviceData: 7,
	time: 3,
	version: 4,
} as const;

/** flag bits within a file time extra record. */
export const TimeFlag = {
	/** timestamps are unix time_t values rather than Windows FILETIME */
	unixTime: 0x01,
	/** an mtime value is present */
	hasMtime: 0x02,
	/** a ctime value is present */
	hasCtime: 0x04,
	/** an atime value is present */
	hasAtime: 0x08,
	/** unix timestamps carry an extra nanosecond field */
	unixNanoseconds: 0x10,
} as const;

/** hash type codes within a file hash extra record. */
export const HashType = {
	blake2sp: 0,
} as const;

/** redirection type codes within a file redirection extra record. */
export const RedirectionType = {
	fileCopy: 5,
	hardLink: 4,
	unixSymlink: 1,
	windowsJunction: 3,
	windowsSymlink: 2,
} as const;

/** flag bits within a file redirection extra record. */
export const RedirectionFlag = {
	/** the redirection target is a directory */
	directory: 0x01,
} as const;

/** flag bits within a unix owner extra record. */
export const OwnerFlag = {
	/** a user name is present */
	hasUserName: 0x01,
	/** a group name is present */
	hasGroupName: 0x02,
	/** a numeric user id is present */
	hasUserId: 0x04,
	/** a numeric group id is present */
	hasGroupId: 0x08,
} as const;

/** flag bits within a file encryption extra record. */
export const FileEncryptionFlag = {
	/** a password check value is present */
	hasCheckValue: 0x01,
	/** checksums are tweaked with the encryption key */
	tweakedChecksums: 0x02,
} as const;

// #endregion

// #region encryption header

/** cipher codes carried by the archive encryption header. */
export const EncryptionAlgorithm = {
	aes256: 0,
} as const;

/** flag bits carried by the archive encryption header. */
export const EncryptionFlag = {
	/** a password check value is present */
	hasCheckValue: 0x01,
} as const;

// #endregion

// #region end of archive header

/** flag bits carried by the end of archive header. */
export const EndArcFlag = {
	/** the archive continues in a further volume */
	notLastVolume: 0x01,
} as const;

// #endregion
