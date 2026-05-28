/**
 * @module
 *
 * the error taxonomy thrown by the {@link unrar}, {@link unrar5}, and
 * {@link unrar3} entry points. every error is an instance of {@link UnrarError},
 * so a caller can branch with `instanceof` for the cases it knows how to
 * recover from (re-prompt on {@link InvalidPasswordError}, ask for more
 * volumes on {@link MissingVolumeError}) and fall through to a generic
 * `UnrarError` for the rest.
 */

/** base class for every error thrown by the rar library. */
export class UnrarError extends Error {
	override name: string = 'UnrarError';
}

/** stored data did not match a checksum or size recorded in the archive. */
export class ChecksumMismatchError extends UnrarError {
	override name: string = 'ChecksumMismatchError';
}

/**
 * a password was supplied but does not match the archive's stored check
 * value. the caller can re-prompt and retry with a different password.
 */
export class InvalidPasswordError extends UnrarError {
	override name: string = 'InvalidPasswordError';
}

/** the source bytes do not begin with a recognized RAR3 or RAR5 signature. */
export class InvalidSignatureError extends UnrarError {
	override name: string = 'InvalidSignatureError';
}

/** the archive's structure is corrupt or violates the format spec; no retry will help. */
export class MalformedArchiveError extends UnrarError {
	override name: string = 'MalformedArchiveError';
}

/**
 * the archive (or one of its entries) is encrypted but no password was
 * supplied. the caller can prompt the user and retry with a password.
 */
export class MissingPasswordError extends UnrarError {
	override name: string = 'MissingPasswordError';
}

/**
 * a split entry's continuation or terminating volume is missing from the
 * reader set. the caller can ask for the missing volumes and retry.
 */
export class MissingVolumeError extends UnrarError {
	override name: string = 'MissingVolumeError';
}

/**
 * the underlying {@link Reader} failed to deliver bytes. distinct from
 * {@link TruncatedArchiveError}, which fires when the reader succeeds but
 * the archive itself ends mid-structure.
 */
export class ReaderError extends UnrarError {
	override name: string = 'ReaderError';
}

/** the archive ends in the middle of a structure. */
export class TruncatedArchiveError extends UnrarError {
	override name: string = 'TruncatedArchiveError';
}

/** the archive uses a feature this library does not implement yet. */
export class UnsupportedFeatureError extends UnrarError {
	override name: string = 'UnsupportedFeatureError';
}
