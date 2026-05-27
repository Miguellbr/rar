/**
 * @module
 *
 * streaming RAR decoders for RAR5 and the RAR1.5 - RAR4 family ("RAR3").
 *
 * archive contents are read through a {@link Reader}; the `./deno` and `./node`
 * entry points provide readers backed by the respective runtime's file APIs.
 *
 * use {@link unrar} when you don't know the format up front — it peeks the
 * signature and dispatches to {@link unrar5} or {@link unrar3} accordingly.
 * use the format-specific entry points when the source is known to be one
 * format and you want the narrower entry type back.
 */

import { InvalidSignatureError, TruncatedArchiveError, UnrarError } from './errors.ts';
import { read } from './utils/buffer.ts';
import type { UnrarOptions } from './options.ts';
import type { Reader } from './reader/types.ts';
import { type Rar3Entry, unrar3 } from './rar3/extract.ts';
import { RAR3_SIGNATURE } from './rar3/constants.ts';
import { type Rar5Entry, unrar5 } from './rar5/extract.ts';
import { RAR5_SIGNATURE } from './rar5/constants.ts';

export type * from './reader/types.ts';
export * from './reader/common.ts';

export {
	ChecksumMismatchError,
	InvalidPasswordError,
	InvalidSignatureError,
	MalformedArchiveError,
	MissingPasswordError,
	MissingVolumeError,
	ReaderError,
	TruncatedArchiveError,
	UnrarError,
	UnsupportedFeatureError,
} from './errors.ts';
export type { UnrarOptions } from './options.ts';
export { Rar5Entry, unrar5 } from './rar5/extract.ts';
export type { VolumeBlock, WalkOptions } from './rar5/extract.ts';
export { walkArchive } from './rar5/extract.ts';
export { Rar3Entry, unrar3 } from './rar3/extract.ts';

/**
 * extracts entries from a RAR archive, automatically detecting whether it is
 * RAR5 or the RAR1.5 - RAR4 family ("RAR3") by reading the first reader's
 * signature. all volumes in a multi-volume set are assumed to be the same
 * format; only the first reader is probed.
 *
 * @param source one reader for a single-volume archive, or the ordered set of
 * volume readers for a multi-volume archive
 * @param options optional settings; `password` is forwarded to whichever
 * format handler runs
 * @returns async generator yielding the archive's file entries; the concrete
 * type is {@link Rar5Entry} for RAR5 archives and {@link Rar3Entry} for RAR3
 * @throws if the source does not begin with a known RAR signature
 */
export async function* unrar(
	source: Reader | readonly Reader[],
	options?: UnrarOptions,
): AsyncGenerator<Rar5Entry | Rar3Entry> {
	const readers: readonly Reader[] = Array.isArray(source) ? source : [source];
	if (readers.length === 0) {
		throw new UnrarError('no readers provided');
	}

	const first = readers[0];
	const probeLength = Math.min(RAR5_SIGNATURE.length, first.length);
	if (probeLength < RAR3_SIGNATURE.length) {
		throw new TruncatedArchiveError('source is too short to be a RAR archive');
	}

	const probe = await read(await first.read(0, probeLength), probeLength);

	if (matches(probe, RAR5_SIGNATURE)) {
		yield* unrar5(source, options);
		return;
	}
	if (matches(probe, RAR3_SIGNATURE)) {
		yield* unrar3(source, { password: options?.password });
		return;
	}

	throw new InvalidSignatureError('source does not start with a RAR signature');
}

const matches = (probe: Uint8Array, signature: Uint8Array): boolean => {
	if (probe.length < signature.length) {
		return false;
	}
	for (let idx = 0; idx < signature.length; idx++) {
		if (probe[idx] !== signature[idx]) {
			return false;
		}
	}
	return true;
};
