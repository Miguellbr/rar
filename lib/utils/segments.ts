import { ChecksumMismatchError } from '../errors.ts';
import type { Reader } from '../reader/types.ts';

import { read } from './buffer.ts';
import { crc32 } from './crc32.ts';

/**
 * @module
 *
 * shared helpers for the RAR5 and RAR3 extractors: a `DataSegment` description
 * of one volume-local slice of an entry's data area, a stream that pulls
 * multiple segments in order, and a lazy-open passthrough used by entry
 * `body` getters whose underlying data is materialized on demand.
 */

/** a slice of an entry's data area within a single volume. */
export interface DataSegment {
	reader: Reader;
	offset: number;
	size: number;
}

/**
 * reads exactly `length` bytes from `reader` at `offset`.
 *
 * @param reader the volume reader
 * @param offset starting byte position within the reader
 * @param length number of bytes to read
 * @returns the requested bytes as a fresh `Uint8Array`
 * @throws if the reader returns fewer than `length` bytes
 */
export const readBytes = async (
	reader: Reader,
	offset: number,
	length: number,
): Promise<Uint8Array<ArrayBuffer>> => {
	return await read(await reader.read(offset, length), length);
};

/**
 * adapts a lazily-opened stream into one that can be returned synchronously.
 * `open` runs on the first pull, not at construction, so a stream that is
 * never consumed never triggers the decode or I/O work behind it. the
 * cancellation flag handles the race where cancel arrives before the `open`
 * callback resolves: without it, the freshly-opened inner stream would be
 * assigned onto an already-cancelled outer stream and leak its reader.
 *
 * @param open invoked once on first pull to produce the inner stream
 * @returns a ReadableStream that delegates to `open()`'s result
 */
export const deferStream = (
	open: () => Promise<ReadableStream<Uint8Array>>,
): ReadableStream<Uint8Array> => {
	let inner: ReadableStreamDefaultReader<Uint8Array> | undefined;
	let opening: Promise<void> | undefined;
	let cancelled = false;
	let cancelReason: unknown;

	const ensureOpen = (): Promise<void> => {
		if (opening !== undefined) {
			return opening;
		}
		opening = (async () => {
			const stream = await open();
			if (cancelled) {
				await stream.cancel(cancelReason);
				return;
			}
			inner = stream.getReader();
		})();
		return opening;
	};

	return new ReadableStream({
		async pull(controller) {
			try {
				await ensureOpen();
			} catch (error) {
				controller.error(error);
				return;
			}
			if (inner === undefined) {
				controller.close();
				return;
			}
			const { done, value } = await inner.read();
			if (done) {
				controller.close();
			} else {
				controller.enqueue(value);
			}
		},
		async cancel(reason) {
			cancelled = true;
			cancelReason = reason;
			await inner?.cancel(reason);
		},
	});
};

/**
 * pulls the bytes of every segment through one ReadableStream, in order, so
 * the decoder (or AES-CBC decrypt stream) can read an entry's data area
 * without ever buffering the whole payload in memory.
 *
 * zero-length segments are skipped because some readers (e.g. fromFetch)
 * cannot represent a zero-byte read as a valid HTTP Range header.
 *
 * @param segments ordered slices of the entry's data area
 * @returns a stream emitting every segment's bytes back-to-back
 */
export const streamSegments = (
	segments: readonly DataSegment[],
): ReadableStream<Uint8Array<ArrayBuffer>> => {
	let index = 0;
	let current: ReadableStreamDefaultReader<Uint8Array<ArrayBuffer>> | undefined;
	let cancelled = false;
	let cancelReason: unknown;

	return new ReadableStream({
		async pull(controller) {
			for (;;) {
				if (cancelled) {
					controller.close();
					return;
				}
				if (current === undefined) {
					// zero-length segments cannot be opened through some readers
					// (e.g. fromFetch builds a malformed `bytes=N--1` Range
					// header when length is 0); skip them entirely.
					while (index < segments.length && segments[index].size === 0) {
						index++;
					}
					if (index === segments.length) {
						controller.close();
						return;
					}

					const segment = segments[index++];
					const stream = await segment.reader.read(segment.offset, segment.size);
					if (cancelled) {
						// cancel arrived while we were awaiting the segment; release
						// the freshly-opened stream rather than orphaning it.
						await stream.cancel(cancelReason);
						controller.close();
						return;
					}
					current = stream.getReader();
				}

				const { done, value } = await current.read();
				if (done) {
					current = undefined;
					continue;
				}

				controller.enqueue(value);
				return;
			}
		},
		async cancel(reason) {
			cancelled = true;
			cancelReason = reason;
			await current?.cancel(reason);
		},
	});
};

/**
 * an incremental integrity check fed one chunk at a time. {@link finalize}
 * runs the comparison after the last byte is seen and throws a
 * {@link ChecksumMismatchError} on mismatch. used by {@link verifyingPassthrough}
 * to validate the stored fast-path body stream of an entry, and by entry
 * decode paths to validate the chunked output before returning it.
 */
export interface IntegrityVerifier {
	update(chunk: Uint8Array<ArrayBuffer>): void;
	/**
	 * called once after the last chunk; compares the accumulated state and
	 * the received byte count against the entry's recorded values.
	 *
	 * @param receivedSize the total number of bytes fed via {@link update}
	 * @throws ChecksumMismatchError when size or hash disagree
	 */
	finalize(receivedSize: number): void;
}

/**
 * wraps `source` so every emitted chunk is fed to `verifier`, and the
 * verifier's `finalize` is called when the source closes. used by entry
 * `body` getters whose fast path streams archive bytes verbatim, so a
 * streamed consumer gets the same integrity guarantee as one going through
 * a buffered decode + finalize path.
 *
 * when `verifier` is `undefined` — e.g. an entry that records neither a
 * CRC32 nor a hash — the source is returned unchanged.
 *
 * @param source the byte stream to verify
 * @param verifier an incremental verifier, or `undefined` to skip
 * @returns a stream that pipes `source` and validates on close
 */
export const verifyingPassthrough = (
	source: ReadableStream<Uint8Array<ArrayBuffer>>,
	verifier: IntegrityVerifier | undefined,
): ReadableStream<Uint8Array<ArrayBuffer>> => {
	if (verifier === undefined) {
		return source;
	}

	let reader: ReadableStreamDefaultReader<Uint8Array<ArrayBuffer>> | undefined;
	let received = 0;
	let cancelled = false;

	return new ReadableStream({
		async pull(controller) {
			if (reader === undefined) {
				if (cancelled) {
					controller.close();
					return;
				}
				reader = source.getReader();
			}

			const { done, value } = await reader.read();
			if (done) {
				try {
					verifier.finalize(received);
				} catch (error) {
					controller.error(error);
					return;
				}
				controller.close();
				return;
			}

			verifier.update(value);
			received += value.length;
			controller.enqueue(value);
		},
		async cancel(reason) {
			cancelled = true;
			await reader?.cancel(reason);
		},
	});
};

/**
 * builds an {@link IntegrityVerifier} that accumulates a running CRC32 and
 * checks both the expected size and the expected CRC at finalization.
 *
 * @param entryName entry name surfaced in error messages
 * @param expectedSize the total byte count the stream should deliver
 * @param expectedCrc the stored CRC32 to compare against
 * @returns a verifier that throws on size or CRC mismatch
 */
export const crc32Verifier = (
	entryName: string,
	expectedSize: number,
	expectedCrc: number,
): IntegrityVerifier => {
	let computed = 0;
	return {
		update(chunk) {
			computed = crc32(chunk, computed);
		},
		finalize(received) {
			if (received !== expectedSize) {
				throw new ChecksumMismatchError(
					`stored data size mismatch: got ${received} bytes, expected ${expectedSize}` +
						` (entry ${entryName})`,
				);
			}
			if (computed !== expectedCrc) {
				throw new ChecksumMismatchError(
					`CRC32 mismatch: ` +
						`stored 0x${expectedCrc.toString(16).padStart(8, '0')}, ` +
						`computed 0x${computed.toString(16).padStart(8, '0')}` +
						` (entry ${entryName})`,
				);
			}
		},
	};
};
