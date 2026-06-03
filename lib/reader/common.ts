import { ReaderError } from '../errors.ts';
import type { Reader } from './types.ts';

/**
 * creates a reader from a Uint8Array
 * @param data the data to read from
 * @returns a reader for the data
 */
export function fromUint8Array(data: Uint8Array<ArrayBuffer>): Reader {
	const totalLength = data.length;

	return {
		length: totalLength,
		// deno-lint-ignore require-await
		async read(offset: number, length?: number): Promise<ReadableStream<Uint8Array<ArrayBuffer>>> {
			const endOffset = length !== undefined ? offset + length : totalLength;

			const slice = data.subarray(offset, endOffset);
			const sliceLength = slice.length;

			let position = 0;

			return new ReadableStream<Uint8Array<ArrayBuffer>>({
				pull(controller) {
					if (position >= sliceLength) {
						controller.close();
						return;
					}

					const size = Math.min(controller.desiredSize!, sliceLength - position);
					const chunk = slice.subarray(position, position + size);

					controller.enqueue(chunk);
					position += size;

					if (position >= sliceLength) {
						controller.close();
						return;
					}
				},
			}, new ByteLengthQueuingStrategy({ highWaterMark: 64 * 1024 }));
		},
	};
}

/**
 * creates a reader from a Blob object
 * @param blob Blob object to read from
 * @returns a reader for the Blob
 */
export function fromFile(blob: Blob): Reader {
	const totalLength = blob.size;

	return {
		length: totalLength,
		// deno-lint-ignore require-await
		async read(offset: number, length?: number): Promise<ReadableStream<Uint8Array<ArrayBuffer>>> {
			const endOffset = length !== undefined ? offset + length : totalLength;

			const slice = blob.slice(offset, endOffset);
			const expected = slice.size;

			// Bun's Blob-backed slice streams can fail to emit a final
			// `{ done: true }` (empty slices never close; others stall a
			// read-until-close consumer), so re-emit the bytes through a stream
			// we close ourselves once the slice length has been delivered,
			// without issuing the trailing read that would block.
			const source = slice.stream().getReader();
			let delivered = 0;

			return new ReadableStream<Uint8Array<ArrayBuffer>>({
				type: 'bytes',
				async pull(rawController) {
					const controller = rawController as ReadableByteStreamController;

					if (delivered >= expected) {
						controller.close();
						source.cancel().catch(() => {});
						return;
					}

					const { done, value } = await source.read();
					if (done) {
						controller.close();
						return;
					}

					if (value.byteLength > 0) {
						delivered += value.byteLength;
						controller.enqueue(value as Uint8Array<ArrayBuffer>);
					}
				},
				cancel(reason) {
					return source.cancel(reason);
				},
			}, { highWaterMark: 64 * 1024 });
		},
	};
}

/** options for {@link fromFetch}. */
export interface FetchReaderOptions {
	/** URL or Request to fetch from. */
	input: string | URL | Request;
	/** custom fetch implementation; defaults to the global `fetch`. */
	fetch?: typeof fetch;
}

/**
 * creates a reader backed by ranged HTTP fetches against a remote resource.
 * @param opts URL or Request to fetch from, plus an optional fetch override
 * @returns a reader for the remote resource
 */
export async function fromFetch(opts: FetchReaderOptions): Promise<Reader> {
	const thisFetch = opts.fetch ?? fetch;

	const totalLength = await (async () => {
		// make a HEAD request to get content length upfront
		const response = await thisFetch(opts.input, { method: 'HEAD' });
		if (!response.ok) {
			throw new ReaderError(`failed to fetch resource: HTTP ${response.status}`);
		}

		const raw = response.headers.get('content-length');
		if (raw === null) {
			throw new ReaderError(`content-length header not available`);
		}

		const value = parseInt(raw, 10);
		if (isNaN(value)) {
			throw new ReaderError(`invalid content-length header`);
		}

		return value;
	})();

	return {
		length: totalLength,
		async read(offset: number, length?: number): Promise<ReadableStream<Uint8Array<ArrayBuffer>>> {
			const endOffset = length !== undefined ? offset + length - 1 : totalLength - 1;

			const req = opts.input;
			const headers = new Headers(req instanceof Request ? req.headers : undefined);
			headers.set('range', `bytes=${offset}-${endOffset}`);

			const response = await thisFetch(req, { headers });

			if (!response.ok) {
				throw new ReaderError(
					`failed to fetch range: HTTP ${response.status} (bytes ${offset}-${endOffset})`,
				);
			}

			if (response.status !== 206) {
				throw new ReaderError(`server does not support range requests`);
			}

			if (response.body === null) {
				throw new ReaderError(`response body is null`);
			}

			return response.body;
		},
	};
}
