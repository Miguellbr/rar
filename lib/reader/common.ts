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
			return slice.stream();
		},
	};
}

export interface FetchReaderOptions {
	input: string | URL | Request;
	fetch?: typeof fetch;
}

/**
 * creates a reader from a fetch URL or Request
 * @param input URL string or Request object to fetch from
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
