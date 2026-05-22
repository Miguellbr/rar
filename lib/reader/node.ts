/**
 * @module
 * This module contains Node.js-specific functions
 */

import type { FileHandle } from 'node:fs/promises';

import type { Reader } from './types.ts';

/**
 * creates a reader from a Node.js' FileHandle
 * @param handle the file handle to read from
 * @returns a reader for the file
 */
export const fromFileHandle = async (handle: FileHandle): Promise<Reader> => {
	const totalLength = (await handle.stat()).size;

	return {
		length: totalLength,
		// deno-lint-ignore require-await
		async read(offset: number, length?: number): Promise<ReadableStream<Uint8Array<ArrayBuffer>>> {
			let remaining = length !== undefined ? length : totalLength - offset;

			return new ReadableStream<Uint8Array<ArrayBuffer>>({
				type: 'bytes',
				async pull(controller) {
					const size = Math.min(controller.desiredSize!, remaining);

					const buffer = new Uint8Array(size);
					const { bytesRead } = await handle.read(buffer, 0, size, offset);

					if (bytesRead === 0) {
						// end of file
						controller.close();
						return;
					}

					if (bytesRead < size) {
						// partial read, slice the buffer
						controller.enqueue(buffer.subarray(0, bytesRead));
					} else {
						controller.enqueue(buffer);
					}

					remaining -= bytesRead;
					offset += bytesRead;

					if (remaining <= 0) {
						controller.close();
						return;
					}
				},
			}, { highWaterMark: 64 * 1024 });
		},
	};
};
