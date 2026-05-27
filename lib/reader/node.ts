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
				async pull(rawController) {
					// the underlying source is `type: 'bytes'`, so the runtime
					// controller is always a byte-stream controller; the
					// generic-typed parameter just doesn't narrow.
					const controller = rawController as ReadableByteStreamController;

					// when a BYOB reader is waiting, read straight into the
					// consumer's buffer and skip the per-pull Uint8Array
					// allocation + queue copy that the default-reader path
					// pays on every chunk.
					const byob = controller.byobRequest;
					if (byob !== null) {
						const view = byob.view as Uint8Array<ArrayBuffer>;
						const cap = view.byteLength <= remaining ? view.byteLength : remaining;
						const target = cap === view.byteLength ? view : new Uint8Array(view.buffer, view.byteOffset, cap);
						const { bytesRead } = await handle.read(target, 0, cap, offset);

						if (bytesRead === 0) {
							byob.respond(0);
							controller.close();
							return;
						}

						remaining -= bytesRead;
						offset += bytesRead;
						byob.respond(bytesRead);

						if (remaining <= 0) {
							controller.close();
						}
						return;
					}

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
