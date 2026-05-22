/**
 * @module
 * This module contains Deno-specific functions
 */

import Mutex from '@mary/mutex';

import type { Reader } from './types.ts';

/**
 * creates a reader from a Deno.FsFile
 * @param file the file to read from
 * @returns a reader for the file
 */
export async function fromFsFile(file: Deno.FsFile): Promise<Reader & Disposable> {
	const mutex = new Mutex();
	const totalLength = (await file.stat()).size;

	return {
		length: totalLength,
		// deno-lint-ignore require-await
		async read(offset: number, length?: number): Promise<ReadableStream<Uint8Array<ArrayBuffer>>> {
			let remaining = length !== undefined ? length : totalLength - offset;

			return new ReadableStream<Uint8Array<ArrayBuffer>>({
				type: 'bytes',
				async pull(controller) {
					using _lock = await mutex.acquire();

					await file.seek(offset, Deno.SeekMode.Start);

					const size = Math.min(controller.desiredSize!, remaining);

					const buffer = new Uint8Array(size);
					const read = await file.read(buffer);

					if (read === null) {
						// end of file
						controller.close();
						return;
					}

					if (read < size) {
						// partial read, slice the buffer
						controller.enqueue(buffer.subarray(0, read));
					} else {
						controller.enqueue(buffer);
					}

					remaining -= read;
					offset += read;

					if (remaining <= 0) {
						controller.close();
						return;
					}
				},
			}, { highWaterMark: 64 * 1024 });
		},
		[Symbol.dispose]() {
			file.close();
		},
	};
}
