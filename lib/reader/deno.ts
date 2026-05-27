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
	// shared across every stream this reader hands out: tracks the OS file
	// pointer so consecutive pulls that already sit at the right offset can
	// skip the seek syscall, and a new stream that picks up where a previous
	// one left off can skip its first seek too. `undefined` forces an initial
	// seek before the first read.
	let knownPosition: number | undefined;

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
					using _lock = await mutex.acquire();

					if (knownPosition !== offset) {
						await file.seek(offset, Deno.SeekMode.Start);
						knownPosition = offset;
					}

					// when a BYOB reader is waiting, write straight into the
					// consumer's buffer and skip the per-pull Uint8Array
					// allocation — saves the producer→queue→consumer memcpy
					// that the default-reader path pays on every chunk.
					const byob = controller.byobRequest;
					if (byob !== null) {
						const view = byob.view as Uint8Array<ArrayBuffer>;
						const cap = view.byteLength <= remaining ? view.byteLength : remaining;
						const target = cap === view.byteLength ? view : new Uint8Array(view.buffer, view.byteOffset, cap);
						const read = await file.read(target);

						if (read === null) {
							byob.respond(0);
							controller.close();
							return;
						}

						knownPosition += read;
						remaining -= read;
						offset += read;
						byob.respond(read);

						if (remaining <= 0) {
							controller.close();
						}
						return;
					}

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

					knownPosition += read;
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
