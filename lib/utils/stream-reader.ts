import Queue from '@mary/ds-queue';

import { concat } from './buffer.ts';

export class StreamReader implements AsyncDisposable {
	#reader: ReadableStreamDefaultReader<Uint8Array>;

	#chunks = new Queue<Uint8Array>();
	#buffered = 0;
	#consumed = 0;

	constructor(stream: ReadableStream<Uint8Array>) {
		this.#reader = stream.getReader();
	}

	get buffered(): number {
		return this.#buffered;
	}

	get consumed(): number {
		return this.#consumed;
	}

	async require(size: number): Promise<void> {
		const reader = this.#reader;
		const chunks = this.#chunks;

		while (this.#buffered < size) {
			const { done, value } = await reader.read();

			if (done) {
				throw new Error(`unexpected end of stream: needed ${size} bytes, have ${this.#buffered}`);
			}

			chunks.enqueue(value);

			this.#buffered += value.length;
		}
	}

	take(size: number): Uint8Array {
		if (size === 0) {
			return new Uint8Array(0);
		}

		if (this.#buffered < size) {
			throw new Error(`needed ${size} bytes, have ${this.#buffered}`);
		}

		const chunks = this.#chunks;
		const needed: Uint8Array[] = [];

		let taken = 0;

		while (taken < size) {
			const chunk = chunks.dequeue()!;
			const chunkLength = chunk.length;

			const took = Math.min(chunkLength, size - taken);

			if (took < chunkLength) {
				// Split chunk
				needed.push(chunk.subarray(0, took));

				chunks.enqueueFront(chunk.subarray(took));

				taken += took;
				break;
			} else {
				needed.push(chunk);

				taken += chunkLength;
			}
		}

		this.#buffered -= size;
		this.#consumed += size;

		if (needed.length === 1) {
			return needed[0];
		} else {
			return concat(needed, size);
		}
	}

	async [Symbol.asyncDispose](): Promise<void> {
		await this.#reader.cancel();
	}
}
