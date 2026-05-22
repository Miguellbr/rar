/**
 * a forward-reading cursor over a byte buffer, providing the primitive reads
 * the RAR5 format is built from: variable-length integers, fixed-width
 * little-endian integers, and length-prefixed byte runs.
 */
export class Cursor {
	readonly #data: Uint8Array;
	readonly #view: DataView;
	#pos: number;

	/**
	 * @param data buffer to read from
	 * @param pos initial read position
	 */
	constructor(data: Uint8Array, pos: number = 0) {
		this.#data = data;
		this.#view = new DataView(data.buffer, data.byteOffset, data.byteLength);
		this.#pos = pos;
	}

	/** current read position */
	get pos(): number {
		return this.#pos;
	}

	/** number of bytes between the current position and the end of the buffer */
	get remaining(): number {
		return this.#data.length - this.#pos;
	}

	/**
	 * moves the cursor to an absolute position.
	 * @param pos position to move to
	 */
	seek(pos: number): void {
		this.#pos = pos;
	}

	/**
	 * advances the cursor without reading.
	 * @param count number of bytes to skip
	 */
	skip(count: number): void {
		this.#pos += count;
	}

	/**
	 * reads a RAR5 variable-length integer: a little-endian base-128 value where
	 * the high bit of each byte marks continuation.
	 * @returns the decoded value
	 * @throws if the encoding does not terminate within 10 bytes or runs past
	 * the end of the buffer
	 */
	vint(): number {
		const data = this.#data;
		const len = data.length;

		let value = 0;
		let scale = 1;

		for (let count = 0; count < 10; count++) {
			if (this.#pos >= len) {
				throw new Error(`vint runs past end of buffer`);
			}

			const byte = data[this.#pos++];

			value += (byte & 0x7f) * scale;

			if ((byte & 0x80) === 0) {
				return value;
			}

			scale *= 128;
		}

		throw new Error(`vint exceeds 10 bytes`);
	}

	/**
	 * reads a single byte.
	 * @returns the byte value
	 */
	byte(): number {
		return this.#data[this.#pos++];
	}

	/**
	 * reads an unsigned little-endian 32-bit integer.
	 * @returns the integer value
	 */
	u32(): number {
		const value = this.#view.getUint32(this.#pos, true);
		this.#pos += 4;

		return value;
	}

	/**
	 * reads a fixed-length run of bytes.
	 * @param count number of bytes to read
	 * @returns a subarray view over the buffer (not a copy)
	 */
	bytes(count: number): Uint8Array {
		const start = this.#data.byteOffset + this.#pos;
		this.#pos += count;

		return new Uint8Array(this.#data.buffer, start, count);
	}

	/**
	 * reads a byte run prefixed by its vint length.
	 * @returns a subarray view over the buffer (not a copy)
	 */
	vstr(): Uint8Array {
		return this.bytes(this.vint());
	}
}
