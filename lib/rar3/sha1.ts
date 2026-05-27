/**
 * @module
 *
 * an incremental SHA-1 with a non-destructive {@link Sha1.digest}: calling
 * `digest()` returns the hash of all bytes fed so far without disturbing the
 * running state, so further `update` calls behave as if `digest` had never
 * been called. RAR3's password KDF needs that capability to snapshot the
 * IV one byte at a time while the hash continues over the next inner-loop
 * iteration.
 *
 * web crypto's `crypto.subtle.digest` is one-shot and cannot be checkpointed
 * mid-hash, hence this small pure-TS implementation.
 */

// SHA-1 initial state.
const H0 = 0x67452301;
const H1 = 0xefcdab89;
const H2 = 0x98badcfe;
const H3 = 0x10325476;
const H4 = 0xc3d2e1f0;

// per-round constants K[0..3] for rounds 0..19, 20..39, 40..59, 60..79.
const K0 = 0x5a827999;
const K1 = 0x6ed9eba1;
const K2 = 0x8f1bbcdc;
const K3 = 0xca62c1d6;

/** incremental SHA-1 supporting non-destructive intermediate digests. */
export class Sha1 {
	#h0 = H0;
	#h1 = H1;
	#h2 = H2;
	#h3 = H3;
	#h4 = H4;

	// unprocessed tail: up to 63 bytes carried over between update calls.
	readonly #buffer = new Uint8Array(64);
	#bufferLen = 0;

	// total bytes ever fed to the hash; used to encode the length tail.
	#totalLen = 0;

	// scratch buffer for the W expansion; reused across processBlock calls so
	// we never allocate inside the inner loop.
	readonly #w = new Uint32Array(80);

	/** feeds more bytes into the hash. */
	update(data: Uint8Array): void {
		let offset = 0;
		let remaining = data.length;
		this.#totalLen += remaining;

		// top off the partial buffer with the first slice of `data` so we can
		// process one full block before switching to the in-place fast path.
		if (this.#bufferLen > 0) {
			const need = 64 - this.#bufferLen;
			if (remaining < need) {
				this.#buffer.set(data, this.#bufferLen);
				this.#bufferLen += remaining;
				return;
			}
			this.#buffer.set(data.subarray(0, need), this.#bufferLen);
			this.#processBlock(this.#buffer, 0);
			this.#bufferLen = 0;
			offset = need;
			remaining -= need;
		}

		// process full 64-byte blocks directly out of `data`.
		while (remaining >= 64) {
			this.#processBlock(data, offset);
			offset += 64;
			remaining -= 64;
		}

		// keep the tail for next time.
		if (remaining > 0) {
			this.#buffer.set(data.subarray(offset, offset + remaining));
			this.#bufferLen = remaining;
		}
	}

	/**
	 * returns the 20-byte SHA-1 hash of all bytes fed so far. the running
	 * state is preserved, so subsequent `update` calls behave as if `digest`
	 * had never been called.
	 */
	digest(): Uint8Array<ArrayBuffer> {
		const savedH0 = this.#h0;
		const savedH1 = this.#h1;
		const savedH2 = this.#h2;
		const savedH3 = this.#h3;
		const savedH4 = this.#h4;

		// finalization: 0x80 byte, zero-pad, 8-byte big-endian bit length.
		const padded = new Uint8Array(128);
		padded.set(this.#buffer.subarray(0, this.#bufferLen));
		padded[this.#bufferLen] = 0x80;

		// if the length doesn't fit in the current block, span across two.
		const spans2 = this.#bufferLen >= 56;
		const lengthOffset = spans2 ? 120 : 56;
		const bitLen = this.#totalLen * 8;
		const high = Math.floor(bitLen / 0x100000000);
		const low = bitLen >>> 0;
		padded[lengthOffset + 0] = (high >>> 24) & 0xff;
		padded[lengthOffset + 1] = (high >>> 16) & 0xff;
		padded[lengthOffset + 2] = (high >>> 8) & 0xff;
		padded[lengthOffset + 3] = high & 0xff;
		padded[lengthOffset + 4] = (low >>> 24) & 0xff;
		padded[lengthOffset + 5] = (low >>> 16) & 0xff;
		padded[lengthOffset + 6] = (low >>> 8) & 0xff;
		padded[lengthOffset + 7] = low & 0xff;

		this.#processBlock(padded, 0);
		if (spans2) {
			this.#processBlock(padded, 64);
		}

		const out = new Uint8Array(20);
		writeBE(out, 0, this.#h0);
		writeBE(out, 4, this.#h1);
		writeBE(out, 8, this.#h2);
		writeBE(out, 12, this.#h3);
		writeBE(out, 16, this.#h4);

		this.#h0 = savedH0;
		this.#h1 = savedH1;
		this.#h2 = savedH2;
		this.#h3 = savedH3;
		this.#h4 = savedH4;

		return out;
	}

	#processBlock(block: Uint8Array, offset: number): void {
		const w = this.#w;
		for (let idx = 0; idx < 16; idx++) {
			const i = offset + idx * 4;
			w[idx] = ((block[i] << 24) | (block[i + 1] << 16) | (block[i + 2] << 8) | block[i + 3]) >>>
				0;
		}
		for (let idx = 16; idx < 80; idx++) {
			const t = w[idx - 3] ^ w[idx - 8] ^ w[idx - 14] ^ w[idx - 16];
			w[idx] = ((t << 1) | (t >>> 31)) >>> 0;
		}

		let a = this.#h0;
		let b = this.#h1;
		let c = this.#h2;
		let d = this.#h3;
		let e = this.#h4;

		for (let idx = 0; idx < 20; idx++) {
			const f = (b & c) | (~b & d);
			const temp = ((((a << 5) | (a >>> 27)) + f + e + K0 + w[idx]) | 0) >>> 0;
			e = d;
			d = c;
			c = ((b << 30) | (b >>> 2)) >>> 0;
			b = a;
			a = temp;
		}
		for (let idx = 20; idx < 40; idx++) {
			const f = b ^ c ^ d;
			const temp = ((((a << 5) | (a >>> 27)) + f + e + K1 + w[idx]) | 0) >>> 0;
			e = d;
			d = c;
			c = ((b << 30) | (b >>> 2)) >>> 0;
			b = a;
			a = temp;
		}
		for (let idx = 40; idx < 60; idx++) {
			const f = (b & c) | (b & d) | (c & d);
			const temp = ((((a << 5) | (a >>> 27)) + f + e + K2 + w[idx]) | 0) >>> 0;
			e = d;
			d = c;
			c = ((b << 30) | (b >>> 2)) >>> 0;
			b = a;
			a = temp;
		}
		for (let idx = 60; idx < 80; idx++) {
			const f = b ^ c ^ d;
			const temp = ((((a << 5) | (a >>> 27)) + f + e + K3 + w[idx]) | 0) >>> 0;
			e = d;
			d = c;
			c = ((b << 30) | (b >>> 2)) >>> 0;
			b = a;
			a = temp;
		}

		this.#h0 = (this.#h0 + a) >>> 0;
		this.#h1 = (this.#h1 + b) >>> 0;
		this.#h2 = (this.#h2 + c) >>> 0;
		this.#h3 = (this.#h3 + d) >>> 0;
		this.#h4 = (this.#h4 + e) >>> 0;
	}
}

const writeBE = (out: Uint8Array, offset: number, value: number): void => {
	out[offset + 0] = (value >>> 24) & 0xff;
	out[offset + 1] = (value >>> 16) & 0xff;
	out[offset + 2] = (value >>> 8) & 0xff;
	out[offset + 3] = value & 0xff;
};
