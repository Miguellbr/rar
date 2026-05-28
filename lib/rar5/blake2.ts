/**
 * @module
 *
 * BLAKE2sp-256 streaming hash, used by RAR5 entries that carry a BLAKE2 hash
 * record instead of a CRC32. BLAKE2sp is the parallel variant defined in §2.10
 * of the BLAKE2 paper: eight BLAKE2s leaves consume the input in 64-byte
 * stripes, then their 32-byte digests feed a single root BLAKE2s. only the
 * parallel hasher is exported; the underlying BLAKE2s class is internal.
 *
 * the implementation assumes a little-endian runtime (every supported target
 * is) and skips configuration BLAKE2sp does not need — no keyed mode, no salt,
 * no personalization, fixed 32-byte output.
 */

// BLAKE2s IV — same constants as SHA-256.
const IV0 = 0x6a09e667;
const IV1 = 0xbb67ae85;
const IV2 = 0x3c6ef372;
const IV3 = 0xa54ff53a;
const IV4 = 0x510e527f;
const IV5 = 0x9b05688c;
const IV6 = 0x1f83d9ab;
const IV7 = 0x5be0cd19;

// SIGMA permutation — 10 rounds × 16 indices, flattened. one row per round so
// the indices line up visually with the BLAKE2 spec.
// deno-fmt-ignore
const SIGMA = new Uint8Array([
	 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
	14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3,
	11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4,
	 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8,
	 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13,
	 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9,
	12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11,
	13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10,
	 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5,
	10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0,
]);

const rotr32 = (x: number, n: number): number => ((x >>> n) | (x << (32 - n))) >>> 0;

// the BLAKE2s G mixing function — eight calls per round.
const g = (
	v: Uint32Array,
	a: number,
	b: number,
	c: number,
	d: number,
	x: number,
	y: number,
): void => {
	v[a] = (v[a] + v[b] + x) | 0;
	v[d] = rotr32(v[d] ^ v[a], 16);
	v[c] = (v[c] + v[d]) | 0;
	v[b] = rotr32(v[b] ^ v[c], 12);
	v[a] = (v[a] + v[b] + y) | 0;
	v[d] = rotr32(v[d] ^ v[a], 8);
	v[c] = (v[c] + v[d]) | 0;
	v[b] = rotr32(v[b] ^ v[c], 7);
};

interface Blake2sParams {
	/** node offset, used as the leaf index for BLAKE2sp leaves; 0 for the root. */
	nodeOffset: number;
	/** node depth — 0 for leaves, 1 for the root. */
	nodeDepth: number;
	/** intermediate digest length passed up the tree (32 for BLAKE2sp). */
	innerLen: number;
	/** fanout — 8 for BLAKE2sp at both levels. */
	fanout: number;
	/** depth — 2 for BLAKE2sp at both levels. */
	depth: number;
}

// sequential / tree-mode BLAKE2s with 32-byte output. fixed key=0, salt=0,
// personalization=0; the parameter block is fully described by `Blake2sParams`.
class Blake2s {
	readonly #h = new Uint32Array(8);
	readonly #buffer = new Uint8Array(64);
	#bufferLen = 0;
	// total bytes fed; encoded as the 64-bit `t` counter at compress time.
	#total = 0;

	// scratch for the compression function; reused across blocks.
	readonly #v = new Uint32Array(16);
	readonly #m = new Uint32Array(16);

	constructor(params: Blake2sParams) {
		// 32-byte parameter block laid out as 8 32-bit words, XORed into IV.
		const p0 = 32 | (params.fanout << 16) | (params.depth << 24);
		const p2 = params.nodeOffset >>> 0;
		const p3 = (params.nodeDepth << 16) | (params.innerLen << 24);

		this.#h[0] = IV0 ^ p0;
		this.#h[1] = IV1;
		this.#h[2] = IV2 ^ p2;
		this.#h[3] = IV3 ^ p3;
		this.#h[4] = IV4;
		this.#h[5] = IV5;
		this.#h[6] = IV6;
		this.#h[7] = IV7;
	}

	update(data: Uint8Array): void {
		const buffer = this.#buffer;
		let bufferLen = this.#bufferLen;
		let offset = 0;
		let remaining = data.length;

		// top off any partial buffer, but only compress the resulting block
		// when more bytes definitely follow — BLAKE2 finalization needs to
		// compress the very last block with the last-block flag set, so we
		// must never empty the buffer speculatively.
		if (bufferLen > 0) {
			const need = 64 - bufferLen;
			if (remaining <= need) {
				buffer.set(data, bufferLen);
				this.#bufferLen = bufferLen + remaining;
				return;
			}
			buffer.set(data.subarray(0, need), bufferLen);
			this.#total += 64;
			this.#compress(buffer, 0, 0, 0);
			bufferLen = 0;
			offset = need;
			remaining -= need;
		}

		// process every full block except the last; the last 1..64 bytes are
		// always parked in `buffer` for digest() to finalize.
		while (remaining > 64) {
			this.#total += 64;
			this.#compress(data, offset, 0, 0);
			offset += 64;
			remaining -= 64;
		}

		if (remaining > 0) {
			buffer.set(data.subarray(offset, offset + remaining));
			bufferLen = remaining;
		}
		this.#bufferLen = bufferLen;
	}

	digest(lastNode: boolean): Uint8Array<ArrayBuffer> {
		const buffer = this.#buffer;
		const bufferLen = this.#bufferLen;
		// pad the buffered tail with zero bytes for the final compress.
		for (let i = bufferLen; i < 64; i++) {
			buffer[i] = 0;
		}
		this.#total += bufferLen;
		// f0 (last-block) is always set on the closing compress; f1
		// (last-node) is set only when this hash is the rightmost at its
		// tree level — i.e. leaf 7 of a BLAKE2sp tree, or the root.
		this.#compress(buffer, 0, 0xffffffff, lastNode ? 0xffffffff : 0);

		const out = new Uint8Array(32);
		const h = this.#h;
		for (let i = 0; i < 8; i++) {
			const w = h[i];
			const j = i << 2;
			out[j] = w & 0xff;
			out[j + 1] = (w >>> 8) & 0xff;
			out[j + 2] = (w >>> 16) & 0xff;
			out[j + 3] = (w >>> 24) & 0xff;
		}
		return out;
	}

	#compress(block: Uint8Array, offset: number, f0: number, f1: number): void {
		const v = this.#v;
		const m = this.#m;
		const h = this.#h;

		for (let i = 0; i < 16; i++) {
			const j = offset + (i << 2);
			m[i] = (block[j] | (block[j + 1] << 8) | (block[j + 2] << 16) | (block[j + 3] << 24)) >>>
				0;
		}

		const tLow = this.#total >>> 0;
		const tHigh = (this.#total - tLow) / 4294967296;

		v[0] = h[0];
		v[1] = h[1];
		v[2] = h[2];
		v[3] = h[3];
		v[4] = h[4];
		v[5] = h[5];
		v[6] = h[6];
		v[7] = h[7];
		v[8] = IV0;
		v[9] = IV1;
		v[10] = IV2;
		v[11] = IV3;
		v[12] = IV4 ^ tLow;
		v[13] = IV5 ^ tHigh;
		v[14] = IV6 ^ f0;
		v[15] = IV7 ^ f1;

		for (let r = 0; r < 10; r++) {
			const s = r << 4;
			g(v, 0, 4, 8, 12, m[SIGMA[s]], m[SIGMA[s + 1]]);
			g(v, 1, 5, 9, 13, m[SIGMA[s + 2]], m[SIGMA[s + 3]]);
			g(v, 2, 6, 10, 14, m[SIGMA[s + 4]], m[SIGMA[s + 5]]);
			g(v, 3, 7, 11, 15, m[SIGMA[s + 6]], m[SIGMA[s + 7]]);
			g(v, 0, 5, 10, 15, m[SIGMA[s + 8]], m[SIGMA[s + 9]]);
			g(v, 1, 6, 11, 12, m[SIGMA[s + 10]], m[SIGMA[s + 11]]);
			g(v, 2, 7, 8, 13, m[SIGMA[s + 12]], m[SIGMA[s + 13]]);
			g(v, 3, 4, 9, 14, m[SIGMA[s + 14]], m[SIGMA[s + 15]]);
		}

		for (let i = 0; i < 8; i++) {
			h[i] = h[i] ^ v[i] ^ v[i + 8];
		}
	}
}

const PARALLELISM = 8;
const LEAF_BLOCK = 64;
const STRIPE = PARALLELISM * LEAF_BLOCK;
const INNER_LEN = 32;

/**
 * incremental BLAKE2sp-256 hasher. feed bytes with {@link Blake2sp.update}
 * and read the 32-byte digest with {@link Blake2sp.digest}; the instance is
 * single-use and must not be updated after digesting.
 */
export class Blake2sp {
	readonly #leaves: Blake2s[];
	#total = 0;

	constructor() {
		this.#leaves = new Array(PARALLELISM);
		for (let i = 0; i < PARALLELISM; i++) {
			this.#leaves[i] = new Blake2s({
				depth: 2,
				fanout: PARALLELISM,
				innerLen: INNER_LEN,
				nodeDepth: 0,
				nodeOffset: i,
			});
		}
	}

	/**
	 * feeds more bytes into the hash. internally routes the input across
	 * eight BLAKE2s leaves in 64-byte stripes.
	 *
	 * @param data the bytes to hash
	 */
	update(data: Uint8Array): void {
		let offset = 0;
		let remaining = data.length;
		while (remaining > 0) {
			// the position within the current 512-byte stripe picks both the
			// active leaf and how far into its 64-byte block we are.
			const stripePos = this.#total % STRIPE;
			const leafIdx = (stripePos / LEAF_BLOCK) | 0;
			const blockPos = stripePos % LEAF_BLOCK;
			const room = LEAF_BLOCK - blockPos;
			const take = remaining < room ? remaining : room;
			this.#leaves[leafIdx].update(data.subarray(offset, offset + take));
			offset += take;
			remaining -= take;
			this.#total += take;
		}
	}

	/**
	 * finalizes the hash and returns the 32-byte digest. each leaf is
	 * finalized (the rightmost leaf with its last-node flag set), the eight
	 * 32-byte intermediates are concatenated, and a single root BLAKE2s
	 * (node_depth=1, last_node) reduces them to the final hash.
	 *
	 * @returns the 32-byte BLAKE2sp-256 digest
	 */
	digest(): Uint8Array<ArrayBuffer> {
		const inner = new Uint8Array(PARALLELISM * INNER_LEN);
		for (let i = 0; i < PARALLELISM; i++) {
			inner.set(this.#leaves[i].digest(i === PARALLELISM - 1), i * INNER_LEN);
		}
		const root = new Blake2s({
			depth: 2,
			fanout: PARALLELISM,
			innerLen: INNER_LEN,
			nodeDepth: 1,
			nodeOffset: 0,
		});
		root.update(inner);
		return root.digest(true);
	}
}
