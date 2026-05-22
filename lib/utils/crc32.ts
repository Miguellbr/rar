const TABLE = /*#__PURE__*/ (() => {
	const table = new Uint32Array(256);

	for (let idx = 0; idx < 256; idx++) {
		let c = idx;

		for (let bit = 0; bit < 8; bit++) {
			c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
		}

		table[idx] = c;
	}

	return table;
})();

/**
 * computes the CRC-32 checksum of a byte sequence, matching the algorithm RAR
 * uses for header and file data checksums.
 *
 * the function can be called incrementally by feeding the previous result back
 * as `seed`, allowing a checksum to be built up across streamed chunks.
 *
 * @param data bytes to checksum
 * @param seed running checksum from a previous chunk, or 0 to start fresh
 * @returns the unsigned 32-bit checksum
 */
export const crc32 = (data: Uint8Array, seed: number = 0): number => {
	let crc = (seed ^ 0xffffffff) >>> 0;

	for (let idx = 0, len = data.length; idx < len; idx++) {
		crc = TABLE[(crc ^ data[idx]) & 0xff] ^ (crc >>> 8);
	}

	return (crc ^ 0xffffffff) >>> 0;
};
