/**
 * @module
 *
 * the RAR5 decompression algorithm ("unpack version 5"): an LZ77 scheme with
 * canonical Huffman coding, organized into self-describing blocks.
 *
 * this is an independent implementation written from an understanding of the
 * format; it does not incorporate code from RARLAB's unrar.
 */

import type { StreamReader } from '../utils/stream-reader.ts';

// #region constants

// huffman table sizes: bit-length codes, literals, distances, low distance
// bits, and repeated distances.
const SIZE_BC = 20;
const SIZE_NC = 306;
const SIZE_DC = 64;
const SIZE_LDC = 16;
const SIZE_RC = 44;
const SIZE_TABLE = SIZE_NC + SIZE_DC + SIZE_LDC + SIZE_RC;

// base size of the sliding window before the dictionary-size multiplier.
const BASE_WINDOW = 0x20000;

// #endregion

// #region bit reader

// a most-significant-bit-first reader over a block's bytes. the backing buffer
// must carry at least 8 bytes of zero padding past the block so that the
// 16- and 32-bit peeks never read out of bounds.
class BitReader {
	readonly #data: Uint8Array;
	/** byte offset of the next unread bit */
	addr: number = 0;
	/** bit offset within that byte, 0 through 7 */
	bit: number = 0;

	constructor(data: Uint8Array) {
		this.#data = data;
	}

	/** the next 16 bits, without consuming them. */
	peek16(): number {
		const p = this.#data;
		const a = this.addr;
		const bits = (p[a] << 16) | (p[a + 1] << 8) | p[a + 2];

		return (bits >>> (8 - this.bit)) & 0xffff;
	}

	/** the next 32 bits, without consuming them. */
	peek32(): number {
		const p = this.#data;
		const a = this.addr;
		const bits = ((p[a] << 24) | (p[a + 1] << 16) | (p[a + 2] << 8) | p[a + 3]) >>> 0;

		if (this.bit === 0) {
			return bits;
		}

		return ((bits << this.bit) | (p[a + 4] >>> (8 - this.bit))) >>> 0;
	}

	/**
	 * advances past `count` bits.
	 * @param count number of bits to skip
	 */
	skip(count: number): void {
		const total = this.bit + count;
		this.addr += total >> 3;
		this.bit = total & 7;
	}

	/**
	 * reads and consumes between 1 and 16 bits.
	 * @param count number of bits to read
	 * @returns the bits, right-aligned
	 */
	read(count: number): number {
		const value = this.peek16() >>> (16 - count);
		this.skip(count);

		return value;
	}
}

// #endregion

// #region huffman

interface DecodeTable {
	size: number;
	decodeLength: Int32Array;
	decodePosition: Uint32Array;
	quickBits: number;
	quickLength: Uint8Array;
	quickNumber: Uint16Array;
	decodeNumber: Uint16Array;
}

// builds a canonical Huffman decode table from per-symbol code lengths.
const createDecodeTable = (lengths: Uint8Array, size: number): DecodeTable => {
	const counts = new Array<number>(16).fill(0);
	for (let idx = 0; idx < size; idx++) {
		counts[lengths[idx] & 15]++;
	}
	counts[0] = 0;

	const decodeLength = new Int32Array(16);
	const decodePosition = new Uint32Array(16);

	let upperLimit = 0;
	for (let len = 1; len < 16; len++) {
		upperLimit += counts[len];
		decodeLength[len] = upperLimit << (16 - len);
		decodePosition[len] = decodePosition[len - 1] + counts[len - 1];
		upperLimit <<= 1;
	}

	if (upperLimit > 65536) {
		throw new Error(`over-subscribed huffman table`);
	}

	const decodeNumber = new Uint16Array(size);
	{
		const cursor = decodePosition.slice();
		for (let idx = 0; idx < size; idx++) {
			const len = lengths[idx] & 15;
			if (len > 0) {
				decodeNumber[cursor[len]++] = idx;
			}
		}
	}

	const quickBits = size === SIZE_NC ? 10 : 7;
	const quickCount = 1 << quickBits;
	const quickLength = new Uint8Array(quickCount);
	const quickNumber = new Uint16Array(quickCount);

	let len = 1;
	for (let code = 0; code < quickCount; code++) {
		const field = code << (16 - quickBits);

		while (len < 16 && field >= decodeLength[len]) {
			len++;
		}
		quickLength[code] = len;

		const position = decodePosition[len & 15] + ((field - decodeLength[len - 1]) >> (16 - len));
		quickNumber[code] = len < 16 && position < size ? decodeNumber[position] : 0;
	}

	return { decodeLength, decodeNumber, decodePosition, quickBits, quickLength, quickNumber, size };
};

// decodes one symbol from the bit stream using a decode table.
const decodeNumber = (table: DecodeTable, bits: BitReader): number => {
	const field = bits.peek16() & 0xfffe;

	if (field < table.decodeLength[table.quickBits]) {
		const code = field >>> (16 - table.quickBits);
		bits.skip(table.quickLength[code]);

		return table.quickNumber[code];
	}

	let length = 15;
	for (let candidate = table.quickBits + 1; candidate < 15; candidate++) {
		if (field < table.decodeLength[candidate]) {
			length = candidate;
			break;
		}
	}

	bits.skip(length);

	const position = table.decodePosition[length] +
		((field - table.decodeLength[length - 1]) >>> (16 - length));

	return table.decodeNumber[position >= table.size ? 0 : position];
};

// #endregion

// #region block parsing

interface BlockHeader {
	tablePresent: boolean;
	lastBlock: boolean;
	/** number of meaningful bits in the block's final byte */
	bitSize: number;
	blockSize: number;
	headerSize: number;
}

const parseBlockHeader = (data: Uint8Array, offset: number): BlockHeader => {
	const flags = data[offset];
	const checksum = data[offset + 1];

	const byteCount = (flags >> 3) & 7;
	if (byteCount > 2) {
		throw new Error(`unsupported block header size`);
	}

	let blockSize = 0;
	for (let idx = 0; idx <= byteCount; idx++) {
		blockSize |= data[offset + 2 + idx] << (8 * idx);
	}

	const expected = 0x5a ^ flags ^ (blockSize & 0xff) ^ ((blockSize >> 8) & 0xff) ^
		((blockSize >> 16) & 0xff);
	if (expected !== checksum) {
		throw new Error(`block header checksum mismatch`);
	}

	return {
		bitSize: flags & 7,
		blockSize,
		headerSize: 2 + byteCount + 1,
		lastBlock: ((flags >> 6) & 1) === 1,
		tablePresent: ((flags >> 7) & 1) === 1,
	};
};

interface Tables {
	literal: DecodeTable;
	distance: DecodeTable;
	lowDistance: DecodeTable;
	repeatDistance: DecodeTable;
}

// reads the Huffman tables stored at the start of a block. the table data
// begins with nibble-packed, run-length-encoded bit lengths; the bit reader is
// left positioned just past it.
const parseTables = (data: Uint8Array, bits: BitReader): Tables => {
	// stage 1: 20 nibble-packed bit lengths, with 15 escaping a zero run.
	const bcLengths = new Uint8Array(SIZE_BC);
	let pos = 0;
	let high = true;

	const nibble = (): number => {
		const value = high ? data[pos] >> 4 : data[pos++] & 0x0f;
		high = !high;
		return value;
	};

	for (let written = 0; written < SIZE_BC;) {
		const value = nibble();

		if (value !== 15) {
			bcLengths[written++] = value;
			continue;
		}

		const run = nibble();
		if (run === 0) {
			bcLengths[written++] = 15;
		} else {
			for (let idx = 0; idx < run + 2 && written < SIZE_BC; idx++) {
				bcLengths[written++] = 0;
			}
		}
	}

	bits.addr = pos;
	bits.bit = high ? 0 : 4;

	const bcTable = createDecodeTable(bcLengths, SIZE_BC);

	// stage 2: the remaining code lengths, Huffman-coded with the bit-length
	// table and a run-length scheme of their own.
	const lengths = new Uint8Array(SIZE_TABLE);
	for (let idx = 0; idx < SIZE_TABLE;) {
		const symbol = decodeNumber(bcTable, bits);

		if (symbol < 16) {
			lengths[idx++] = symbol;
			continue;
		}

		let run: number;
		if (symbol === 16 || symbol === 18) {
			run = (bits.peek16() >>> 13) + 3;
			bits.skip(3);
		} else {
			run = (bits.peek16() >>> 9) + 11;
			bits.skip(7);
		}

		if (symbol < 18) {
			// repeat the previous length
			if (idx === 0) {
				throw new Error(`huffman table repeat with no previous length`);
			}
			for (; run > 0 && idx < SIZE_TABLE; run--, idx++) {
				lengths[idx] = lengths[idx - 1];
			}
		} else {
			// a run of zero lengths
			for (; run > 0 && idx < SIZE_TABLE; run--, idx++) {
				lengths[idx] = 0;
			}
		}
	}

	return {
		distance: createDecodeTable(lengths.subarray(SIZE_NC, SIZE_NC + SIZE_DC), SIZE_DC),
		literal: createDecodeTable(lengths.subarray(0, SIZE_NC), SIZE_NC),
		lowDistance: createDecodeTable(
			lengths.subarray(SIZE_NC + SIZE_DC, SIZE_NC + SIZE_DC + SIZE_LDC),
			SIZE_LDC,
		),
		repeatDistance: createDecodeTable(lengths.subarray(SIZE_NC + SIZE_DC + SIZE_LDC), SIZE_RC),
	};
};

// #endregion

// #region filters

// filter type codes carried in the stream. RAR5 only emits the first four.
const FILTER_DELTA = 0;
const FILTER_E8 = 1;
const FILTER_E8E9 = 2;
const FILTER_ARM = 3;

interface Filter {
	type: number;
	/** absolute window offset the filter transforms, in monotonic write coordinates */
	blockStart: number;
	blockLength: number;
	/** interleaved channel count, for the delta filter */
	channels: number;
}

// reads a little-endian value prefixed by a 2-bit byte count.
const parseFilterValue = (bits: BitReader): number => {
	const byteCount = bits.read(2) + 1;

	let value = 0;
	for (let idx = 0; idx < byteCount; idx++) {
		value += (bits.peek16() >>> 8) * 2 ** (idx * 8);
		bits.skip(8);
	}

	return value;
};

// reads a filter command from the stream, as introduced by literal code 256.
const parseFilter = (bits: BitReader, writePtr: number): Filter => {
	const blockStart = parseFilterValue(bits);
	const blockLength = parseFilterValue(bits);

	const type = bits.peek16() >>> 13;
	bits.skip(3);

	const channels = type === FILTER_DELTA ? bits.read(5) + 1 : 1;

	return { blockLength, blockStart: writePtr + blockStart, channels, type };
};

const readLe32 = (data: Uint8Array, offset: number): number => {
	return (data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) |
		(data[offset + 3] << 24)) >>> 0;
};

const writeLe32 = (data: Uint8Array, offset: number, value: number): void => {
	data[offset] = value;
	data[offset + 1] = value >>> 8;
	data[offset + 2] = value >>> 16;
	data[offset + 3] = value >>> 24;
};

// transforms a filtered window region, returning the corrected bytes. the
// window is read modulo `mask + 1`, so the same routine serves both the
// dictionary-sized circular window used across solid runs and the one-shot
// window used for standalone entries.
const runFilter = (filter: Filter, window: Uint8Array, mask: number): Uint8Array => {
	const { blockLength, blockStart, channels, type } = filter;
	const out = new Uint8Array(blockLength);

	// stage the filter's input bytes from the (possibly circular) window into a
	// linear scratch buffer; non-delta filters then read and write in place.
	for (let idx = 0; idx < blockLength; idx++) {
		out[idx] = window[(blockStart + idx) & mask];
	}

	switch (type) {
		case FILTER_DELTA: {
			// each channel is delta-decoded independently, then interleaved. the
			// scratch buffer carries the source bytes; results go into a fresh
			// buffer to avoid clobbering still-unread source bytes.
			const result = new Uint8Array(blockLength);
			let source = 0;
			for (let channel = 0; channel < channels; channel++) {
				let previous = 0;
				for (let dest = channel; dest < blockLength; dest += channels) {
					previous = (previous - out[source]) & 0xff;
					result[dest] = previous;
					source++;
				}
			}
			return result;
		}
		case FILTER_E8:
		case FILTER_E8E9: {
			// rewrites x86 call/jump targets from relative to absolute form.
			const extended = type === FILTER_E8E9;
			const fileSize = 0x1000000;

			for (let idx = 0; idx < blockLength - 4;) {
				const opcode = out[idx++];
				if (opcode === 0xe8 || (extended && opcode === 0xe9)) {
					// blockStart is monotonic; use floating-point modulo to keep
					// `at` correct past the 32-bit boundary in long solid runs.
					const at = (idx + blockStart) % fileSize;
					const addr = readLe32(out, idx);

					if (addr & 0x80000000) {
						if (((addr + at) & 0x80000000) === 0) {
							writeLe32(out, idx, (addr + fileSize) >>> 0);
						}
					} else if ((addr - fileSize) & 0x80000000) {
						writeLe32(out, idx, (addr - at) >>> 0);
					}

					idx += 4;
				}
			}
			return out;
		}
		case FILTER_ARM: {
			// rewrites ARM branch-and-link instruction offsets.
			for (let idx = 0; idx < blockLength - 3; idx += 4) {
				if (out[idx + 3] === 0xeb) {
					let offset = readLe32(out, idx) & 0x00ffffff;
					offset = (offset - Math.floor((idx + blockStart) / 4)) & 0x00ffffff;
					writeLe32(out, idx, (offset | 0xeb000000) >>> 0);
				}
			}
			return out;
		}
		default: {
			throw new Error(`unsupported filter type ${type}`);
		}
	}
};

// #endregion

// #region unpack

// derives a match length from a length code, reading extra bits as needed.
const decodeLength = (code: number, bits: BitReader): number => {
	if (code < 8) {
		return 2 + code;
	}

	const extra = (code >> 2) - 1;
	const length = 2 + ((4 | (code & 3)) << extra);

	return length + bits.read(extra);
};

/**
 * receives decoded chunks as they settle. chunks are owned by the sink once
 * delivered; the decoder does not retain them. a sink that returns a promise
 * pauses the decoder until the promise resolves, providing backpressure.
 */
export type DecodeSink = (chunk: Uint8Array<ArrayBuffer>) => void | Promise<void>;

/**
 * a stateful RAR5 decoder.
 *
 * one instance carries the sliding window, repeat-distance cache, last match
 * length, Huffman tables, and pending filter list across {@link Rar5Decoder.decode}
 * calls. each call extracts the data of a single archive entry; consecutive
 * calls represent the entries of a solid run sharing one decompression state.
 *
 * the window is sized from the dictionary exponent passed to the constructor
 * and is held internally as a circular buffer; an entry's uncompressed output
 * is streamed to a sink in chunks as bytes settle, without ever buffering the
 * whole entry, so entries larger than the window decode without trouble.
 */
export class Rar5Decoder {
	readonly #windowSize: number;
	readonly #windowMask: number;
	readonly #window: Uint8Array;

	#distCache: [number, number, number, number] = [0, 0, 0, 0];
	#lastLength = 0;
	/** monotonic count of bytes ever written to the window */
	#write = 0;
	#tables?: Tables;
	/** filters whose range has not been fully written yet */
	#pending: Filter[] = [];
	/**
	 * filters whose range is fully written and whose post-filter bytes are
	 * computed, waiting to be overlaid on top of the emit chunks they cover.
	 * keyed by the filter's `blockStart` in write-pointer coordinates.
	 */
	#ready: Map<number, Uint8Array> = new Map();

	/**
	 * @param dictionarySizeExponent the dictionary-size exponent from the entry's
	 * compression information field; the window size is `0x20000 << exponent`
	 */
	constructor(dictionarySizeExponent: number) {
		this.#windowSize = BASE_WINDOW * 2 ** dictionarySizeExponent;
		this.#windowMask = this.#windowSize - 1;
		this.#window = new Uint8Array(this.#windowSize);
	}

	/**
	 * decodes the data area of one RAR5 file entry, appending its bytes to the
	 * shared window and emitting decoded chunks to `sink` as they settle.
	 *
	 * compressed bytes are pulled from `input` one LZ block at a time, so the
	 * full compressed payload never needs to be buffered. chunks are emitted
	 * after each block, bounded above by the next pending filter's start so a
	 * filter never has to rewrite bytes that were already sent. across a solid
	 * run, the share of state carries over: pending filters of the previous
	 * entry remain pending until their range completes in a later entry.
	 *
	 * @param input compressed bytes of the entry's data area, in order
	 * @param unpackedSize the expected uncompressed size
	 * @param sink receives each decoded chunk in order
	 * @throws if the stream is invalid, a filter straddles the entry boundary,
	 * or unemitted bytes outstrip the dictionary window
	 */
	async decode(input: StreamReader, unpackedSize: number, sink: DecodeSink): Promise<void> {
		const mask = this.#windowMask;
		const window = this.#window;
		const windowSize = this.#windowSize;
		const startWrite = this.#write;
		const targetWrite = startWrite + unpackedSize;

		let emitted = startWrite;

		const flush = async (final: boolean): Promise<void> => {
			// turn newly-completed filters into pre-computed overlay bytes. the
			// filter reads from the window, so we must run it before the LZ loop
			// overwrites its range.
			{
				const stillPending: Filter[] = [];
				for (const filter of this.#pending) {
					const fe = filter.blockStart + filter.blockLength;
					if (fe > this.#write) {
						stillPending.push(filter);
						continue;
					}
					if (fe <= emitted) {
						// the filter's range ended before any of the bytes we still
						// owe; the original bytes are gone, but neither are they
						// needed.
						continue;
					}
					if (filter.blockStart < emitted) {
						throw new Error(`filter range begins before already-emitted bytes`);
					}
					this.#ready.set(filter.blockStart, runFilter(filter, window, mask));
				}
				this.#pending = stillPending;
			}

			// emit up to the first byte that a still-pending filter will rewrite.
			let safeEnd = final ? targetWrite : this.#write;
			for (const filter of this.#pending) {
				if (filter.blockStart < safeEnd) {
					safeEnd = filter.blockStart;
				}
			}
			if (safeEnd > targetWrite) {
				safeEnd = targetWrite;
			}
			if (safeEnd <= emitted) {
				return;
			}

			const size = safeEnd - emitted;
			const chunk = new Uint8Array(size);
			for (let idx = 0; idx < size; idx++) {
				chunk[idx] = window[(emitted + idx) & mask];
			}

			// overlay any ready filter whose range intersects this chunk; one whose
			// tail still lies past `safeEnd` keeps its remaining bytes around for
			// the next emit cycle to apply.
			for (const [fs, filtered] of this.#ready) {
				const fe = fs + filtered.length;
				const overlayStart = Math.max(fs, emitted);
				const overlayEnd = Math.min(fe, safeEnd);
				if (overlayEnd <= overlayStart) {
					continue;
				}
				chunk.set(
					filtered.subarray(overlayStart - fs, overlayEnd - fs),
					overlayStart - emitted,
				);
				if (overlayEnd >= fe) {
					this.#ready.delete(fs);
				}
			}

			await sink(chunk);
			emitted = safeEnd;
		};

		// the LZ copy primitive: bytes are written to the window modulo its
		// size, and matches may overlap the write pointer so the loop must
		// proceed byte by byte.
		const copy = (length: number, distance: number): void => {
			for (let idx = 0; idx < length; idx++) {
				window[(this.#write + idx) & mask] = window[(this.#write + idx - distance) & mask];
			}
			this.#write += length;
		};

		while (this.#write < targetWrite) {
			// the block header is 3-5 bytes: 2 fixed (flags + checksum) plus 1-3
			// little-endian size bytes. read the fixed pair first so the size
			// nibble in `flags` tells us how many more to pull.
			await input.require(2);
			const headerProbe = input.take(2);
			const sizeBytes = ((headerProbe[0] >> 3) & 7) + 1;
			await input.require(sizeBytes);
			const headerTail = input.take(sizeBytes);

			const headerBuf = new Uint8Array(2 + sizeBytes);
			headerBuf.set(headerProbe);
			headerBuf.set(headerTail, 2);
			const header = parseBlockHeader(headerBuf, 0);

			// the LZ engine reads up to 4 bytes past the bit-stream end via
			// peek32, so pad the block buffer with 8 zero bytes.
			await input.require(header.blockSize);
			const blockPayload = input.take(header.blockSize);
			const block = new Uint8Array(header.blockSize + 8);
			block.set(blockPayload);

			const bits = new BitReader(block);
			if (header.tablePresent) {
				this.#tables = parseTables(block, bits);
			}
			if (this.#tables === undefined) {
				throw new Error(`block references huffman tables that were never defined`);
			}
			const tables = this.#tables;

			const blockBitSize = 1 + header.bitSize;
			const lastByte = header.blockSize - 1;

			while (this.#write < targetWrite) {
				if (bits.addr > lastByte || (bits.addr === lastByte && bits.bit >= blockBitSize)) {
					break;
				}

				const symbol = decodeNumber(tables.literal, bits);

				if (symbol < 256) {
					window[this.#write++ & mask] = symbol;
					continue;
				}

				if (symbol === 256) {
					this.#pending.push(parseFilter(bits, this.#write));
					continue;
				}

				if (symbol === 257) {
					if (this.#lastLength !== 0) {
						copy(this.#lastLength, this.#distCache[0]);
					}
					continue;
				}

				if (symbol < 262) {
					// a match reusing one of the cached distances
					const cacheIndex = symbol - 258;
					const distance = this.#distCache[cacheIndex];
					for (let idx = cacheIndex; idx > 0; idx--) {
						this.#distCache[idx] = this.#distCache[idx - 1];
					}
					this.#distCache[0] = distance;

					const length = decodeLength(decodeNumber(tables.repeatDistance, bits), bits);
					this.#lastLength = length;
					copy(length, distance);
					continue;
				}

				// a match with a freshly coded distance
				let length = decodeLength(symbol - 262, bits);
				const slot = decodeNumber(tables.distance, bits);

				let distance = 1;
				let extraBits = 0;
				if (slot < 4) {
					distance += slot;
				} else {
					extraBits = (slot >> 1) - 1;
					distance += (2 | (slot & 1)) << extraBits;
				}

				if (extraBits > 0) {
					if (extraBits >= 4) {
						if (extraBits > 4) {
							const high = bits.peek32();
							bits.skip(extraBits - 4);
							distance += (high >>> (36 - extraBits)) << 4;
						}
						distance += decodeNumber(tables.lowDistance, bits);
					} else {
						distance += bits.read(extraBits);
					}
				}

				// longer distances imply the encoder spent fewer length codes.
				if (distance > 0x100) {
					length++;
					if (distance > 0x2000) {
						length++;
						if (distance > 0x40000) {
							length++;
						}
					}
				}

				this.#distCache[3] = this.#distCache[2];
				this.#distCache[2] = this.#distCache[1];
				this.#distCache[1] = this.#distCache[0];
				this.#distCache[0] = distance;
				this.#lastLength = length;
				copy(length, distance);
			}

			await flush(false);

			// once unemitted bytes outgrow the window, the LZ loop will start
			// overwriting bytes the sink hasn't received yet. this usually means
			// a filter range so large that it pins emission past the window;
			// surface it cleanly rather than producing wrong bytes.
			if (this.#write - emitted > windowSize) {
				throw new Error(
					`unemitted bytes (${this.#write - emitted}) exceed window size (${windowSize})`,
				);
			}

			if (header.lastBlock) {
				break;
			}
		}

		if (this.#write !== targetWrite) {
			throw new Error(`decompressed ${this.#write - startWrite} bytes, expected ${unpackedSize}`);
		}

		await flush(true);

		if (emitted !== targetWrite) {
			throw new Error(`pending filter prevents final emission past byte ${emitted - startWrite}`);
		}
	}
}

// #endregion
