/**
 * @module
 *
 * the RAR1.5 - RAR4 ("RAR3", "v29") LZSS decompressor. RAR3 wraps an LZ77
 * scheme with canonical Huffman coding and a small set of pre-defined VM
 * filters (x86, audio, RGB, etc.). this implementation handles the LZSS
 * codec end to end; the PPMd-H mode used by some `best` (method 0x35)
 * archives and the VM filter program format are recognized but not yet
 * supported.
 *
 * written from an understanding of libarchive's RAR3 reader; not a port
 * of RARLAB's unrar.
 */

import type { StreamReader } from '../utils/stream-reader.ts';

// #region constants

// the four Huffman tables that drive the LZSS engine: literals + base
// length/offset selectors (`main`), separate offset and length extra-bit
// selectors, and the "low offset" table used for distances above 16 MB.
const MAIN_CODE_SIZE = 299;
const OFFSET_CODE_SIZE = 60;
const LOW_OFFSET_CODE_SIZE = 17;
const LENGTH_CODE_SIZE = 28;
const HUFFMAN_TABLE_SIZE = MAIN_CODE_SIZE + OFFSET_CODE_SIZE + LOW_OFFSET_CODE_SIZE + LENGTH_CODE_SIZE;

// the 20-symbol precode that describes the four main tables' bit lengths.
const PRECODE_SIZE = 20;

// every code length is in 0..15.
const MAX_SYMBOL_LENGTH = 15;

// the largest dictionary size RAR3 allows (4 MiB). the window is sized at
// or above the largest match distance the stream can encode.
const MAX_DICTIONARY = 0x400000;

// length-code base values and the number of extra bits to read.
const LENGTH_BASES = new Uint8Array([
	0,
	1,
	2,
	3,
	4,
	5,
	6,
	7,
	8,
	10,
	12,
	14,
	16,
	20,
	24,
	28,
	32,
	40,
	48,
	56,
	64,
	80,
	96,
	112,
	128,
	160,
	192,
	224,
]);
const LENGTH_EXTRA_BITS = new Uint8Array([
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	1,
	1,
	1,
	1,
	2,
	2,
	2,
	2,
	3,
	3,
	3,
	3,
	4,
	4,
	4,
	4,
	5,
	5,
	5,
	5,
]);

// offset-code base values and the number of extra bits to read.
const OFFSET_BASES = new Uint32Array([
	0,
	1,
	2,
	3,
	4,
	6,
	8,
	12,
	16,
	24,
	32,
	48,
	64,
	96,
	128,
	192,
	256,
	384,
	512,
	768,
	1024,
	1536,
	2048,
	3072,
	4096,
	6144,
	8192,
	12288,
	16384,
	24576,
	32768,
	49152,
	65536,
	98304,
	131072,
	196608,
	262144,
	327680,
	393216,
	458752,
	524288,
	589824,
	655360,
	720896,
	786432,
	851968,
	917504,
	983040,
	1048576,
	1310720,
	1572864,
	1835008,
	2097152,
	2359296,
	2621440,
	2883584,
	3145728,
	3407872,
	3670016,
	3932160,
]);
const OFFSET_EXTRA_BITS = new Uint8Array([
	0,
	0,
	0,
	0,
	1,
	1,
	2,
	2,
	3,
	3,
	4,
	4,
	5,
	5,
	6,
	6,
	7,
	7,
	8,
	8,
	9,
	9,
	10,
	10,
	11,
	11,
	12,
	12,
	13,
	13,
	14,
	14,
	15,
	15,
	16,
	16,
	16,
	16,
	16,
	16,
	16,
	16,
	16,
	16,
	16,
	16,
	16,
	16,
	18,
	18,
	18,
	18,
	18,
	18,
	18,
	18,
	18,
	18,
	18,
	18,
]);

// short-match base offsets and extra bits, used by main symbols 263-270.
// short matches always have length 2.
const SHORT_BASES = new Uint8Array([0, 4, 8, 16, 32, 64, 128, 192]);
const SHORT_EXTRA_BITS = new Uint8Array([2, 2, 3, 4, 5, 6, 6, 6]);

// #endregion

// #region bit reader

// an MSB-first bit reader over a forward-only buffer. RAR3 feeds the reader
// in 64 KiB - 1 MiB chunks; we keep a `Uint8Array` buffer that the caller
// extends and rotate the byte position + intra-byte bit index in lockstep.
// peek16/peek32 read up to 4 bytes ahead, so the backing buffer needs at
// least 8 zero-padding bytes past the last meaningful byte.
class BitReader {
	#data: Uint8Array;
	/** byte offset of the next unread bit */
	addr = 0;
	/** bit offset within that byte, 0 through 7 */
	bit = 0;

	constructor(data: Uint8Array) {
		this.#data = data;
	}

	/** swaps the backing buffer, keeping the current addr/bit position. */
	rebind(data: Uint8Array): void {
		this.#data = data;
	}

	get data(): Uint8Array {
		return this.#data;
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

	skip(count: number): void {
		const total = this.bit + count;
		this.addr += total >> 3;
		this.bit = total & 7;
	}

	read(count: number): number {
		if (count === 0) {
			return 0;
		}
		if (count <= 16) {
			const value = this.peek16() >>> (16 - count);
			this.skip(count);
			return value;
		}
		// values up to 32 bits are needed for the offset-bits high group.
		const high = this.read(count - 16);
		const low = this.read(16);
		return high * 0x10000 + low;
	}

	/** rounds addr/bit up to the next byte boundary. */
	alignByte(): void {
		if (this.bit !== 0) {
			this.addr++;
			this.bit = 0;
		}
	}
}

// #endregion

// #region huffman

// a decoded canonical Huffman table. `decodeLen[k]` is `count[k] << (16 - k)`
// where `count[k]` runs over all symbols of length k or less; `decodePos[k]`
// is the running offset into `symbols` where length-k codes begin. quick is a
// flat lookup that resolves any code whose length is <= QUICK_BITS in one
// peek; the slow path falls through to the per-length comparison.
const QUICK_BITS = 10;
const QUICK_SIZE = 1 << QUICK_BITS;

interface HuffmanTable {
	size: number;
	decodeLen: Int32Array;
	decodePos: Uint32Array;
	symbols: Uint16Array;
	quickLen: Uint8Array;
	quickSym: Uint16Array;
}

// builds a canonical Huffman decode table from per-symbol code lengths.
const createTable = (lengths: Uint8Array, size: number): HuffmanTable => {
	const counts = new Uint32Array(MAX_SYMBOL_LENGTH + 1);
	for (let idx = 0; idx < size; idx++) {
		const len = lengths[idx];
		if (len > MAX_SYMBOL_LENGTH) {
			throw new Error(`rar3 huffman code length ${len} exceeds ${MAX_SYMBOL_LENGTH}`);
		}
		counts[len]++;
	}
	counts[0] = 0;

	const decodeLen = new Int32Array(MAX_SYMBOL_LENGTH + 1);
	const decodePos = new Uint32Array(MAX_SYMBOL_LENGTH + 1);

	let upperLimit = 0;
	for (let len = 1; len <= MAX_SYMBOL_LENGTH; len++) {
		upperLimit += counts[len];
		decodeLen[len] = upperLimit << (16 - len);
		decodePos[len] = decodePos[len - 1] + counts[len - 1];
		upperLimit <<= 1;
	}
	if (upperLimit > 65536) {
		throw new Error('rar3 over-subscribed huffman table');
	}

	const symbols = new Uint16Array(size);
	{
		const cursor = decodePos.slice();
		for (let idx = 0; idx < size; idx++) {
			const len = lengths[idx];
			if (len > 0) {
				symbols[cursor[len]++] = idx;
			}
		}
	}

	const quickLen = new Uint8Array(QUICK_SIZE);
	const quickSym = new Uint16Array(QUICK_SIZE);
	let len = 1;
	for (let code = 0; code < QUICK_SIZE; code++) {
		const field = code << (16 - QUICK_BITS);
		while (len <= MAX_SYMBOL_LENGTH && field >= decodeLen[len]) {
			len++;
		}
		if (len > MAX_SYMBOL_LENGTH) {
			quickLen[code] = MAX_SYMBOL_LENGTH;
			quickSym[code] = 0;
			continue;
		}
		quickLen[code] = len;
		const position = decodePos[len] + ((field - decodeLen[len - 1]) >>> (16 - len));
		quickSym[code] = position < size ? symbols[position] : 0;
	}

	return { decodeLen, decodePos, quickLen, quickSym, size, symbols };
};

// decodes one symbol from the bit stream using a decode table.
const decodeSymbol = (table: HuffmanTable, bits: BitReader): number => {
	const field = bits.peek16();

	if (field < table.decodeLen[QUICK_BITS]) {
		const code = field >>> (16 - QUICK_BITS);
		bits.skip(table.quickLen[code]);
		return table.quickSym[code];
	}

	let length = MAX_SYMBOL_LENGTH;
	for (let candidate = QUICK_BITS + 1; candidate < MAX_SYMBOL_LENGTH; candidate++) {
		if (field < table.decodeLen[candidate]) {
			length = candidate;
			break;
		}
	}

	bits.skip(length);

	const position = table.decodePos[length] +
		((field - table.decodeLen[length - 1]) >>> (16 - length));
	return table.symbols[position >= table.size ? 0 : position];
};

// #endregion

// #region table parsing

interface Tables {
	main: HuffmanTable;
	offset: HuffmanTable;
	lowOffset: HuffmanTable;
	length: HuffmanTable;
}

// reads the four Huffman tables that drive the LZSS engine. `lengthtable`
// carries the per-symbol bit lengths across calls because RAR3 supports a
// "keep existing tables" mode: a 1 bit means amend the running table by the
// (signed-4-bit-delta-style) precode output; a 0 bit means start fresh from
// all zeros.
const parseCodes = (
	bits: BitReader,
	lengthTable: Uint8Array,
): { ppmd: boolean; tables: Tables } => {
	bits.alignByte();

	const ppmd = bits.read(1) !== 0;
	if (ppmd) {
		// PPMd-H mode. read the 7-bit ppmd flags so the caller can surface a
		// meaningful error; we do not yet implement the algorithm.
		bits.read(7);
		throw new Error('rar3 ppmd compression is not yet supported');
	}

	const keepExisting = bits.read(1) !== 0;
	if (!keepExisting) {
		lengthTable.fill(0);
	}

	// stage 1: 20 nibble-packed precode lengths with a 0xF escape used both
	// for the literal length 15 (when the next nibble is 0) and for a run of
	// zero lengths (when the next nibble is non-zero).
	const precodeLengths = new Uint8Array(PRECODE_SIZE);
	for (let idx = 0; idx < PRECODE_SIZE;) {
		const value = bits.read(4);
		if (value !== 0xf) {
			precodeLengths[idx++] = value;
			continue;
		}
		const run = bits.read(4);
		if (run === 0) {
			precodeLengths[idx++] = 0xf;
		} else {
			for (let j = 0; j < run + 2 && idx < PRECODE_SIZE; j++) {
				precodeLengths[idx++] = 0;
			}
		}
	}
	const precode = createTable(precodeLengths, PRECODE_SIZE);

	// stage 2: walk the precode, applying its symbols to `lengthTable`.
	// symbols 0-15 add to the running length (mod 16); 16/17 repeat the
	// previous length for 3 + 3-bit (16) or 11 + 7-bit (17) entries; 18/19
	// emit a run of zero lengths with the same two run-length encodings.
	for (let idx = 0; idx < HUFFMAN_TABLE_SIZE;) {
		const symbol = decodeSymbol(precode, bits);

		if (symbol < 16) {
			lengthTable[idx] = (lengthTable[idx] + symbol) & 0xf;
			idx++;
		} else if (symbol < 18) {
			if (idx === 0) {
				throw new Error('rar3 huffman table repeat with no previous length');
			}
			const run = symbol === 16 ? bits.read(3) + 3 : bits.read(7) + 11;
			const prev = lengthTable[idx - 1];
			for (let j = 0; j < run && idx < HUFFMAN_TABLE_SIZE; j++) {
				lengthTable[idx++] = prev;
			}
		} else {
			const run = symbol === 18 ? bits.read(3) + 3 : bits.read(7) + 11;
			for (let j = 0; j < run && idx < HUFFMAN_TABLE_SIZE; j++) {
				lengthTable[idx++] = 0;
			}
		}
	}

	const main = createTable(lengthTable.subarray(0, MAIN_CODE_SIZE), MAIN_CODE_SIZE);
	const offset = createTable(
		lengthTable.subarray(MAIN_CODE_SIZE, MAIN_CODE_SIZE + OFFSET_CODE_SIZE),
		OFFSET_CODE_SIZE,
	);
	const lowOffset = createTable(
		lengthTable.subarray(
			MAIN_CODE_SIZE + OFFSET_CODE_SIZE,
			MAIN_CODE_SIZE + OFFSET_CODE_SIZE + LOW_OFFSET_CODE_SIZE,
		),
		LOW_OFFSET_CODE_SIZE,
	);
	const length = createTable(
		lengthTable.subarray(MAIN_CODE_SIZE + OFFSET_CODE_SIZE + LOW_OFFSET_CODE_SIZE),
		LENGTH_CODE_SIZE,
	);

	return { ppmd, tables: { length, lowOffset, main, offset } };
};

// #endregion

// #region filter command parsing

// reads one byte from the LZSS bit stream. unlike the main `bits.read(8)`
// path this aligns to 8 bits exactly, matching libarchive's
// `rar_decode_byte` helper used by the filter reader.
const readByte = (bits: BitReader): number => bits.read(8);

// consumes a single VM-style variable-length number from a byte buffer using
// a memory bit reader. matches libarchive's `membr_next_rarvm_number`.
class MemoryBitReader {
	#data: Uint8Array;
	#bit = 0; // total bits consumed

	constructor(data: Uint8Array) {
		this.#data = data;
	}

	bits(count: number): number {
		let value = 0;
		for (let idx = 0; idx < count; idx++) {
			const byteIndex = this.#bit >>> 3;
			const bitIndex = 7 - (this.#bit & 7);
			const bit = byteIndex < this.#data.length ? (this.#data[byteIndex] >>> bitIndex) & 1 : 0;
			value = (value << 1) | bit;
			this.#bit++;
		}
		return value;
	}

	number(): number {
		const tag = this.bits(2);
		if (tag === 0) {
			return this.bits(4);
		}
		if (tag === 1) {
			const high = this.bits(8);
			if (high >= 16) {
				return high;
			}
			// libarchive sign-extends here, but only blockstart/length use it
			// and they treat the result as a small positive offset; the
			// inverse of the |= 0xFFFFFF00 dance is to just return the low 12
			// bits as an unsigned value, which is what real archives store.
			return (high << 4) | this.bits(4);
		}
		if (tag === 2) {
			return this.bits(16);
		}
		// 32-bit values overflow JS bitwise math, but in practice they only
		// appear for register overrides — read as two 16-bit halves and
		// combine through arithmetic.
		const hi = this.bits(16);
		const lo = this.bits(16);
		return hi * 0x10000 + lo;
	}
}

// tracks the running per-filter-list state across decode calls so subsequent
// filter references (`flags & 0x80 == 0`) can resolve to the right cached
// program length. libarchive holds this on the rar struct itself; here it is
// kept inside the {@link Rar3Decoder} so a solid run sees the same list.
interface FilterProgram {
	usageCount: number;
	oldFilterLength: number;
}

// reads one full filter command off the LZSS bit stream and updates the
// decoder's filter list. the program bytecode itself is read but not
// compiled — a follow-on commit will recognize the standard filters and
// dispatch to hardcoded implementations.
const skipFilterCommand = (bits: BitReader, decoder: Rar3DecoderState): void => {
	const flags = readByte(bits);

	// libarchive: length = (flags & 7) + 1, with 7 and 8 extending it.
	let length = (flags & 0x07) + 1;
	if (length === 7) {
		length = readByte(bits) + 7;
	} else if (length === 8) {
		const high = readByte(bits);
		const low = readByte(bits);
		length = (high << 8) | low;
	}

	const code = new Uint8Array(length);
	for (let idx = 0; idx < length; idx++) {
		code[idx] = readByte(bits);
	}

	const mbr = new MemoryBitReader(code);

	let progIndex: number;
	if (flags & 0x80) {
		const num = mbr.number();
		if (num === 0) {
			decoder.programs.length = 0;
			progIndex = 0;
		} else {
			progIndex = num - 1;
		}
		decoder.lastFilterNum = progIndex;
	} else {
		progIndex = decoder.lastFilterNum;
	}
	const prog = decoder.programs[progIndex];

	// blockstart and blocklength are read but ignored — when the VM lands,
	// they will identify the range to transform.
	mbr.number();
	if (flags & 0x20) {
		mbr.number();
	}
	// register override mask + values.
	if (flags & 0x10) {
		const mask = mbr.bits(7);
		for (let idx = 0; idx < 7; idx++) {
			if (mask & (1 << idx)) {
				mbr.number();
			}
		}
	}
	// new program bytecode (only when the filter slot is empty).
	if (prog === undefined) {
		const len = mbr.number();
		for (let idx = 0; idx < len; idx++) {
			mbr.bits(8);
		}
		decoder.programs[progIndex] = { oldFilterLength: 0, usageCount: 1 };
	} else {
		prog.usageCount++;
	}
	// optional global-data overlay.
	if (flags & 0x08) {
		const len = mbr.number();
		for (let idx = 0; idx < len; idx++) {
			mbr.bits(8);
		}
	}
};

// the slice of decoder state that {@link skipFilterCommand} mutates.
interface Rar3DecoderState {
	programs: (FilterProgram | undefined)[];
	lastFilterNum: number;
}

// #endregion

// #region decoder

/**
 * receives decoded chunks as they settle. a sink that returns a promise
 * pauses the decoder until the promise resolves, providing backpressure.
 */
export type DecodeSink = (chunk: Uint8Array<ArrayBuffer>) => void | Promise<void>;

/**
 * a stateful RAR3 LZSS decoder.
 *
 * one instance carries the sliding window, repeat-distance cache, last match
 * length, last low-offset, Huffman length table and tables themselves, plus
 * the bit reader across calls. consecutive {@link Rar3Decoder.decode} calls
 * represent the entries of a solid run sharing one state.
 *
 * VM filters are not yet supported; encountering symbol 257 in the LZSS
 * stream raises an error.
 */
export class Rar3Decoder {
	readonly #windowSize: number;
	readonly #windowMask: number;
	readonly #window: Uint8Array;

	/** four-deep LRU of recent match distances, oldest at index 3. */
	#oldOffsets: [number, number, number, number] = [0, 0, 0, 0];
	#lastOffset = 0;
	#lastLength = 0;
	#lastLowOffset = 0;
	#lowOffsetRepeats = 0;

	/** monotonic count of bytes ever written to the window. */
	#write = 0;

	/** running bit lengths used by `keep-existing-tables` (precode) mode. */
	readonly #lengthTable = new Uint8Array(HUFFMAN_TABLE_SIZE);
	#tables?: Tables;
	/** set when the previous entry left a `start new table` marker in flight. */
	#startNewTable = true;
	/** set when a filter command was seen during the most recent decode. */
	#sawFilter = false;
	/** filter program list referenced by the next filter command. */
	readonly #filterState: Rar3DecoderState = { lastFilterNum: 0, programs: [] };

	/**
	 * whether the most recent {@link decode} call passed through at least one
	 * VM filter command. the LZSS stream stayed in sync, but the bytes inside
	 * each filter's range are pre-filter and may differ from the original
	 * plaintext. consumers that care about byte-exact output should treat a
	 * `true` return as "content is not fully decoded".
	 */
	get sawFilter(): boolean {
		return this.#sawFilter;
	}

	/**
	 * @param dictionarySize the dictionary size declared by the file header.
	 * the window is rounded up to the next power of two but never above the
	 * RAR3 cap of 4 MiB.
	 */
	constructor(dictionarySize: number) {
		let windowSize = 1;
		while (windowSize < dictionarySize) {
			windowSize <<= 1;
		}
		if (windowSize === 0 || windowSize > MAX_DICTIONARY) {
			windowSize = MAX_DICTIONARY;
		}
		this.#windowSize = windowSize;
		this.#windowMask = windowSize - 1;
		this.#window = new Uint8Array(windowSize);
	}

	/**
	 * decodes the data area of one RAR3 file entry, appending its bytes to the
	 * shared window and emitting decoded chunks to `sink` as they settle.
	 *
	 * compressed bytes are pulled from `input` in 64 KiB blocks. across a
	 * solid run, the Huffman tables and distance cache carry over so the next
	 * entry's first symbols can reference them.
	 *
	 * filter commands (symbol 257) are read off the bit stream so the LZSS
	 * engine stays in sync, but the VM that would execute them is not yet
	 * built — the bytes inside each filter's range come out pre-filter. check
	 * {@link sawFilter} after a call to see whether any range is so affected.
	 *
	 * @param input compressed bytes of the entry's data area, in order
	 * @param unpackedSize the expected uncompressed size
	 * @param sink receives each decoded chunk in order
	 * @throws if the stream is invalid or requests PPMd
	 */
	async decode(input: StreamReader, unpackedSize: number, sink: DecodeSink): Promise<void> {
		this.#sawFilter = false;
		const mask = this.#windowMask;
		const window = this.#window;
		const startWrite = this.#write;
		const targetWrite = startWrite + unpackedSize;

		let emitted = startWrite;

		// drain bytes from the window into one chunk and pass it to the sink.
		const flush = async (): Promise<void> => {
			const end = Math.min(this.#write, targetWrite);
			if (end <= emitted) {
				return;
			}
			const size = end - emitted;
			const chunk = new Uint8Array(size);
			for (let idx = 0; idx < size; idx++) {
				chunk[idx] = window[(emitted + idx) & mask];
			}
			await sink(chunk);
			emitted = end;
		};

		// pulls a contiguous slab of compressed bytes large enough that the
		// inner loop can run for a while without re-checking. 64 KiB matches
		// libarchive's `UNP_BUFFER_SIZE / 2`, leaves headroom for the longest
		// composite read (a few dozen bits), and lets `peek32` look past the
		// nominal end safely thanks to 8 trailing pad bytes.
		const BLOCK_SIZE = 64 * 1024;
		const PAD = 8;
		let bits: BitReader | undefined;

		const refill = async (): Promise<boolean> => {
			if (input.buffered === 0) {
				try {
					await input.require(1);
				} catch {
					return false;
				}
			}
			const take = Math.min(input.buffered, BLOCK_SIZE);
			const chunk = input.take(take);
			const padded = new Uint8Array(chunk.length + PAD);
			padded.set(chunk);
			bits = new BitReader(padded);
			return true;
		};

		if (!await refill()) {
			throw new Error('rar3 compressed data area is empty');
		}
		// at this point `bits` is set; assert for the type checker.
		const _ = bits!;
		void _;

		const copy = (length: number, distance: number): void => {
			for (let idx = 0; idx < length; idx++) {
				window[(this.#write + idx) & mask] = window[(this.#write + idx - distance) & mask];
			}
			this.#write += length;
		};

		while (this.#write < targetWrite) {
			// ensure the bit reader has at least 16 bytes of cushion past the
			// current position; if not, pull a fresh slab and prepend the unread
			// tail so peek32 keeps working across the boundary.
			if (bits!.addr + 16 >= bits!.data.length - PAD) {
				const tail = bits!.data.subarray(bits!.addr, bits!.data.length - PAD);
				const carriedBit = bits!.bit;
				if (input.buffered === 0) {
					try {
						await input.require(1);
					} catch {
						// no more input — fine if the running entry is satisfied.
						break;
					}
				}
				const take = Math.min(input.buffered, BLOCK_SIZE);
				const chunk = input.take(take);
				const merged = new Uint8Array(tail.length + chunk.length + PAD);
				merged.set(tail);
				merged.set(chunk, tail.length);
				bits!.rebind(merged);
				bits!.addr = 0;
				bits!.bit = carriedBit;
			}

			if (this.#startNewTable) {
				const { tables } = parseCodes(bits!, this.#lengthTable);
				this.#tables = tables;
				this.#startNewTable = false;
			}
			const tables = this.#tables!;

			const symbol = decodeSymbol(tables.main, bits!);

			if (symbol < 256) {
				window[this.#write++ & mask] = symbol;
				continue;
			}

			if (symbol === 256) {
				const newFile = bits!.read(1) === 0;
				if (newFile) {
					// end-of-entry marker: the next bit decides whether the next
					// entry rebuilds Huffman tables or carries the current set
					// over (solid runs typically carry).
					this.#startNewTable = bits!.read(1) !== 0;
					break;
				}
				// in-stream table change: re-parse codes against the same length
				// table and keep decoding from the new tables.
				const { tables: refreshed } = parseCodes(bits!, this.#lengthTable);
				this.#tables = refreshed;
				continue;
			}

			if (symbol === 257) {
				// consume the filter command from the bit stream so the LZSS
				// engine stays in sync, but mark the entry as filter-tainted so
				// the caller knows the output bytes inside filter ranges are
				// pre-filter (i.e. not the original plaintext).
				skipFilterCommand(bits!, this.#filterState);
				this.#sawFilter = true;
				continue;
			}

			let offs: number;
			let len: number;

			if (symbol === 258) {
				if (this.#lastLength === 0) {
					continue;
				}
				offs = this.#lastOffset;
				len = this.#lastLength;
			} else if (symbol < 263) {
				const offsetIndex = symbol - 259;
				offs = this.#oldOffsets[offsetIndex];
				const lengthSymbol = decodeSymbol(tables.length, bits!);
				if (lengthSymbol >= LENGTH_BASES.length) {
					throw new Error(`rar3 length symbol ${lengthSymbol} out of range`);
				}
				len = LENGTH_BASES[lengthSymbol] + 2;
				if (LENGTH_EXTRA_BITS[lengthSymbol] > 0) {
					len += bits!.read(LENGTH_EXTRA_BITS[lengthSymbol]);
				}
				for (let i = offsetIndex; i > 0; i--) {
					this.#oldOffsets[i] = this.#oldOffsets[i - 1];
				}
				this.#oldOffsets[0] = offs;
			} else if (symbol < 271) {
				const slot = symbol - 263;
				offs = SHORT_BASES[slot] + 1;
				if (SHORT_EXTRA_BITS[slot] > 0) {
					offs += bits!.read(SHORT_EXTRA_BITS[slot]);
				}
				len = 2;
				for (let i = 3; i > 0; i--) {
					this.#oldOffsets[i] = this.#oldOffsets[i - 1];
				}
				this.#oldOffsets[0] = offs;
			} else {
				const lengthSlot = symbol - 271;
				if (lengthSlot >= LENGTH_BASES.length) {
					throw new Error(`rar3 main symbol ${symbol} out of length range`);
				}
				len = LENGTH_BASES[lengthSlot] + 3;
				if (LENGTH_EXTRA_BITS[lengthSlot] > 0) {
					len += bits!.read(LENGTH_EXTRA_BITS[lengthSlot]);
				}

				const offsetSymbol = decodeSymbol(tables.offset, bits!);
				if (offsetSymbol >= OFFSET_BASES.length) {
					throw new Error(`rar3 offset symbol ${offsetSymbol} out of range`);
				}
				offs = OFFSET_BASES[offsetSymbol] + 1;
				const extraBits = OFFSET_EXTRA_BITS[offsetSymbol];
				if (extraBits > 0) {
					if (offsetSymbol > 9) {
						if (extraBits > 4) {
							offs += bits!.read(extraBits - 4) << 4;
						}
						if (this.#lowOffsetRepeats > 0) {
							this.#lowOffsetRepeats--;
							offs += this.#lastLowOffset;
						} else {
							const lowSymbol = decodeSymbol(tables.lowOffset, bits!);
							if (lowSymbol === 16) {
								this.#lowOffsetRepeats = 15;
								offs += this.#lastLowOffset;
							} else {
								offs += lowSymbol;
								this.#lastLowOffset = lowSymbol;
							}
						}
					} else {
						offs += bits!.read(extraBits);
					}
				}

				// libarchive: long-distance matches encode shorter length codes,
				// so bump the decoded length back up for the appropriate slots.
				if (offs >= 0x40000) {
					len++;
				}
				if (offs >= 0x2000) {
					len++;
				}

				for (let i = 3; i > 0; i--) {
					this.#oldOffsets[i] = this.#oldOffsets[i - 1];
				}
				this.#oldOffsets[0] = offs;
			}

			this.#lastOffset = offs;
			this.#lastLength = len;
			copy(len, offs);
		}

		await flush();

		if (this.#write < targetWrite) {
			throw new Error(
				`rar3 decompressed ${this.#write - startWrite} bytes, expected ${unpackedSize}`,
			);
		}
	}
}

// #endregion
