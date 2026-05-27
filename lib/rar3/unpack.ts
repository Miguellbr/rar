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

import { crc32 } from '../utils/crc32.ts';

import type { StreamReader } from '../utils/stream-reader.ts';
import { PPMD_CORRUPT, PPMD_END_OF_DATA, type PpmdByteIn, RAR3PpmdModel } from './ppmd.ts';

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

// the decision a parseCodes call hands back to the decoder loop: either a
// fresh set of Huffman tables (LZSS mode) or the parameters needed to
// initialise or refresh the PPMd-H model.
type CodeMode =
	| { kind: 'huffman'; tables: Tables }
	| {
		kind: 'ppmd';
		/** present only on a "full reinit" block; the model is rebuilt with these */
		init?: { dictSize: number; maxorder: number };
		/** escape symbol value the decoder loop watches for */
		escape: number;
	};

// reads the four Huffman tables that drive the LZSS engine. `lengthtable`
// carries the per-symbol bit lengths across calls because RAR3 supports a
// "keep existing tables" mode: a 1 bit means amend the running table by the
// (signed-4-bit-delta-style) precode output; a 0 bit means start fresh from
// all zeros.
const parseCodes = (
	bits: BitReader,
	lengthTable: Uint8Array,
): CodeMode => {
	bits.alignByte();

	const ppmd = bits.read(1) !== 0;
	if (ppmd) {
		// PPMd-H block — 7 flag bits, then optionally dict size (8 bits) and
		// escape symbol (8 bits). flag bit 0x20 means "full reinit" (read dict
		// size + max order); without it we reuse the existing PPMd model but
		// still reinitialise the range decoder.
		const flags = bits.read(7);
		let dictSize: number | undefined;
		if ((flags & 0x20) !== 0) {
			dictSize = (bits.read(8) + 1) << 20;
		}
		let escape = 2;
		if ((flags & 0x40) !== 0) {
			escape = bits.read(8);
		}
		if ((flags & 0x20) !== 0) {
			let maxorder = (flags & 0x1f) + 1;
			if (maxorder > 16) {
				maxorder = 16 + (maxorder - 16) * 3;
			}
			if (maxorder < 2) {
				throw new Error(`rar3 ppmd maxorder ${maxorder} out of range`);
			}
			return { escape, init: { dictSize: dictSize!, maxorder }, kind: 'ppmd' };
		}
		return { escape, kind: 'ppmd' };
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

	return { kind: 'huffman', tables: { length, lowOffset, main, offset } };
};

// #endregion

// #region filters

// VM memory layout matches libarchive's PROGRAM_WORK_SIZE / VM_MEMORY_SIZE.
// the filter source bytes go in `[0, blockLength)` and the standard filters
// either rewrite in place (e8/e8e9) or write the result into
// `[blockLength, 2*blockLength)`. the upper bound (256 KiB) caps the
// per-filter range; archives that exceed it are malformed.
const VM_MEMORY_SIZE = 0x40000;
const PROGRAM_SYSTEM_GLOBAL_ADDRESS = 0x3c000;

// the standard RAR3 filter programs that ship with WinRAR. each entry's
// fingerprint is `(byteLength, crc32(bytecode))`; libarchive packs both into
// a uint64 (`length << 32 | crc`) for the same purpose.
const enum FilterKind {
	Audio,
	Delta,
	E8,
	E8E9,
	Rgb,
	Unknown,
}

const FILTER_FINGERPRINTS = new Map<string, FilterKind>([
	[`29:${(0x0e06077d).toString(16)}`, FilterKind.Delta],
	[`53:${(0xad576887).toString(16)}`, FilterKind.E8],
	[`57:${(0x3cd7e57e).toString(16)}`, FilterKind.E8E9],
	[`149:${(0x1c2c5dc8).toString(16)}`, FilterKind.Rgb],
	[`216:${(0xbc85e701).toString(16)}`, FilterKind.Audio],
]);

const fingerprint = (bytecode: Uint8Array): FilterKind => {
	const key = `${bytecode.length}:${crc32(bytecode).toString(16)}`;
	return FILTER_FINGERPRINTS.get(key) ?? FilterKind.Unknown;
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
			// libarchive `membr_next_rarvm_number` sign-extends low-high values
			// by OR-ing 0xFFFFFF00 into the 12-bit composite, producing a
			// negative int32 for high<16. blockstart/blocklength consumers
			// rely on the resulting negative offset.
			return (0xffffff00 | (high << 4) | this.bits(4)) | 0;
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

// a compiled (well, fingerprinted) filter program. the program list lives on
// the decoder state and is referenced by index in subsequent filter commands.
interface FilterProgram {
	kind: FilterKind;
	usageCount: number;
	oldFilterLength: number;
}

// a queued filter: its parsed parameters plus a pointer to the program. the
// LZSS engine emits its filter list one at a time as the LZ output catches up
// to each `blockStart`.
interface PendingFilter {
	prog: FilterProgram;
	/** in monotonic write coordinates (shared across the solid run). */
	blockStart: number;
	blockLength: number;
	/** registers[0..7]; non-zero entries come from the filter command. */
	registers: Uint32Array;
}

// the slice of decoder state that {@link parseFilterCommand} mutates.
interface Rar3DecoderState {
	programs: (FilterProgram | undefined)[];
	lastFilterNum: number;
	stack: PendingFilter[];
}

// reads one full filter command off the LZSS bit stream, enrolling its program
// in the decoder state on first sight and pushing a {@link PendingFilter} onto
// the stack. the program bytecode is fingerprinted against the standard
// WinRAR filter set; archives carrying a custom program raise an error at
// execute time (parse still succeeds so the LZSS bit stream stays in sync).
//
// the filter payload can be up to ~65 KiB long, far beyond the 16-byte refill
// cushion the main LZSS loop maintains. `ensureBytes` is the same refill
// closure the loop uses, called here to enlarge the bit reader's backing
// buffer before each composite read.
const parseFilterCommand = async (
	bits: BitReader,
	state: Rar3DecoderState,
	lzssPosition: number,
	windowSize: number,
	ensureBytes: (count: number) => Promise<void>,
): Promise<void> => {
	// flags + up to a 2-byte extended length prefix.
	await ensureBytes(3);
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

	// the program bytecode is `length` bytes; reserve extra cushion so the
	// next LZSS loop iteration's peek16/peek32 stays in-buffer too.
	await ensureBytes(length + 16);

	const code = new Uint8Array(length);
	for (let idx = 0; idx < length; idx++) {
		code[idx] = readByte(bits);
	}

	const mbr = new MemoryBitReader(code);

	let progIndex: number;
	if (flags & 0x80) {
		const num = mbr.number();
		if (num === 0) {
			state.programs.length = 0;
			state.stack.length = 0;
			progIndex = 0;
		} else {
			progIndex = num - 1;
		}
		if (progIndex > state.programs.length) {
			throw new Error(`rar3 filter command references program ${progIndex} past list end`);
		}
		state.lastFilterNum = progIndex;
	} else {
		progIndex = state.lastFilterNum;
	}
	let prog = state.programs[progIndex];

	// blockStart is signed (small-magnitude values come back negative through
	// `mbr.number`'s sign extension) and adds onto the current LZSS write
	// position; flag 0x40 bumps it by 258 (the "long form").
	let blockStart = mbr.number() + lzssPosition;
	if (flags & 0x40) {
		blockStart += 258;
	}

	let blockLength: number;
	if (flags & 0x20) {
		blockLength = mbr.number();
	} else {
		blockLength = prog?.oldFilterLength ?? 0;
	}

	if (blockLength > windowSize || blockLength > VM_MEMORY_SIZE) {
		throw new Error(
			`rar3 filter block length ${blockLength} exceeds window (${windowSize}) or VM cap`,
		);
	}

	// libarchive's parse_filter seeds the register file with the system
	// global address, the block length, and the program usage count.
	const registers = new Uint32Array(8);
	registers[3] = PROGRAM_SYSTEM_GLOBAL_ADDRESS;
	registers[4] = blockLength;
	registers[5] = prog?.usageCount ?? 0;
	registers[7] = VM_MEMORY_SIZE;

	if (flags & 0x10) {
		const mask = mbr.bits(7);
		for (let idx = 0; idx < 7; idx++) {
			if (mask & (1 << idx)) {
				registers[idx] = mbr.number() >>> 0;
			}
		}
	}

	if (prog === undefined) {
		const len = mbr.number();
		if (len === 0 || len > 0x10000) {
			throw new Error(`rar3 filter bytecode length ${len} out of range`);
		}
		const bytecode = new Uint8Array(len);
		for (let idx = 0; idx < len; idx++) {
			bytecode[idx] = mbr.bits(8);
		}
		// the bytecode carries an XOR checksum in byte 0; libarchive uses it
		// to reject corrupted programs before computing the fingerprint.
		let xor = 0;
		for (let idx = 1; idx < len; idx++) {
			xor ^= bytecode[idx];
		}
		if (xor !== bytecode[0]) {
			throw new Error('rar3 filter bytecode XOR checksum mismatch');
		}
		prog = { kind: fingerprint(bytecode), oldFilterLength: 0, usageCount: 1 };
		state.programs[progIndex] = prog;
	} else {
		prog.usageCount++;
	}
	prog.oldFilterLength = blockLength;

	// optional global-data overlay. the standard filters don't consult it, so
	// we just walk past the bits to keep the MemoryBitReader in sync.
	if (flags & 0x08) {
		const len = mbr.number();
		for (let idx = 0; idx < len; idx++) {
			mbr.bits(8);
		}
	}

	state.stack.push({ blockLength, blockStart, prog, registers });
};

// transforms one filter's input bytes (`source`, taken from the window) into
// the post-filter output. the standard executors are translated from
// libarchive's `execute_filter_*` helpers.
//
// `entryPos` is the entry-relative offset where the filter's range begins; the
// e8/e8e9 filter uses it as the base for its absolute-address rewrites, while
// the others ignore it.
const runFilter = (filter: PendingFilter, source: Uint8Array, entryPos: number): Uint8Array => {
	const { blockLength, prog, registers } = filter;

	switch (prog.kind) {
		case FilterKind.Delta: {
			const channels = registers[0];
			if (channels === 0) {
				throw new Error('rar3 delta filter with zero channels');
			}
			const result = new Uint8Array(blockLength);
			let srcIdx = 0;
			for (let ch = 0; ch < channels; ch++) {
				let prev = 0;
				for (let dst = ch; dst < blockLength; dst += channels) {
					prev = (prev - source[srcIdx++]) & 0xff;
					result[dst] = prev;
				}
			}
			return result;
		}
		case FilterKind.E8:
		case FilterKind.E8E9: {
			const e9also = prog.kind === FilterKind.E8E9;
			const fileSize = 0x1000000;
			const out = new Uint8Array(blockLength);
			out.set(source.subarray(0, blockLength));
			if (blockLength <= 4) {
				return out;
			}
			for (let i = 0; i + 5 <= blockLength;) {
				const op = out[i];
				if (op === 0xe8 || (e9also && op === 0xe9)) {
					const currpos = (entryPos + i + 1) >>> 0;
					const address = readLe32(out, i + 1) | 0;
					if (address < 0 && currpos >= (-address >>> 0)) {
						writeLe32(out, i + 1, (address + fileSize) >>> 0);
					} else if (address >= 0 && address < fileSize) {
						writeLe32(out, i + 1, (address - currpos) >>> 0);
					}
					i += 5;
				} else {
					i++;
				}
			}
			return out;
		}
		case FilterKind.Rgb: {
			const stride = registers[0];
			const byteOffset = registers[1];
			if (stride === 0 || stride > blockLength || blockLength < 3 || byteOffset > 2) {
				throw new Error('rar3 rgb filter parameters invalid');
			}
			const result = new Uint8Array(blockLength);
			let src = 0;
			for (let i = 0; i < 3; i++) {
				let byte = 0;
				// `prev` walks the previous scanline; it starts negative for the
				// first row (no prior data) and the predictor falls through.
				let prev = i - stride;
				for (let j = i; j < blockLength; j += 3) {
					if (prev >= 0 && prev + 3 < blockLength) {
						const a = result[prev + 3];
						const b = result[prev];
						const delta1 = Math.abs(a - b);
						const delta2 = Math.abs(byte - b);
						const delta3 = Math.abs(a - b + byte - b);
						if (delta1 > delta2 || delta1 > delta3) {
							byte = delta2 <= delta3 ? a : b;
						}
					}
					byte = (byte - source[src++]) & 0xff;
					result[j] = byte;
					prev += 3;
				}
			}
			for (let i = byteOffset; i + 2 < blockLength; i += 3) {
				result[i] = (result[i] + result[i + 1]) & 0xff;
				result[i + 2] = (result[i + 2] + result[i + 1]) & 0xff;
			}
			return result;
		}
		case FilterKind.Audio: {
			const channels = registers[0];
			if (channels === 0) {
				throw new Error('rar3 audio filter with zero channels');
			}
			const result = new Uint8Array(blockLength);
			let src = 0;
			for (let ch = 0; ch < channels; ch++) {
				const error = [0, 0, 0, 0, 0, 0, 0];
				const weight = [0, 0, 0];
				const delta = [0, 0, 0];
				let lastByte = 0;
				let lastDelta = 0;
				let count = 0;
				for (let j = ch; j < blockLength; j += channels) {
					const deltaIn = (source[src++] << 24) >> 24; // int8
					delta[2] = delta[1];
					delta[1] = lastDelta - delta[0];
					delta[0] = lastDelta;
					const predicted = ((8 * lastByte +
						weight[0] * delta[0] +
						weight[1] * delta[1] +
						weight[2] * delta[2]) >> 3) & 0xff;
					const byte = (predicted - deltaIn) & 0xff;
					const predError = deltaIn << 3;
					error[0] += Math.abs(predError);
					error[1] += Math.abs(predError - delta[0]);
					error[2] += Math.abs(predError + delta[0]);
					error[3] += Math.abs(predError - delta[1]);
					error[4] += Math.abs(predError + delta[1]);
					error[5] += Math.abs(predError - delta[2]);
					error[6] += Math.abs(predError + delta[2]);
					lastDelta = (byte - lastByte) << 24 >> 24; // int8 wrap
					lastByte = byte;
					result[j] = byte;
					if ((count++ & 0x1f) === 0) {
						let idx = 0;
						for (let k = 1; k < 7; k++) {
							if (error[k] < error[idx]) {
								idx = k;
							}
						}
						error.fill(0);
						switch (idx) {
							case 1:
								if (weight[0] >= -16) weight[0]--;
								break;
							case 2:
								if (weight[0] < 16) weight[0]++;
								break;
							case 3:
								if (weight[1] >= -16) weight[1]--;
								break;
							case 4:
								if (weight[1] < 16) weight[1]++;
								break;
							case 5:
								if (weight[2] >= -16) weight[2]--;
								break;
							case 6:
								if (weight[2] < 16) weight[2]++;
								break;
						}
					}
				}
			}
			return result;
		}
		case FilterKind.Unknown: {
			throw new Error('rar3 filter program is not one of the standard set');
		}
	}
};

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
 * length, last low-offset, Huffman length table and tables themselves, the bit
 * reader, and the VM filter list across calls. consecutive
 * {@link Rar3Decoder.decode} calls represent the entries of a solid run
 * sharing one state.
 *
 * filter execution covers the standard WinRAR programs (e8, e8e9, delta, rgb,
 * audio); archives carrying a custom bytecode raise an "unknown filter
 * program" error when the filter would execute.
 */
export class Rar3Decoder {
	/** the maximum window size implied by the file header's dictionary flag,
	 * rounded up to a power of two. matches with distance up to this value can
	 * appear in the bit stream. */
	readonly #targetSize: number;
	/** the actually-allocated window. starts at zero length and grows toward
	 * `#targetSize` only when an entry's expected output (or accumulated solid
	 * history) requires more. for small archives the window never reaches
	 * `#targetSize`, sparing a multi-megabyte allocation up front. */
	#window: Uint8Array = new Uint8Array(0);
	#windowMask = 0;

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
	/**
	 * PPMd-H state carried across solid-run entries. lifetime mirrors `#tables`
	 * — re-set at every block boundary based on what `parseCodes` returns.
	 */
	#ppmd?: { model: RAR3PpmdModel; escape: number };
	/** filter program list and pending filter queue, shared across the solid run. */
	readonly #filterState: Rar3DecoderState = { lastFilterNum: 0, programs: [], stack: [] };
	/**
	 * filters whose range is fully written and whose post-filter bytes are
	 * computed, waiting to be overlaid on top of the emit chunks they cover.
	 * keyed by the filter's `blockStart` in write-pointer coordinates.
	 */
	readonly #ready = new Map<number, Uint8Array>();

	/**
	 * @param dictionarySize the dictionary size declared by the file header.
	 * the window is rounded up to the next power of two but never above the
	 * RAR3 cap of 4 MiB.
	 */
	constructor(dictionarySize: number) {
		let target = 1;
		while (target < dictionarySize) {
			target <<= 1;
		}
		if (target === 0 || target > MAX_DICTIONARY) {
			target = MAX_DICTIONARY;
		}
		this.#targetSize = target;
	}

	/** the dictionary capacity this decoder was sized for. the underlying
	 * window may currently be smaller (lazy-allocated to fit decoded content),
	 * but matches with distances up to this value are guaranteed handlable. */
	get windowSize(): number {
		return this.#targetSize;
	}

	/**
	 * ensures the window can hold at least `neededWrite` bytes contiguously
	 * (no circular wraparound), up to `#targetSize`. on growth, existing
	 * contents at positions `[0, #write)` are preserved one-to-one — this is
	 * safe because we only grow while still in the no-wrap regime where every
	 * byte sits at its logical address.
	 */
	#ensureCapacity(neededWrite: number): void {
		const current = this.#window.length;
		if (current >= this.#targetSize) {
			return;
		}
		if (current >= neededWrite) {
			return;
		}
		let cap = current === 0 ? 1 : current;
		while (cap < neededWrite) {
			cap <<= 1;
		}
		if (cap > this.#targetSize) {
			cap = this.#targetSize;
		}
		const grown = new Uint8Array(cap);
		if (this.#write > 0) {
			grown.set(this.#window.subarray(0, this.#write));
		}
		this.#window = grown;
		this.#windowMask = cap - 1;
	}

	/**
	 * resets the carry-over state so this decoder can be driven for a fresh
	 * non-solid entry without reallocating the multi-megabyte window. clears
	 * write position, distance cache, Huffman tables, PPMd state, and filter
	 * queue; the window bytes themselves are left intact (LZ matches can only
	 * reference positions in `[0, write)`, so stale bytes are unreachable).
	 */
	reset(): void {
		this.#oldOffsets = [0, 0, 0, 0];
		this.#lastOffset = 0;
		this.#lastLength = 0;
		this.#lastLowOffset = 0;
		this.#lowOffsetRepeats = 0;
		this.#write = 0;
		this.#lengthTable.fill(0);
		this.#tables = undefined;
		this.#startNewTable = true;
		this.#ppmd = undefined;
		this.#filterState.lastFilterNum = 0;
		this.#filterState.programs.length = 0;
		this.#filterState.stack.length = 0;
		this.#ready.clear();
	}

	/**
	 * decodes the data area of one RAR3 file entry, appending its bytes to the
	 * shared window and emitting decoded chunks to `sink` as they settle.
	 *
	 * compressed bytes are pulled from `input` in 64 KiB blocks. across a
	 * solid run, the Huffman tables, distance cache, and pending filter list
	 * carry over so the next entry's first symbols can reference them.
	 *
	 * filter commands (symbol 257) are parsed, their programs are fingerprinted
	 * against the standard WinRAR filter set, and they execute when their range
	 * is fully written — the resulting post-filter bytes overlay the raw LZ
	 * output before reaching the sink.
	 *
	 * @param input compressed bytes of the entry's data area, in order
	 * @param unpackedSize the expected uncompressed size
	 * @param sink receives each decoded chunk in order
	 * @throws if the stream is invalid, requests PPMd, or carries a filter
	 * program outside the standard set
	 */
	async decode(input: StreamReader, unpackedSize: number, sink: DecodeSink): Promise<void> {
		// size the window to fit this entry's output (plus any accumulated
		// solid-run history), capped at the declared dictionary target. this
		// is the only point growth can happen — after this the locals below
		// pin the buffer for the entry.
		this.#ensureCapacity(this.#write + unpackedSize);

		const mask = this.#windowMask;
		const window = this.#window;
		const windowSize = window.length;
		const startWrite = this.#write;
		const targetWrite = startWrite + unpackedSize;

		// the longest single LZ copy is ~260 bytes (length base 224 + 31 extra
		// + base bumps); leave generous headroom so periodic flushing always
		// runs before the next iteration could overwrite unflushed window data.
		// when the window grew exactly to fit this entry (still below the
		// declared cap), writes won't wrap, so unflushed bytes are safe — set
		// the threshold past `targetWrite` to disable mid-flushing entirely.
		const FLUSH_MARGIN = 512;
		const FLUSH_HIGH_WATER = targetWrite > windowSize
			? windowSize - FLUSH_MARGIN
			: unpackedSize + 1;

		let emitted = startWrite;

		// for any pending filter whose range is now complete, stage the source
		// bytes from the window and run the filter (chaining when consecutive
		// filters share the same blockStart/blockLength). filtered bytes land
		// in `#ready` keyed by blockStart so the next emit can overlay them.
		const tryRunFilters = (): void => {
			const stillPending: PendingFilter[] = [];
			let lastFiltered: Uint8Array | undefined;
			let lastBlockStart = -1;
			let lastBlockLength = -1;
			for (const f of this.#filterState.stack) {
				const end = f.blockStart + f.blockLength;
				if (this.#write < end) {
					stillPending.push(f);
					continue;
				}
				if (f.blockStart < emitted) {
					throw new Error('rar3 filter range begins before already-emitted bytes');
				}
				let source: Uint8Array;
				if (
					f.blockStart === lastBlockStart && f.blockLength === lastBlockLength &&
					lastFiltered !== undefined
				) {
					// chained: same range as the previous filter, source is its output.
					source = lastFiltered;
				} else {
					source = new Uint8Array(f.blockLength);
					// monotonic range in the circular window — at most one wrap.
					const startInWindow = f.blockStart & mask;
					if (startInWindow + f.blockLength <= windowSize) {
						source.set(window.subarray(startInWindow, startInWindow + f.blockLength));
					} else {
						const partA = windowSize - startInWindow;
						source.set(window.subarray(startInWindow));
						source.set(window.subarray(0, f.blockLength - partA), partA);
					}
				}
				const entryPos = f.blockStart - startWrite;
				const filtered = runFilter(f, source, entryPos);
				this.#ready.set(f.blockStart, filtered);
				lastFiltered = filtered;
				lastBlockStart = f.blockStart;
				lastBlockLength = f.blockLength;
			}
			this.#filterState.stack = stillPending;
		};

		// drain bytes from the window into one chunk and pass it to the sink.
		// called periodically inside the loop so that the unflushed window slice
		// never reaches `windowSize`, which would let later writes wrap over
		// and overwrite bytes the sink has not yet received. emission is
		// bounded by the earliest still-pending filter's start, and ready
		// filters' post-filter bytes overlay the chunk in place.
		const flush = async (final: boolean): Promise<void> => {
			tryRunFilters();

			let safeEnd = final ? targetWrite : Math.min(this.#write, targetWrite);
			for (const f of this.#filterState.stack) {
				if (f.blockStart < safeEnd) {
					safeEnd = f.blockStart;
				}
			}
			if (safeEnd <= emitted) {
				return;
			}

			const size = safeEnd - emitted;
			const chunk = new Uint8Array(size);
			// copy from the window using typed-array `set()` instead of a
			// byte loop. the window is circular, so a single contiguous
			// monotonic range can wrap; in that case fall back to two sets.
			const startInWindow = emitted & mask;
			if (startInWindow + size <= windowSize) {
				chunk.set(window.subarray(startInWindow, startInWindow + size));
			} else {
				const partA = windowSize - startInWindow;
				chunk.set(window.subarray(startInWindow));
				chunk.set(window.subarray(0, size - partA), partA);
			}

			// overlay ready filters whose range intersects the chunk. any
			// portion that tails past `safeEnd` stays in `#ready` for the
			// next emit cycle.
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

		// pulls a contiguous slab of compressed bytes large enough that the
		// inner loop can run for a while without re-checking. 64 KiB matches
		// libarchive's `UNP_BUFFER_SIZE / 2`, leaves headroom for the longest
		// composite read (a few dozen bits), and lets `peek32` look past the
		// nominal end safely thanks to 8 trailing pad bytes.
		const BLOCK_SIZE = 64 * 1024;
		const PAD = 8;
		let bits: BitReader | undefined;

		// grows the bit reader's backing buffer until it has at least `count`
		// bytes available past the current position (plus PAD). when the
		// source is exhausted but the bit reader still has unread bytes,
		// returns true — peek16/peek32 stay safe thanks to the PAD cushion
		// and the encoder's last symbols sit at the tail of the real data.
		// only returns false once the bit reader has nothing usable left.
		const ensureBytes = async (count: number): Promise<boolean> => {
			while (bits === undefined || bits.addr + count > bits.data.length - PAD) {
				if (input.buffered === 0) {
					try {
						await input.require(1);
					} catch {
						return bits !== undefined && bits.addr + 5 <= bits.data.length;
					}
				}
				const take = Math.min(input.buffered, BLOCK_SIZE);
				const chunk = input.take(take);
				if (bits === undefined) {
					const padded = new Uint8Array(chunk.length + PAD);
					padded.set(chunk);
					bits = new BitReader(padded);
					continue;
				}
				const tail = bits.data.subarray(bits.addr, bits.data.length - PAD);
				const carriedBit = bits.bit;
				const merged = new Uint8Array(tail.length + chunk.length + PAD);
				merged.set(tail);
				merged.set(chunk, tail.length);
				bits.rebind(merged);
				bits.addr = 0;
				bits.bit = carriedBit;
			}
			return true;
		};

		// `skipFilterCommand` calls ensureBytes too, but bits is rebound in
		// place so its local reference stays valid. wrap it so the throwing
		// `ensureBytes` variant is hidden behind a void-returning shim that
		// the filter parser can `await` without worrying about exhaustion mid
		// command (which would be a malformed archive).
		const ensureBytesOrThrow = async (count: number): Promise<void> => {
			if (!await ensureBytes(count)) {
				throw new Error('rar3 filter command extends past end of compressed data');
			}
		};

		if (!await ensureBytes(16)) {
			if (unpackedSize === 0) {
				// 0-byte entry with no data area: nothing to do. solid follow-ups
				// will start cleanly because the bit position is unchanged.
				return;
			}
			throw new Error('rar3 compressed data area is empty');
		}
		// at this point `bits` is set; assert for the type checker.
		const _ = bits!;
		void _;

		const copy = (length: number, distance: number): void => {
			const write = this.#write;
			// when source and destination ranges don't overlap (distance >=
			// length), and neither end wraps the window, hand the copy off
			// to `copyWithin` — a single native memmove instead of a per-byte
			// js loop. the overlap case (distance < length) needs the runlength
			// repeat semantics: each new byte may be a byte we just wrote.
			if (distance >= length) {
				const dst = write & mask;
				const src = (write - distance) & mask;
				if (dst + length <= windowSize && src + length <= windowSize) {
					window.copyWithin(dst, src, src + length);
					this.#write = write + length;
					return;
				}
			}
			for (let idx = 0; idx < length; idx++) {
				window[(write + idx) & mask] = window[(write + idx - distance) & mask];
			}
			this.#write = write + length;
		};

		// the loop terminates on the symbol-256 end-of-entry marker rather than
		// on `write >= targetWrite`, so the marker is always consumed and a
		// follow-up solid entry begins at a clean bit position. the
		// write-overflow check at the top guards against malformed archives
		// that emit literals past the declared size.
		let endMarkerSeen = false;
		while (!endMarkerSeen) {
			if (this.#write > targetWrite) {
				throw new Error(`rar3 wrote past expected ${unpackedSize} bytes`);
			}

			// keep at most `windowSize - 512` bytes unflushed so the next
			// iteration's copy can't overwrite bytes that haven't reached the
			// sink. for a small entry this typically only runs at the end.
			if (this.#write - emitted >= FLUSH_HIGH_WATER) {
				await flush(false);
			}

			if (!await ensureBytes(16)) {
				// no more input — the caller validates write < targetWrite below.
				break;
			}

			if (this.#startNewTable) {
				const mode = parseCodes(bits!, this.#lengthTable);
				if (mode.kind === 'huffman') {
					this.#tables = mode.tables;
					this.#ppmd = undefined;
				} else {
					this.#tables = undefined;
					if (mode.init === undefined && this.#ppmd === undefined) {
						throw new Error(
							'rar3 ppmd reuse block with no prior model state',
						);
					}
					// the byte source has to be rebound per block — entry 2 of
					// a solid run would get its own BitReader, not the one we
					// built the model with — so the stream object always points
					// at the current call's bit reader.
					const ppmdStream: PpmdByteIn = {
						read: () => {
							if (bits!.bit !== 0) {
								bits!.alignByte();
							}
							if (bits!.addr >= bits!.data.length - 8) {
								return 0;
							}
							return bits!.read(8);
						},
					};
					// drain whatever's still in flight so the sync PPMd decoder
					// won't run out of bytes mid-symbol. PPMd archives in the
					// wild fit comfortably in memory at per-entry granularity.
					await ensureBytes(1 << 30);
					bits!.alignByte();
					const model = mode.init !== undefined ? new RAR3PpmdModel(mode.init.dictSize) : this.#ppmd!.model;
					if (!model.initRangeDecoder(ppmdStream)) {
						throw new Error('rar3 ppmd range decoder init failed');
					}
					if (mode.init !== undefined) {
						model.initEsc = mode.escape;
						model.init(mode.init.maxorder);
					}
					this.#ppmd = { escape: mode.escape, model };
				}
				this.#startNewTable = false;
			}

			if (this.#ppmd !== undefined) {
				const { model, escape } = this.#ppmd;
				// PPMd entries terminate on an in-stream end-of-data marker
				// (escape + code 2). we must consume it — even after the
				// output budget is met — so the model state stays in sync
				// with the encoder for the next solid entry.
				for (;;) {
					if (this.#write > targetWrite) {
						throw new Error(`rar3 wrote past expected ${unpackedSize} bytes`);
					}
					if (this.#write - emitted >= FLUSH_HIGH_WATER) {
						await flush(false);
					}

					const sym = model.decodeSymbol();
					if (sym === PPMD_CORRUPT || sym === PPMD_END_OF_DATA) {
						throw new Error('rar3 ppmd: decoder reported invalid symbol');
					}
					if (sym !== escape) {
						window[this.#write++ & mask] = sym;
						continue;
					}

					const code = model.decodeSymbol();
					if (code < 0) {
						throw new Error('rar3 ppmd: invalid escape code');
					}
					if (code === 0) {
						// in-stream "new table" marker: loop back to parseCodes.
						this.#startNewTable = true;
						break;
					}
					if (code === 2) {
						// end-of-data for the current entry. model state
						// survives; the next entry's decode() must re-parse a
						// fresh block header and re-prime the range decoder
						// against its own bit reader.
						this.#startNewTable = true;
						endMarkerSeen = true;
						break;
					}
					if (code === 3) {
						throw new Error('rar3 ppmd: filter commands are not supported');
					}
					if (code === 4) {
						let lzssOffset = 0;
						for (let i = 2; i >= 0; i--) {
							const piece = model.decodeSymbol();
							if (piece < 0) {
								throw new Error('rar3 ppmd: truncated offset symbol');
							}
							lzssOffset |= piece << (i * 8);
						}
						const length = model.decodeSymbol();
						if (length < 0) {
							throw new Error('rar3 ppmd: truncated length symbol');
						}
						copy(length + 32, lzssOffset + 2);
						continue;
					}
					if (code === 5) {
						const length = model.decodeSymbol();
						if (length < 0) {
							throw new Error('rar3 ppmd: truncated repeat length');
						}
						copy(length + 4, 1);
						continue;
					}
					// any other escape code: treat as a literal of the escape value.
					window[this.#write++ & mask] = sym;
				}

				if (endMarkerSeen) {
					break;
				}
				// fell out via the in-stream "new table" marker; loop back
				// to parseCodes for the refreshed block header.
				continue;
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
					endMarkerSeen = true;
					break;
				}
				// in-stream table change: re-parse codes against the same length
				// table and keep decoding from the new tables.
				const refreshed = parseCodes(bits!, this.#lengthTable);
				if (refreshed.kind !== 'huffman') {
					throw new Error('rar3 in-stream table refresh switched to ppmd unexpectedly');
				}
				this.#tables = refreshed.tables;
				continue;
			}

			if (symbol === 257) {
				// parse the filter command off the bit stream and stage it on
				// the decoder's filter stack; the queued filter will execute
				// when the LZSS engine has produced enough output to cover
				// its `[blockStart, blockStart + blockLength)` range.
				await parseFilterCommand(
					bits!,
					this.#filterState,
					this.#write,
					this.#targetSize,
					ensureBytesOrThrow,
				);
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

		await flush(true);

		if (this.#write < targetWrite) {
			throw new Error(
				`rar3 decompressed ${this.#write - startWrite} bytes, expected ${unpackedSize}`,
			);
		}
		if (emitted < targetWrite) {
			throw new Error(
				`rar3 pending filter prevents final emission past byte ${emitted - startWrite}`,
			);
		}
	}
}

// #endregion
