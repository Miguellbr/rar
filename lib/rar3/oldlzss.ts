/**
 * @module
 *
 * decoders for the LZSS streams used by RAR 1.5 and RAR 2.x. these legacy
 * formats are still needed to decompress oldComment subblocks embedded in
 * MAIN and FILE headers of pre-RAR3 archives; modern file data follows the
 * v29 LZSS engine in `unpack.ts` instead.
 *
 * the decoders are designed for the comment use case: in-memory, one-shot,
 * non-solid. they assume the caller has already isolated the compressed
 * stream and knows the decompressed length. neither decoder handles the
 * audio-track variant of RAR2.x — comments never carry audio blocks.
 *
 * structure (state machine and table values) follows RARLAB unrar's
 * `Unpack::Unpack15` / `Unpack::Unpack20` in `unpack15.cpp` / `unpack20.cpp`.
 * the implementation is a from-scratch TypeScript port (clean-room).
 */

import { MalformedArchiveError, UnsupportedFeatureError } from '../errors.ts';

// #region bit reader

// MSB-first bit reader. `fgetbits()` returns the next 16 bits without
// consuming them; `addbits(n)` advances by n bits. the backing buffer needs
// at least three zero-padding bytes past the last meaningful byte so a peek
// near the end of the stream cannot read past the buffer.
class BitReader {
	#data: Uint8Array;
	#addr = 0;
	#bit = 0;

	constructor(data: Uint8Array) {
		// pad with extra bytes so peeks near the end stay in bounds.
		const padded = new Uint8Array(data.length + 4);
		padded.set(data);
		this.#data = padded;
	}

	/** the next 16 bits, MSB-first, without consuming them. */
	peek16(): number {
		const a = this.#addr;
		const bits = (this.#data[a] << 16) | (this.#data[a + 1] << 8) | this.#data[a + 2];
		return (bits >>> (8 - this.#bit)) & 0xffff;
	}

	addbits(count: number): void {
		const total = this.#bit + count;
		this.#addr += total >>> 3;
		this.#bit = total & 7;
	}

	/** returns the next 16 bits and consumes `count` of them. */
	readbits(count: number): number {
		const value = this.peek16() >>> (16 - count);
		this.addbits(count);
		return value;
	}
}

// #endregion

// #region v15 tables

// the constant tables from `unpack15.cpp`. each `STARTHFx` and `STARTLx` is
// the minimum bit length for that table; `DEC_*` is a cumulative-distribution
// boundary array whose entries determine how many bits to consume; `POS_*` is
// the per-bit-length symbol-offset that DecodeNum adds at the end.
const STARTL1 = 2;
const STARTL2 = 3;
const STARTHF0 = 4;
const STARTHF1 = 5;
const STARTHF2 = 5;
const STARTHF3 = 6;
const STARTHF4 = 8;

const DEC_L1 = [0x8000, 0xa000, 0xc000, 0xd000, 0xe000, 0xea00, 0xee00, 0xf000, 0xf200, 0xf200, 0xffff];
const POS_L1 = [0, 0, 0, 2, 3, 5, 7, 11, 16, 20, 24, 32, 32];

const DEC_L2 = [0xa000, 0xc000, 0xd000, 0xe000, 0xea00, 0xee00, 0xf000, 0xf200, 0xf240, 0xffff];
const POS_L2 = [0, 0, 0, 0, 5, 7, 9, 13, 18, 22, 26, 34, 36];

const DEC_HF0 = [0x8000, 0xc000, 0xe000, 0xf200, 0xf200, 0xf200, 0xf200, 0xf200, 0xffff];
const POS_HF0 = [0, 0, 0, 0, 0, 8, 16, 24, 33, 33, 33, 33, 33];

const DEC_HF1 = [0x2000, 0xc000, 0xe000, 0xf000, 0xf200, 0xf200, 0xf7e0, 0xffff];
const POS_HF1 = [0, 0, 0, 0, 0, 0, 4, 44, 60, 76, 80, 80, 127];

const DEC_HF2 = [0x1000, 0x2400, 0x8000, 0xc000, 0xfa00, 0xffff, 0xffff, 0xffff];
const POS_HF2 = [0, 0, 0, 0, 0, 0, 2, 7, 53, 117, 233, 0, 0];

const DEC_HF3 = [0x0800, 0x2400, 0xee00, 0xfe80, 0xffff, 0xffff, 0xffff];
const POS_HF3 = [0, 0, 0, 0, 0, 0, 0, 2, 16, 218, 251, 0, 0];

const DEC_HF4 = [0xff00, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff];
const POS_HF4 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0];

// short-LZ length tables, indexed by huffman position 0..14. position 1 (for
// SHORT_LEN1) and position 3 (for SHORT_LEN2) are dynamically overridden by
// `Buf60 + 3` at lookup time — captured below as `Buf60Pos*`.
const SHORT_LEN1 = [1, 3, 4, 4, 5, 6, 7, 8, 8, 4, 4, 5, 6, 6, 4, 0];
const SHORT_XOR1 = [0, 0xa0, 0xd0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff, 0xc0, 0x80, 0x90, 0x98, 0x9c, 0xb0];
const SHORT_LEN2 = [2, 3, 3, 3, 4, 4, 5, 6, 6, 4, 4, 5, 6, 6, 4, 0];
const SHORT_XOR2 = [0, 0x40, 0x60, 0xa0, 0xd0, 0xe0, 0xf0, 0xf8, 0xfc, 0xc0, 0x80, 0x90, 0x98, 0x9c, 0xb0];

// #endregion

// #region v15 decoder

// `DecodeNum` from unpack15.cpp: looks up the high bits of `bits` (a 16-bit
// peeked value) in `decTab`, advancing the bit reader past the matched
// code. returns the symbol-table position.
const decodeNumV15 = (
	reader: BitReader,
	bits: number,
	startPos: number,
	decTab: readonly number[],
	posTab: readonly number[],
): number => {
	const num = bits & 0xfff0;
	let i = 0;
	while (i < decTab.length && decTab[i] <= num) {
		i++;
		startPos++;
	}
	reader.addbits(startPos);
	const prev = i > 0 ? decTab[i - 1] : 0;
	return ((num - prev) >>> (16 - startPos)) + posTab[startPos];
};

// initializes the ChSetB MTF table after the per-byte values have been
// seeded (each high byte = its rank). the low-byte "frequency" is set
// piecewise to 7..0 over 32-byte spans, matching `Unpack::CorrHuff` from
// unpack15.cpp. the same routine is reused at runtime to rebuild the table
// when a frequency saturates.
const corrHuff = (chset: Uint16Array, nToPl: Uint8Array): void => {
	let pos = 0;
	for (let i = 7; i >= 0; i--) {
		for (let j = 0; j < 32; j++, pos++) {
			chset[pos] = (chset[pos] & 0xff00) | i;
		}
	}
	nToPl.fill(0);
	for (let i = 6; i >= 0; i--) {
		nToPl[i] = (7 - i) * 32;
	}
};

interface State15 {
	reader: BitReader;
	window: Uint8Array;
	windowMask: number;
	out: Uint8Array;
	outIdx: number;
	unpPtr: number;
	prevPtr: number;
	firstWinDone: boolean;
	destUnpSize: number;

	oldDist: Int32Array;
	oldDistPtr: number;
	lastDist: number;
	lastLength: number;

	chSet: Uint16Array;
	chSetA: Uint16Array;
	chSetB: Uint16Array;
	chSetC: Uint16Array;
	nToPl: Uint8Array;
	nToPlB: Uint8Array;
	nToPlC: Uint8Array;

	flagBuf: number;
	flagsCnt: number;
	stMode: number;
	lCount: number;
	numHuf: number;

	avrPlc: number;
	avrPlcB: number;
	avrLn1: number;
	avrLn2: number;
	avrLn3: number;
	buf60: number;
	nlzb: number;
	nhfb: number;
	maxDist3: number;
}

const initState15 = (reader: BitReader, decompressedSize: number): State15 => {
	const WIN_SIZE = 0x10000;
	const state: State15 = {
		avrLn1: 0,
		avrLn2: 0,
		avrLn3: 0,
		avrPlc: 0x3500,
		avrPlcB: 0,
		buf60: 0,
		chSet: new Uint16Array(256),
		chSetA: new Uint16Array(256),
		chSetB: new Uint16Array(256),
		chSetC: new Uint16Array(256),
		destUnpSize: decompressedSize,
		firstWinDone: false,
		flagBuf: 0,
		flagsCnt: 0,
		lCount: 0,
		lastDist: 0,
		lastLength: 0,
		maxDist3: 0x2001,
		nhfb: 0x80,
		nlzb: 0x80,
		nToPl: new Uint8Array(256),
		nToPlB: new Uint8Array(256),
		nToPlC: new Uint8Array(256),
		numHuf: 0,
		oldDist: new Int32Array(4),
		oldDistPtr: 0,
		out: new Uint8Array(decompressedSize),
		outIdx: 0,
		prevPtr: 0,
		reader,
		stMode: 0,
		unpPtr: 0,
		window: new Uint8Array(WIN_SIZE),
		windowMask: WIN_SIZE - 1,
	};

	for (let i = 0; i < 256; i++) {
		state.chSet[i] = i << 8;
		state.chSetB[i] = i << 8;
		state.chSetA[i] = i;
		// ChSetC[i] = (-i & 0xff) << 8
		state.chSetC[i] = ((256 - i) & 0xff) << 8;
	}
	corrHuff(state.chSetB, state.nToPlB);
	return state;
};

const writeByte = (state: State15, byte: number): void => {
	state.window[state.unpPtr] = byte;
	if (state.outIdx < state.out.length) {
		state.out[state.outIdx++] = byte;
	}
	state.unpPtr = (state.unpPtr + 1) & state.windowMask;
};

// copies `length` bytes from `distance` back in the window. malformed
// streams may request distances that overshoot the populated dictionary; we
// emit zero bytes in that case, matching unrar's 2024.04.18 fix.
const copyString15 = (state: State15, distance: number, length: number): void => {
	state.destUnpSize -= length;
	const bad = (!state.firstWinDone && distance > state.unpPtr) ||
		distance > state.window.length ||
		distance === 0;

	while (length-- > 0) {
		const byte = bad ? 0 : state.window[(state.unpPtr - distance) & state.windowMask];
		writeByte(state, byte);
	}
};

// decodes the next flag byte into `state.flagBuf` using the chSetC MTF table.
// each flag bit (read MSB-first) selects the LZ-vs-Huffman branch in the
// main loop.
const getFlagsBuf = (state: State15): void => {
	const flagsPlace = decodeNumV15(state.reader, state.reader.peek16(), STARTHF2, DEC_HF2, POS_HF2);
	if (flagsPlace >= state.chSetC.length) {
		return;
	}

	const pos = flagsPlace;
	let flags: number;
	let newPlace: number;
	while (true) {
		flags = state.chSetC[pos];
		state.flagBuf = flags >>> 8;
		newPlace = state.nToPlC[flags & 0xff];
		state.nToPlC[flags & 0xff] = (newPlace + 1) & 0xff;
		flags = (flags + 1) & 0xffff;
		if ((flags & 0xff) !== 0) {
			break;
		}
		corrHuff(state.chSetC, state.nToPlC);
	}

	state.chSetC[pos] = state.chSetC[newPlace];
	state.chSetC[newPlace] = flags;
};

// decodes one byte via the chSet MTF table, choosing among five Hf
// tables by the rolling `avrPlc` average. updates the table position
// hierarchy and triggers a rebuild when a frequency saturates.
const huffDecode = (state: State15): void => {
	const bits = state.reader.peek16();
	let bytePlace: number;
	if (state.avrPlc > 0x75ff) {
		bytePlace = decodeNumV15(state.reader, bits, STARTHF4, DEC_HF4, POS_HF4);
	} else if (state.avrPlc > 0x5dff) {
		bytePlace = decodeNumV15(state.reader, bits, STARTHF3, DEC_HF3, POS_HF3);
	} else if (state.avrPlc > 0x35ff) {
		bytePlace = decodeNumV15(state.reader, bits, STARTHF2, DEC_HF2, POS_HF2);
	} else if (state.avrPlc > 0x0dff) {
		bytePlace = decodeNumV15(state.reader, bits, STARTHF1, DEC_HF1, POS_HF1);
	} else {
		bytePlace = decodeNumV15(state.reader, bits, STARTHF0, DEC_HF0, POS_HF0);
	}
	bytePlace &= 0xff;

	if (state.stMode !== 0) {
		if (bytePlace === 0 && bits > 0xfff) {
			bytePlace = 0x100;
		}
		bytePlace = (bytePlace - 1) & 0xffff;
		if (bytePlace === 0xffff) {
			// "end of state-mode" / fallback to a short distance copy.
			const bits2 = state.reader.peek16();
			state.reader.addbits(1);
			if ((bits2 & 0x8000) !== 0) {
				state.numHuf = 0;
				state.stMode = 0;
				return;
			}
			const length = (bits2 & 0x4000) !== 0 ? 4 : 3;
			state.reader.addbits(1);
			let distance = decodeNumV15(state.reader, state.reader.peek16(), STARTHF2, DEC_HF2, POS_HF2);
			distance = (distance << 5) | (state.reader.peek16() >>> 11);
			state.reader.addbits(5);
			copyString15(state, distance, length);
			return;
		}
	} else if (state.numHuf++ >= 16 && state.flagsCnt === 0) {
		state.stMode = 1;
	}

	state.avrPlc += bytePlace;
	state.avrPlc -= state.avrPlc >>> 8;
	state.nhfb += 16;
	if (state.nhfb > 0xff) {
		state.nhfb = 0x90;
		state.nlzb >>>= 1;
	}

	writeByte(state, state.chSet[bytePlace] >>> 8);
	state.destUnpSize--;

	while (true) {
		const cur = state.chSet[bytePlace];
		const idx = cur & 0xff;
		const newPlace = state.nToPl[idx];
		state.nToPl[idx] = (newPlace + 1) & 0xff;
		const next = (cur + 1) & 0xffff;
		if ((next & 0xff) > 0xa1) {
			corrHuff(state.chSet, state.nToPl);
		} else {
			state.chSet[bytePlace] = state.chSet[newPlace];
			state.chSet[newPlace] = next;
			return;
		}
	}
};

const shortLen1At = (state: State15, pos: number): number => {
	return pos === 1 ? state.buf60 + 3 : SHORT_LEN1[pos];
};

const shortLen2At = (state: State15, pos: number): number => {
	return pos === 3 ? state.buf60 + 3 : SHORT_LEN2[pos];
};

// decodes a short-range match. small fixed table of xor codes selects the
// length symbol; distances are reused from the recent-distance ring.
const shortLZ = (state: State15): void => {
	state.numHuf = 0;
	let bitField = state.reader.peek16();
	if (state.lCount === 2) {
		state.reader.addbits(1);
		if (bitField >= 0x8000) {
			copyString15(state, state.lastDist, state.lastLength);
			return;
		}
		bitField = (bitField << 1) & 0xffff;
		state.lCount = 0;
	}

	bitField >>>= 8;

	const useTable1 = state.avrLn1 < 37;
	const lookup = useTable1 ? shortLen1At : shortLen2At;
	const xor = useTable1 ? SHORT_XOR1 : SHORT_XOR2;

	let length = 0;
	while (true) {
		const len = lookup(state, length);
		if (((bitField ^ xor[length]) & (~(0xff >>> len) & 0xff)) === 0) {
			break;
		}
		length++;
	}
	state.reader.addbits(lookup(state, length));

	if (length >= 9) {
		if (length === 9) {
			state.lCount++;
			copyString15(state, state.lastDist, state.lastLength);
			return;
		}
		if (length === 14) {
			state.lCount = 0;
			length = decodeNumV15(state.reader, state.reader.peek16(), STARTL2, DEC_L2, POS_L2) + 5;
			const distance = ((state.reader.peek16() >>> 1) | 0x8000) >>> 0;
			state.reader.addbits(15);
			state.lastLength = length;
			state.lastDist = distance;
			copyString15(state, distance, length);
			return;
		}

		state.lCount = 0;
		const saveLength = length;
		const distance = state.oldDist[(state.oldDistPtr - (length - 9)) & 3] & 0xffffffff;
		length = decodeNumV15(state.reader, state.reader.peek16(), STARTL1, DEC_L1, POS_L1) + 2;
		if (length === 0x101 && saveLength === 10) {
			state.buf60 ^= 1;
			return;
		}
		let adjLen = length;
		if (distance > 256) adjLen++;
		if (distance >= state.maxDist3) adjLen++;

		state.oldDist[state.oldDistPtr] = distance;
		state.oldDistPtr = (state.oldDistPtr + 1) & 3;
		state.lastLength = adjLen;
		state.lastDist = distance;
		copyString15(state, distance, adjLen);
		return;
	}

	state.lCount = 0;
	state.avrLn1 += length;
	state.avrLn1 -= state.avrLn1 >>> 4;

	const distPlace = decodeNumV15(state.reader, state.reader.peek16(), STARTHF2, DEC_HF2, POS_HF2) & 0xff;
	let distance = state.chSetA[distPlace];
	const newDistPlace = distPlace - 1;
	if (newDistPlace !== -1) {
		const lastDistance = state.chSetA[newDistPlace];
		state.chSetA[newDistPlace + 1] = lastDistance;
		state.chSetA[newDistPlace] = distance;
	}
	length += 2;
	distance += 1;
	state.oldDist[state.oldDistPtr] = distance;
	state.oldDistPtr = (state.oldDistPtr + 1) & 3;
	state.lastLength = length;
	state.lastDist = distance;
	copyString15(state, distance, length);
};

// decodes a long-range match. length and distance-place are chosen via the
// `avrLn2` / `avrPlcB` adaptive averages; the final distance comes from the
// chSetB MTF table plus a 7-bit suffix.
const longLZ = (state: State15): void => {
	state.numHuf = 0;
	state.nlzb += 16;
	if (state.nlzb > 0xff) {
		state.nlzb = 0x90;
		state.nhfb >>>= 1;
	}
	const oldAvr2 = state.avrLn2;

	let bitField = state.reader.peek16();
	let length: number;
	if (state.avrLn2 >= 122) {
		length = decodeNumV15(state.reader, bitField, STARTL2, DEC_L2, POS_L2);
	} else if (state.avrLn2 >= 64) {
		length = decodeNumV15(state.reader, bitField, STARTL1, DEC_L1, POS_L1);
	} else if (bitField < 0x100) {
		length = bitField;
		state.reader.addbits(16);
	} else {
		let bits = 0;
		while (((bitField << bits) & 0x8000) === 0) {
			bits++;
		}
		state.reader.addbits(bits + 1);
		length = bits;
	}

	state.avrLn2 += length;
	state.avrLn2 -= state.avrLn2 >>> 5;

	bitField = state.reader.peek16();
	let distPlace: number;
	if (state.avrPlcB > 0x28ff) {
		distPlace = decodeNumV15(state.reader, bitField, STARTHF2, DEC_HF2, POS_HF2);
	} else if (state.avrPlcB > 0x6ff) {
		distPlace = decodeNumV15(state.reader, bitField, STARTHF1, DEC_HF1, POS_HF1);
	} else {
		distPlace = decodeNumV15(state.reader, bitField, STARTHF0, DEC_HF0, POS_HF0);
	}

	state.avrPlcB += distPlace;
	state.avrPlcB -= state.avrPlcB >>> 8;

	let distance: number;
	let newDistPlace = 0;
	while (true) {
		distance = state.chSetB[distPlace & 0xff];
		newDistPlace = state.nToPlB[distance & 0xff];
		state.nToPlB[distance & 0xff] = (newDistPlace + 1) & 0xff;
		distance = (distance + 1) & 0xffff;
		if ((distance & 0xff) === 0) {
			corrHuff(state.chSetB, state.nToPlB);
		} else {
			break;
		}
	}

	state.chSetB[distPlace & 0xff] = state.chSetB[newDistPlace];
	state.chSetB[newDistPlace] = distance;

	distance = ((distance & 0xff00) | (state.reader.peek16() >>> 8)) >>> 1;
	state.reader.addbits(7);

	const oldAvr3 = state.avrLn3;
	if (length !== 1 && length !== 4) {
		if (length === 0 && distance <= state.maxDist3) {
			state.avrLn3++;
			state.avrLn3 -= state.avrLn3 >>> 8;
		} else if (state.avrLn3 > 0) {
			state.avrLn3--;
		}
	}
	length += 3;
	if (distance >= state.maxDist3) length++;
	if (distance <= 256) length += 8;
	if (oldAvr3 > 0xb0 || (state.avrPlc >= 0x2a00 && oldAvr2 < 0x40)) {
		state.maxDist3 = 0x7f00;
	} else {
		state.maxDist3 = 0x2001;
	}
	state.oldDist[state.oldDistPtr] = distance;
	state.oldDistPtr = (state.oldDistPtr + 1) & 3;
	state.lastLength = length;
	state.lastDist = distance;
	copyString15(state, distance, length);
};

const unpack15 = (state: State15): void => {
	state.destUnpSize--;
	if (state.destUnpSize >= 0) {
		getFlagsBuf(state);
		state.flagsCnt = 8;
	}

	while (state.destUnpSize >= 0) {
		state.unpPtr &= state.windowMask;
		state.firstWinDone = state.firstWinDone || state.prevPtr > state.unpPtr;
		state.prevPtr = state.unpPtr;

		if (state.stMode !== 0) {
			huffDecode(state);
			continue;
		}

		state.flagsCnt--;
		if (state.flagsCnt < 0) {
			getFlagsBuf(state);
			state.flagsCnt = 7;
		}

		if ((state.flagBuf & 0x80) !== 0) {
			state.flagBuf = (state.flagBuf << 1) & 0xff;
			if (state.nlzb > state.nhfb) {
				longLZ(state);
			} else {
				huffDecode(state);
			}
		} else {
			state.flagBuf = (state.flagBuf << 1) & 0xff;
			state.flagsCnt--;
			if (state.flagsCnt < 0) {
				getFlagsBuf(state);
				state.flagsCnt = 7;
			}
			if ((state.flagBuf & 0x80) !== 0) {
				state.flagBuf = (state.flagBuf << 1) & 0xff;
				if (state.nlzb > state.nhfb) {
					huffDecode(state);
				} else {
					longLZ(state);
				}
			} else {
				state.flagBuf = (state.flagBuf << 1) & 0xff;
				shortLZ(state);
			}
		}
	}
};

/**
 * decompresses a RAR 1.5 (`extractVersion=15`) LZSS stream.
 *
 * @param data the compressed bytes from the on-disk subblock
 * @param decompressedSize declared decompressed length
 * @returns the decompressed bytes, or `undefined` if decoding failed
 */
export const decodeOldLzss15 = (data: Uint8Array, decompressedSize: number): Uint8Array | undefined => {
	if (decompressedSize <= 0) {
		return new Uint8Array(0);
	}
	try {
		const reader = new BitReader(data);
		const state = initState15(reader, decompressedSize);
		unpack15(state);
		if (state.outIdx !== decompressedSize) {
			return undefined;
		}
		return state.out;
	} catch {
		return undefined;
	}
};

// #endregion

// #region v20 huffman

// canonical Huffman decoder. `decodeLen[k]` stores the left-aligned upper
// limit code for length k (i.e. `cumulative_count[k] << (16 - k)`), used to
// pick the correct length given the next 16 bits. `decodePos[k]` is the
// offset into `symbols` where length-k codes start. `symbols` holds the
// alphabet ordered by canonical code; v20's longest code is 15 bits so we
// fix a max code length of 15.
const MAX_HUFF_LEN = 15;

interface HuffmanTable {
	size: number;
	decodeLen: Int32Array;
	decodePos: Uint32Array;
	symbols: Uint16Array;
}

const buildHuffmanTable = (lengths: Uint8Array, size: number): HuffmanTable => {
	const counts = new Uint32Array(MAX_HUFF_LEN + 1);
	for (let idx = 0; idx < size; idx++) {
		const len = lengths[idx];
		if (len > MAX_HUFF_LEN) {
			throw new MalformedArchiveError(
				`RAR2 Huffman code length out of range: ${len} > ${MAX_HUFF_LEN}`,
			);
		}
		counts[len]++;
	}
	counts[0] = 0;

	const decodeLen = new Int32Array(MAX_HUFF_LEN + 1);
	const decodePos = new Uint32Array(MAX_HUFF_LEN + 1);

	let upperLimit = 0;
	for (let len = 1; len <= MAX_HUFF_LEN; len++) {
		upperLimit += counts[len];
		decodeLen[len] = upperLimit << (16 - len);
		decodePos[len] = decodePos[len - 1] + counts[len - 1];
		upperLimit <<= 1;
	}
	if (upperLimit > 65536) {
		throw new MalformedArchiveError('over-subscribed RAR2 Huffman table');
	}

	const symbols = new Uint16Array(size);
	const cursor = decodePos.slice();
	for (let idx = 0; idx < size; idx++) {
		const len = lengths[idx];
		if (len > 0) {
			symbols[cursor[len]++] = idx;
		}
	}

	return { decodeLen, decodePos, size, symbols };
};

const decodeHuffSymbol = (table: HuffmanTable, reader: BitReader): number => {
	const field = reader.peek16();

	let length = MAX_HUFF_LEN;
	for (let candidate = 1; candidate < MAX_HUFF_LEN; candidate++) {
		if (field < table.decodeLen[candidate]) {
			length = candidate;
			break;
		}
	}

	reader.addbits(length);
	const position = table.decodePos[length] + ((field - table.decodeLen[length - 1]) >>> (16 - length));
	return table.symbols[position >= table.size ? 0 : position];
};

// #endregion

// #region v20 tables

const NC20 = 298;
const DC20 = 48;
const RC20 = 28;
const BC20 = 19;

// length/distance tables for v20's main LD/DD/RD codes. each symbol in the
// alphabet beyond a base value uses a fixed number of extra raw bits.
const L_DECODE_V20 = [
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
];
const L_BITS_V20 = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5];

const D_DECODE_V20 = [
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
];
const D_BITS_V20 = [
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
];
const SD_DECODE_V20 = [0, 4, 8, 16, 32, 64, 128, 192];
const SD_BITS_V20 = [2, 2, 3, 4, 5, 6, 6, 6];

// #endregion

// #region v20 decoder

interface State20 {
	reader: BitReader;
	window: Uint8Array;
	windowMask: number;
	out: Uint8Array;
	outIdx: number;
	unpPtr: number;
	prevPtr: number;
	firstWinDone: boolean;
	destUnpSize: number;

	oldDist: Int32Array;
	oldDistPtr: number;
	lastDist: number;
	lastLength: number;

	// the 4-bit-per-symbol code-length table carried across `ReadTables20`
	// invocations. for a non-solid block it starts zeroed and accumulates
	// deltas from each table block; here we always re-init it.
	unpOldTable: Uint8Array;

	tables?: {
		ld: HuffmanTable;
		dd: HuffmanTable;
		rd: HuffmanTable;
	};
}

const initState20 = (reader: BitReader, decompressedSize: number): State20 => {
	const WIN_SIZE = 0x100000;
	return {
		destUnpSize: decompressedSize,
		firstWinDone: false,
		lastDist: 0,
		lastLength: 0,
		oldDist: new Int32Array(4),
		oldDistPtr: 0,
		out: new Uint8Array(decompressedSize),
		outIdx: 0,
		prevPtr: 0,
		reader,
		unpOldTable: new Uint8Array(NC20 + DC20 + RC20),
		unpPtr: 0,
		window: new Uint8Array(WIN_SIZE),
		windowMask: WIN_SIZE - 1,
	};
};

const writeByte20 = (state: State20, byte: number): void => {
	state.window[state.unpPtr] = byte;
	if (state.outIdx < state.out.length) {
		state.out[state.outIdx++] = byte;
	}
	state.unpPtr = (state.unpPtr + 1) & state.windowMask;
};

// the generic LZ copy. distances pointing past the populated window (or 0)
// emit zeros — matches unrar's `CopyString` behavior on malformed input.
const copyString20 = (state: State20, length: number, distance: number): void => {
	state.lastDist = distance;
	state.oldDist[state.oldDistPtr] = distance;
	state.oldDistPtr = (state.oldDistPtr + 1) & 3;
	state.lastLength = length;
	state.destUnpSize -= length;

	const bad = distance === 0 ||
		distance > state.window.length ||
		(distance > state.unpPtr && !state.firstWinDone);

	for (let i = 0; i < length; i++) {
		const byte = bad ? 0 : state.window[(state.unpPtr - distance) & state.windowMask];
		writeByte20(state, byte);
	}
};

// reads a fresh set of LD/DD/RD Huffman tables out of the bitstream and
// stores them on the state. the first 2 stream bits are
// `AudioBlock | TableReset`; we reject audio blocks (comments never carry
// audio) and re-zero the carry-over table when reset is set.
const readTables20 = (state: State20): boolean => {
	const reader = state.reader;
	const bitField = reader.peek16();
	const audio = (bitField & 0x8000) !== 0;
	if (audio) {
		// audio mode is only used for compressed PCM data; comments never carry
		// audio blocks, so we treat this as malformed.
		throw new UnsupportedFeatureError('RAR2 audio block not supported');
	}
	if ((bitField & 0x4000) === 0) {
		state.unpOldTable.fill(0);
	}
	reader.addbits(2);

	const tableSize = NC20 + DC20 + RC20;

	const bitLengths = new Uint8Array(BC20);
	for (let i = 0; i < BC20; i++) {
		bitLengths[i] = reader.peek16() >>> 12;
		reader.addbits(4);
	}
	const precode = buildHuffmanTable(bitLengths, BC20);

	const table = new Uint8Array(tableSize);
	for (let i = 0; i < tableSize;) {
		const number = decodeHuffSymbol(precode, reader);
		if (number < 16) {
			table[i] = (number + state.unpOldTable[i]) & 0xf;
			i++;
		} else if (number === 16) {
			let n = (reader.peek16() >>> 14) + 3;
			reader.addbits(2);
			if (i === 0) {
				return false;
			}
			while (n-- > 0 && i < tableSize) {
				table[i] = table[i - 1];
				i++;
			}
		} else {
			let n: number;
			if (number === 17) {
				n = (reader.peek16() >>> 13) + 3;
				reader.addbits(3);
			} else {
				n = (reader.peek16() >>> 9) + 11;
				reader.addbits(7);
			}
			while (n-- > 0 && i < tableSize) {
				table[i++] = 0;
			}
		}
	}

	state.tables = {
		dd: buildHuffmanTable(table.subarray(NC20, NC20 + DC20), DC20),
		ld: buildHuffmanTable(table.subarray(0, NC20), NC20),
		rd: buildHuffmanTable(table.subarray(NC20 + DC20), RC20),
	};
	state.unpOldTable.set(table);
	return true;
};

const unpack20 = (state: State20): void => {
	if (!readTables20(state)) {
		return;
	}
	state.destUnpSize--;

	while (state.destUnpSize >= 0) {
		state.unpPtr &= state.windowMask;
		state.firstWinDone = state.firstWinDone || state.prevPtr > state.unpPtr;
		state.prevPtr = state.unpPtr;

		const number = decodeHuffSymbol(state.tables!.ld, state.reader);

		if (number < 256) {
			writeByte20(state, number);
			state.destUnpSize--;
			continue;
		}
		if (number > 269) {
			const idx = number - 270;
			let length = L_DECODE_V20[idx] + 3;
			let bits = L_BITS_V20[idx];
			if (bits > 0) {
				length += state.reader.peek16() >>> (16 - bits);
				state.reader.addbits(bits);
			}

			const distNumber = decodeHuffSymbol(state.tables!.dd, state.reader);
			let distance = D_DECODE_V20[distNumber] + 1;
			bits = D_BITS_V20[distNumber];
			if (bits > 0) {
				distance += state.reader.peek16() >>> (16 - bits);
				state.reader.addbits(bits);
			}

			if (distance >= 0x2000) {
				length++;
				if (distance >= 0x40000) {
					length++;
				}
			}
			copyString20(state, length, distance);
			continue;
		}
		if (number === 269) {
			if (!readTables20(state)) {
				return;
			}
			continue;
		}
		if (number === 256) {
			copyString20(state, state.lastLength, state.lastDist);
			continue;
		}
		if (number < 261) {
			const distance = state.oldDist[(state.oldDistPtr - (number - 256)) & 3] >>> 0;
			const lengthNumber = decodeHuffSymbol(state.tables!.rd, state.reader);
			let length = L_DECODE_V20[lengthNumber] + 2;
			const bits = L_BITS_V20[lengthNumber];
			if (bits > 0) {
				length += state.reader.peek16() >>> (16 - bits);
				state.reader.addbits(bits);
			}
			if (distance >= 0x101) {
				length++;
				if (distance >= 0x2000) {
					length++;
					if (distance >= 0x40000) {
						length++;
					}
				}
			}
			copyString20(state, length, distance);
			continue;
		}
		// 261..268: 2-byte short match with a fixed-table distance.
		const idx = number - 261;
		let distance = SD_DECODE_V20[idx] + 1;
		const bits = SD_BITS_V20[idx];
		if (bits > 0) {
			distance += state.reader.peek16() >>> (16 - bits);
			state.reader.addbits(bits);
		}
		copyString20(state, 2, distance);
	}
};

/**
 * decompresses a RAR 2.x (`extractVersion=20` or 26) LZSS stream.
 *
 * @param data the compressed bytes from the on-disk subblock
 * @param decompressedSize declared decompressed length
 * @returns the decompressed bytes, or `undefined` if decoding failed
 */
export const decodeOldLzss20 = (data: Uint8Array, decompressedSize: number): Uint8Array | undefined => {
	if (decompressedSize <= 0) {
		return new Uint8Array(0);
	}
	try {
		const reader = new BitReader(data);
		const state = initState20(reader, decompressedSize);
		unpack20(state);
		if (state.outIdx !== decompressedSize) {
			return undefined;
		}
		return state.out;
	} catch {
		return undefined;
	}
};

// #endregion
