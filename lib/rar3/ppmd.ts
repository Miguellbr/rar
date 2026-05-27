/**
 * @module
 *
 * PPMd variant H decoder for RAR3 archives. ported from libarchive's
 * `archive_ppmd7.c` and `archive_ppmd_private.h` (both public domain;
 * Igor Pavlov 2010, based on PPMd var.H by Dmitry Shkarin 2001), with the
 * encoder and the 7z-specific range decoder dropped — RAR uses only the
 * `PpmdRAR_RangeDec_*` variants.
 *
 * memory model: PPMd-H allocates many small variable-size records (state
 * arrays and contexts) referenced by 4-byte byte-offsets into a single
 * backing buffer. this module keeps that arrangement in TypeScript so
 * that the allocator (free lists, glue-blocks, units2index tables) and
 * the model's reference invariants can mirror the C line-for-line. all
 * structure fields are accessed via {@link RAR3PpmdMemory} helpers that
 * read/write little-endian u16/u32 values out of the backing
 * `Uint8Array`.
 *
 * data structures (matching the C layout):
 *   CPpmd_State (6 bytes): Symbol u8, Freq u8, SuccessorLow u16,
 *                         SuccessorHigh u16
 *   CPpmd7_Context (8 bytes): NumStats u16, SummFreq u16, Stats u32,
 *                            Suffix u32
 *   when a context has NumStats == 1, its last 6 bytes (SummFreq + Stats)
 *   are reinterpreted as a CPpmd_State (the `Ppmd7Context_OneState` macro).
 *   UNIT_SIZE = 12 (two CPpmd_States, or one context + 4 bytes of slack).
 */

import { MalformedArchiveError } from '../errors.ts';

// #region constants

const PPMD_INT_BITS = 7;
const PPMD_PERIOD_BITS = 7;
const PPMD_BIN_SCALE = 1 << (PPMD_INT_BITS + PPMD_PERIOD_BITS);

const PPMD_N1 = 4;
const PPMD_N2 = 4;
const PPMD_N3 = 4;
const PPMD_N4 = ((128 + 3 - 1 * PPMD_N1 - 2 * PPMD_N2 - 3 * PPMD_N3) / 4) | 0;
const PPMD_NUM_INDEXES = PPMD_N1 + PPMD_N2 + PPMD_N3 + PPMD_N4;

const PPMD7_MIN_ORDER = 2;
const PPMD7_MAX_ORDER = 64;

const PPMD7_MIN_MEM_SIZE = 1 << 11;

const UNIT_SIZE = 12;
const MAX_FREQ = 124;
const kTopValue = 1 << 24;

// the initial bin-escape table and the exponential escape lookup, copied
// verbatim from PPMd var.H.
const kInitBinEsc: ReadonlyArray<number> = [
	0x3cdd,
	0x1f3f,
	0x59bf,
	0x48f3,
	0x64a1,
	0x5abc,
	0x6632,
	0x6051,
];
const PPMD7_kExpEscape: ReadonlyArray<number> = [
	25,
	14,
	9,
	7,
	5,
	5,
	4,
	4,
	4,
	3,
	3,
	3,
	2,
	2,
	2,
	2,
];

// CPpmd_State field offsets within a state record.
const STATE_SYMBOL = 0;
const STATE_FREQ = 1;
const STATE_SUCC_LO = 2;
const STATE_SUCC_HI = 4;
const STATE_SIZE = 6;

// CPpmd7_Context field offsets within a context record.
const CTX_NUM_STATS = 0;
const CTX_SUMM_FREQ = 2;
const CTX_STATS = 4;
const CTX_SUFFIX = 8;
// for one-state contexts, the State view starts at CTX_SUMM_FREQ.
const CTX_ONE_STATE_OFFSET = CTX_SUMM_FREQ;

// glue-blocks node layout, used during free-list coalescing.
const NODE_STAMP = 0;
const NODE_NU = 2;
const NODE_NEXT = 4;
const NODE_PREV = 8;

// #endregion

// #region range decoder

/**
 * `IByteIn` source for the range decoder. each `read()` returns the next
 * compressed byte from the underlying bit stream, or `0` when exhausted —
 * matching the C interface which treats EOF as zero bytes.
 */
export interface PpmdByteIn {
	read(): number;
}

/**
 * RAR variant of the PPMd-H range decoder. shares the structure with the
 * 7z variant but uses `Bottom = 0x8000` and an additive `Decode` step
 * (rather than the 7z subtractive one).
 */
export class RAR3PpmdRangeDecoder {
	#range = 0xffffffff >>> 0;
	#code = 0;
	#low = 0;
	#bottom = 0;
	#stream: PpmdByteIn;

	constructor(stream: PpmdByteIn) {
		this.#stream = stream;
	}

	/** swaps the byte source. used at block boundaries. */
	setStream(stream: PpmdByteIn): void {
		this.#stream = stream;
	}

	/** initialises the decoder by reading four header bytes from the stream. */
	init(): boolean {
		this.#low = 0;
		this.#bottom = 0;
		this.#range = 0xffffffff >>> 0;
		this.#code = 0;
		for (let i = 0; i < 4; i++) {
			this.#code = ((this.#code << 8) | this.#stream.read()) >>> 0;
		}
		if (this.#code >= 0xffffffff) {
			return false;
		}
		this.#bottom = 0x8000;
		return true;
	}

	getThreshold(total: number): number {
		// JS divides through float64 which can round wrong for some u32
		// magnitudes near precision boundaries; use BigInt for both quotients
		// so the result matches C's integer division exactly.
		this.#range = Number(BigInt(this.#range >>> 0) / BigInt(total >>> 0)) >>> 0;
		const diff = (this.#code - this.#low) >>> 0;
		return Number(BigInt(diff) / BigInt(this.#range)) >>> 0;
	}

	decode(start: number, size: number): void {
		this.#low = (this.#low + start * this.#range) >>> 0;
		this.#range = (this.#range * size) >>> 0;
		this.#normalize();
	}

	decodeBit(size0: number): number {
		const value = this.getThreshold(PPMD_BIN_SCALE);
		if (value < size0) {
			this.decode(0, size0);
			return 0;
		}
		this.decode(size0, PPMD_BIN_SCALE - size0);
		return 1;
	}

	/** true when the decoder is in a clean end-of-stream state. */
	isFinishedOK(): boolean {
		return this.#code === 0;
	}

	#normalize(): void {
		// faithful port of Range_Normalize, but careful with JS 32-bit math:
		// `low + range` may overflow 32 bits, so we compare via the unsigned
		// representation after applying `>>> 0`.
		for (;;) {
			const sumXor = (this.#low ^ ((this.#low + this.#range) >>> 0)) >>> 0;
			if (sumXor >= kTopValue) {
				if (this.#range >= this.#bottom) {
					break;
				}
				// per the RAR variant: range = -low & (bottom - 1)
				this.#range = (((-this.#low) >>> 0) & (this.#bottom - 1)) >>> 0;
			}
			this.#code = ((this.#code << 8) | this.#stream.read()) >>> 0;
			this.#range = (this.#range << 8) >>> 0;
			this.#low = (this.#low << 8) >>> 0;
		}
	}
}

// #endregion

// #region model

/**
 * symbols returned by {@link RAR3PpmdModel.decodeSymbol} alongside the
 * actual byte: `-1` indicates the end-of-data marker, `-2` indicates a
 * corrupted stream.
 */
export const PPMD_END_OF_DATA = -1;
export const PPMD_CORRUPT = -2;

/**
 * full PPMd-H state: backing buffer, free-list bookkeeping, context tree
 * pointers, and the SEE / bin-summ tables. one instance is shared across
 * the lifetime of a single PPMd block; restart-on-failure mirrors the
 * `RestartModel` behaviour from the C.
 */
export class RAR3PpmdModel {
	// --- backing memory ---
	readonly #base: Uint8Array;
	readonly #view: DataView;
	readonly #size: number;
	readonly #alignOffset: number;

	// --- decoder + scratch buffers ---
	readonly #ranger: RAR3PpmdRangeDecoder;
	readonly #u2i: Uint8Array = new Uint8Array(128);
	readonly #i2u: Uint8Array = new Uint8Array(PPMD_NUM_INDEXES);
	readonly #ns2Indx: Uint8Array = new Uint8Array(256);
	readonly #ns2BSIndx: Uint8Array = new Uint8Array(256);
	readonly #hb2Flag: Uint8Array = new Uint8Array(256);

	// FreeList[PPMD_NUM_INDEXES] of u32 offsets.
	readonly #freeList: Uint32Array = new Uint32Array(PPMD_NUM_INDEXES);

	// BinSumm[128][64] of u16.
	readonly #binSumm: Uint16Array = new Uint16Array(128 * 64);

	// SEE[25][16] = three bytes each (Summ u16, Shift u8, Count u8).
	readonly #seeSumm: Uint16Array = new Uint16Array(25 * 16);
	readonly #seeShift: Uint8Array = new Uint8Array(25 * 16);
	readonly #seeCount: Uint8Array = new Uint8Array(25 * 16);
	#dummySeeSumm = 0;
	#dummySeeShift = 0;
	#dummySeeCount = 0;

	// pointers expressed as byte offsets into #base.
	#text = 0;
	#loUnit = 0;
	#hiUnit = 0;
	#unitsStart = 0;
	#glueCount = 0;
	#minContext = 0;
	#maxContext = 0;
	#foundState = 0;
	#orderFall = 0;
	#initEsc = 0;
	#prevSuccess = 0;
	#maxOrder = 0;
	#runLength = 0;
	#initRL = 0;
	#hiBitsFlag = 0;

	// `selectedSeeIdx` tracks the SEE row/col that the last MakeEscFreq used,
	// so callers can update it without re-passing the index. encoded as
	// row*16 + col, or -1 for the DummySee.
	#lastSeeIdx = -1;

	/**
	 * @param size the PPMd memory size in bytes (RAR sends "dictionary size",
	 * which directly maps onto the backing buffer). minimum is 2 KiB,
	 * maximum should be a small power of two of MiB.
	 */
	constructor(size: number) {
		if (size < PPMD7_MIN_MEM_SIZE) {
			throw new MalformedArchiveError(`PPMd memory size below 2 KiB minimum: ${size}`);
		}
		const alignOffset = (4 - (size & 3)) & 3;
		const totalSize = alignOffset + size + UNIT_SIZE;
		this.#base = new Uint8Array(totalSize);
		this.#view = new DataView(this.#base.buffer, this.#base.byteOffset, this.#base.byteLength);
		this.#size = size;
		this.#alignOffset = alignOffset;
		// the range decoder is given a placeholder stream up front; callers
		// rebind it per block via {@link initRangeDecoder} since RAR3's solid
		// PPMd reuses the model across entries that each have their own byte
		// stream.
		this.#ranger = new RAR3PpmdRangeDecoder({ read: () => 0 });

		this.#buildIndexTables();
	}

	/**
	 * binds a new byte source and primes the range decoder with its next
	 * four bytes. called once after construction and again at every block
	 * boundary — RAR3 re-inits the range decoder there even when the model
	 * is being reused.
	 */
	initRangeDecoder(stream: PpmdByteIn): boolean {
		this.#ranger.setStream(stream);
		return this.#ranger.init();
	}

	/**
	 * resets the model to its empty state with the supplied max order.
	 * follows the C `Ppmd7_Init` + `RestartModel`.
	 */
	init(maxOrder: number): void {
		if (maxOrder < PPMD7_MIN_ORDER || maxOrder > PPMD7_MAX_ORDER) {
			throw new MalformedArchiveError(`PPMd max order out of range: ${maxOrder}`);
		}
		this.#maxOrder = maxOrder;
		this.#restartModel();
		this.#dummySeeShift = PPMD_PERIOD_BITS;
		this.#dummySeeSumm = 0;
		this.#dummySeeCount = 64;
	}

	/** the current InitEsc, exposed so the RAR caller can pre-set it. */
	get initEsc(): number {
		return this.#initEsc;
	}
	set initEsc(value: number) {
		this.#initEsc = value;
	}

	/**
	 * decodes the next symbol from the stream.
	 * @returns a byte value `0..255`, {@link PPMD_END_OF_DATA} (-1) at
	 * end-of-data, or {@link PPMD_CORRUPT} (-2) for an invalid frequency
	 */
	decodeSymbol(): number {
		const charMask = new Uint8Array(256);
		const minCtx = this.#minContext;
		const numStats = this.#u16(minCtx + CTX_NUM_STATS);

		if (numStats !== 1) {
			const statsBase = this.#u32(minCtx + CTX_STATS);
			const summFreq = this.#u16(minCtx + CTX_SUMM_FREQ);
			const count = this.#ranger.getThreshold(summFreq);
			let s = statsBase;
			let hiCnt = this.#u8(s + STATE_FREQ);
			if (count < hiCnt) {
				this.#ranger.decode(0, hiCnt);
				this.#foundState = s;
				const symbol = this.#u8(s + STATE_SYMBOL);
				this.#update1_0();
				return symbol;
			}
			this.#prevSuccess = 0;
			let i = numStats - 1;
			do {
				s += STATE_SIZE;
				hiCnt += this.#u8(s + STATE_FREQ);
				if (hiCnt > count) {
					this.#ranger.decode(hiCnt - this.#u8(s + STATE_FREQ), this.#u8(s + STATE_FREQ));
					this.#foundState = s;
					const symbol = this.#u8(s + STATE_SYMBOL);
					this.#update1();
					return symbol;
				}
			} while (--i);
			if (count >= summFreq) {
				return PPMD_CORRUPT;
			}
			this.#hiBitsFlag = this.#hb2Flag[this.#u8(this.#foundState + STATE_SYMBOL)];
			this.#ranger.decode(hiCnt, summFreq - hiCnt);
			charMask.fill(0xff);
			charMask[this.#u8(s + STATE_SYMBOL)] = 0;
			i = numStats - 1;
			do {
				s -= STATE_SIZE;
				charMask[this.#u8(s + STATE_SYMBOL)] = 0;
			} while (--i);
		} else {
			const probIdx = this.#getBinSummIdx();
			const prob = this.#binSumm[probIdx];
			if (this.#ranger.decodeBit(prob) === 0) {
				this.#binSumm[probIdx] = ppmdUpdateProb0(prob);
				const stateOff = minCtx + CTX_ONE_STATE_OFFSET;
				this.#foundState = stateOff;
				const symbol = this.#u8(stateOff + STATE_SYMBOL);
				this.#updateBin();
				return symbol;
			}
			this.#binSumm[probIdx] = ppmdUpdateProb1(prob);
			const newProb = this.#binSumm[probIdx];
			this.#initEsc = PPMD7_kExpEscape[newProb >>> 10];
			charMask.fill(0xff);
			charMask[this.#u8(minCtx + CTX_ONE_STATE_OFFSET + STATE_SYMBOL)] = 0;
			this.#prevSuccess = 0;
		}

		for (;;) {
			const minCtxNow = this.#minContext;
			const numMasked = this.#u16(minCtxNow + CTX_NUM_STATS);
			let next = minCtxNow;
			do {
				this.#orderFall++;
				const suffix = this.#u32(next + CTX_SUFFIX);
				if (suffix === 0) {
					return PPMD_END_OF_DATA;
				}
				next = suffix;
			} while (this.#u16(next + CTX_NUM_STATS) === numMasked);
			this.#minContext = next;

			let s = this.#u32(next + CTX_STATS);
			let hiCnt = 0;
			const num = this.#u16(next + CTX_NUM_STATS) - numMasked;
			const ps: number[] = new Array(num);
			let i = 0;
			let writeIdx = 0;
			do {
				const sym = this.#u8(s + STATE_SYMBOL);
				const masked = charMask[sym];
				// masked is 0 when the symbol is excluded; equivalent to the C
				// `int k = (int)(MASK(s->Symbol))` which is 0 or -1 (after
				// signed-char interpretation). we only want the included slots.
				if (masked !== 0) {
					hiCnt += this.#u8(s + STATE_FREQ);
					ps[writeIdx++] = s;
					i++;
				}
				s += STATE_SIZE;
			} while (i !== num);

			const escResult = this.#makeEscFreq(numMasked);
			const freqSum = escResult + hiCnt;
			const count = this.#ranger.getThreshold(freqSum);

			if (count < hiCnt) {
				let acc = 0;
				let chosen = 0;
				for (let pi = 0; pi < writeIdx; pi++) {
					acc += this.#u8(ps[pi] + STATE_FREQ);
					if (acc > count) {
						chosen = ps[pi];
						break;
					}
				}
				const freq = this.#u8(chosen + STATE_FREQ);
				this.#ranger.decode(acc - freq, freq);
				this.#seeUpdate();
				this.#foundState = chosen;
				const symbol = this.#u8(chosen + STATE_SYMBOL);
				this.#update2();
				return symbol;
			}
			if (count >= freqSum) {
				return PPMD_CORRUPT;
			}
			this.#ranger.decode(hiCnt, freqSum - hiCnt);
			this.#seeAddSum(freqSum);
			// mask the included symbols out for the next escape round.
			for (let pi = writeIdx - 1; pi >= 0; pi--) {
				charMask[this.#u8(ps[pi] + STATE_SYMBOL)] = 0;
			}
		}
	}

	// --- allocator ---

	#buildIndexTables(): void {
		let k = 0;
		for (let i = 0; i < PPMD_NUM_INDEXES; i++) {
			const step = i >= 12 ? 4 : ((i >> 2) + 1);
			for (let s = 0; s < step; s++) {
				this.#u2i[k++] = i;
			}
			this.#i2u[i] = k;
		}

		this.#ns2BSIndx[0] = 0 << 1;
		this.#ns2BSIndx[1] = 1 << 1;
		for (let i = 2; i < 11; i++) {
			this.#ns2BSIndx[i] = 2 << 1;
		}
		for (let i = 11; i < 256; i++) {
			this.#ns2BSIndx[i] = 3 << 1;
		}

		this.#ns2Indx[0] = 0;
		this.#ns2Indx[1] = 1;
		this.#ns2Indx[2] = 2;
		let m = 2;
		let kCount = 1;
		for (let i = 3; i < 256; i++) {
			this.#ns2Indx[i] = m;
			if (--kCount === 0) {
				m++;
				kCount = m - 2;
			}
		}

		for (let i = 0; i < 0x40; i++) {
			this.#hb2Flag[i] = 0;
		}
		for (let i = 0x40; i < 256; i++) {
			this.#hb2Flag[i] = 8;
		}
	}

	#u2b(nu: number): number {
		return (nu * UNIT_SIZE) >>> 0;
	}

	#u2iIndex(nu: number): number {
		return this.#u2i[nu - 1];
	}

	#i2uUnits(indx: number): number {
		return this.#i2u[indx];
	}

	#insertNode(node: number, indx: number): void {
		this.#writeU32(node, this.#freeList[indx]);
		this.#freeList[indx] = node;
	}

	#removeNode(indx: number): number {
		const node = this.#freeList[indx];
		this.#freeList[indx] = this.#u32(node);
		return node;
	}

	#splitBlock(ptr: number, oldIndx: number, newIndx: number): void {
		const nu = this.#i2uUnits(oldIndx) - this.#i2uUnits(newIndx);
		const splitAt = ptr + this.#u2b(this.#i2uUnits(newIndx));
		let i = this.#u2iIndex(nu);
		if (this.#i2uUnits(i) !== nu) {
			i--;
			const k = this.#i2uUnits(i);
			this.#insertNode(splitAt + this.#u2b(k), nu - k - 1);
		}
		this.#insertNode(splitAt, i);
	}

	#glueFreeBlocks(): void {
		const head = this.#alignOffset + this.#size;
		let n = head;
		this.#glueCount = 255;

		for (let i = 0; i < PPMD_NUM_INDEXES; i++) {
			const nu = this.#i2uUnits(i);
			let next = this.#freeList[i];
			this.#freeList[i] = 0;
			while (next !== 0) {
				const node = next;
				this.#writeU32(node + NODE_NEXT, n);
				const prevOfN = node;
				this.#writeU32(n + NODE_PREV, prevOfN);
				n = node;
				next = this.#u32(node);
				this.#writeU16(node + NODE_STAMP, 0);
				this.#writeU16(node + NODE_NU, nu);
			}
		}
		this.#writeU16(head + NODE_STAMP, 1);
		this.#writeU32(head + NODE_NEXT, n);
		this.#writeU32(n + NODE_PREV, head);
		if (this.#loUnit !== this.#hiUnit) {
			this.#writeU16(this.#loUnit + NODE_STAMP, 1);
		}

		while (n !== head) {
			let nu = this.#u16(n + NODE_NU);
			for (;;) {
				const node2 = n + nu * UNIT_SIZE;
				const node2Nu = this.#u16(node2 + NODE_NU);
				nu += node2Nu;
				const stamp = this.#u16(node2 + NODE_STAMP);
				if (stamp !== 0 || nu >= 0x10000) {
					break;
				}
				const node2Prev = this.#u32(node2 + NODE_PREV);
				const node2Next = this.#u32(node2 + NODE_NEXT);
				this.#writeU32(node2Prev + NODE_NEXT, node2Next);
				this.#writeU32(node2Next + NODE_PREV, node2Prev);
				this.#writeU16(n + NODE_NU, nu);
			}
			n = this.#u32(n + NODE_NEXT);
		}

		for (let cur = this.#u32(head + NODE_NEXT); cur !== head;) {
			let nu = this.#u16(cur + NODE_NU);
			const next = this.#u32(cur + NODE_NEXT);
			let chunkPtr = cur;
			while (nu > 128) {
				this.#insertNode(chunkPtr, PPMD_NUM_INDEXES - 1);
				chunkPtr += 128 * UNIT_SIZE;
				nu -= 128;
			}
			let i = this.#u2iIndex(nu);
			if (this.#i2uUnits(i) !== nu) {
				i--;
				const k = this.#i2uUnits(i);
				this.#insertNode(chunkPtr + this.#u2b(k), nu - k - 1);
			}
			this.#insertNode(chunkPtr, i);
			cur = next;
		}
	}

	#allocUnits(indx: number): number {
		if (this.#freeList[indx] !== 0) {
			return this.#removeNode(indx);
		}
		const numBytes = this.#u2b(this.#i2uUnits(indx));
		if (numBytes <= this.#hiUnit - this.#loUnit) {
			const retVal = this.#loUnit;
			this.#loUnit += numBytes;
			return retVal;
		}
		return this.#allocUnitsRare(indx);
	}

	#allocUnitsRare(indx: number): number {
		if (this.#glueCount === 0) {
			this.#glueFreeBlocks();
			if (this.#freeList[indx] !== 0) {
				return this.#removeNode(indx);
			}
		}
		let i = indx;
		for (;;) {
			i++;
			if (i === PPMD_NUM_INDEXES) {
				const numBytes = this.#u2b(this.#i2uUnits(indx));
				this.#glueCount--;
				if (this.#unitsStart - this.#text > numBytes) {
					this.#unitsStart -= numBytes;
					return this.#unitsStart;
				}
				return 0;
			}
			if (this.#freeList[i] !== 0) {
				break;
			}
		}
		const retVal = this.#removeNode(i);
		this.#splitBlock(retVal, i, indx);
		return retVal;
	}

	#shrinkUnits(oldPtr: number, oldNU: number, newNU: number): number {
		const i0 = this.#u2iIndex(oldNU);
		const i1 = this.#u2iIndex(newNU);
		if (i0 === i1) {
			return oldPtr;
		}
		if (this.#freeList[i1] !== 0) {
			const ptr = this.#removeNode(i1);
			this.#memCpyUnits(ptr, oldPtr, newNU);
			this.#insertNode(oldPtr, i0);
			return ptr;
		}
		this.#splitBlock(oldPtr, i0, i1);
		return oldPtr;
	}

	#memCpyUnits(dst: number, src: number, nu: number): void {
		const bytes = nu * UNIT_SIZE;
		this.#base.copyWithin(dst, src, src + bytes);
		// copyWithin is a no-op when src === dst; otherwise this is the
		// canonical way to do an in-buffer move in TS.
	}

	// --- model ---

	#restartModel(): void {
		this.#freeList.fill(0);
		this.#text = this.#alignOffset;
		this.#hiUnit = this.#text + this.#size;
		this.#loUnit = this.#unitsStart = this.#hiUnit -
			Math.floor(this.#size / 8 / UNIT_SIZE) * 7 * UNIT_SIZE;
		this.#glueCount = 0;

		this.#orderFall = this.#maxOrder;
		this.#runLength = this.#initRL = -(this.#maxOrder < 12 ? this.#maxOrder : 12) - 1;
		this.#prevSuccess = 0;

		this.#hiUnit -= UNIT_SIZE;
		this.#minContext = this.#maxContext = this.#hiUnit;
		this.#writeU32(this.#minContext + CTX_SUFFIX, 0);
		this.#writeU16(this.#minContext + CTX_NUM_STATS, 256);
		this.#writeU16(this.#minContext + CTX_SUMM_FREQ, 256 + 1);
		this.#foundState = this.#loUnit;
		this.#loUnit += this.#u2b(256 / 2);
		this.#writeU32(this.#minContext + CTX_STATS, this.#foundState);

		for (let i = 0; i < 256; i++) {
			const s = this.#foundState + i * STATE_SIZE;
			this.#writeU8(s + STATE_SYMBOL, i);
			this.#writeU8(s + STATE_FREQ, 1);
			this.#setSuccessor(s, 0);
		}

		for (let i = 0; i < 128; i++) {
			for (let k = 0; k < 8; k++) {
				const val = PPMD_BIN_SCALE - Math.floor(kInitBinEsc[k] / (i + 2));
				for (let m = 0; m < 64; m += 8) {
					this.#binSumm[i * 64 + m + k] = val;
				}
			}
		}

		for (let i = 0; i < 25; i++) {
			for (let k = 0; k < 16; k++) {
				const idx = i * 16 + k;
				this.#seeShift[idx] = PPMD_PERIOD_BITS - 4;
				this.#seeSumm[idx] = (5 * i + 10) << this.#seeShift[idx];
				this.#seeCount[idx] = 4;
			}
		}
	}

	#getBinSummIdx(): number {
		// matches the macro Ppmd7_GetBinSumm: picks a row by the one-state's
		// freq-1 and a column built from prevSuccess + suffix-numstats slot +
		// hiBits flag + suffix-onestate hiBits flag * 2 + runLength bit.
		const minCtx = this.#minContext;
		const oneStateFreq = this.#u8(minCtx + CTX_ONE_STATE_OFFSET + STATE_FREQ);
		const suffix = this.#u32(minCtx + CTX_SUFFIX);
		const suffixNumStats = this.#u16(suffix + CTX_NUM_STATS);
		this.#hiBitsFlag = this.#hb2Flag[this.#u8(this.#foundState + STATE_SYMBOL)];
		const oneStateSymbol = this.#u8(minCtx + CTX_ONE_STATE_OFFSET + STATE_SYMBOL);
		const col = this.#prevSuccess +
			this.#ns2BSIndx[suffixNumStats - 1] +
			this.#hiBitsFlag +
			2 * this.#hb2Flag[oneStateSymbol] +
			((this.#runLength >> 26) & 0x20);
		return (oneStateFreq - 1) * 64 + col;
	}

	#makeEscFreq(numMasked: number): number {
		const minCtx = this.#minContext;
		const numStats = this.#u16(minCtx + CTX_NUM_STATS);
		const nonMasked = numStats - numMasked;
		if (numStats !== 256) {
			const suffix = this.#u32(minCtx + CTX_SUFFIX);
			const suffixNumStats = this.#u16(suffix + CTX_NUM_STATS);
			const summFreq = this.#u16(minCtx + CTX_SUMM_FREQ);
			const row = this.#ns2Indx[nonMasked - 1];
			const col = (nonMasked < suffixNumStats - numStats ? 1 : 0) +
				(2 * (summFreq < 11 * numStats ? 1 : 0)) +
				(4 * (numMasked > nonMasked ? 1 : 0)) +
				this.#hiBitsFlag;
			const idx = row * 16 + col;
			this.#lastSeeIdx = idx;
			const summ = this.#seeSumm[idx];
			const r = summ >>> this.#seeShift[idx];
			this.#seeSumm[idx] = summ - r;
			return r === 0 ? 1 : r;
		}
		this.#lastSeeIdx = -1;
		return 1;
	}

	#seeUpdate(): void {
		if (this.#lastSeeIdx < 0) {
			if (this.#dummySeeShift < PPMD_PERIOD_BITS) {
				if (--this.#dummySeeCount === 0) {
					this.#dummySeeSumm <<= 1;
					this.#dummySeeCount = 3 << this.#dummySeeShift++;
				}
			}
			return;
		}
		const idx = this.#lastSeeIdx;
		if (this.#seeShift[idx] < PPMD_PERIOD_BITS) {
			if (--this.#seeCount[idx] === 0) {
				this.#seeSumm[idx] <<= 1;
				this.#seeCount[idx] = (3 << this.#seeShift[idx]++) & 0xff;
			}
		}
	}

	#seeAddSum(value: number): void {
		if (this.#lastSeeIdx < 0) {
			this.#dummySeeSumm = (this.#dummySeeSumm + value) & 0xffff;
			return;
		}
		const idx = this.#lastSeeIdx;
		this.#seeSumm[idx] = (this.#seeSumm[idx] + value) & 0xffff;
	}

	#setSuccessor(state: number, value: number): void {
		this.#writeU16(state + STATE_SUCC_LO, value & 0xffff);
		this.#writeU16(state + STATE_SUCC_HI, (value >>> 16) & 0xffff);
	}

	#getSuccessor(state: number): number {
		return (this.#u16(state + STATE_SUCC_LO) | (this.#u16(state + STATE_SUCC_HI) << 16)) >>> 0;
	}

	// --- update / rescale ---

	#rescale(): void {
		const minCtx = this.#minContext;
		const statsBase = this.#u32(minCtx + CTX_STATS);
		const fs = this.#foundState;

		// move FoundState to the front of the stats array.
		const tmp = this.#readState(fs);
		for (let cur = fs; cur !== statsBase; cur -= STATE_SIZE) {
			this.#copyState(cur, cur - STATE_SIZE);
		}
		this.#writeState(statsBase, tmp);

		let escFreq = this.#u16(minCtx + CTX_SUMM_FREQ) - this.#u8(statsBase + STATE_FREQ);
		this.#writeU8(statsBase + STATE_FREQ, this.#u8(statsBase + STATE_FREQ) + 4);
		const adder = this.#orderFall !== 0 ? 1 : 0;
		this.#writeU8(statsBase + STATE_FREQ, (this.#u8(statsBase + STATE_FREQ) + adder) >>> 1);
		let sumFreq = this.#u8(statsBase + STATE_FREQ);

		let s = statsBase;
		let i = this.#u16(minCtx + CTX_NUM_STATS) - 1;
		do {
			s += STATE_SIZE;
			escFreq -= this.#u8(s + STATE_FREQ);
			this.#writeU8(s + STATE_FREQ, (this.#u8(s + STATE_FREQ) + adder) >>> 1);
			sumFreq += this.#u8(s + STATE_FREQ);
			if (this.#u8(s + STATE_FREQ) > this.#u8(s - STATE_SIZE + STATE_FREQ)) {
				let s1 = s;
				const tmp1 = this.#readState(s1);
				do {
					this.#copyState(s1, s1 - STATE_SIZE);
					s1 -= STATE_SIZE;
				} while (s1 !== statsBase && tmp1.freq > this.#u8(s1 - STATE_SIZE + STATE_FREQ));
				this.#writeState(s1, tmp1);
			}
		} while (--i);

		if (this.#u8(s + STATE_FREQ) === 0) {
			const origNumStats = this.#u16(minCtx + CTX_NUM_STATS);
			let drop = 0;
			while (this.#u8(s + STATE_FREQ) === 0) {
				drop++;
				s -= STATE_SIZE;
			}
			escFreq += drop;
			const newNumStats = origNumStats - drop;
			this.#writeU16(minCtx + CTX_NUM_STATS, newNumStats);
			if (newNumStats === 1) {
				const stash = this.#readState(statsBase);
				let f = stash.freq;
				while (escFreq > 1) {
					f = (f - (f >>> 1)) & 0xff;
					escFreq >>>= 1;
				}
				this.#insertNode(statsBase, this.#u2iIndex((origNumStats + 1) >>> 1));
				// rewrite the one-state inside the context.
				const oneStateOff = minCtx + CTX_ONE_STATE_OFFSET;
				this.#writeU8(oneStateOff + STATE_SYMBOL, stash.symbol);
				this.#writeU8(oneStateOff + STATE_FREQ, f);
				this.#writeU16(oneStateOff + STATE_SUCC_LO, stash.succLo);
				this.#writeU16(oneStateOff + STATE_SUCC_HI, stash.succHi);
				this.#foundState = oneStateOff;
				return;
			}
			const n0 = (origNumStats + 1) >>> 1;
			const n1 = (newNumStats + 1) >>> 1;
			if (n0 !== n1) {
				const newStats = this.#shrinkUnits(statsBase, n0, n1);
				this.#writeU32(minCtx + CTX_STATS, newStats);
			}
		}
		this.#writeU16(minCtx + CTX_SUMM_FREQ, (sumFreq + escFreq - (escFreq >>> 1)) & 0xffff);
		this.#foundState = this.#u32(minCtx + CTX_STATS);
	}

	#update1(): void {
		const s = this.#foundState;
		this.#writeU8(s + STATE_FREQ, this.#u8(s + STATE_FREQ) + 4);
		const minCtx = this.#minContext;
		this.#writeU16(minCtx + CTX_SUMM_FREQ, this.#u16(minCtx + CTX_SUMM_FREQ) + 4);
		if (this.#u8(s + STATE_FREQ) > this.#u8(s - STATE_SIZE + STATE_FREQ)) {
			this.#swapStates(s, s - STATE_SIZE);
			this.#foundState = s - STATE_SIZE;
			if (this.#u8(this.#foundState + STATE_FREQ) > MAX_FREQ) {
				this.#rescale();
			}
		}
		this.#nextContext();
	}

	#update1_0(): void {
		const minCtx = this.#minContext;
		const summFreq = this.#u16(minCtx + CTX_SUMM_FREQ);
		const freq = this.#u8(this.#foundState + STATE_FREQ);
		this.#prevSuccess = 2 * freq > summFreq ? 1 : 0;
		this.#runLength += this.#prevSuccess;
		this.#writeU16(minCtx + CTX_SUMM_FREQ, summFreq + 4);
		const newFreq = freq + 4;
		this.#writeU8(this.#foundState + STATE_FREQ, newFreq);
		if (newFreq > MAX_FREQ) {
			this.#rescale();
		}
		this.#nextContext();
	}

	#updateBin(): void {
		const fs = this.#foundState;
		const freq = this.#u8(fs + STATE_FREQ);
		this.#writeU8(fs + STATE_FREQ, freq + (freq < 128 ? 1 : 0));
		this.#prevSuccess = 1;
		this.#runLength++;
		this.#nextContext();
	}

	#update2(): void {
		const minCtx = this.#minContext;
		this.#writeU16(minCtx + CTX_SUMM_FREQ, this.#u16(minCtx + CTX_SUMM_FREQ) + 4);
		const newFreq = this.#u8(this.#foundState + STATE_FREQ) + 4;
		this.#writeU8(this.#foundState + STATE_FREQ, newFreq);
		if (newFreq > MAX_FREQ) {
			this.#rescale();
		}
		this.#runLength = this.#initRL;
		this.#updateModel();
	}

	#nextContext(): void {
		const c = this.#getSuccessor(this.#foundState);
		if (this.#orderFall === 0 && c > this.#text) {
			this.#minContext = this.#maxContext = c;
		} else {
			this.#updateModel();
		}
	}

	#updateModel(): void {
		let fSuccessor = this.#getSuccessor(this.#foundState);
		let c: number;

		if (
			this.#u8(this.#foundState + STATE_FREQ) < MAX_FREQ / 4 &&
			this.#u32(this.#minContext + CTX_SUFFIX) !== 0
		) {
			c = this.#u32(this.#minContext + CTX_SUFFIX);
			const cNumStats = this.#u16(c + CTX_NUM_STATS);
			if (cNumStats === 1) {
				const oneState = c + CTX_ONE_STATE_OFFSET;
				const f = this.#u8(oneState + STATE_FREQ);
				if (f < 32) {
					this.#writeU8(oneState + STATE_FREQ, f + 1);
				}
			} else {
				let s = this.#u32(c + CTX_STATS);
				const foundSym = this.#u8(this.#foundState + STATE_SYMBOL);
				if (this.#u8(s + STATE_SYMBOL) !== foundSym) {
					do {
						s += STATE_SIZE;
					} while (this.#u8(s + STATE_SYMBOL) !== foundSym);
					if (this.#u8(s + STATE_FREQ) >= this.#u8(s - STATE_SIZE + STATE_FREQ)) {
						this.#swapStates(s, s - STATE_SIZE);
						s -= STATE_SIZE;
					}
				}
				if (this.#u8(s + STATE_FREQ) < MAX_FREQ - 9) {
					this.#writeU8(s + STATE_FREQ, this.#u8(s + STATE_FREQ) + 2);
					this.#writeU16(c + CTX_SUMM_FREQ, this.#u16(c + CTX_SUMM_FREQ) + 2);
				}
			}
		}

		if (this.#orderFall === 0) {
			const succ = this.#createSuccessors(true);
			if (succ === 0) {
				this.#restartModel();
				return;
			}
			this.#minContext = this.#maxContext = succ;
			this.#setSuccessor(this.#foundState, this.#minContext);
			return;
		}

		this.#writeU8(this.#text++, this.#u8(this.#foundState + STATE_SYMBOL));
		let successor = this.#text;
		if (this.#text >= this.#unitsStart) {
			this.#restartModel();
			return;
		}

		if (fSuccessor !== 0) {
			if (fSuccessor <= successor) {
				const cs = this.#createSuccessors(false);
				if (cs === 0) {
					this.#restartModel();
					return;
				}
				fSuccessor = cs;
			}
			if (--this.#orderFall === 0) {
				successor = fSuccessor;
				if (this.#maxContext !== this.#minContext) {
					this.#text--;
				}
			}
		} else {
			this.#setSuccessor(this.#foundState, successor);
			fSuccessor = this.#minContext;
		}

		const ns = this.#u16(this.#minContext + CTX_NUM_STATS);
		const s0 = this.#u16(this.#minContext + CTX_SUMM_FREQ) - ns -
			(this.#u8(this.#foundState + STATE_FREQ) - 1);

		c = this.#maxContext;
		while (c !== this.#minContext) {
			const ns1 = this.#u16(c + CTX_NUM_STATS);
			if (ns1 !== 1) {
				if ((ns1 & 1) === 0) {
					const oldNU = ns1 >>> 1;
					const i = this.#u2iIndex(oldNU);
					if (i !== this.#u2iIndex(oldNU + 1)) {
						const ptr = this.#allocUnits(i + 1);
						if (ptr === 0) {
							this.#restartModel();
							return;
						}
						const oldPtr = this.#u32(c + CTX_STATS);
						this.#memCpyUnits(ptr, oldPtr, oldNU);
						this.#insertNode(oldPtr, i);
						this.#writeU32(c + CTX_STATS, ptr);
					}
				}
				const summFreq = this.#u16(c + CTX_SUMM_FREQ);
				const add1 = 2 * ns1 < ns ? 1 : 0;
				const add2 = 4 * ns1 <= ns && summFreq <= 8 * ns1 ? 2 : 0;
				this.#writeU16(c + CTX_SUMM_FREQ, summFreq + add1 + add2);
			} else {
				const sPtr = this.#allocUnits(0);
				if (sPtr === 0) {
					this.#restartModel();
					return;
				}
				const oneState = c + CTX_ONE_STATE_OFFSET;
				this.#copyState(sPtr, oneState);
				this.#writeU32(c + CTX_STATS, sPtr);
				let f = this.#u8(sPtr + STATE_FREQ);
				if (f < MAX_FREQ / 4 - 1) {
					f = (f << 1) & 0xff;
				} else {
					f = MAX_FREQ - 4;
				}
				this.#writeU8(sPtr + STATE_FREQ, f);
				this.#writeU16(c + CTX_SUMM_FREQ, f + this.#initEsc + (ns > 3 ? 1 : 0));
			}

			const cf = 2 * this.#u8(this.#foundState + STATE_FREQ) *
				(this.#u16(c + CTX_SUMM_FREQ) + 6);
			const sf = s0 + this.#u16(c + CTX_SUMM_FREQ);
			let resultFreq: number;
			if (cf < 6 * sf) {
				resultFreq = 1 + (cf > sf ? 1 : 0) + (cf >= 4 * sf ? 1 : 0);
				this.#writeU16(c + CTX_SUMM_FREQ, this.#u16(c + CTX_SUMM_FREQ) + 3);
			} else {
				resultFreq = 4 + (cf >= 9 * sf ? 1 : 0) + (cf >= 12 * sf ? 1 : 0) + (cf >= 15 * sf ? 1 : 0);
				this.#writeU16(c + CTX_SUMM_FREQ, this.#u16(c + CTX_SUMM_FREQ) + resultFreq);
			}

			const sNew = this.#u32(c + CTX_STATS) + ns1 * STATE_SIZE;
			this.#setSuccessor(sNew, successor);
			this.#writeU8(sNew + STATE_SYMBOL, this.#u8(this.#foundState + STATE_SYMBOL));
			this.#writeU8(sNew + STATE_FREQ, resultFreq);
			this.#writeU16(c + CTX_NUM_STATS, ns1 + 1);

			c = this.#u32(c + CTX_SUFFIX);
		}
		this.#maxContext = this.#minContext = fSuccessor;
	}

	#createSuccessors(skip: boolean): number {
		let c = this.#minContext;
		const upBranch = this.#getSuccessor(this.#foundState);
		const ps: number[] = [];

		if (!skip) {
			ps.push(this.#foundState);
		}

		while (this.#u32(c + CTX_SUFFIX) !== 0) {
			c = this.#u32(c + CTX_SUFFIX);
			let s: number;
			if (this.#u16(c + CTX_NUM_STATS) !== 1) {
				s = this.#u32(c + CTX_STATS);
				const targetSym = this.#u8(this.#foundState + STATE_SYMBOL);
				while (this.#u8(s + STATE_SYMBOL) !== targetSym) {
					s += STATE_SIZE;
				}
			} else {
				s = c + CTX_ONE_STATE_OFFSET;
			}
			const successor = this.#getSuccessor(s);
			if (successor !== upBranch) {
				c = successor;
				if (ps.length === 0) {
					return c;
				}
				break;
			}
			ps.push(s);
		}

		const upStateSymbol = this.#u8(upBranch);
		const upStateSuccessor = upBranch + 1;
		let upStateFreq: number;
		if (this.#u16(c + CTX_NUM_STATS) === 1) {
			upStateFreq = this.#u8(c + CTX_ONE_STATE_OFFSET + STATE_FREQ);
		} else {
			let s = this.#u32(c + CTX_STATS);
			while (this.#u8(s + STATE_SYMBOL) !== upStateSymbol) {
				s += STATE_SIZE;
			}
			const cf = this.#u8(s + STATE_FREQ) - 1;
			const s0 = this.#u16(c + CTX_SUMM_FREQ) - this.#u16(c + CTX_NUM_STATS) - cf;
			upStateFreq = 1 +
				(2 * cf <= s0 ? (5 * cf > s0 ? 1 : 0) : (Math.floor((2 * cf + 3 * s0 - 1) / (2 * s0))));
		}

		while (ps.length !== 0) {
			let c1: number;
			if (this.#hiUnit !== this.#loUnit) {
				this.#hiUnit -= UNIT_SIZE;
				c1 = this.#hiUnit;
			} else if (this.#freeList[0] !== 0) {
				c1 = this.#removeNode(0);
			} else {
				c1 = this.#allocUnitsRare(0);
				if (c1 === 0) {
					return 0;
				}
			}
			this.#writeU16(c1 + CTX_NUM_STATS, 1);
			const oneState = c1 + CTX_ONE_STATE_OFFSET;
			this.#writeU8(oneState + STATE_SYMBOL, upStateSymbol);
			this.#writeU8(oneState + STATE_FREQ, upStateFreq);
			this.#setSuccessor(oneState, upStateSuccessor);
			this.#writeU32(c1 + CTX_SUFFIX, c);
			const target = ps.pop()!;
			this.#setSuccessor(target, c1);
			c = c1;
		}
		return c;
	}

	#swapStates(a: number, b: number): void {
		const tmp = this.#readState(a);
		this.#copyState(a, b);
		this.#writeState(b, tmp);
	}

	#readState(off: number): { symbol: number; freq: number; succLo: number; succHi: number } {
		return {
			freq: this.#u8(off + STATE_FREQ),
			succHi: this.#u16(off + STATE_SUCC_HI),
			succLo: this.#u16(off + STATE_SUCC_LO),
			symbol: this.#u8(off + STATE_SYMBOL),
		};
	}

	#writeState(off: number, s: { symbol: number; freq: number; succLo: number; succHi: number }): void {
		this.#writeU8(off + STATE_SYMBOL, s.symbol);
		this.#writeU8(off + STATE_FREQ, s.freq);
		this.#writeU16(off + STATE_SUCC_LO, s.succLo);
		this.#writeU16(off + STATE_SUCC_HI, s.succHi);
	}

	#copyState(dst: number, src: number): void {
		this.#base.copyWithin(dst, src, src + STATE_SIZE);
	}

	// --- raw memory helpers ---

	#u8(off: number): number {
		return this.#base[off];
	}
	#u16(off: number): number {
		return this.#view.getUint16(off, true);
	}
	#u32(off: number): number {
		return this.#view.getUint32(off, true);
	}
	#writeU8(off: number, value: number): void {
		this.#base[off] = value & 0xff;
	}
	#writeU16(off: number, value: number): void {
		this.#view.setUint16(off, value & 0xffff, true);
	}
	#writeU32(off: number, value: number): void {
		this.#view.setUint32(off, value >>> 0, true);
	}
}

// #endregion

// helper functions for PROB updates outside the class (kept top-level so
// they can be reused if other PPMd variants land later).

const PPMD_GET_MEAN = (summ: number): number => ((summ + (1 << (PPMD_PERIOD_BITS - 2))) >>> PPMD_PERIOD_BITS);

export const ppmdUpdateProb0 = (prob: number): number =>
	(prob + (1 << PPMD_INT_BITS) - PPMD_GET_MEAN(prob)) & 0xffff;
export const ppmdUpdateProb1 = (prob: number): number => (prob - PPMD_GET_MEAN(prob)) & 0xffff;
