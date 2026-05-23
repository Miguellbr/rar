import { concat, decodeUtf8From, read } from '../utils/buffer.ts';
import { StreamReader } from '../utils/stream-reader.ts';

import type { Reader } from '../reader/types.ts';
import type { FileBlock, Rar3Block } from './block.ts';
import { parseBlock } from './block.ts';
import { CompressMethod, FileFlag, RAR3_SIGNATURE } from './constants.ts';
import { Rar3Decoder } from './unpack.ts';

/**
 * @module
 *
 * sequential extraction of RAR3 (RAR1.5 - RAR4) archives. {@link unrar3} walks
 * a volume's block headers and yields a {@link Rar3Entry} for each file it
 * contains, stitching split entries across volumes when an ordered list of
 * readers is supplied.
 *
 * stored entries (method 0x30) extract verbatim. compressed entries flow
 * through the {@link Rar3Decoder} LZSS engine; the engine throws on PPMd
 * blocks and on VM filter symbols, both of which are not yet supported.
 * password-protected entries also throw at read time.
 */

// #region helpers

const COMMON_HEADER_SIZE = 7;
// COMMON_HEADER_SIZE plus the optional 4-byte add_size field that LONG_BLOCK
// brings; never crosses past a real block's header.
const HEADER_PROBE_SIZE = COMMON_HEADER_SIZE + 4;

// reads exactly `length` bytes from `reader` at `offset`.
const readBytes = async (
	reader: Reader,
	offset: number,
	length: number,
): Promise<Uint8Array<ArrayBuffer>> => {
	return await read(await reader.read(offset, length), length);
};

// adapts a lazily-opened stream into one that can be returned synchronously.
const deferStream = (
	open: () => Promise<ReadableStream<Uint8Array>>,
): ReadableStream<Uint8Array> => {
	let inner: ReadableStreamDefaultReader<Uint8Array> | undefined;

	return new ReadableStream({
		async start(controller) {
			try {
				inner = (await open()).getReader();
			} catch (error) {
				controller.error(error);
			}
		},
		async pull(controller) {
			if (inner === undefined) {
				controller.close();
				return;
			}
			const { done, value } = await inner.read();
			if (done) {
				controller.close();
			} else {
				controller.enqueue(value);
			}
		},
		async cancel() {
			await inner?.cancel();
		},
	});
};

// a slice of an entry's data area within a single volume.
interface DataSegment {
	reader: Reader;
	offset: number;
	size: number;
}

// streams the bytes of every segment in order without buffering them all up.
const streamSegments = (
	segments: readonly DataSegment[],
): ReadableStream<Uint8Array<ArrayBuffer>> => {
	let index = 0;
	let current: ReadableStreamDefaultReader<Uint8Array<ArrayBuffer>> | undefined;

	return new ReadableStream({
		async pull(controller) {
			for (;;) {
				if (current === undefined) {
					if (index === segments.length) {
						controller.close();
						return;
					}
					const segment = segments[index++];
					current = (await segment.reader.read(segment.offset, segment.size)).getReader();
				}
				const { done, value } = await current.read();
				if (done) {
					current = undefined;
					continue;
				}
				controller.enqueue(value);
				return;
			}
		},
		async cancel() {
			await current?.cancel();
		},
	});
};

// #endregion

// #region archive walking

/**
 * a parsed block paired with the volume reader it came from.
 */
export interface VolumeBlock {
	reader: Reader;
	block: Rar3Block;
}

// reads the header bytes of one block starting at `offset`. RAR3 headers are
// at most 7 + 4 = 11 bytes for the common+add_size prefix; the parser slices
// out exactly the declared headerSize from there.
const readHeaderBytes = async (
	reader: Reader,
	offset: number,
): Promise<Uint8Array<ArrayBuffer>> => {
	const probeLen = Math.min(HEADER_PROBE_SIZE, reader.length - offset);
	const probe = await readBytes(reader, offset, probeLen);
	if (probe.length < COMMON_HEADER_SIZE) {
		throw new Error(`rar3 archive truncated near 0x${offset.toString(16)}`);
	}
	const headerSize = probe[5] | (probe[6] << 8);
	if (headerSize < COMMON_HEADER_SIZE) {
		throw new Error(
			`rar3 block at 0x${offset.toString(16)} has invalid headerSize ${headerSize}`,
		);
	}
	if (offset + headerSize > reader.length) {
		throw new Error(
			`rar3 archive truncated: block at 0x${offset.toString(16)} declares ${headerSize}` +
				` bytes, ${reader.length - offset} available`,
		);
	}
	if (headerSize <= probe.length) {
		return probe.subarray(0, headerSize) as Uint8Array<ArrayBuffer>;
	}
	// rare: a header bigger than HEADER_PROBE_SIZE. read the full span fresh.
	return await readBytes(reader, offset, headerSize);
};

// walks every block of a single RAR3 volume, yielding each parsed header
// paired with the reader it came from.
async function* walkVolume(reader: Reader): AsyncGenerator<VolumeBlock> {
	if (reader.length < RAR3_SIGNATURE.length) {
		throw new Error(`not a rar3 archive: file shorter than the signature`);
	}
	const signature = await readBytes(reader, 0, RAR3_SIGNATURE.length);
	for (let idx = 0; idx < RAR3_SIGNATURE.length; idx++) {
		if (signature[idx] !== RAR3_SIGNATURE[idx]) {
			throw new Error(`not a rar3 archive: signature not found`);
		}
	}

	let offset = RAR3_SIGNATURE.length;
	while (offset + COMMON_HEADER_SIZE <= reader.length) {
		const headerBytes = await readHeaderBytes(reader, offset);
		const block = parseBlock(headerBytes, offset);
		yield { block, reader };

		if (block.kind === 'endArc') {
			break;
		}
		offset = block.dataOffset + block.dataSize;
	}
}

// walks every volume in order, yielding all blocks tagged with their reader.
async function* walkVolumes(readers: readonly Reader[]): AsyncGenerator<VolumeBlock> {
	for (const reader of readers) {
		yield* walkVolume(reader);
	}
}

// #endregion

// #region entry

/**
 * a single file entry within a RAR3 archive.
 *
 * metadata is available immediately; the entry's content is read lazily when
 * {@link Rar3Entry.body} or one of the convenience readers is accessed. an
 * entry whose data is split across volumes spans multiple readers internally.
 *
 * compressed entries are exposed in the listing but throw on read; only
 * stored (method 0x30) entries are extractable until the RAR3 decompressor
 * lands.
 */
export class Rar3Entry {
	readonly #head: FileBlock;
	readonly #segments: DataSegment[];
	readonly #finalCrc: number;
	readonly #decoder?: Rar3Decoder;

	#chunks?: Promise<Uint8Array<ArrayBuffer>[]>;

	/** @ignore */
	constructor(
		head: FileBlock,
		segments: DataSegment[],
		finalCrc: number,
		decoder?: Rar3Decoder,
	) {
		this.#head = head;
		this.#segments = segments;
		this.#finalCrc = finalCrc;
		this.#decoder = decoder;
	}

	/** the entry's path within the archive, with forward slashes as separators. */
	get filename(): string {
		return this.#head.name.replaceAll('\\', '/');
	}

	/** the uncompressed size of the entry. */
	get size(): number {
		return this.#head.unpackedSize;
	}

	/** the size the entry occupies across the archive's data area, summed over volumes. */
	get compressedSize(): number {
		let total = 0;
		for (const segment of this.#segments) {
			total += segment.size;
		}
		return total;
	}

	/** the compression method byte (0x30 stored, 0x33 normal, 0x35 best). */
	get compressionMethod(): number {
		return this.#head.method;
	}

	/** whether the entry is a directory. */
	get isDirectory(): boolean {
		return (this.#head.fileFlags & FileFlag.dictMask) === FileFlag.directory;
	}

	/** whether the entry is a unix symlink. */
	get isSymlink(): boolean {
		return this.#head.hostOs === 3 && (this.#head.attributes & 0xf000) === 0xa000;
	}

	/** the symlink target, when stored inline. for RAR3 the target is the file body. */
	get linkTarget(): string | undefined {
		return undefined;
	}

	/** whether the entry's data is encrypted. */
	get isEncrypted(): boolean {
		return (this.#head.fileFlags & FileFlag.password) !== 0;
	}

	/** whether the entry is part of a solid block. */
	get isSolid(): boolean {
		return (this.#head.fileFlags & FileFlag.solid) !== 0;
	}

	/** whether the entry's data spans multiple volumes. */
	get isSplit(): boolean {
		return this.#segments.length > 1;
	}

	/** the data CRC32 stored for this entry; final-part CRC for a split entry. */
	get crc32(): number {
		return this.#finalCrc;
	}

	/** the last modification time, milliseconds since the unix epoch. */
	get mtime(): number {
		const ext = this.#head.extMtime;
		const time = ext?.time ?? this.#head.mtime;
		// RAR3 timestamps are local time; treat them as UTC for the conversion
		// so the displayed wall-clock matches `date_time` lines in dumprar.
		return Date.UTC(time.year, time.month - 1, time.day, time.hour, time.minute, time.second) +
			Math.floor((ext?.nanos ?? 0) / 1e6);
	}

	/** the OS-specific attribute bits (unix st_mode, Windows file attributes). */
	get mode(): number {
		return this.#head.attributes;
	}

	#materialize(): Promise<Uint8Array<ArrayBuffer>[]> {
		if (this.#chunks === undefined) {
			this.#chunks = this.#decode();
		}
		return this.#chunks;
	}

	async #decode(): Promise<Uint8Array<ArrayBuffer>[]> {
		if (this.isEncrypted) {
			throw new Error(
				`cannot read ${this.filename}: rar3 password-protected entries are not yet supported`,
			);
		}

		const expected = this.#head.unpackedSize;
		const source = streamSegments(this.#segments);

		if (this.#head.method === CompressMethod.stored) {
			// stored: the concatenated segment bytes are the content verbatim.
			const collected: Uint8Array<ArrayBuffer>[] = [];
			let total = 0;
			for await (const chunk of source) {
				collected.push(chunk);
				total += chunk.length;
			}
			if (total !== expected) {
				throw new Error(
					`stored data is ${total} bytes, expected ${expected}`,
				);
			}
			return collected;
		}

		if (this.#decoder === undefined) {
			throw new Error(
				`cannot read ${this.filename}: rar3 compression method 0x${
					this.#head.method.toString(16)
				} requires a decoder that was not initialized for this entry`,
			);
		}

		// compressed: hand the segments to the shared LZSS decoder. an empty
		// expected size means nothing to do, but we still need to drain the
		// stream so a later cached read does not see leftover bytes.
		const chunks: Uint8Array<ArrayBuffer>[] = [];
		if (expected === 0) {
			return chunks;
		}

		await using reader = new StreamReader(source);
		await this.#decoder.decode(reader, expected, (chunk) => {
			chunks.push(chunk);
		});
		return chunks;
	}

	/**
	 * a readable stream of the entry's content. unencrypted stored entries
	 * stream segment by segment without buffering once consumed; subsequent
	 * consumers replay from a cached copy.
	 */
	get body(): ReadableStream<Uint8Array> {
		// fast path: an unencrypted stored entry that has not yet been consumed
		// elsewhere can stream straight from segments without holding a cache.
		const cacheable = this.isEncrypted || this.#head.method !== CompressMethod.stored;
		if (!cacheable && this.#chunks === undefined) {
			return streamSegments(this.#segments);
		}

		return deferStream(async () => {
			const chunks = await this.#materialize();
			let idx = 0;
			return new ReadableStream({
				pull(controller) {
					if (idx < chunks.length) {
						controller.enqueue(chunks[idx++]);
					} else {
						controller.close();
					}
				},
			});
		});
	}

	/** reads the entry content as bytes. */
	async bytes(): Promise<Uint8Array<ArrayBuffer>> {
		const chunks = await this.#materialize();
		if (chunks.length === 1) {
			return chunks[0];
		}
		return concat(chunks, this.size);
	}

	/** reads the entry content as an ArrayBuffer. */
	async arrayBuffer(): Promise<ArrayBuffer> {
		const bytes = await this.bytes();
		if (bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength) {
			return bytes.buffer;
		}
		return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
	}

	/** reads the entry content as a Blob. */
	async blob(): Promise<Blob> {
		return new Blob([await this.bytes()]);
	}

	/** reads the entry content as UTF-8 text. */
	async text(): Promise<string> {
		return decodeUtf8From(await this.bytes());
	}

	/** reads the entry content as UTF-8 text and parses it as JSON. */
	async json(): Promise<unknown> {
		return JSON.parse(await this.text());
	}

	/**
	 * forces the entry's body to be decoded if it has not already been. used by
	 * the iterator to advance a shared solid-run decoder past this entry before
	 * yielding the next one.
	 * @ignore
	 */
	async _drain(): Promise<void> {
		if (this.#decoder !== undefined) {
			await this.#materialize();
		}
	}
}

// #endregion

// #region unrar3

/**
 * extracts entries from a RAR3 (RAR1.5 - RAR4) archive.
 *
 * the archive is read through `source`, which is either a single {@link Reader}
 * for a self-contained archive or an ordered list of readers for the volumes
 * of a multi-volume set. entries are yielded in archive order; a file whose
 * data spans volumes is yielded once after its final segment is seen.
 * superseded file versions are omitted.
 *
 * compressed entries flow through the LZSS decoder; PPMd blocks and the VM
 * filter symbol throw at read time, pending implementations of each.
 *
 * @param source one reader for a single-volume archive, or the ordered set of
 * volume readers for a multi-volume archive
 * @returns async generator yielding the archive's file entries
 * @throws if a volume is not a RAR3 archive, a header overruns the file, or a
 * split file's continuation is missing
 */
export async function* unrar3(
	source: Reader | readonly Reader[],
): AsyncGenerator<Rar3Entry> {
	const readers: readonly Reader[] = Array.isArray(source) ? source : [source];

	let openHead: FileBlock | undefined;
	let openSegments: DataSegment[] = [];

	let decoder: Rar3Decoder | undefined;
	let pending: Rar3Entry | undefined;

	for await (const { reader, block } of walkVolumes(readers)) {
		if (block.kind !== 'file') {
			continue;
		}
		if ((block.fileFlags & FileFlag.version) !== 0) {
			continue;
		}

		const splitBefore = (block.fileFlags & FileFlag.splitBefore) !== 0;
		const splitAfter = (block.fileFlags & FileFlag.splitAfter) !== 0;

		if (splitBefore) {
			if (openHead === undefined || openHead.name !== block.name) {
				throw new Error(
					`split continuation for ${block.name} without a preceding head;` +
						` the first volume may be missing`,
				);
			}
			openSegments.push({ offset: block.dataOffset, reader, size: block.dataSize });
		} else {
			if (openHead !== undefined) {
				throw new Error(
					`new entry ${block.name} encountered while ${openHead.name} is still split;` +
						` a continuation volume may be missing`,
				);
			}
			openHead = block;
			openSegments = [{ offset: block.dataOffset, reader, size: block.dataSize }];
		}

		if (splitAfter) {
			continue;
		}

		const head = openHead;
		const segments = openSegments;
		const finalCrc = block.crc;
		openHead = undefined;
		openSegments = [];

		const method = head.method;
		const solid = (head.fileFlags & FileFlag.solid) !== 0;
		const dictSize = dictionarySizeFromFlags(head.fileFlags);

		let entry: Rar3Entry;
		if (method === CompressMethod.stored) {
			// stored entries skip the LZSS decoder, but the decoder state has to
			// keep up if a later solid run depends on this entry's bytes — RAR3
			// does not write stored entries into a solid run, so we can leave
			// the decoder alone here.
			entry = new Rar3Entry(head, segments, finalCrc);
		} else if (!solid) {
			// the head of a (potentially solid) compressed run gets a fresh
			// decoder; subsequent solid entries reuse it.
			decoder = new Rar3Decoder(dictSize);
			entry = new Rar3Entry(head, segments, finalCrc, decoder);
		} else if (decoder !== undefined) {
			// a solid continuation: the previous entry must finish decoding so
			// the shared tables and dictionary are in the right state.
			if (pending !== undefined) {
				await pending._drain();
			}
			entry = new Rar3Entry(head, segments, finalCrc, decoder);
		} else {
			// solid entry without a preceding run head; report at read time so
			// callers can choose to skip it without aborting the iteration.
			entry = new Rar3Entry(head, segments, finalCrc);
		}

		pending = entry;
		yield entry;
	}

	if (openHead !== undefined) {
		throw new Error(
			`split file ${openHead.name} was not terminated; the final volume may be missing`,
		);
	}
}

// returns the dictionary size in bytes implied by an entry's file flags.
const dictionarySizeFromFlags = (fileFlags: number): number => {
	const dict = fileFlags & FileFlag.dictMask;
	if (dict === FileFlag.directory) {
		return 64 * 1024;
	}
	return 64 * 1024 << (dict >> 5);
};

// #endregion
