import {
	InvalidSignatureError,
	MalformedArchiveError,
	MissingPasswordError,
	MissingVolumeError,
	TruncatedArchiveError,
} from '../errors.ts';
import { concat, decodeUtf8From, read } from '../utils/buffer.ts';
import { type DataSegment, deferStream, readBytes, streamSegments } from '../utils/segments.ts';
import { StreamReader } from '../utils/stream-reader.ts';

import type { UnrarOptions } from '../options.ts';
import { fromUint8Array } from '../reader/common.ts';
import type { Reader } from '../reader/types.ts';
import type { FileBlock, Rar3Block } from './block.ts';
import { parseBlock } from './block.ts';
import { CompressMethod, FileFlag, MainFlag, RAR3_SIGNATURE } from './constants.ts';
import { decryptRar3HeadersIfNeeded, decryptRar3Stream } from './crypto.ts';
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
// the probe is sized to cover almost every block we'll meet in one
// reader.read() — RAR3 file/main/sub headers in the wild fit easily under
// 512 bytes (32-byte fixed prefix + a short filename + a few extras).
// reading more bytes than the header turns into a no-op subarray; reading
// fewer would force a second round trip to fetch the rest, which is
// exactly what we're avoiding by oversizing the probe.
const HEADER_PROBE_SIZE = 512;

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
		throw new TruncatedArchiveError(`RAR3 archive truncated: near 0x${offset.toString(16)}`);
	}
	const headerSize = probe[5] | (probe[6] << 8);
	if (headerSize < COMMON_HEADER_SIZE) {
		throw new MalformedArchiveError(
			`invalid RAR3 header size: ${headerSize} (at 0x${offset.toString(16)})`,
		);
	}
	if (offset + headerSize > reader.length) {
		throw new TruncatedArchiveError(
			`RAR3 block truncated: declares ${headerSize} bytes,` +
				` ${reader.length - offset} available (at 0x${offset.toString(16)})`,
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
		throw new TruncatedArchiveError(`not a RAR3 archive: file shorter than the signature`);
	}
	const signature = await readBytes(reader, 0, RAR3_SIGNATURE.length);
	for (let idx = 0; idx < RAR3_SIGNATURE.length; idx++) {
		if (signature[idx] !== RAR3_SIGNATURE[idx]) {
			throw new InvalidSignatureError(`not a RAR3 archive: signature not found`);
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
 * stored and LZSS-compressed entries (including password-protected ones,
 * when the caller passes `password` to {@link unrar3}) extract end to end;
 * PPMd-compressed entries throw at read time pending the PPMd decoder.
 */
export class Rar3Entry {
	readonly #head: FileBlock;
	readonly #segments: DataSegment[];
	readonly #finalCrc: number;
	readonly #decoder?: Rar3Decoder;
	readonly #password?: string;

	#chunks?: Promise<Uint8Array<ArrayBuffer>[]>;

	/** @ignore */
	constructor(
		head: FileBlock,
		segments: DataSegment[],
		finalCrc: number,
		decoder?: Rar3Decoder,
		password?: string,
	) {
		this.#head = head;
		this.#segments = segments;
		this.#finalCrc = finalCrc;
		this.#decoder = decoder;
		this.#password = password;
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

	/**
	 * the last modification time, milliseconds since the unix epoch, or `NaN`
	 * when the archive stored an unset / invalid DOS time. RAR3 timestamps are
	 * local time; this getter treats them as UTC so the displayed wall-clock
	 * matches `date_time` lines in dumprar.
	 */
	get mtime(): number {
		const ext = this.#head.extMtime;
		const time = ext?.time ?? this.#head.mtime;
		// DOS month/day are 1-based; some encoders write 0 for "unknown".
		// surface that as NaN rather than silently rolling into the previous
		// year via Date.UTC(year, -1, 0, ...).
		if (time.month < 1 || time.month > 12 || time.day < 1 || time.day > 31) {
			return Number.NaN;
		}
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
		if (this.isEncrypted && (this.#password === undefined || this.#head.salt === undefined)) {
			throw new MissingPasswordError(
				`encrypted RAR3 entry: password required` +
					` (entry ${this.filename}, header must carry a salt)`,
			);
		}

		const expected = this.#head.unpackedSize;

		if (this.#head.method === CompressMethod.stored) {
			// stored entries flow straight from the segment readers into a
			// pre-allocated result buffer; no chunk-list bookkeeping, no final
			// concat. for an encrypted stored entry, AES-CBC pads the ciphertext
			// up to a 16-byte block so the source may deliver a few trailing
			// bytes past `expected`; the read-loop stops at `expected` and
			// cancels the rest. multi-segment entries still go through the
			// segment stitcher.
			const source = this.isEncrypted
				? await decryptRar3Stream(
					this.#password!,
					this.#head.salt!,
					streamSegments(this.#segments),
				)
				: this.#segments.length === 1
				? await this.#segments[0].reader.read(
					this.#segments[0].offset,
					this.#segments[0].size,
				)
				: streamSegments(this.#segments);
			return [await read(source, expected)];
		}

		const ciphertext = streamSegments(this.#segments);
		const source = this.isEncrypted
			? await decryptRar3Stream(this.#password!, this.#head.salt!, ciphertext)
			: ciphertext;

		if (this.#decoder === undefined) {
			throw new MalformedArchiveError(
				`solid RAR3 entry has no preceding run head:` +
					` ${this.filename} (compression method 0x${this.#head.method.toString(16)})`,
			);
		}

		// compressed: hand the segments to the shared LZSS decoder. a 0-byte
		// entry still goes through decode so the LZSS end-of-entry marker
		// (which the encoder writes for every entry, regardless of size) is
		// consumed — otherwise the next solid entry would read those bits as
		// its own first symbol.
		const chunks: Uint8Array<ArrayBuffer>[] = [];
		await using reader = new StreamReader(source);
		await this.#decoder.decode(reader, expected, (chunk) => {
			chunks.push(chunk);
		});
		return chunks;
	}

	/**
	 * a readable stream of the entry's content. unencrypted stored entries
	 * stream segment by segment without buffering once consumed; encrypted
	 * and LZSS-compressed entries first materialize through {@link #decode}
	 * and subsequent consumers replay from a cached copy.
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

// reads a reader's full bytes and returns a fresh Uint8Array. used when an
// hpsw volume needs to be header-decrypted in memory before walking.
const slurpReader = async (reader: Reader): Promise<Uint8Array> => {
	const stream = await reader.read(0, reader.length);
	return await read(stream, reader.length);
};

// determines whether a volume's main header sets MAIN_PASSWORD by peeking
// the first two block headers (mark + main). returns false on any read or
// parse failure so the caller can defer error handling to the walker.
const hasEncryptedHeaders = async (reader: Reader): Promise<boolean> => {
	const probeLen = Math.min(reader.length, RAR3_SIGNATURE.length + COMMON_HEADER_SIZE);
	if (probeLen < RAR3_SIGNATURE.length + COMMON_HEADER_SIZE) {
		return false;
	}
	try {
		const probe = await readBytes(reader, 0, probeLen);
		const mainOffset = RAR3_SIGNATURE.length;
		const mainType = probe[mainOffset + 2];
		const mainFlags = probe[mainOffset + 3] | (probe[mainOffset + 4] << 8);
		return mainType === 0x73 /* main */ && (mainFlags & MainFlag.password) !== 0;
	} catch {
		return false;
	}
};

// for each input reader: if its main header is encrypted, slurp + decrypt
// and return a synthetic in-memory reader; otherwise pass through unchanged.
const prepareReaders = async (
	inputReaders: readonly Reader[],
	password: string | undefined,
): Promise<readonly Reader[]> => {
	const out: Reader[] = [];
	for (const reader of inputReaders) {
		if (!(await hasEncryptedHeaders(reader))) {
			out.push(reader);
			continue;
		}
		if (password === undefined) {
			throw new MissingPasswordError(
				'RAR3 archive has encrypted headers: password required',
			);
		}
		const raw = await slurpReader(reader);
		const decrypted = await decryptRar3HeadersIfNeeded(password, raw);
		// fromUint8Array requires Uint8Array<ArrayBuffer>, which is what
		// decryptRar3HeadersIfNeeded returns (it always allocates fresh).
		out.push(fromUint8Array(decrypted as Uint8Array<ArrayBuffer>));
	}
	return out;
};

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
 * password-protected entries decrypt on read when `options.password` is
 * supplied.
 *
 * @param source one reader for a single-volume archive, or the ordered set of
 * volume readers for a multi-volume archive
 * @param options optional settings such as a password for encrypted entries
 * @returns async generator yielding the archive's file entries
 * @throws if a volume is not a RAR3 archive, a header overruns the file, or a
 * split file's continuation is missing
 */
export async function* unrar3(
	source: Reader | readonly Reader[],
	options?: UnrarOptions,
): AsyncGenerator<Rar3Entry> {
	const inputReaders: readonly Reader[] = Array.isArray(source) ? source : [source];
	const password = options?.password;

	// hpsw archives: any volume whose main header sets MAIN_PASSWORD needs to
	// be slurped into memory and header-decrypted in one pass before the
	// streaming walker can read it. unencrypted volumes pass through with no
	// extra allocation.
	const readers = await prepareReaders(inputReaders, password);

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
				throw new MissingVolumeError(
					`split continuation without a preceding head: ${block.name}` +
						` (first volume may be missing)`,
				);
			}
			openSegments.push({ offset: block.dataOffset, reader, size: block.dataSize });
		} else {
			if (openHead !== undefined) {
				throw new MissingVolumeError(
					`unterminated split entry: ${openHead.name} interrupted by ${block.name}` +
						` (continuation volume may be missing)`,
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
			entry = new Rar3Entry(head, segments, finalCrc, undefined, password);
		} else if (!solid) {
			// the head of a (potentially solid) compressed run; subsequent
			// solid entries reuse the decoder. when the previous run's
			// decoder already owns a window large enough for this entry we
			// reset its state in place — the (1-4 MiB) window allocation
			// dominates the cost of decoding small entries in archives that
			// share a dict size across many file headers.
			if (decoder !== undefined && decoder.windowSize >= dictSize) {
				decoder.reset();
			} else {
				decoder = new Rar3Decoder(dictSize);
			}
			entry = new Rar3Entry(head, segments, finalCrc, decoder, password);
		} else if (decoder !== undefined) {
			// a solid continuation: the previous entry must finish decoding so
			// the shared tables and dictionary are in the right state.
			if (pending !== undefined) {
				await pending._drain();
			}
			entry = new Rar3Entry(head, segments, finalCrc, decoder, password);
		} else {
			// solid entry without a preceding run head; report at read time so
			// callers can choose to skip it without aborting the iteration.
			entry = new Rar3Entry(head, segments, finalCrc, undefined, password);
		}

		pending = entry;
		yield entry;
	}

	if (openHead !== undefined) {
		throw new MissingVolumeError(
			`unterminated split entry: ${openHead.name} (final volume may be missing)`,
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
