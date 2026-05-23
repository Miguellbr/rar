import { concat, decodeUtf8From, read } from '../utils/buffer.ts';
import { crc32 } from '../utils/crc32.ts';
import { StreamReader } from '../utils/stream-reader.ts';

import type { Reader } from '../reader/types.ts';
import type { FileBlock, FileEncryption } from './block.ts';
import { isDirectory, isSymlink, parseBlock } from './block.ts';
import { BlockFlag, COMPRESSION_SOLID, FileEncryptionFlag, RAR5_SIGNATURE } from './constants.ts';
import { decryptAesCbc, decryptAesCbcStream, KeyCache, tweakCrc32, verifyCheckValue } from './crypto.ts';
import { Cursor } from './cursor.ts';
import { Rar5Decoder } from './unpack.ts';

/**
 * @module
 *
 * sequential extraction of RAR5 archives. {@link unrar} walks an archive's
 * block headers and yields a {@link RarEntry} for each file it contains, and
 * for multi-volume archives stitches a file's data segments across volumes
 * into a single logical entry.
 */

// reads exactly `length` bytes from the reader at `offset`.
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

// pulls the bytes of every segment through one ReadableStream, in order, so
// the decoder (or AES-CBC decrypt stream) can read an entry's data area
// without ever buffering the whole payload in memory.
const streamSegments = (segments: DataSegment[]): ReadableStream<Uint8Array<ArrayBuffer>> => {
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

/**
 * a parsed block paired with the volume reader it came from; `block.dataOffset`
 * is relative to that reader and is corrected when the volume uses encrypted
 * block headers.
 */
export interface VolumeBlock {
	reader: Reader;
	block: import('./block.ts').Rar5Block;
}

// reads the header bytes of one block starting at `offset`, returning the
// cleartext bytes plus the number of bytes the block's header frame occupies
// in the archive. for an encrypted-header archive the frame includes a leading
// 16-byte IV and the rounded-up ciphertext; for a plain archive the frame is
// just the header itself.
const readHeaderFrame = async (
	reader: Reader,
	offset: number,
	headerCipher: CryptoKey | undefined,
): Promise<{ headerBytes: Uint8Array; frameSize: number }> => {
	if (headerCipher === undefined) {
		// the header size is only known once the CRC and the size vint are read.
		const peek = await readBytes(reader, offset, Math.min(8, reader.length - offset));
		const probe = new Cursor(peek);
		probe.skip(4);
		const headerSize = probe.vint() + probe.pos;

		const headerBytes = await readBytes(reader, offset, headerSize);
		return { frameSize: headerSize, headerBytes };
	}

	// encrypted header frame: [16-byte IV][ciphertext rounded to 16-byte multiple].
	const iv = await readBytes(reader, offset, 16);
	const firstEnc = await readBytes(reader, offset + 16, 16);
	const firstDec = await decryptAesCbc(headerCipher, iv, firstEnc);

	const probe = new Cursor(firstDec);
	probe.skip(4);
	const headerSize = probe.vint() + probe.pos;
	const cipherSize = (headerSize + 15) & ~15;

	if (cipherSize <= 16) {
		const headerBytes = new Uint8Array(headerSize);
		headerBytes.set(firstDec.subarray(0, headerSize));
		return { frameSize: 16 + 16, headerBytes };
	}

	// the CBC chain continues from the first ciphertext block, which acts as
	// the IV for the rest of the frame.
	const restEnc = await readBytes(reader, offset + 16 + 16, cipherSize - 16);
	const restDec = await decryptAesCbc(headerCipher, firstEnc, restEnc);

	const headerBytes = new Uint8Array(headerSize);
	headerBytes.set(firstDec);
	headerBytes.set(restDec.subarray(0, headerSize - 16), 16);
	return { frameSize: 16 + cipherSize, headerBytes };
};

// walks the block headers of one RAR5 volume, reading only header bytes. when
// the volume begins with an encryption header the walker derives the header
// AES key from the supplied `keys` cache and decrypts every subsequent block
// header before parsing it. every parsed block is yielded with its data offset
// corrected for the on-disk header frame size.
async function* walkVolume(
	reader: Reader,
	keys: KeyCache | undefined,
): AsyncGenerator<VolumeBlock> {
	const signature = await readBytes(reader, 0, RAR5_SIGNATURE.length);
	for (let idx = 0; idx < RAR5_SIGNATURE.length; idx++) {
		if (signature[idx] !== RAR5_SIGNATURE[idx]) {
			throw new Error(`not a rar5 archive: signature not found`);
		}
	}

	let offset = RAR5_SIGNATURE.length;
	let headerCipher: CryptoKey | undefined;

	while (offset + 4 < reader.length) {
		const { frameSize, headerBytes } = await readHeaderFrame(reader, offset, headerCipher);
		const parsed = parseBlock(headerBytes, offset);

		// the data area follows the whole (possibly encrypted) header frame, not
		// just the cleartext header parseBlock saw.
		const dataOffset = offset + frameSize;
		const block = headerCipher === undefined ? parsed : { ...parsed, dataOffset };

		if (block.kind === 'encryption') {
			if (headerCipher !== undefined) {
				throw new Error(`unexpected nested encryption header`);
			}
			if (keys === undefined) {
				throw new Error(`encrypted archive: a password is required`);
			}
			if (block.algorithm !== 0) {
				throw new Error(
					`encrypted archive: encryption algorithm ${block.algorithm} is not supported`,
				);
			}

			const { aes, derived } = await keys.get(block.salt, block.kdfCount);
			if (block.checkValue !== undefined) {
				verifyCheckValue(block.checkValue, derived.checkValue);
			}
			headerCipher = aes;
		}

		yield { block, reader };

		if (block.kind === 'endArc') {
			break;
		}

		offset = dataOffset + block.dataSize;
	}
}

// walks every volume in order, yielding every parsed block tagged with its
// volume reader.
async function* walkVolumes(
	readers: readonly Reader[],
	keys: KeyCache | undefined,
): AsyncGenerator<VolumeBlock> {
	for (const reader of readers) {
		yield* walkVolume(reader, keys);
	}
}

/** options shared by archive walkers. */
export interface WalkOptions {
	/**
	 * the password used to decrypt encrypted block headers. derivation is
	 * cached per (salt, KDF count) pair, so the work runs once for an archive
	 * even when many headers are encrypted.
	 */
	password?: string;
}

/**
 * walks every parsed block of a RAR5 archive (or multi-volume set), yielding
 * each block paired with the reader it came from. encrypted block headers are
 * decrypted on the fly when a password is supplied; for an archive whose
 * headers are not encrypted no password is needed.
 *
 * @param source one reader for a single-volume archive, or the ordered set of
 * volume readers for a multi-volume archive
 * @param options optional settings such as the password for encrypted headers
 * @returns async generator yielding every block, with `block.dataOffset`
 * corrected for the on-disk header frame size
 */
export const walkArchive = (
	source: Reader | readonly Reader[],
	options?: WalkOptions,
): AsyncGenerator<VolumeBlock> => {
	const readers: readonly Reader[] = Array.isArray(source) ? source : [source];
	const keys = options?.password !== undefined ? new KeyCache(options.password) : undefined;
	return walkVolumes(readers, keys);
};

/**
 * a single file entry within a RAR5 archive.
 *
 * metadata is available immediately; the entry's content is read lazily from
 * the archive when {@link RarEntry.body} or one of the convenience readers is
 * accessed. an entry that belongs to a solid run shares its decompression
 * state with the entries preceding it, and an entry whose data is split
 * across volumes spans multiple readers internally; the {@link unrar}
 * iterator drives both kinds of coordination so callers can simply consume
 * entries in order.
 */
export class RarEntry {
	readonly #head: FileBlock;
	readonly #segments: DataSegment[];
	readonly #finalCrc: number | undefined;
	readonly #decoder?: Rar5Decoder;
	readonly #keys?: KeyCache;

	// the entry's content as decoded chunks. populated by exactly one decode
	// pass on first consumption; subsequent consumers replay from this cache.
	#chunks?: Promise<Uint8Array<ArrayBuffer>[]>;

	/** @ignore */
	constructor(
		head: FileBlock,
		segments: DataSegment[],
		finalCrc: number | undefined,
		decoder?: Rar5Decoder,
		keys?: KeyCache,
	) {
		this.#head = head;
		this.#segments = segments;
		this.#finalCrc = finalCrc;
		this.#decoder = decoder;
		this.#keys = keys;
	}

	/**
	 * the entry's path within the archive, with forward slashes as separators.
	 * @returns the entry name
	 */
	get filename(): string {
		return this.#head.name;
	}

	/**
	 * the uncompressed size of the entry.
	 * @returns size in bytes
	 */
	get size(): number {
		return this.#head.unpackedSize;
	}

	/**
	 * the size the entry occupies across the archive's data area; for a split
	 * entry this is the sum of every volume's contribution.
	 * @returns size in bytes
	 */
	get compressedSize(): number {
		let total = 0;
		for (const segment of this.#segments) {
			total += segment.size;
		}
		return total;
	}

	/**
	 * the compression method, 0 for stored.
	 * @returns the method code, 0 through 5
	 */
	get compressionMethod(): number {
		return (this.#head.compressionInfo >> 7) & 0x07;
	}

	/**
	 * whether the entry is a directory.
	 * @returns true for a directory entry
	 */
	get isDirectory(): boolean {
		return isDirectory(this.#head);
	}

	/**
	 * whether the entry is a symlink, junction, or similar link.
	 * @returns true for a link entry
	 */
	get isSymlink(): boolean {
		return isSymlink(this.#head);
	}

	/**
	 * the link target, for symlink and other redirection entries.
	 * @returns the target path, or undefined for a non-link entry
	 */
	get linkTarget(): string | undefined {
		return this.#head.redirection?.target;
	}

	/**
	 * whether the entry's data is encrypted.
	 * @returns true for an encrypted entry
	 */
	get isEncrypted(): boolean {
		return this.#head.encryption !== undefined;
	}

	/**
	 * whether the entry is part of a solid block, and so depends on the
	 * decompression state of the entries before it.
	 * @returns true for a solid entry
	 */
	get isSolid(): boolean {
		return (this.#head.compressionInfo & COMPRESSION_SOLID) !== 0;
	}

	/**
	 * whether the entry's data is split across multiple volumes.
	 * @returns true for a multi-segment entry
	 */
	get isSplit(): boolean {
		return this.#segments.length > 1;
	}

	/**
	 * the data CRC32, when the archive records one. for a split entry this is
	 * the running CRC from the final volume, covering the full reconstructed
	 * content.
	 * @returns the checksum, or undefined when absent
	 */
	get crc32(): number | undefined {
		return this.#finalCrc;
	}

	/**
	 * the last modification time.
	 * @returns timestamp in milliseconds, or undefined when absent
	 */
	get mtime(): number | undefined {
		const time = this.#head.mtime;
		return time !== undefined ? time.seconds * 1000 + Math.floor(time.nanos / 1e6) : undefined;
	}

	/**
	 * the OS-specific attributes; the unix st_mode or Windows attribute bits.
	 * @returns the attributes value
	 */
	get mode(): number {
		return this.#head.attributes;
	}

	// runs the one decode pass for this entry on first consumption and caches
	// the resulting chunks; every later body/bytes/_drain call replays from the
	// cache. for an entry with a shared solid-run decoder, the iterator awaits
	// this before yielding the next solid entry so the decoder state stays in
	// sync with archive order.
	#materialize(): Promise<Uint8Array<ArrayBuffer>[]> {
		if (this.#chunks === undefined) {
			this.#chunks = this.#decode();
		}
		return this.#chunks;
	}

	async #decode(): Promise<Uint8Array<ArrayBuffer>[]> {
		const encryption = this.#head.encryption;

		let source: ReadableStream<Uint8Array<ArrayBuffer>>;
		if (encryption !== undefined) {
			source = await this.#decryptStream(encryption);
		} else {
			source = streamSegments(this.#segments);
		}

		const chunks = await this.#runPipeline(source);
		await this.#verifyCrc32(chunks);
		return chunks;
	}

	async #runPipeline(
		source: ReadableStream<Uint8Array<ArrayBuffer>>,
	): Promise<Uint8Array<ArrayBuffer>[]> {
		if (this.#decoder === undefined) {
			// a stored entry's concatenated bytes are its content verbatim; an
			// encrypted stored entry is CBC-padded to a 16-byte block, so the
			// drained payload may run past the declared size and must be trimmed.
			const expected = this.#head.unpackedSize;
			const collected: Uint8Array<ArrayBuffer>[] = [];
			let total = 0;
			for await (const chunk of source) {
				collected.push(chunk);
				total += chunk.length;
			}
			if (total < expected) {
				throw new Error(
					`stored data is ${total} bytes, expected at least ${expected}`,
				);
			}
			if (total === expected) {
				return collected.length === 1 ? collected : [concat(collected, total)];
			}
			const merged = collected.length === 1 ? collected[0] : concat(collected, total);
			return [new Uint8Array(merged.buffer, merged.byteOffset, expected)];
		}

		const chunks: Uint8Array<ArrayBuffer>[] = [];
		await using reader = new StreamReader(source);
		await this.#decoder.decode(reader, this.#head.unpackedSize, (chunk) => {
			chunks.push(chunk);
		});
		return chunks;
	}

	// verifies the recorded CRC32 against the decoded plaintext, applying the
	// TWEAKED transform for encrypted entries when set. silent when no CRC is
	// recorded (e.g. blake-hashed entries) so callers that rely on that branch
	// still see a clean read.
	async #verifyCrc32(chunks: readonly Uint8Array<ArrayBuffer>[]): Promise<void> {
		const stored = this.#finalCrc;
		if (stored === undefined) {
			return;
		}

		let computed = 0;
		for (const chunk of chunks) {
			computed = crc32(chunk, computed);
		}

		let expected = computed;
		const encryption = this.#head.encryption;
		if (
			encryption !== undefined &&
			(encryption.flags & FileEncryptionFlag.tweakedChecksums) !== 0 &&
			this.#keys !== undefined
		) {
			const { derived } = await this.#keys.get(encryption.salt, encryption.kdfCount);
			expected = await tweakCrc32(derived.hmacKey, computed);
		}

		if (expected !== stored) {
			throw new Error(
				`crc32 mismatch for ${this.#head.name}: ` +
					`stored 0x${stored.toString(16).padStart(8, '0')}, ` +
					`computed 0x${expected.toString(16).padStart(8, '0')}`,
			);
		}
	}

	// builds a stream of plaintext bytes from the entry's encrypted data area,
	// verifying the stored password check value up front so a wrong password
	// surfaces before any decryption work runs.
	async #decryptStream(
		encryption: FileEncryption,
	): Promise<ReadableStream<Uint8Array<ArrayBuffer>>> {
		if (this.#keys === undefined) {
			throw new Error(
				`cannot read ${this.#head.name}: a password is required for encrypted entries`,
			);
		}
		if (encryption.algorithm !== 0) {
			throw new Error(
				`cannot read ${this.#head.name}: encryption algorithm ${encryption.algorithm} is not supported`,
			);
		}

		const { aes, derived } = await this.#keys.get(encryption.salt, encryption.kdfCount);

		if (
			(encryption.flags & FileEncryptionFlag.hasCheckValue) !== 0 &&
			encryption.checkValue !== undefined
		) {
			verifyCheckValue(encryption.checkValue, derived.checkValue);
		}

		// the IV (and the rest of the encryption record) was sliced out of the
		// archive header bytes, whose array buffer is not exposed to Web Crypto's
		// narrowed `BufferSource`; a 16-byte copy detaches it cleanly.
		return decryptAesCbcStream(aes, encryption.iv.slice(), streamSegments(this.#segments));
	}

	/**
	 * a readable stream of the entry's decompressed content. for an unencrypted
	 * stored entry that has not yet been consumed elsewhere, segments stream
	 * directly without buffering; otherwise the single decode pass runs and its
	 * chunks are emitted in order.
	 * @returns a stream of the entry data
	 */
	get body(): ReadableStream<Uint8Array> {
		// an unencrypted stored entry can stream segment by segment without
		// going through the decoder. once its chunks have been cached elsewhere
		// (e.g. by bytes()), the cache path is cheaper.
		if (
			this.#decoder === undefined && this.#chunks === undefined &&
			this.#head.encryption === undefined
		) {
			return streamSegments(this.#segments);
		}

		return deferStream(async () => {
			const chunks = await this.#materialize();
			let index = 0;
			return new ReadableStream({
				pull(controller) {
					if (index < chunks.length) {
						controller.enqueue(chunks[index++]);
					} else {
						controller.close();
					}
				},
			});
		});
	}

	/**
	 * reads the entry content as bytes.
	 * @returns the content as a Uint8Array
	 */
	async bytes(): Promise<Uint8Array<ArrayBuffer>> {
		const chunks = await this.#materialize();
		if (chunks.length === 1) {
			return chunks[0];
		}
		return concat(chunks, this.#head.unpackedSize);
	}

	/**
	 * reads the entry content as an ArrayBuffer.
	 * @returns the content as an ArrayBuffer
	 */
	async arrayBuffer(): Promise<ArrayBuffer> {
		const bytes = await this.bytes();

		if (bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength) {
			return bytes.buffer;
		}

		return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
	}

	/**
	 * reads the entry content as a Blob.
	 * @returns the content as a Blob
	 */
	async blob(): Promise<Blob> {
		return new Blob([await this.bytes()]);
	}

	/**
	 * reads the entry content as text, decoded as UTF-8.
	 * @returns the content as a string
	 */
	async text(): Promise<string> {
		return decodeUtf8From(await this.bytes());
	}

	/**
	 * reads the entry content as UTF-8 text and parses it as JSON.
	 * @returns the parsed value
	 */
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

/** options controlling how {@link unrar} reads an archive. */
export interface UnrarOptions {
	/**
	 * the password used to decrypt entries with encrypted data. password
	 * derivation is cached per (salt, KDF count) pair, so the work runs once
	 * for an archive even when many entries are encrypted.
	 */
	password?: string;
}

/**
 * extracts entries from a RAR5 archive.
 *
 * the archive is read through `source`, which is either a single {@link Reader}
 * for a self-contained archive or an ordered list of readers for the volumes
 * of a multi-volume set. entries are yielded in archive order as their headers
 * are walked; a file whose data spans volumes is yielded once after its final
 * segment is seen. superseded file versions are omitted.
 *
 * entries that belong to a solid run share a single decompression window; the
 * iterator ensures the previous entry's body is materialized before yielding
 * the next solid entry, so consumers can treat them like any other entry.
 *
 * @param source one reader for a single-volume archive, or the ordered set of
 * volume readers for a multi-volume archive
 * @param options optional settings such as the password for encrypted entries
 * @returns async generator yielding the archive's file entries
 * @throws if a volume is not a RAR5 archive, a header fails validation, or a
 * split file's continuation is missing
 */
export async function* unrar(
	source: Reader | readonly Reader[],
	options?: UnrarOptions,
): AsyncGenerator<RarEntry> {
	const readers: readonly Reader[] = Array.isArray(source) ? source : [source];
	const keys = options?.password !== undefined ? new KeyCache(options.password) : undefined;

	let decoder: Rar5Decoder | undefined;
	let pending: RarEntry | undefined;

	let openHead: FileBlock | undefined;
	let openSegments: DataSegment[] = [];

	for await (const { reader, block } of walkVolumes(readers, keys)) {
		if (block.kind !== 'file') {
			continue;
		}

		// superseded versions never reach the listing.
		if (block.version !== undefined) {
			continue;
		}

		const splitBefore = (block.blockFlags & BlockFlag.splitBefore) !== 0;
		const splitAfter = (block.blockFlags & BlockFlag.splitAfter) !== 0;

		if (splitBefore) {
			if (openHead === undefined || openHead.name !== block.name) {
				throw new Error(
					`split continuation for ${block.name} without a preceding head; ` +
						`the first volume may be missing`,
				);
			}
			openSegments.push({ offset: block.dataOffset, reader, size: block.dataSize });
		} else {
			if (openHead !== undefined) {
				throw new Error(
					`new entry ${block.name} encountered while ${openHead.name} is still split; ` +
						`a continuation volume may be missing`,
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

		const method = (head.compressionInfo >> 7) & 0x07;
		const solid = (head.compressionInfo & COMPRESSION_SOLID) !== 0;
		const dictExp = (head.compressionInfo >> 10) & 0x0f;

		let entry: RarEntry;

		if (method === 0) {
			// a stored entry is independent of any solid run; reading it does not
			// touch the decoder's state.
			entry = new RarEntry(head, segments, finalCrc, undefined, keys);
		} else if (!solid) {
			// the head of a (potentially solid) run gets a fresh decoder.
			decoder = new Rar5Decoder(dictExp);
			entry = new RarEntry(head, segments, finalCrc, decoder, keys);
		} else if (decoder !== undefined) {
			// a continuation of the current solid run; the previous entry must
			// finish decoding so the shared window is in the right state.
			if (pending !== undefined) {
				await pending._drain();
			}
			entry = new RarEntry(head, segments, finalCrc, decoder, keys);
		} else {
			// a solid entry without a preceding run head; surface as an error at
			// read time rather than silently producing wrong bytes.
			entry = new RarEntry(head, segments, finalCrc, undefined, keys);
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
