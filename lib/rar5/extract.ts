import { concat, decodeUtf8From, read } from '../utils/buffer.ts';

import type { Reader } from '../reader/types.ts';
import type { FileBlock, FileEncryption } from './block.ts';
import { isDirectory, isSymlink, parseBlock } from './block.ts';
import { BlockFlag, COMPRESSION_SOLID, FileEncryptionFlag, RAR5_SIGNATURE } from './constants.ts';
import type { DerivedKeys } from './crypto.ts';
import { decryptAesCbc, deriveKeys, importAesKey } from './crypto.ts';
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

// reads the bytes of a single segment.
const readSegment = (segment: DataSegment): Promise<Uint8Array<ArrayBuffer>> => {
	return readBytes(segment.reader, segment.offset, segment.size);
};

// concatenates the bytes of every data segment into one buffer. used to feed
// the decompressor when an entry's data is split across multiple volumes.
const readSegments = async (segments: DataSegment[]): Promise<Uint8Array<ArrayBuffer>> => {
	if (segments.length === 1) {
		return await readSegment(segments[0]);
	}

	let total = 0;
	for (const segment of segments) {
		total += segment.size;
	}

	const chunks = await Promise.all(segments.map(readSegment));
	return concat(chunks, total);
};

// pulls the bytes of every segment through one ReadableStream. for stored
// entries this avoids buffering the whole payload in memory.
const streamSegments = (segments: DataSegment[]): ReadableStream<Uint8Array> => {
	let index = 0;
	let current: ReadableStreamDefaultReader<Uint8Array> | undefined;

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

// a file block paired with the volume reader it came from. block.dataOffset
// is relative to that reader.
interface VolumeFileBlock {
	reader: Reader;
	block: FileBlock;
}

// walks the block headers of one RAR5 volume, reading only header bytes.
async function* walkVolume(reader: Reader): AsyncGenerator<VolumeFileBlock> {
	const signature = await readBytes(reader, 0, RAR5_SIGNATURE.length);
	for (let idx = 0; idx < RAR5_SIGNATURE.length; idx++) {
		if (signature[idx] !== RAR5_SIGNATURE[idx]) {
			throw new Error(`not a rar5 archive: signature not found`);
		}
	}

	let offset = RAR5_SIGNATURE.length;

	while (offset + 4 < reader.length) {
		// the header size is only known once the CRC and the size vint are read.
		const peek = await readBytes(reader, offset, Math.min(8, reader.length - offset));
		const probe = new Cursor(peek);
		probe.skip(4);
		const headerSize = probe.vint() + probe.pos;

		const block = parseBlock(await readBytes(reader, offset, headerSize), offset);

		if (block.kind === 'file') {
			yield { block, reader };
		}

		if (block.kind === 'endArc') {
			break;
		}

		offset = block.dataOffset + block.dataSize;
	}
}

// walks every volume in order, yielding file blocks tagged with their reader.
async function* walkVolumes(readers: readonly Reader[]): AsyncGenerator<VolumeFileBlock> {
	for (const reader of readers) {
		yield* walkVolume(reader);
	}
}

// a cache of keys derived for a given (password, salt, kdfCount) so that the
// 32k-iteration KDF runs once per archive rather than once per encrypted
// entry. the AES key handle is also cached so that Web Crypto only sees the
// raw key bytes once.
class KeyCache {
	readonly #password: string;
	readonly #entries = new Map<string, Promise<{ derived: DerivedKeys; aes: CryptoKey }>>();

	constructor(password: string) {
		this.#password = password;
	}

	get(salt: Uint8Array, kdfCount: number): Promise<{ derived: DerivedKeys; aes: CryptoKey }> {
		// the salt is 16 bytes and the count is a single byte, so a hex-prefix
		// key is unique and cheap to build.
		let saltHex = '';
		for (const byte of salt) {
			saltHex += byte.toString(16).padStart(2, '0');
		}

		const cacheKey = `${kdfCount}:${saltHex}`;
		const existing = this.#entries.get(cacheKey);
		if (existing !== undefined) {
			return existing;
		}

		const computed = (async () => {
			const derived = await deriveKeys(this.#password, salt, kdfCount);
			const aes = await importAesKey(derived.aesKey);
			return { aes, derived };
		})();
		this.#entries.set(cacheKey, computed);
		return computed;
	}
}

// verifies a derived check value against the one stored in an entry's
// encryption record. the stored value is 8 bytes of folded PBKDF2 output
// plus the first 4 bytes of its SHA-256.
const verifyCheckValue = (stored: Uint8Array, derived: Uint8Array): void => {
	if (stored.length !== derived.length) {
		throw new Error(`password does not match: check value length differs`);
	}
	let diff = 0;
	for (let idx = 0; idx < stored.length; idx++) {
		diff |= stored[idx] ^ derived[idx];
	}
	if (diff !== 0) {
		throw new Error(`password does not match: check value mismatch`);
	}
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

	#bytes?: Promise<Uint8Array<ArrayBuffer>>;

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

	// resolves to the entry's decompressed bytes, computing them once and
	// caching the result. for an entry with a shared decoder, the iterator
	// awaits this before yielding the next solid entry so the decoder state
	// stays in sync with archive order.
	#materialize(): Promise<Uint8Array<ArrayBuffer>> {
		if (this.#bytes === undefined) {
			this.#bytes = this.#decode();
		}
		return this.#bytes;
	}

	async #decode(): Promise<Uint8Array<ArrayBuffer>> {
		const encryption = this.#head.encryption;

		let compressed = await readSegments(this.#segments);

		if (encryption !== undefined) {
			compressed = await this.#decryptDataArea(encryption, compressed);
		}

		if (this.#decoder === undefined) {
			// a stored entry's concatenated data segments are its content
			// verbatim; an encrypted stored entry is padded to a 16-byte block,
			// so trim to the declared unpacked size.
			const expected = this.#head.unpackedSize;
			if (compressed.length === expected) {
				return compressed;
			}
			if (compressed.length < expected) {
				throw new Error(
					`stored data is ${compressed.length} bytes, expected at least ${expected}`,
				);
			}
			return new Uint8Array(compressed.buffer, compressed.byteOffset, expected);
		}

		return this.#decoder.decode(compressed, this.#head.unpackedSize);
	}

	// decrypts an entry's full ciphertext, verifying the stored password check
	// value when present so the caller hears about a wrong password before any
	// decompression attempt runs.
	async #decryptDataArea(
		encryption: FileEncryption,
		ciphertext: Uint8Array<ArrayBuffer>,
	): Promise<Uint8Array<ArrayBuffer>> {
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
		return await decryptAesCbc(aes, encryption.iv.slice(), ciphertext);
	}

	/**
	 * a readable stream of the entry's decompressed content. for stored entries
	 * this streams the raw data segments without buffering them in memory.
	 * @returns a stream of the entry data
	 */
	get body(): ReadableStream<Uint8Array> {
		// stored, never-yet-decoded entries can stream segment by segment.
		if (
			this.#decoder === undefined && this.#bytes === undefined &&
			this.#head.encryption === undefined
		) {
			return streamSegments(this.#segments);
		}

		return deferStream(async () => {
			const bytes = await this.#materialize();
			return new ReadableStream({
				start(controller) {
					controller.enqueue(bytes);
					controller.close();
				},
			});
		});
	}

	/**
	 * reads the entry content as bytes.
	 * @returns the content as a Uint8Array
	 */
	async bytes(): Promise<Uint8Array<ArrayBuffer>> {
		return await this.#materialize();
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

	for await (const { reader, block } of walkVolumes(readers)) {
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
