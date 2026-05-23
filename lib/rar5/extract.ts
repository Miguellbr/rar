import { decodeUtf8From, read } from '../utils/buffer.ts';

import type { Reader } from '../reader/types.ts';
import type { FileBlock } from './block.ts';
import { isDirectory, isSymlink, parseBlock } from './block.ts';
import { BlockFlag, COMPRESSION_SOLID, RAR5_SIGNATURE } from './constants.ts';
import { Cursor } from './cursor.ts';
import { Rar5Decoder } from './unpack.ts';

/**
 * @module
 *
 * sequential extraction of RAR5 archives. {@link unrar} walks an archive's
 * block headers and yields a {@link RarEntry} for each file it contains.
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

// walks the block headers of a RAR5 archive, reading only header bytes.
async function* walkArchive(reader: Reader): AsyncGenerator<FileBlock> {
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
			yield block;
		}

		if (block.kind === 'endArc') {
			break;
		}

		offset = block.dataOffset + block.dataSize;
	}
}

/**
 * a single file entry within a RAR5 archive.
 *
 * metadata is available immediately; the entry's content is read lazily from
 * the archive when {@link RarEntry.body} or one of the convenience readers is
 * accessed. an entry that belongs to a solid run shares its decompression
 * state with the entries preceding it; the {@link unrar} iterator drives that
 * coordination so callers can simply consume entries in order.
 */
export class RarEntry {
	readonly #reader: Reader;
	readonly #block: FileBlock;
	readonly #decoder?: Rar5Decoder;

	#bytes?: Promise<Uint8Array<ArrayBuffer>>;

	/** @ignore */
	constructor(reader: Reader, block: FileBlock, decoder?: Rar5Decoder) {
		this.#reader = reader;
		this.#block = block;
		this.#decoder = decoder;
	}

	/**
	 * the entry's path within the archive, with forward slashes as separators.
	 * @returns the entry name
	 */
	get filename(): string {
		return this.#block.name;
	}

	/**
	 * the uncompressed size of the entry.
	 * @returns size in bytes
	 */
	get size(): number {
		return this.#block.unpackedSize;
	}

	/**
	 * the size the entry occupies in the archive's data area.
	 * @returns size in bytes
	 */
	get compressedSize(): number {
		return this.#block.dataSize;
	}

	/**
	 * the compression method, 0 for stored.
	 * @returns the method code, 0 through 5
	 */
	get compressionMethod(): number {
		return (this.#block.compressionInfo >> 7) & 0x07;
	}

	/**
	 * whether the entry is a directory.
	 * @returns true for a directory entry
	 */
	get isDirectory(): boolean {
		return isDirectory(this.#block);
	}

	/**
	 * whether the entry is a symlink, junction, or similar link.
	 * @returns true for a link entry
	 */
	get isSymlink(): boolean {
		return isSymlink(this.#block);
	}

	/**
	 * the link target, for symlink and other redirection entries.
	 * @returns the target path, or undefined for a non-link entry
	 */
	get linkTarget(): string | undefined {
		return this.#block.redirection?.target;
	}

	/**
	 * whether the entry's data is encrypted.
	 * @returns true for an encrypted entry
	 */
	get isEncrypted(): boolean {
		return this.#block.encryption !== undefined;
	}

	/**
	 * whether the entry is part of a solid block, and so depends on the
	 * decompression state of the entries before it.
	 * @returns true for a solid entry
	 */
	get isSolid(): boolean {
		return (this.#block.compressionInfo & COMPRESSION_SOLID) !== 0;
	}

	/**
	 * the data CRC32, when the archive records one.
	 * @returns the checksum, or undefined when absent
	 */
	get crc32(): number | undefined {
		return this.#block.crc;
	}

	/**
	 * the last modification time.
	 * @returns timestamp in milliseconds, or undefined when absent
	 */
	get mtime(): number | undefined {
		const time = this.#block.mtime;
		return time !== undefined ? time.seconds * 1000 + Math.floor(time.nanos / 1e6) : undefined;
	}

	/**
	 * the OS-specific attributes; the unix st_mode or Windows attribute bits.
	 * @returns the attributes value
	 */
	get mode(): number {
		return this.#block.attributes;
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
		const block = this.#block;

		if (block.encryption !== undefined) {
			throw new Error(`cannot read ${block.name}: encrypted entries are not yet supported`);
		}

		const compressed = await readBytes(this.#reader, block.dataOffset, block.dataSize);

		if (this.#decoder === undefined) {
			// a stored entry's data area is its content verbatim.
			return compressed;
		}

		return this.#decoder.decode(compressed, block.unpackedSize);
	}

	/**
	 * a readable stream of the entry's decompressed content.
	 * @returns a stream of the entry data
	 */
	get body(): ReadableStream<Uint8Array> {
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

/**
 * extracts entries from a RAR5 archive.
 *
 * the archive is read through `reader`; entries are yielded in archive order as
 * their headers are walked. superseded file versions and the trailing parts of
 * split files are omitted.
 *
 * entries that belong to a solid run share a single decompression window; the
 * iterator ensures the previous entry's body is materialized before yielding
 * the next solid entry, so consumers can treat them like any other entry.
 *
 * @param reader data source to read the archive from
 * @returns async generator yielding the archive's file entries
 * @throws if the source is not a RAR5 archive or a header fails validation
 */
export async function* unrar(reader: Reader): AsyncGenerator<RarEntry> {
	let decoder: Rar5Decoder | undefined;
	let pending: RarEntry | undefined;

	for await (const block of walkArchive(reader)) {
		// superseded versions and split continuations are not standalone entries.
		if (block.version !== undefined || (block.blockFlags & BlockFlag.splitBefore) !== 0) {
			continue;
		}

		const method = (block.compressionInfo >> 7) & 0x07;
		const solid = (block.compressionInfo & COMPRESSION_SOLID) !== 0;
		const dictExp = (block.compressionInfo >> 10) & 0x0f;

		let entry: RarEntry;

		if (method === 0) {
			// a stored entry is independent of any solid run; reading it does not
			// touch the decoder's state.
			entry = new RarEntry(reader, block);
		} else if (!solid) {
			// the head of a (potentially solid) run gets a fresh decoder.
			decoder = new Rar5Decoder(dictExp);
			entry = new RarEntry(reader, block, decoder);
		} else if (decoder !== undefined) {
			// a continuation of the current solid run; the previous entry must
			// finish decoding so the shared window is in the right state.
			if (pending !== undefined) {
				await pending._drain();
			}
			entry = new RarEntry(reader, block, decoder);
		} else {
			// a solid entry without a preceding run head; surface as an error at
			// read time rather than silently producing wrong bytes.
			entry = new RarEntry(reader, block);
		}

		pending = entry;
		yield entry;
	}
}
