const fromCharCode = String.fromCharCode;

export const textEncoder = new TextEncoder();
export const textDecoder = new TextDecoder();

export function concat(arrays: Uint8Array[], size?: number): Uint8Array<ArrayBuffer> {
	let written = 0;

	// deno-lint-ignore prefer-const
	let len = arrays.length;
	let idx: number;

	if (size === undefined) {
		for (idx = size = 0; idx < len; idx++) {
			const chunk = arrays[idx];
			size += chunk.length;
		}
	}

	const buffer = new Uint8Array(size);

	for (idx = 0; idx < len; idx++) {
		const chunk = arrays[idx];

		buffer.set(chunk, written);
		written += chunk.length;
	}

	return buffer;
}

export async function read(
	stream: ReadableStream<Uint8Array>,
	size: number,
): Promise<Uint8Array<ArrayBuffer>> {
	// fast path: a byte-type stream lets us request bytes straight into a
	// pre-allocated buffer with no producer-side memcpy. Web Crypto pipes
	// (decrypt streams) and user-supplied non-byte sources don't support
	// BYOB; fall back to the default-reader copy loop when getReader throws.
	//
	// the BYOB reader setup (and the TypeError throw when the stream isn't
	// byte-typed) carries ~µs of fixed overhead. for tiny reads — header
	// probes, signature checks, etc. — that swamps the per-byte savings, so
	// only attempt BYOB once the request is large enough to amortize the
	// setup. the threshold is empirical: profiling many small reads through
	// a non-byte stream (fromUint8Array) showed BYOB-setup-and-throw as
	// double-digit percent of total time on the in-memory LZSS bench.
	let byob: ReadableStreamBYOBReader | undefined;
	if (size >= 4096) {
		try {
			byob = stream.getReader({ mode: 'byob' });
		} catch {
			// fall through to default-reader path below
		}
	}

	if (byob !== undefined) {
		let buffer = new ArrayBuffer(size);
		let pos = 0;
		let drained = false;
		try {
			while (pos < size) {
				const view = new Uint8Array(buffer, pos, size - pos);
				const { done, value } = await byob.read(view);
				if (done) {
					drained = true;
					break;
				}
				// BYOB read transfers the input view's buffer into `value`;
				// reassign so the next iteration's view sees the live buffer.
				buffer = value.buffer as ArrayBuffer;
				pos += value.byteLength;
			}
		} finally {
			if (!drained) {
				await byob.cancel();
			} else {
				byob.releaseLock();
			}
		}
		if (pos < size) {
			throw new Error(`unexpected end of stream: expected ${size} bytes, got ${pos}`);
		}
		return new Uint8Array(buffer, 0, size);
	}

	const buffer = new Uint8Array(size);
	const reader = stream.getReader();
	let pos = 0;
	let drained = false;

	try {
		while (pos < size) {
			const { done, value } = await reader.read();
			if (done) {
				drained = true;
				break;
			}
			const length = value.length;
			const room = size - pos;
			if (length <= room) {
				buffer.set(value, pos);
				pos += length;
			} else {
				buffer.set(value.subarray(0, room), pos);
				pos = size;
			}
		}
	} finally {
		// when the stream is already at end, cancel is a no-op; when we have
		// enough bytes but the producer might still deliver more (e.g. AES-CBC
		// padding past the declared plaintext length), cancel releases its
		// resources without the costly async-iterator `return()` dance.
		if (!drained) {
			await reader.cancel();
		} else {
			reader.releaseLock();
		}
	}

	if (pos < size) {
		throw new Error(`unexpected end of stream: expected ${size} bytes, got ${pos}`);
	}

	return buffer;
}

export const decodeUtf8From = (from: Uint8Array, offset?: number, length?: number): string => {
	let buffer: Uint8Array;

	if (offset === undefined) {
		buffer = from;
	} else if (length === undefined) {
		buffer = from.subarray(offset);
	} else {
		buffer = from.subarray(offset, offset + length);
	}

	const end = buffer.length;
	if (end > 24) {
		return textDecoder.decode(buffer);
	}

	{
		let str = '';
		let idx = 0;

		for (; idx + 3 < end; idx += 4) {
			const a = buffer[idx];
			const b = buffer[idx + 1];
			const c = buffer[idx + 2];
			const d = buffer[idx + 3];

			if ((a | b | c | d) & 0x80) {
				return str + textDecoder.decode(buffer.subarray(idx));
			}

			str += fromCharCode(a, b, c, d);
		}

		for (; idx < end; idx++) {
			const x = buffer[idx];

			if (x & 0x80) {
				return str + textDecoder.decode(buffer.subarray(idx));
			}

			str += fromCharCode(x);
		}

		return str;
	}
};
