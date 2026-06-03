import { fromFile } from '../lib/reader/common.ts';

/**
 * @module
 *
 * `fromFile` (Blob reader) regression coverage. Bun's Blob-backed slice
 * streams can deliver their bytes but fail to emit a final `{ done: true }`
 * (empty slices never close at all), so `fromFile` bounds the read to the
 * slice length and closes the stream itself. these tests pin that behaviour
 * with a source stream that never closes on its own.
 */

const eq = (got: unknown, want: unknown, label: string): void => {
	if (JSON.stringify(got) !== JSON.stringify(want)) {
		throw new Error(`${label}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
	}
};

// a Blob whose slice streams deliver their bytes but never emit a final
// `{ done: true }` — the Bun behaviour fromFile has to defend against.
const neverClosingBlob = (payload: Uint8Array<ArrayBuffer>): Blob =>
	({
		size: payload.byteLength,
		slice(start = 0, end = payload.byteLength) {
			const part = payload.subarray(start, end);
			return {
				size: part.byteLength,
				stream: () =>
					new ReadableStream<Uint8Array<ArrayBuffer>>({
						start(controller) {
							if (part.byteLength > 0) {
								// fresh buffer per chunk, like a real Blob.stream(); a byte
								// stream detaches whatever it enqueues.
								controller.enqueue(part.slice() as Uint8Array<ArrayBuffer>);
							}
							// deliberately never close()
						},
					}),
			};
		},
	}) as unknown as Blob;

// drains a stream to completion, failing fast instead of hanging if it never
// closes (the symptom this guards against).
const collectBounded = async (stream: ReadableStream<Uint8Array>): Promise<Uint8Array> => {
	let timer: ReturnType<typeof setTimeout> | undefined;
	const timeout = new Promise<never>((_, reject) => {
		timer = setTimeout(() => reject(new Error('stream did not close within 5s')), 5000);
	});
	const drain = (async () => {
		const chunks: Uint8Array[] = [];
		let total = 0;
		for await (const chunk of stream) {
			chunks.push(chunk);
			total += chunk.byteLength;
		}
		const merged = new Uint8Array(total);
		let pos = 0;
		for (const chunk of chunks) {
			merged.set(chunk, pos);
			pos += chunk.byteLength;
		}
		return merged;
	})();
	try {
		return await Promise.race([drain, timeout]);
	} finally {
		clearTimeout(timer);
	}
};

Deno.test('fromFile: a non-empty range ends even when the source never closes', async () => {
	const payload = new Uint8Array(1000);
	for (let i = 0; i < payload.length; i++) {
		payload[i] = (i * 3) & 0xff;
	}
	const reader = fromFile(neverClosingBlob(payload));
	const got = await collectBounded(await reader.read(100, 300));
	eq([...got], [...payload.subarray(100, 400)], 'bytes');
});

Deno.test('fromFile: an empty range ends with no bytes', async () => {
	const payload = new Uint8Array(1000);
	const reader = fromFile(neverClosingBlob(payload));
	const got = await collectBounded(await reader.read(100, 0));
	eq(got.byteLength, 0, 'length');
});
