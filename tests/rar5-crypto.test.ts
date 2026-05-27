import { MalformedArchiveError } from '../lib/errors.ts';
import { decryptAesCbc, decryptAesCbcStream, importAesKey } from '../lib/rar5/crypto.ts';

/**
 * @module
 *
 * tests for the AES-CBC streaming decryption path. the rarfile fixtures all
 * have encrypted entries small enough to fit in one {@link decryptAesCbcStream}
 * batch, so multi-batch chaining is exercised here with synthetic data.
 */

const STREAM_BATCH_BYTES = 4096;

// encrypts a plaintext with AES-256-CBC the way RAR5 stores it: padded to a
// 16-byte boundary, no PKCS#7 trailer. emits the ciphertext bytes, which can
// later be fed back through decryptAesCbc / decryptAesCbcStream.
const encryptRar5Style = async (
	key: CryptoKey,
	iv: Uint8Array<ArrayBuffer>,
	plaintext: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> => {
	// pad plaintext to 16 bytes with PKCS#7 so Web Crypto's AES-CBC encrypt is
	// happy, then drop the final padding block — its corresponding plaintext
	// bytes are not part of the RAR5 ciphertext.
	const padded = new Uint8Array(
		await crypto.subtle.encrypt({ iv, name: 'AES-CBC' }, key, plaintext),
	);
	const trimmed = (plaintext.length + 15) & ~15;
	return new Uint8Array(padded.buffer, padded.byteOffset, trimmed);
};

const buildStream = (
	chunks: Uint8Array<ArrayBuffer>[],
): ReadableStream<Uint8Array<ArrayBuffer>> => {
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
};

const drain = async (
	stream: ReadableStream<Uint8Array<ArrayBuffer>>,
): Promise<Uint8Array<ArrayBuffer>> => {
	const chunks: Uint8Array<ArrayBuffer>[] = [];
	let total = 0;
	for await (const chunk of stream) {
		chunks.push(chunk);
		total += chunk.length;
	}
	const out = new Uint8Array(total);
	let offset = 0;
	for (const chunk of chunks) {
		out.set(chunk, offset);
		offset += chunk.length;
	}
	return out;
};

const setupKey = async (): Promise<{ key: CryptoKey; iv: Uint8Array<ArrayBuffer> }> => {
	const keyBytes = new Uint8Array(32);
	crypto.getRandomValues(keyBytes);
	const iv = new Uint8Array(16);
	crypto.getRandomValues(iv);
	const key = await importAesKey(keyBytes);
	return { iv, key };
};

Deno.test('decryptAesCbcStream: matches the one-shot decrypt for a single-batch payload', async () => {
	const { iv, key } = await setupKey();
	const plaintext = new Uint8Array(2048);
	crypto.getRandomValues(plaintext);

	const ciphertext = await encryptRar5Style(key, iv, plaintext);
	const oneShot = await decryptAesCbc(key, iv.slice(), ciphertext);
	const streamed = await drain(decryptAesCbcStream(key, iv.slice(), buildStream([ciphertext])));

	if (oneShot.length !== streamed.length) {
		throw new Error(`length mismatch: oneShot=${oneShot.length} streamed=${streamed.length}`);
	}
	for (let idx = 0; idx < oneShot.length; idx++) {
		if (oneShot[idx] !== streamed[idx]) {
			throw new Error(`byte ${idx} differs: oneShot=${oneShot[idx]} streamed=${streamed[idx]}`);
		}
	}
	for (let idx = 0; idx < plaintext.length; idx++) {
		if (streamed[idx] !== plaintext[idx]) {
			throw new Error(`plaintext byte ${idx} differs after round trip`);
		}
	}
});

Deno.test('decryptAesCbcStream: chains correctly across batches', async () => {
	const { iv, key } = await setupKey();

	// 3 batches' worth of plaintext exercises at least two IV chain transitions.
	const plaintext = new Uint8Array(STREAM_BATCH_BYTES * 3);
	crypto.getRandomValues(plaintext);

	const ciphertext = await encryptRar5Style(key, iv, plaintext);

	// chunk the ciphertext into oddly-sized pieces so the streaming decrypt
	// has to buffer across reads to assemble each batch.
	const chunks: Uint8Array<ArrayBuffer>[] = [];
	for (let offset = 0; offset < ciphertext.length; offset += 273) {
		const end = Math.min(offset + 273, ciphertext.length);
		chunks.push(ciphertext.slice(offset, end));
	}

	const streamed = await drain(decryptAesCbcStream(key, iv.slice(), buildStream(chunks)));

	if (streamed.length !== ciphertext.length) {
		throw new Error(`length mismatch: streamed=${streamed.length} expected=${ciphertext.length}`);
	}
	for (let idx = 0; idx < plaintext.length; idx++) {
		if (streamed[idx] !== plaintext[idx]) {
			throw new Error(`plaintext byte ${idx} differs after round trip`);
		}
	}
});

Deno.test('decryptAesCbcStream: rejects an unaligned final length', async () => {
	const { iv, key } = await setupKey();
	const bad = new Uint8Array(17);
	crypto.getRandomValues(bad);

	let threw = false;
	try {
		await drain(decryptAesCbcStream(key, iv.slice(), buildStream([bad])));
	} catch (error) {
		threw = true;
		if (!(error instanceof MalformedArchiveError)) {
			throw new Error(`unexpected error: ${error}`);
		}
	}
	if (!threw) {
		throw new Error('expected an unaligned-length error');
	}
});

Deno.test('decryptAesCbcStream: handles an empty stream', async () => {
	const { iv, key } = await setupKey();
	const streamed = await drain(decryptAesCbcStream(key, iv.slice(), buildStream([])));
	if (streamed.length !== 0) {
		throw new Error(`expected an empty result, got ${streamed.length} bytes`);
	}
});
