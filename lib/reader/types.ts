/** random-access byte source backing every {@link unrar}-family entry point. */
export interface Reader {
	/** total length of the source in bytes. */
	length: number;
	/**
	 * streams `length` bytes starting at `offset`, or to the end when `length`
	 * is omitted.
	 */
	read(offset: number, length?: number): Promise<ReadableStream<Uint8Array<ArrayBuffer>>>;
}
