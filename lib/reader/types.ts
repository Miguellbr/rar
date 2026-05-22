/**
 * interface for reading data from a zip source
 */
export interface Reader {
	/** total length of the data source */
	length: number;
	/** reads data from the specified offset and length */
	read(offset: number, length?: number): Promise<ReadableStream<Uint8Array<ArrayBuffer>>>;
}
