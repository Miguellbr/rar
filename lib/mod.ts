/**
 * @module
 *
 * a streaming RAR5 decoder.
 *
 * archive contents are read through a {@link Reader}; the `./deno` and `./node`
 * entry points provide readers backed by the respective runtime's file APIs.
 */

export type * from './reader/types.ts';
export * from './reader/common.ts';
