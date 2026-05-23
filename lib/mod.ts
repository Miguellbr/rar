/**
 * @module
 *
 * streaming RAR decoders for RAR5 and the RAR1.5 - RAR4 family ("RAR3").
 *
 * archive contents are read through a {@link Reader}; the `./deno` and `./node`
 * entry points provide readers backed by the respective runtime's file APIs.
 *
 * RAR5 archives extract end to end via {@link unrar}. RAR3 archives are
 * listable end to end via {@link unrar3}, but only stored entries (method
 * 0x30) can be read back today — calling body/bytes on a compressed RAR3
 * entry throws until the RAR3 decompressor lands.
 */

export type * from './reader/types.ts';
export * from './reader/common.ts';

export * from './rar5/extract.ts';
export { Rar3Entry, unrar3 } from './rar3/extract.ts';
