/**
 * @module
 *
 * options that the RAR3, RAR5, and format-agnostic entry points all accept.
 * keeping them in a single module avoids both extract paths defining
 * parallel `{ password? }` shapes that callers have to remember to keep in
 * sync.
 */

/** options recognised by every {@link unrar}-family entry point. */
export interface UnrarOptions {
	/** password used to decrypt encrypted entries. */
	password?: string;
}

/** options recognised by the archive header walkers. */
export interface WalkOptions {
	/** password used to decrypt encrypted block headers. */
	password?: string;
}
