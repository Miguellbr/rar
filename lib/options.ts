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
	/**
	 * the password used to decrypt entries with encrypted data. for RAR5,
	 * key derivation is cached per (salt, KDF count) pair so the work runs
	 * once per archive even when many entries are encrypted. for RAR3, the
	 * `rar3_s2k` KDF is rerun per encrypted entry because each entry carries
	 * its own salt.
	 */
	password?: string;
}

/** options recognised by the archive header walkers. */
export interface WalkOptions {
	/**
	 * the password used to decrypt encrypted block headers. RAR5 derives the
	 * header key once per (salt, KDF count) pair via an internal cache; RAR3
	 * decrypts each volume's header span in one pass when its main header is
	 * marked password-protected.
	 */
	password?: string;
}
