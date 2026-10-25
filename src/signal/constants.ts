/**
 * Signal protocol constants.
 *
 * WhatsApp uses a fork of the Signal Double Ratchet protocol with a few
 * differences that matter for wire compatibility:
 *
 * - The pre-key bundle is **not** a Signal protobuf message; it is fetched
 *   through the `usync`/`iq` node protocol and carries raw key material.
 * - The session identifier is the *base key* (the local one-time pre-key
 *   public key) rather than a random 32-byte session id.
 * - The ratchet is "half-double": WhatsApp keeps a *receiving* chain per
 *   remote ratchet key instead of a single chain, so a device that was
 *   offline can still decrypt messages sent while it was away.
 */

/** Signal protocol version used by current WhatsApp clients. */
export const SIGNAL_VERSION = 3

/** Signal group protocol version. */
export const SIGNAL_GROUP_VERSION = 3

/** Length of the truncated HMAC tag appended to every Signal message. */
export const SIGNAL_MAC_SIZE = 8

/** Maximum number of messages we keep skipped-ahead keys for. */
export const MAX_UNUSED_KEYS = 2000

/** Maximum distance a message counter may be ahead of the current chain. */
export const FUTURE_MESSAGES_MAX = 2000

/**
 * Maximum number of superseded sessions kept per peer.
 *
 * A peer may re-key a conversation at any time; the messages that were
 * encrypted with the old key can still arrive afterwards, so the replaced
 * sessions are kept around for a while.
 */
export const MAX_PREV_SESSIONS = 40

/**
 * Maximum number of sender-key generations kept per sender and group.
 *
 * A participant may re-key a group at any time. The messages that were
 * encrypted with the previous key can still arrive afterwards, so the
 * replaced generations are kept around for a while.
 */
export const MAX_SENDER_KEY_STATES = 5

/** Label used when deriving the next chain key. */
export const MESSAGE_KEY_LABEL = new Uint8Array([1])

/** Label used when deriving the next chain key. */
export const CHAIN_KEY_LABEL = new Uint8Array([2])

/** HKDF info string for the session root/chain key derivation. */
export const WHISPER_TEXT_INFO = new Uint8Array([
    0x57, 0x68, 0x69, 0x73, 0x70, 0x65, 0x72, 0x54, 0x65, 0x78, 0x74,
]) // "WhisperText"

/** HKDF info string for the ratchet key derivation. */
export const WHISPER_RATCHET_INFO = new Uint8Array([
    0x57, 0x68, 0x69, 0x73, 0x70, 0x65, 0x72, 0x52, 0x61, 0x74, 0x63, 0x68, 0x65, 0x74,
]) // "WhisperRatchet"

/** HKDF info string for the message key derivation. */
export const WHISPER_MESSAGE_KEYS_INFO = new Uint8Array([
    0x57, 0x68, 0x69, 0x73, 0x70, 0x65, 0x72, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x4b, 0x65,
    0x79, 0x73,
]) // "WhisperMessageKeys"

/** HKDF info string for the group (sender key) derivation. */
export const WHISPER_GROUP_INFO = new Uint8Array([
    0x57, 0x68, 0x69, 0x73, 0x70, 0x65, 0x72, 0x47, 0x72, 0x6f, 0x75, 0x70,
]) // "WhisperGroup"

/**
 * Prefix prepended to the shared secret before HKDF.
 *
 * 32 bytes of `0xff` — this is Signal's "version" marker that keeps the
 * derived keys from colliding with pre-Signal versions.
 */
export const SIGNAL_PREFIX = new Uint8Array(32).fill(0xff)
