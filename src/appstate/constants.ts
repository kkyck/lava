/**
 * App-state synchronisation constants.
 *
 * WhatsApp keeps a small set of *collections* in sync between the devices of
 * one account: the chat list, the contacts, the labels, the mute and archive
 * settings. Every device may change them, so the server brokers the changes
 * as *mutations*, which are encrypted and MACed per device.
 *
 * The names, the key layout and the HKDF context strings below are the ones
 * the official clients use, so a Lava device and an official device can
 * share the same collection state.
 */

import { utf8 } from '../crypto/primitives.js'

/** The collections the server keeps in sync. */
export const APP_STATE_COLLECTIONS = Object.freeze({
    REGULAR: 'regular',
    REGULAR_LOW: 'regular_low',
    REGULAR_HIGH: 'regular_high',
    CRITICAL_BLOCK: 'critical_block',
    CRITICAL_UNBLOCK_LOW: 'critical_unblock_low',
})

/**
 * The collections a client syncs by default.
 *
 * The order matches the official client: the critical ones come first, so a
 * failed round does not block the regular collections.
 */
export const APP_STATE_DEFAULT_COLLECTIONS = Object.freeze([
    APP_STATE_COLLECTIONS.CRITICAL_UNBLOCK_LOW,
    APP_STATE_COLLECTIONS.CRITICAL_BLOCK,
    APP_STATE_COLLECTIONS.REGULAR_LOW,
    APP_STATE_COLLECTIONS.REGULAR,
    APP_STATE_COLLECTIONS.REGULAR_HIGH,
])

/** The media types the app-state blobs are stored under. */
export const APP_STATE_KEY_TYPES = Object.freeze({
    MD_APP_STATE: 'md-app-state',
    MD_MSG_HIST: 'md-msg-hist',
})

/** The HKDF context strings of the app-state key schedule. */
export const APP_STATE_KDF_INFO = Object.freeze({
    /** Derives the index, value and MAC keys of a sync key. */
    MUTATION_KEYS: utf8('WhatsApp Mutation Keys'),
    /** Expands a value MAC into the points of the LT-hash digest. */
    PATCH_INTEGRITY: utf8('WhatsApp Patch Integrity'),
})

/** The outcome of a collection round. */
export const APP_STATE_COLLECTION_STATES = Object.freeze({
    SUCCESS: 'success',
    SUCCESS_HAS_MORE: 'success_has_more',
    CONFLICT: 'conflict',
    CONFLICT_HAS_MORE: 'conflict_has_more',
    ERROR_RETRY: 'error_retry',
    ERROR_FATAL: 'error_fatal',
    /**
     * The collection cannot be processed because a sync key is missing.
     *
     * The client asks the peer for the key and tries again.
     */
    BLOCKED: 'blocked',
})

/** The error codes the server answers a collection with. */
export const APP_STATE_ERROR_CODES = Object.freeze({
    CONFLICT: '409',
    BAD_REQUEST: '400',
    NOT_FOUND: '404',
    NOT_ALLOWED: '405',
    NOT_ACCEPTABLE: '406',
})

/** The length of the derived key material of one sync key. */
export const APP_STATE_DERIVED_KEY_LENGTH = 160

/** The end of the index HMAC key inside the derived key material. */
export const APP_STATE_DERIVED_INDEX_KEY_END = 32

/** The end of the value encryption key inside the derived key material. */
export const APP_STATE_DERIVED_VALUE_ENCRYPTION_KEY_END = 64

/** The end of the value MAC key inside the derived key material. */
export const APP_STATE_DERIVED_VALUE_MAC_KEY_END = 96

/** The end of the snapshot MAC key inside the derived key material. */
export const APP_STATE_DERIVED_SNAPSHOT_MAC_KEY_END = 128

/** The end of the patch MAC key inside the derived key material. */
export const APP_STATE_DERIVED_PATCH_MAC_KEY_END = 160

/** The length of a value MAC. */
export const APP_STATE_VALUE_MAC_LENGTH = 32

/** The length of the associated-data length field of a value MAC. */
export const APP_STATE_MAC_OCTET_LENGTH = 8

/** The length of the initialisation vector of an encrypted mutation. */
export const APP_STATE_IV_LENGTH = 16

/** The length of the LT-hash digest of a collection. */
export const APP_STATE_LT_HASH_SIZE = 128

/** The number of bytes of one point of the LT-hash digest. */
export const APP_STATE_POINT_SIZE = 2

/** The digest of an empty collection. */
export const APP_STATE_EMPTY_LT_HASH = new Uint8Array(APP_STATE_LT_HASH_SIZE)

/** The version a collection starts at. */
export const APP_STATE_DEFAULT_COLLECTION_VERSION = 0

/** The length of the secret part of a sync key. */
export const APP_STATE_SYNC_KEY_LENGTH = 32

/**
 * The length of a sync key id.
 *
 * The id is two big-endian bytes of the device index followed by four
 * big-endian bytes of the epoch, which is how the official client lays it
 * out.
 */
export const APP_STATE_SYNC_KEY_ID_LENGTH = 6
