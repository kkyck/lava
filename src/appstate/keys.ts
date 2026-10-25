/**
 * The app-state sync keys.
 *
 * Every device of an account holds its own sync key. The key has an id that
 * names the device and an epoch that says how often the key was rotated:
 *
 * ```text
 *   key id (6 bytes)
 *     ├─ device index (2 bytes, big endian)
 *     └─ epoch        (4 bytes, big endian)
 * ```
 *
 * The epoch is what makes the newest key win: a device that rotates its key
 * bumps the epoch, and the other devices then prefer the newer key over
 * their own.
 */

import { randomBytesOf, randomInt } from '../crypto/primitives.js'
import { APP_STATE_SYNC_KEY_ID_LENGTH, APP_STATE_SYNC_KEY_LENGTH } from './constants.js'

/** An app-state sync key. */
export interface AppStateSyncKey {
    /** The id of the key: the device index and the epoch. */
    keyId: Uint8Array
    /** The secret of the key. */
    keyData: Uint8Array
    /** The timestamp the key was created at, in milliseconds. */
    timestamp: number
}

/**
 * Reads the device index out of a sync key id.
 *
 * @param keyId The key id.
 * @returns The device index, or `null` when the id is too short.
 */
export function syncKeyDeviceId(keyId: Uint8Array): number | null {
    if (keyId.length < APP_STATE_SYNC_KEY_ID_LENGTH) return null
    return (keyId[0]! << 8) | keyId[1]!
}

/**
 * Reads the epoch out of a sync key id.
 *
 * @param keyId The key id.
 * @returns The epoch, or `-1` when the id is too short.
 */
export function syncKeyEpoch(keyId: Uint8Array): number {
    if (keyId.length < APP_STATE_SYNC_KEY_ID_LENGTH) return -1
    return (
        keyId[2]! * 0x1000000 +
        keyId[3]! * 0x10000 +
        keyId[4]! * 0x100 +
        keyId[5]!
    )
}

/**
 * Builds the id of a sync key.
 *
 * @param deviceIndex The index of the device that owns the key.
 * @param epoch The epoch of the key.
 */
export function buildSyncKeyId(deviceIndex: number, epoch: number): Uint8Array {
    const id = new Uint8Array(APP_STATE_SYNC_KEY_ID_LENGTH)
    id[0] = (deviceIndex >>> 8) & 0xff
    id[1] = deviceIndex & 0xff
    id[2] = (epoch >>> 24) & 0xff
    id[3] = (epoch >>> 16) & 0xff
    id[4] = (epoch >>> 8) & 0xff
    id[5] = epoch & 0xff
    return id
}

/**
 * Picks the key a device should use to write.
 *
 * The key with the highest epoch wins; on a tie the lower device index
 * wins, so every device of the account picks the same key.
 *
 * @param keys The keys to choose from.
 * @returns The active key, or `null` when there is none.
 */
export function pickActiveSyncKey(
    keys: Iterable<AppStateSyncKey>,
): AppStateSyncKey | null {
    let active: AppStateSyncKey | null = null
    for (const key of keys) {
        if (!active) {
            active = key
            continue
        }
        const currentEpoch = syncKeyEpoch(active.keyId)
        const nextEpoch = syncKeyEpoch(key.keyId)
        if (nextEpoch > currentEpoch) {
            active = key
            continue
        }
        if (nextEpoch < currentEpoch) continue
        const nextDeviceId = syncKeyDeviceId(key.keyId)
        const currentDeviceId = syncKeyDeviceId(active.keyId)
        if (nextDeviceId !== null && currentDeviceId !== null && nextDeviceId < currentDeviceId) {
            active = key
        }
    }
    return active
}

/**
 * Generates a fresh sync key for a device.
 *
 * The epoch is drawn at random so two devices that pair at the same moment
 * do not end up with the same key id.
 *
 * @param deviceIndex The index of the device that owns the key.
 * @param timestamp The creation timestamp, in milliseconds.
 */
export function generateSyncKey(deviceIndex: number, timestamp: number): AppStateSyncKey {
    // The epoch is a 32-bit counter; the official client draws it from
    // `[1, 65537)`, which keeps the id short and readable.
    const epoch = randomInt(65537) || 1
    return {
        keyId: buildSyncKeyId(deviceIndex, epoch),
        keyData: randomBytesOf(APP_STATE_SYNC_KEY_LENGTH),
        timestamp,
    }
}
