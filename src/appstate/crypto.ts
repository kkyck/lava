/**
 * The cryptography of app-state synchronisation.
 *
 * Every mutation of a collection is encrypted for one sync key and carries
 * two MACs: an *index* MAC over the index of the record, and a *value* MAC
 * over the encrypted value. The index MAC lets the server tell whether two
 * devices changed the same record; the value MAC makes the ciphertext
 * tamper evident.
 *
 * A collection's state is summarised by an *LT-hash*: a digest of 64
 * sixteen-bit points that is updated whenever a value MAC is added or
 * removed. The digest proves that two devices hold the same collection
 * without the server having to read any of it.
 */

import {
    aesCbcDecrypt,
    aesCbcEncrypt,
    concat,
    equalBytes,
    fromUtf8,
    hkdf,
    hmacSha256,
    hmacSha512,
    randomBytesOf,
    utf8,
} from '../crypto/primitives.js'
import { encode, decode } from '../proto/codec.js'
import {
    APP_STATE_DERIVED_INDEX_KEY_END,
    APP_STATE_DERIVED_KEY_LENGTH,
    APP_STATE_DERIVED_PATCH_MAC_KEY_END,
    APP_STATE_DERIVED_SNAPSHOT_MAC_KEY_END,
    APP_STATE_DERIVED_VALUE_ENCRYPTION_KEY_END,
    APP_STATE_DERIVED_VALUE_MAC_KEY_END,
    APP_STATE_EMPTY_LT_HASH,
    APP_STATE_IV_LENGTH,
    APP_STATE_KDF_INFO,
    APP_STATE_MAC_OCTET_LENGTH,
    APP_STATE_POINT_SIZE,
    APP_STATE_VALUE_MAC_LENGTH,
} from './constants.js'

/** The keys derived from one app-state sync key. */
export interface AppStateDerivedKeys {
    /** Authenticates the index of a record. */
    indexHmacKey: Uint8Array
    /** Encrypts the value of a record. */
    valueEncryptionAesKey: Uint8Array
    /** Authenticates the encrypted value of a record. */
    valueMacHmacKey: Uint8Array
    /** Authenticates the LT-hash digest of a collection. */
    snapshotMacHmacKey: Uint8Array
    /** Authenticates a patch of a collection. */
    patchMacHmacKey: Uint8Array
}

/** The operation of a mutation. */
export type AppStateOperation = 'set' | 'remove'

/** The arguments of an encrypted mutation. */
export interface AppStateEncryptArgs {
    /** The operation the mutation performs. */
    operation: AppStateOperation
    /** The id of the sync key the mutation is encrypted for. */
    keyId: Uint8Array
    /** The secret of the sync key. */
    keyData: Uint8Array
    /** The index of the record, as text. */
    index: string
    /** The value of the record; absent for a removal. */
    value?: Record<string, unknown>
    /** The version of the record. */
    version: number
    /** The initialisation vector; a fresh one is used when omitted. */
    iv?: Uint8Array
}

/** The result of an encrypted mutation. */
export interface AppStateEncryptedMutation {
    /** The MAC over the index of the record. */
    indexMac: Uint8Array
    /** The encrypted value: the IV, the ciphertext and the value MAC. */
    valueBlob: Uint8Array
    /** The MAC over the encrypted value. */
    valueMac: Uint8Array
}

/** The arguments of a decrypted mutation. */
export interface AppStateDecryptArgs {
    /** The operation the mutation performs. */
    operation: AppStateOperation
    /** The id of the sync key the mutation was encrypted for. */
    keyId: Uint8Array
    /** The secret of the sync key. */
    keyData: Uint8Array
    /** The MAC over the index of the record. */
    indexMac: Uint8Array
    /** The encrypted value: the IV, the ciphertext and the value MAC. */
    valueBlob: Uint8Array
}

/** The result of a decrypted mutation. */
export interface AppStateDecryptedMutation {
    /** The index of the record, as text. */
    index: string
    /** The value of the record; absent for a removal. */
    value?: Record<string, unknown>
    /** The version of the record. */
    version: number
    /** The MAC over the index of the record. */
    indexMac: Uint8Array
    /** The MAC over the encrypted value. */
    valueMac: Uint8Array
}

/**
 * The crypto of app-state synchronisation.
 *
 * The derived keys are cached, because a sync round touches the same key
 * for every record of every collection.
 */
export class AppStateCrypto {
    private readonly derivedKeys = new Map<string, AppStateDerivedKeys>()

    /** The maximum number of derived key sets kept in the cache. */
    private readonly cacheLimit: number

    /**
     * @param cacheLimit The maximum number of derived key sets to keep.
     */
    constructor(cacheLimit = 64) {
        this.cacheLimit = Math.max(0, cacheLimit)
    }

    /** Empties the derived-key cache. */
    clearCache(): void {
        this.derivedKeys.clear()
    }

    /**
     * Derives the index, value and MAC keys of a sync key.
     *
     * @param keyData The secret of the sync key.
     */
    deriveKeys(keyData: Uint8Array): AppStateDerivedKeys {
        const cacheKey = bytesKey(keyData)
        const cached = this.derivedKeys.get(cacheKey)
        if (cached) {
            // Refresh the entry so the cache evicts the least recently used
            // one instead of the oldest.
            this.derivedKeys.delete(cacheKey)
            this.derivedKeys.set(cacheKey, cached)
            return cached
        }

        const derived = hkdf(
            keyData,
            null,
            APP_STATE_KDF_INFO.MUTATION_KEYS,
            APP_STATE_DERIVED_KEY_LENGTH,
        )
        const keys: AppStateDerivedKeys = {
            indexHmacKey: derived.subarray(0, APP_STATE_DERIVED_INDEX_KEY_END),
            valueEncryptionAesKey: derived.subarray(
                APP_STATE_DERIVED_INDEX_KEY_END,
                APP_STATE_DERIVED_VALUE_ENCRYPTION_KEY_END,
            ),
            valueMacHmacKey: derived.subarray(
                APP_STATE_DERIVED_VALUE_ENCRYPTION_KEY_END,
                APP_STATE_DERIVED_VALUE_MAC_KEY_END,
            ),
            snapshotMacHmacKey: derived.subarray(
                APP_STATE_DERIVED_VALUE_MAC_KEY_END,
                APP_STATE_DERIVED_SNAPSHOT_MAC_KEY_END,
            ),
            patchMacHmacKey: derived.subarray(
                APP_STATE_DERIVED_SNAPSHOT_MAC_KEY_END,
                APP_STATE_DERIVED_PATCH_MAC_KEY_END,
            ),
        }
        if (this.cacheLimit > 0) {
            this.derivedKeys.set(cacheKey, keys)
            while (this.derivedKeys.size > this.cacheLimit) {
                const oldest = this.derivedKeys.keys().next().value
                if (oldest === undefined) break
                this.derivedKeys.delete(oldest)
            }
        }
        return keys
    }

    /**
     * Computes the MAC over the index of a record.
     *
     * @param indexHmacKey The index HMAC key.
     * @param indexBytes The index, as bytes.
     */
    generateIndexMac(indexHmacKey: Uint8Array, indexBytes: Uint8Array): Uint8Array {
        return hmacSha256(indexHmacKey, indexBytes)
    }

    /**
     * Encrypts one mutation.
     *
     * @param args The mutation to encrypt.
     */
    encryptMutation(args: AppStateEncryptArgs): AppStateEncryptedMutation {
        const derived = this.deriveKeys(args.keyData)
        const indexBytes = utf8(args.index)
        const encoded = encode('SyncActionData', {
            index: indexBytes,
            ...(args.value !== undefined ? { value: args.value } : {}),
            padding: new Uint8Array(0),
            version: args.version,
        })
        const iv = args.iv ?? randomBytesOf(APP_STATE_IV_LENGTH)
        if (iv.length !== APP_STATE_IV_LENGTH) {
            throw new Error(`app-state: invalid IV length ${iv.length}`)
        }

        const indexMac = this.generateIndexMac(derived.indexHmacKey, indexBytes)
        const cipherText = aesCbcEncrypt(derived.valueEncryptionAesKey, iv, encoded)
        const associatedData = generateAssociatedData(args.operation, args.keyId)
        const valueMac = this.generateValueMac(
            derived.valueMacHmacKey,
            associatedData,
            iv,
            cipherText,
        )
        return {
            indexMac,
            valueBlob: concat(iv, cipherText, valueMac),
            valueMac,
        }
    }

    /**
     * Verifies and decrypts one mutation.
     *
     * @param args The mutation to decrypt.
     */
    decryptMutation(args: AppStateDecryptArgs): AppStateDecryptedMutation {
        const minLength = APP_STATE_IV_LENGTH + APP_STATE_VALUE_MAC_LENGTH
        if (args.valueBlob.length < minLength) {
            throw new Error('app-state: invalid mutation value blob')
        }
        const derived = this.deriveKeys(args.keyData)
        const iv = args.valueBlob.subarray(0, APP_STATE_IV_LENGTH)
        const valueMac = args.valueBlob.subarray(
            args.valueBlob.length - APP_STATE_VALUE_MAC_LENGTH,
        )
        const cipherText = args.valueBlob.subarray(
            APP_STATE_IV_LENGTH,
            args.valueBlob.length - APP_STATE_VALUE_MAC_LENGTH,
        )

        const associatedData = generateAssociatedData(args.operation, args.keyId)
        const expectedMac = this.generateValueMac(
            derived.valueMacHmacKey,
            associatedData,
            iv,
            cipherText,
        )
        if (!equalBytes(valueMac, expectedMac)) {
            throw new Error('app-state: mutation value MAC mismatch')
        }

        const plaintext = aesCbcDecrypt(derived.valueEncryptionAesKey, iv, cipherText)
        const action = decode('SyncActionData', plaintext)
        const index = action.index
        if (!(index instanceof Uint8Array)) {
            throw new Error('app-state: missing sync action index')
        }
        const version = action.version
        if (typeof version !== 'number') {
            throw new Error('app-state: missing sync action version')
        }
        const generatedIndexMac = this.generateIndexMac(derived.indexHmacKey, index)
        if (!equalBytes(generatedIndexMac, args.indexMac)) {
            throw new Error('app-state: mutation index MAC mismatch')
        }

        const value = action.value
        return {
            index: fromUtf8(index),
            ...(value !== undefined && value !== null
                ? { value: value as Record<string, unknown> }
                : {}),
            version,
            indexMac: args.indexMac,
            valueMac,
        }
    }

    /**
     * Computes the MAC over the LT-hash digest of a collection.
     *
     * @param keyData The secret of the sync key.
     * @param ltHash The digest of the collection.
     * @param version The version of the collection.
     * @param collectionName The name of the collection.
     */
    generateSnapshotMac(
        keyData: Uint8Array,
        ltHash: Uint8Array,
        version: number,
        collectionName: string,
    ): Uint8Array {
        const derived = this.deriveKeys(keyData)
        return hmacSha256(
            derived.snapshotMacHmacKey,
            ltHash,
            intToBytes(8, version),
            utf8(collectionName),
        )
    }

    /**
     * Computes the MAC over a patch of a collection.
     *
     * @param keyData The secret of the sync key.
     * @param snapshotMac The MAC over the resulting digest.
     * @param valueMacs The MACs of the values the patch carries.
     * @param version The version the patch produces.
     * @param collectionName The name of the collection.
     */
    generatePatchMac(
        keyData: Uint8Array,
        snapshotMac: Uint8Array,
        valueMacs: readonly Uint8Array[],
        version: number,
        collectionName: string,
    ): Uint8Array {
        const derived = this.deriveKeys(keyData)
        return hmacSha256(
            derived.patchMacHmacKey,
            snapshotMac,
            ...valueMacs,
            intToBytes(8, version),
            utf8(collectionName),
        )
    }

    /**
     * Adds value MACs to a digest.
     *
     * @param base The digest to update.
     * @param addValues The MACs to add.
     */
    ltHashAdd(base: Uint8Array, addValues: readonly Uint8Array[]): Uint8Array {
        return this.ltHashApply(base, addValues, (left, right) => left + right)
    }

    /**
     * Removes value MACs from a digest.
     *
     * @param base The digest to update.
     * @param removeValues The MACs to remove.
     */
    ltHashSubtract(base: Uint8Array, removeValues: readonly Uint8Array[]): Uint8Array {
        return this.ltHashApply(base, removeValues, (left, right) => left - right)
    }

    /**
     * Removes and adds value MACs in one step.
     *
     * @param base The digest to update.
     * @param addValues The MACs to add.
     * @param removeValues The MACs to remove.
     */
    ltHashSubtractThenAdd(
        base: Uint8Array,
        addValues: readonly Uint8Array[],
        removeValues: readonly Uint8Array[],
    ): { hash: Uint8Array; subtractResult: Uint8Array } {
        const subtractResult = this.ltHashSubtract(base, removeValues)
        const hash = this.ltHashAdd(subtractResult, addValues)
        return { hash, subtractResult }
    }

    /**
     * Computes the MAC over an encrypted value.
     *
     * @param valueMacHmacKey The value MAC key.
     * @param associatedData The operation and the key id.
     * @param iv The initialisation vector.
     * @param cipherText The ciphertext.
     */
    generateValueMac(
        valueMacHmacKey: Uint8Array,
        associatedData: Uint8Array,
        iv: Uint8Array,
        cipherText: Uint8Array,
    ): Uint8Array {
        const octetLength = new Uint8Array(APP_STATE_MAC_OCTET_LENGTH)
        octetLength[octetLength.length - 1] = associatedData.length & 0xff
        const full = hmacSha512(valueMacHmacKey, associatedData, iv, cipherText, octetLength)
        return full.subarray(0, APP_STATE_VALUE_MAC_LENGTH)
    }

    private ltHashApply(
        base: Uint8Array,
        values: readonly Uint8Array[],
        combine: (left: number, right: number) => number,
    ): Uint8Array {
        if (values.length === 0) return base
        const expanded = values.map((value) =>
            hkdf(value, null, APP_STATE_KDF_INFO.PATCH_INTEGRITY, APP_STATE_EMPTY_LT_HASH.length),
        )
        const out = new Uint8Array(base.length)
        pointwiseWithOverflow(base, expanded[0]!, combine, out)
        for (let i = 1; i < expanded.length; i++) {
            pointwiseWithOverflow(out, expanded[i]!, combine, out)
        }
        return out
    }
}

/**
 * Adds or subtracts two digests point by point.
 *
 * The points are sixteen bit and wrap around, so the digest stays the same
 * size no matter how many records a collection holds.
 */
function pointwiseWithOverflow(
    left: Uint8Array,
    right: Uint8Array,
    combine: (left: number, right: number) => number,
    out: Uint8Array,
): Uint8Array {
    if (left.length !== right.length) {
        throw new Error('app-state: LT-hash input length mismatch')
    }
    if (left.length % APP_STATE_POINT_SIZE !== 0) {
        throw new Error('app-state: LT-hash input alignment mismatch')
    }
    if (out.length !== left.length) {
        throw new Error('app-state: LT-hash output length mismatch')
    }
    for (let offset = 0; offset < left.length; offset += APP_STATE_POINT_SIZE) {
        const value = combine(
            left[offset]! | (left[offset + 1]! << 8),
            right[offset]! | (right[offset + 1]! << 8),
        )
        out[offset] = value & 0xff
        out[offset + 1] = (value >>> 8) & 0xff
    }
    return out
}

/**
 * Builds the associated data of a value MAC.
 *
 * The operation is stored as its one-based code, so the MAC covers whether
 * the record was set or removed.
 */
function generateAssociatedData(
    operation: AppStateOperation,
    keyId: Uint8Array,
): Uint8Array {
    const out = new Uint8Array(1 + keyId.length)
    out[0] = operation === 'remove' ? 2 : 1
    out.set(keyId, 1)
    return out
}

/** Encodes a non-negative integer as big-endian bytes. */
function intToBytes(length: number, value: number): Uint8Array {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new Error(`app-state: invalid integer value ${value}`)
    }
    const out = new Uint8Array(length)
    let current = value
    for (let i = length - 1; i >= 0; i--) {
        out[i] = current & 0xff
        current = Math.floor(current / 256)
    }
    return out
}

/** Builds a cache key for the derived keys. */
function bytesKey(value: Uint8Array): string {
    let out = ''
    for (const byte of value) out += String.fromCharCode(byte)
    return out
}
