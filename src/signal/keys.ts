/**
 * Signal key material: registration info, pre-keys and the key store.
 *
 * A WhatsApp device owns four kinds of long-lived key material:
 *
 * - an **identity key pair** (the device's "fingerprint"), tied to a random
 *   **registration id**,
 * - a **signed pre-key**, signed by the identity key so that other devices
 *   can verify it without a prior handshake,
 * - a pool of **one-time pre-keys**, each usable exactly once, and
 * - the **remote identities** of the devices we talk to.
 *
 * {@link SignalKeyStore} keeps that material in memory and can export/import
 * a JSON-serialisable snapshot so it can be persisted by the caller. The
 * store performs no file I/O itself: persistence is the application's job.
 */

import { xeddsaSign } from '../crypto/curve25519.js'
import { randomInt, toSerializedPublicKey } from '../crypto/primitives.js'
import { generateSerializedKeyPair, type SerializedKeyPair } from './session.js'

/** Upper bound (exclusive) of a Signal registration id. */
const REGISTRATION_ID_MAX = 16381

/**
 * Upper bound (exclusive) of a pre-key id.
 *
 * The protocol carries pre-key ids in a **three byte** field, so an id must
 * never exceed `0xFFFFFF`. A larger value would be truncated on the wire and
 * the server would hand out a different id than the one stored locally, which
 * breaks the pre-key handshake.
 *
 * The official client uses the very same border (`PRE_KEY_NON_INCLUSIVE_UPPER_
 * BORDER = 16777215`) and wraps the counter around when it is reached, so the
 * ids handed out here stay inside `[1, 16777215)` too.
 */
const PRE_KEY_ID_MAX = 0xffffff

/** The first id that may be handed out. */
const PRE_KEY_ID_MIN = 1

/**
 * Maximum number of one-time pre-keys kept in the pool.
 *
 * Uploaded pre-keys stay in the pool, because the server keeps handing them
 * out and the device must still be able to decrypt the pre-key message that
 * uses them. The server consumes a pre-key for every new inbound session, so
 * the pool shrinks at the same rate it grows — but a long-lived device that
 * never receives a message would otherwise pile up keys forever.
 *
 * The oldest entries are dropped first, which mirrors the bounded key table
 * the official clients keep.
 */
export const MAX_RETAINED_PRE_KEYS = 4096

/**
 * The registration info of a device.
 *
 * The registration id is a small random number that the server uses to
 * address a device; it is *not* a secret.
 */
export interface RegistrationInfo {
    /** Random id in `[1, 16381)`. */
    registrationId: number
    /** The device's identity key pair. */
    identityKeyPair: SerializedKeyPair
}

/** A one-time pre-key. */
export interface PreKeyRecord {
    /** Id of the pre-key. */
    keyId: number
    /** The pre-key pair. */
    keyPair: SerializedKeyPair
}

/** A signed pre-key. */
export interface SignedPreKeyRecord {
    /** Id of the pre-key. */
    keyId: number
    /** The pre-key pair. */
    keyPair: SerializedKeyPair
    /** XEdDSA signature over the serialized public key. */
    signature: Uint8Array
}

/** A JSON-serialisable snapshot of a {@link SignalKeyStore}. */
export interface SignalKeyStoreSnapshot {
    /** Snapshot format version. */
    version: number
    /** Registration info, if present. */
    registration: {
        /** Registration id. */
        registrationId: number
        /** Base64 encoded identity public key. */
        identityPublicKey: string
        /** Base64 encoded identity private key. */
        identityPrivateKey: string
    } | null
    /** The current signed pre-key. */
    signedPreKey: SerializedSignedPreKey | null
    /** The previous signed pre-key, kept for verification of older messages. */
    previousSignedPreKey: SerializedSignedPreKey | null
    /** The pool of one-time pre-keys. */
    preKeys: SerializedPreKey[]
    /** The next pre-key id to hand out. */
    nextPreKeyId?: number
    /** The next signed pre-key id to hand out. */
    nextSignedPreKeyId?: number
    /** The id of the first pre-key that has not been uploaded yet. */
    firstUnuploadedPreKeyId?: number
    /** Whether the server currently holds a batch of our pre-keys. */
    serverHasPreKeys?: boolean
    /** Remote identity keys, keyed by address. */
    remoteIdentities: Record<string, string>
}

/** A JSON-serialisable signed pre-key. */
export interface SerializedSignedPreKey {
    /** Id of the pre-key. */
    keyId: number
    /** Base64 encoded public key. */
    publicKey: string
    /** Base64 encoded private key. */
    privateKey: string
    /** Base64 encoded XEdDSA signature. */
    signature: string
}

/** A JSON-serialisable one-time pre-key. */
export interface SerializedPreKey {
    /** Id of the pre-key. */
    keyId: number
    /** Base64 encoded public key. */
    publicKey: string
    /** Base64 encoded private key. */
    privateKey: string
}

// ─── Key generation ───────────────────────────────────────────────────────────

/**
 * Generates a Signal registration id.
 *
 * Signal requires the id to fit into 14 bits (`[1, 16381)`); the value 0 is
 * reserved as "no registration".
 */
export function generateRegistrationId(): number {
    return 1 + randomInt(REGISTRATION_ID_MAX - 1)
}

/**
 * Generates a fresh registration id together with a new identity key pair.
 */
export function generateRegistrationInfo(): RegistrationInfo {
    return {
        registrationId: generateRegistrationId(),
        identityKeyPair: generateSerializedKeyPair(),
    }
}

/**
 * Generates a one-time pre-key with the given id.
 */
export function generatePreKeyPair(keyId: number): PreKeyRecord {
    return {
        keyId,
        keyPair: generateSerializedKeyPair(),
    }
}

/**
 * Generates a signed pre-key.
 *
 * The signature is an XEdDSA signature over the *serialized* public key
 * (33 bytes, `0x05` prefixed), produced with the identity private key. The
 * receiver verifies it with the identity public key it learned from the
 * server, which is what makes the pre-key trustworthy.
 *
 * @param keyId Id of the pre-key.
 * @param signingPrivateKey The identity private key used for signing.
 */
export function generateSignedPreKey(
    keyId: number,
    signingPrivateKey: Uint8Array,
): SignedPreKeyRecord {
    const keyPair = generateSerializedKeyPair()
    const serializedPublicKey = toSerializedPublicKey(keyPair.pubKey)
    return {
        keyId,
        keyPair,
        signature: xeddsaSign(signingPrivateKey, serializedPublicKey),
    }
}

/**
 * Generates a random one-time pre-key id.
 *
 * The value is limited to the three byte field the protocol uses, so it can
 * never be truncated on the wire. Use
 * {@link SignalKeyStore.allocatePreKeyId} to obtain ids that are unique
 * inside the device.
 */
export function generatePreKeyId(): number {
    return 1 + randomInt(PRE_KEY_ID_MAX - 1)
}

// ─── Key store ────────────────────────────────────────────────────────────────

/**
 * In-memory storage for the Signal key material of a single device.
 *
 * The store deliberately knows nothing about persistence: call
 * {@link SignalKeyStore.export} to obtain a JSON-serialisable snapshot and
 * {@link SignalKeyStore.import} to restore it.
 */
export class SignalKeyStore {
    /** Registration info of this device. */
    private registration: RegistrationInfo | null = null

    /** The signed pre-key currently advertised to the server. */
    private signedPreKey: SignedPreKeyRecord | null = null

    /** The previous signed pre-key, still accepted for verification. */
    private previousSignedPreKey: SignedPreKeyRecord | null = null

    /** Pool of unused one-time pre-keys. */
    private readonly preKeys = new Map<number, PreKeyRecord>()

    /** The next pre-key id to hand out. */
    private nextPreKeyId = 1

    /**
     * The next signed pre-key id to hand out.
     *
     * Signed pre-keys live in their own id namespace — the official clients
     * track them separately (`signal_last_spk_id` versus
     * `signal_next_pk_id`) — so a signed pre-key may reuse the number of a
     * one-time pre-key without any ambiguity.
     */
    private nextSignedPreKeyId = 1

    /** The id of the first one-time pre-key that was not uploaded yet. */
    private firstUnuploadedPreKeyId = 1

    /** Whether the server currently holds a batch of our pre-keys. */
    private serverHasPreKeys = false

    /** Identity public keys of remote devices, keyed by address. */
    private readonly remoteIdentities = new Map<string, Uint8Array>()

    /** Returns the registration info, or `null` when it has not been set. */
    getRegistrationInfo(): RegistrationInfo | null {
        return this.registration
    }

    /** Stores the registration info of this device. */
    setRegistrationInfo(info: RegistrationInfo): void {
        this.registration = {
            registrationId: info.registrationId,
            identityKeyPair: {
                pubKey: new Uint8Array(info.identityKeyPair.pubKey),
                privKey: new Uint8Array(info.identityKeyPair.privKey),
            },
        }
    }

    /**
     * Returns a signed pre-key.
     *
     * @param id When given, the current *or* previous signed pre-key with that
     *           id is returned. Without an id the current signed pre-key is
     *           returned.
     */
    getSignedPreKey(id?: number): SignedPreKeyRecord | null {
        if (id === undefined) return this.signedPreKey
        if (this.signedPreKey && this.signedPreKey.keyId === id) return this.signedPreKey
        if (this.previousSignedPreKey && this.previousSignedPreKey.keyId === id) {
            return this.previousSignedPreKey
        }
        return null
    }

    /** Replaces the current signed pre-key (the previous one is dropped). */
    setSignedPreKey(record: SignedPreKeyRecord): void {
        this.signedPreKey = cloneSignedPreKey(record)
        this.noteSignedPreKeyId(record.keyId)
    }

    /**
     * Installs a new signed pre-key and demotes the current one to
     * "previous", so that messages signed with it can still be verified.
     */
    rotateSignedPreKey(newRecord: SignedPreKeyRecord): void {
        if (this.signedPreKey) {
            this.previousSignedPreKey = this.signedPreKey
        }
        this.signedPreKey = cloneSignedPreKey(newRecord)
        this.noteSignedPreKeyId(newRecord.keyId)
    }

    /**
     * Allocates a fresh signed pre-key id.
     *
     * Signed pre-keys have their own id namespace, so their counter is
     * independent of the one-time pre-key counter. The ids start at `1` and
     * wrap back to `1` when the upper border is reached — exactly like the
     * official clients do.
     */
    allocateSignedPreKeyId(): number {
        const id =
            this.nextSignedPreKeyId >= PRE_KEY_ID_MAX ? PRE_KEY_ID_MIN : this.nextSignedPreKeyId
        this.nextSignedPreKeyId = id + 1
        return id
    }

    /** The next signed pre-key id that will be handed out. */
    getNextSignedPreKeyId(): number {
        return this.nextSignedPreKeyId
    }

    /**
     * Sets the next signed pre-key id to hand out.
     *
     * The counter must never go back, or a signed pre-key id that was
     * already advertised would be used twice.
     *
     * @param id The next id to hand out.
     */
    setNextSignedPreKeyId(id: number): void {
        if (Number.isSafeInteger(id) && id > this.nextSignedPreKeyId) {
            this.nextSignedPreKeyId = id
        }
    }

    /**
     * Makes sure the signed pre-key counter is beyond the given id.
     *
     * @param id The id that was used.
     */
    private noteSignedPreKeyId(id: number): void {
        if (id >= this.nextSignedPreKeyId) this.nextSignedPreKeyId = id + 1
    }

    /** Returns the one-time pre-key with the given id, if it is available. */
    getPreKey(id: number): PreKeyRecord | undefined {
        return this.preKeys.get(id)
    }

    /** Adds a one-time pre-key to the pool. */
    addPreKey(record: PreKeyRecord): void {
        this.preKeys.set(record.keyId, {
            keyId: record.keyId,
            keyPair: {
                pubKey: new Uint8Array(record.keyPair.pubKey),
                privKey: new Uint8Array(record.keyPair.privKey),
            },
        })
        if (record.keyId >= this.nextPreKeyId) this.nextPreKeyId = record.keyId + 1
    }

    /**
     * Allocates a fresh pre-key id.
     *
     * The ids are handed out sequentially, exactly like the official clients
     * do, so they are unique inside the device and always fit the three byte
     * field the protocol uses for them. Ids that are already in the pool are
     * skipped.
     *
     * Signed pre-keys live in their own id namespace, so they never block a
     * one-time pre-key id.
     */
    allocatePreKeyId(): number {
        let id = this.nextPreKeyId
        while (this.preKeys.has(id)) {
            id += 1
        }
        this.nextPreKeyId = id + 1
        return id
    }

    /**
     * Sets the next pre-key id to hand out.
     *
     * The counter must never go back: a pre-key id that was already handed
     * out must not be reused, not even after a restart.
     *
     * @param id The next id to hand out.
     */
    setNextPreKeyId(id: number): void {
        if (Number.isSafeInteger(id) && id > this.nextPreKeyId) this.nextPreKeyId = id
    }

    /** The next pre-key id that will be handed out. */
    getNextPreKeyId(): number {
        return this.nextPreKeyId
    }

    /**
     * Removes a one-time pre-key from the pool and returns it.
     *
     * A pre-key must only be consumed once: replaying it would allow an
     * attacker to re-establish an old session.
     */
    consumePreKey(id: number): PreKeyRecord | undefined {
        const record = this.preKeys.get(id)
        if (!record) return undefined
        this.preKeys.delete(id)
        return record
    }

    /** Number of unused one-time pre-keys. */
    getPreKeyCount(): number {
        return this.preKeys.size
    }

    /**
     * Returns the unused one-time pre-keys, oldest id first.
     *
     * The caller uploads a batch of them to the server and removes the
     * uploaded ones from the pool.
     */
    listPreKeys(limit = Number.POSITIVE_INFINITY): PreKeyRecord[] {
        const ids = [...this.preKeys.keys()].sort((a, b) => a - b)
        const count = Math.min(ids.length, limit)
        const out: PreKeyRecord[] = []
        for (let i = 0; i < count; i += 1) {
            const record = this.preKeys.get(ids[i]!)
            if (record) out.push(record)
        }
        return out
    }

    /**
     * Returns the one-time pre-keys whose id is at least `startId`.
     *
     * The filter runs **before** the limit, exactly like the official
     * clients do (`keyId > startId - 1` with a `limit`). Filtering after the
     * limit would silently drop the newest keys as soon as the pool grows
     * beyond the batch size.
     *
     * @param startId The lowest id to return (inclusive).
     * @param limit The maximum number of keys to return.
     */
    getPreKeysByRange(startId: number, limit: number): PreKeyRecord[] {
        const ids = [...this.preKeys.keys()]
            .filter((id) => id >= startId)
            .sort((a, b) => a - b)
        const out: PreKeyRecord[] = []
        for (let i = 0; i < Math.min(ids.length, limit); i += 1) {
            const record = this.preKeys.get(ids[i]!)
            if (record) out.push(record)
        }
        return out
    }

    /**
     * Returns a batch of one-time pre-keys, generating the missing ones.
     *
     * The batch starts at the first pre-key that was not uploaded yet. The
     * number of keys that still have to be generated is derived from the
     * counters — `nextPreKeyId - firstUnuploadedPreKeyId` keys are already
     * there but not uploaded yet — so the pool always ends up with exactly
     * `count` keys that are ready to be handed to the server.
     *
     * This mirrors the official `getOrGenPreKeys`: the ids of the fresh keys
     * continue the sequential counter, so they are unique and always fit the
     * three byte field the protocol uses for them.
     *
     * @param count The number of keys the caller wants.
     * @param gen Generates a pre-key for a given id.
     */
    getOrGenPreKeys(count: number, gen: (keyId: number) => PreKeyRecord): PreKeyRecord[] {
        if (!Number.isSafeInteger(count) || count <= 0) {
            throw new Error(`invalid pre-key count: ${count}`)
        }

        const start = this.firstUnuploadedPreKeyId
        const pending = this.nextPreKeyId - start
        const missing = count - pending
        if (missing > 0) {
            for (let i = 0; i < missing; i += 1) {
                const keyId = this.nextPreKeyId
                this.addPreKey(gen(keyId))
            }
        }
        return this.getPreKeysByRange(start, count)
    }

    /**
     * Marks every pre-key up to `keyId` as uploaded.
     *
     * The upload cursor only moves forward: a pre-key that was already
     * uploaded must never be uploaded a second time, and the boundary check
     * makes sure a bogus id cannot move the cursor backwards.
     *
     * @param keyId The id of the last uploaded pre-key.
     */
    markKeyAsUploaded(keyId: number): void {
        if (!Number.isSafeInteger(keyId) || keyId < 0) {
            throw new Error(`pre-key ${keyId} is out of boundary`)
        }
        if (keyId >= this.nextPreKeyId) {
            throw new Error(`pre-key ${keyId} is out of boundary`)
        }
        if (keyId + 1 > this.firstUnuploadedPreKeyId) {
            this.firstUnuploadedPreKeyId = keyId + 1
        }
    }

    /** The id of the first one-time pre-key that was not uploaded yet. */
    getFirstUnuploadedPreKeyId(): number {
        return this.firstUnuploadedPreKeyId
    }

    /**
     * Sets the id of the first one-time pre-key that was not uploaded yet.
     *
     * The cursor must never go back, or an already uploaded pre-key would be
     * uploaded again.
     *
     * @param id The new cursor.
     */
    setFirstUnuploadedPreKeyId(id: number): void {
        if (Number.isSafeInteger(id) && id > this.firstUnuploadedPreKeyId) {
            this.firstUnuploadedPreKeyId = id
        }
    }

    /** Whether the server currently holds a batch of our pre-keys. */
    getServerHasPreKeys(): boolean {
        return this.serverHasPreKeys
    }

    /**
     * Records whether the server currently holds a batch of our pre-keys.
     *
     * @param value The new flag value.
     */
    setServerHasPreKeys(value: boolean): void {
        this.serverHasPreKeys = value
    }

    /**
     * Drops the oldest uploaded pre-keys when the pool grew too large.
     *
     * Pre-keys that were not uploaded yet are never dropped, and neither are
     * the ones that were uploaded most recently: the server may still hand
     * them out, and the device has to be able to decrypt the message that
     * uses them.
     *
     * @param max The maximum number of keys to keep.
     *
     * @returns The ids that were dropped.
     */
    prunePreKeys(max = MAX_RETAINED_PRE_KEYS): number[] {
        if (this.preKeys.size <= max) return []
        const dropped: number[] = []
        const ids = [...this.preKeys.keys()].sort((a, b) => a - b)
        for (const id of ids) {
            if (this.preKeys.size <= max) break
            if (id >= this.firstUnuploadedPreKeyId) continue
            this.preKeys.delete(id)
            dropped.push(id)
        }
        return dropped
    }

    /** Stores the identity public key of a remote device. */
    setRemoteIdentity(address: string, publicKey: Uint8Array): void {
        this.remoteIdentities.set(address, new Uint8Array(publicKey))
    }

    /** Returns the identity public key of a remote device, if known. */
    getRemoteIdentity(address: string): Uint8Array | undefined {
        return this.remoteIdentities.get(address)
    }

    /** Removes the identity of a remote device (e.g. after an unpair). */
    removeRemoteIdentity(address: string): boolean {
        return this.remoteIdentities.delete(address)
    }

    /**
     * Exports the store as a JSON-serialisable snapshot.
     *
     * All binary values are base64 encoded so the snapshot can be handed to
     * `JSON.stringify` without further processing.
     */
    export(): SignalKeyStoreSnapshot {
        const snapshot: SignalKeyStoreSnapshot = {
            version: 1,
            registration: null,
            signedPreKey: this.signedPreKey ? serializeSignedPreKey(this.signedPreKey) : null,
            previousSignedPreKey: this.previousSignedPreKey
                ? serializeSignedPreKey(this.previousSignedPreKey)
                : null,
            preKeys: [...this.preKeys.values()].map((record) => ({
                keyId: record.keyId,
                publicKey: toBase64(record.keyPair.pubKey),
                privateKey: toBase64(record.keyPair.privKey),
            })),
            nextPreKeyId: this.nextPreKeyId,
            nextSignedPreKeyId: this.nextSignedPreKeyId,
            firstUnuploadedPreKeyId: this.firstUnuploadedPreKeyId,
            serverHasPreKeys: this.serverHasPreKeys,
            remoteIdentities: {},
        }

        if (this.registration) {
            snapshot.registration = {
                registrationId: this.registration.registrationId,
                identityPublicKey: toBase64(this.registration.identityKeyPair.pubKey),
                identityPrivateKey: toBase64(this.registration.identityKeyPair.privKey),
            }
        }

        for (const [address, publicKey] of this.remoteIdentities) {
            snapshot.remoteIdentities[address] = toBase64(publicKey)
        }

        return snapshot
    }

    /**
     * Restores the store from a snapshot produced by {@link export}.
     *
     * The store is cleared first, so importing fully replaces its contents.
     */
    import(snapshot: SignalKeyStoreSnapshot): void {
        this.registration = null
        this.signedPreKey = null
        this.previousSignedPreKey = null
        this.preKeys.clear()
        this.remoteIdentities.clear()

        if (snapshot.registration) {
            this.registration = {
                registrationId: snapshot.registration.registrationId,
                identityKeyPair: {
                    pubKey: fromBase64(snapshot.registration.identityPublicKey),
                    privKey: fromBase64(snapshot.registration.identityPrivateKey),
                },
            }
        }

        if (snapshot.signedPreKey) {
            this.signedPreKey = deserializeSignedPreKey(snapshot.signedPreKey)
        }
        if (snapshot.previousSignedPreKey) {
            this.previousSignedPreKey = deserializeSignedPreKey(snapshot.previousSignedPreKey)
        }
        for (const record of snapshot.preKeys ?? []) {
            this.preKeys.set(record.keyId, {
                keyId: record.keyId,
                keyPair: {
                    pubKey: fromBase64(record.publicKey),
                    privKey: fromBase64(record.privateKey),
                },
            })
        }
        this.nextPreKeyId = 1
        if (snapshot.nextPreKeyId !== undefined) this.setNextPreKeyId(snapshot.nextPreKeyId)
        this.nextSignedPreKeyId = 1
        if (snapshot.nextSignedPreKeyId !== undefined) {
            this.setNextSignedPreKeyId(snapshot.nextSignedPreKeyId)
        }
        this.firstUnuploadedPreKeyId = 1
        if (snapshot.firstUnuploadedPreKeyId !== undefined) {
            this.setFirstUnuploadedPreKeyId(snapshot.firstUnuploadedPreKeyId)
        }
        this.serverHasPreKeys = snapshot.serverHasPreKeys === true
        for (const [address, publicKey] of Object.entries(snapshot.remoteIdentities ?? {})) {
            this.remoteIdentities.set(address, fromBase64(publicKey))
        }
    }
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/** Copies a signed pre-key record. */
function cloneSignedPreKey(record: SignedPreKeyRecord): SignedPreKeyRecord {
    return {
        keyId: record.keyId,
        keyPair: {
            pubKey: new Uint8Array(record.keyPair.pubKey),
            privKey: new Uint8Array(record.keyPair.privKey),
        },
        signature: new Uint8Array(record.signature),
    }
}

/** Serialises a signed pre-key record. */
function serializeSignedPreKey(record: SignedPreKeyRecord): SerializedSignedPreKey {
    return {
        keyId: record.keyId,
        publicKey: toBase64(record.keyPair.pubKey),
        privateKey: toBase64(record.keyPair.privKey),
        signature: toBase64(record.signature),
    }
}

/** Restores a signed pre-key record. */
function deserializeSignedPreKey(record: SerializedSignedPreKey): SignedPreKeyRecord {
    return {
        keyId: record.keyId,
        keyPair: {
            pubKey: fromBase64(record.publicKey),
            privKey: fromBase64(record.privateKey),
        },
        signature: fromBase64(record.signature),
    }
}

/** Base64-encodes a byte string. */
function toBase64(value: Uint8Array): string {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength).toString('base64')
}

/** Decodes a base64 string into a fresh byte array. */
function fromBase64(value: string): Uint8Array {
    return new Uint8Array(Buffer.from(value, 'base64'))
}
