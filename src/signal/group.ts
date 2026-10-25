/**
 * Signal group ("sender key") encryption.
 *
 * Group messages do not use the double ratchet: every participant encrypts
 * with a *sender key* that is distributed to the other members once and then
 * ratcheted forward on its own.
 *
 * The flow is:
 *
 * 1. The sender creates a **sender key** (id, chain key, signing key pair).
 * 2. It sends a {@link SenderKeyDistributionMessage} to every participant,
 *    wrapped in the WhatsApp `axolotlSenderKeyDistributionMessage` field.
 * 3. Every group message is encrypted with a key derived from the sender key
 *    chain and signed with the sender key's signing key.
 *
 * The chain ratchet is the same shape as the pairwise one, but the derived
 * material is a 50-byte *seed* instead of separate cipher/MAC keys: the first
 * 16 bytes are the CBC initialisation vector, the next 32 bytes the AES-256
 * key.
 */

import { xeddsaSign, xeddsaVerify } from '../crypto/curve25519.js'
import {
    aesCbcDecrypt,
    aesCbcEncrypt,
    concat,
    fromSerializedPublicKey,
    hkdf,
    hmacSha256,
    prependVersion,
    randomBytesOf,
    toSerializedPublicKey,
} from '../crypto/primitives.js'
import { decode, encode } from '../proto/codec.js'
// Registers the protobuf descriptors used by this module.
import '../proto/schema.js'
import {
    CHAIN_KEY_LABEL,
    FUTURE_MESSAGES_MAX,
    MAX_UNUSED_KEYS,
    MESSAGE_KEY_LABEL,
    SIGNAL_GROUP_VERSION,
    WHISPER_GROUP_INFO,
} from './constants.js'
import { generateSerializedKeyPair, type SerializedKeyPair } from './session.js'
import {
    deserializeSenderKeyRecord,
    serializeSenderKeyRecord,
    type SerializedSenderKeyRecord,
    type SerializedSenderKeyState,
} from './persistence.js'

/** Length of the XEdDSA signature appended to every sender key message. */
export const SENDER_KEY_SIGNATURE_LENGTH = 64

/** Length of the derived sender key seed (IV + AES key + 2 spare bytes). */
export const SENDER_KEY_SEED_LENGTH = 50

/** A message key derived from a sender key chain. */
export interface SenderKeyMessageKey {
    /** Position of the message inside the chain. */
    iteration: number
    /** 50-byte seed holding the IV and the AES-256 key. */
    seed: Uint8Array
}

/** The result of one sender key derivation step. */
export interface SenderKeyDerivation {
    /** The derived seed (IV + AES key). */
    seed: Uint8Array
    /** The chain key of the next iteration. */
    nextChainKey: Uint8Array
    /** The message key for the current iteration. */
    messageKey: SenderKeyMessageKey
}

/** The state of one sender key. */
export interface SenderKeyRecord {
    /** The group the key belongs to. */
    groupId: string
    /** Address of the device that owns the key. */
    sender: string
    /** Id of the sender key. */
    keyId: number
    /** Iteration of the next message to be produced/consumed. */
    iteration: number
    /** Current chain key. */
    chainKey: Uint8Array
    /** Signing public key (33-byte serialized form). */
    signingPublicKey: Uint8Array
    /** Signing private key (32 bytes); only present on the sending side. */
    signingPrivateKey?: Uint8Array
    /** Keys retained for messages that arrive out of order. */
    unusedMessageKeys: SenderKeyMessageKey[]
}

/** The payload of a sender key distribution message. */
export interface SenderKeyDistribution {
    /** Id of the sender key. */
    keyId: number
    /** Iteration the sender key was at when it was distributed. */
    iteration: number
    /** Chain key at that iteration. */
    chainKey: Uint8Array
    /** Signing public key (33-byte serialized form). */
    signingPublicKey: Uint8Array
}

/** The result of encrypting a group message. */
export interface GroupEncryptionResult {
    /** The versioned sender key distribution message. */
    distributionMessage: Uint8Array
    /** Versioned sender key message plus its XEdDSA signature. */
    ciphertext: Uint8Array
    /** Id of the sender key used. */
    keyId: number
}

// ─── Chain derivation ─────────────────────────────────────────────────────────

/**
 * Derives the message key and the next chain key of a sender key chain.
 *
 * The construction mirrors the pairwise ratchet:
 *
 * - `nextChainKey = HMAC-SHA256(chainKey, 0x02)`
 * - `messageInputKey = HMAC-SHA256(chainKey, 0x01)`
 * - `seed = HKDF-SHA256(messageInputKey, info = "WhisperGroup", 50)`
 *
 * @param iteration The iteration the derived key belongs to.
 * @param chainKey The current chain key.
 */
export function deriveSenderKeyMessageKey(
    iteration: number,
    chainKey: Uint8Array,
): SenderKeyDerivation {
    if (chainKey.length !== 32) {
        throw new Error('sender key chain key must be 32 bytes')
    }
    const nextChainKey = hmacSha256(chainKey, CHAIN_KEY_LABEL).subarray(0, 32)
    const messageInputKey = hmacSha256(chainKey, MESSAGE_KEY_LABEL)
    const seed = hkdf(messageInputKey, null, WHISPER_GROUP_INFO, SENDER_KEY_SEED_LENGTH)
    return {
        seed,
        nextChainKey: new Uint8Array(nextChainKey),
        messageKey: { iteration, seed },
    }
}

/**
 * The ratcheting chain of a sender key.
 *
 * The chain is a simple counter: every message advances the chain key once
 * and the derived seed is used for exactly one message.
 */
export class SenderKeyChain {
    /** Iteration of the next message. */
    iteration: number

    /** Current chain key. */
    chainKey: Uint8Array

    /**
     * @param iteration The iteration to start at.
     * @param chainKey The chain key to start from.
     */
    constructor(iteration: number, chainKey: Uint8Array) {
        if (chainKey.length !== 32) {
            throw new Error('sender key chain key must be 32 bytes')
        }
        this.iteration = iteration
        this.chainKey = new Uint8Array(chainKey)
    }

    /**
     * Derives a message key without advancing the chain.
     *
     * @param iteration The iteration to derive.
     * @param chainKey The chain key to derive from.
     */
    deriveSenderKeyMessageKey(iteration: number, chainKey: Uint8Array): SenderKeyDerivation {
        return deriveSenderKeyMessageKey(iteration, chainKey)
    }

    /**
     * Derives the message key of the current iteration and advances the chain.
     */
    advance(): SenderKeyDerivation {
        const derived = deriveSenderKeyMessageKey(this.iteration, this.chainKey)
        this.chainKey = derived.nextChainKey
        this.iteration = derived.messageKey.iteration + 1
        return derived
    }
}

// ─── Sender key manager ───────────────────────────────────────────────────────

/** Options for {@link SenderKeyManager}. */
export interface SenderKeyManagerOptions {
    /** Address of the local device; used as the owner of outgoing keys. */
    localAddress?: string
    /**
     * Called when a sender key changed.
     *
     * The chain key advances with every group message and the received keys
     * are the only way to decrypt a group message at all, so the caller has
     * to persist the state when this fires.
     */
    onSenderKeysChanged?: () => void
}

/**
 * Manages the sender keys of every group the device participates in.
 *
 * Two kinds of state are kept:
 *
 * - *own* sender keys, one per group, including the signing private key,
 * - *received* sender keys, one per (group, remote device) pair, which only
 *   contain the public part.
 */
export class SenderKeyManager {
    /** Address of the local device. */
    private readonly localAddress: string

    /** The options the manager was created with. */
    private readonly options: SenderKeyManagerOptions

    /** Own sender keys, keyed by group id. */
    private readonly ownKeys = new Map<string, SenderKeyRecord>()

    /** Received sender keys, keyed by `groupId \u0000 sender`. */
    private readonly receivedKeys = new Map<string, SenderKeyRecord>()

    /**
     * @param options Optional configuration.
     */
    constructor(options: SenderKeyManagerOptions = {}) {
        this.options = options
        this.localAddress = options.localAddress ?? ''
    }

    /**
     * Reports a change of the sender-key state.
     *
     * Every write goes through here, so the persistence callback fires for
     * every change of the chain keys.
     */
    private notifyChanged(): void {
        this.options.onSenderKeysChanged?.()
    }

    /**
     * Returns the sender key of `groupId`, creating it when necessary.
     *
     * A fresh sender key gets a random id, a random chain key and a fresh
     * signing key pair.
     */
    ensureSenderKey(groupId: string): SenderKeyRecord {
        const existing = this.ownKeys.get(groupId)
        if (existing) return existing

        const signingKeyPair = generateSerializedKeyPair()
        const record: SenderKeyRecord = {
            groupId,
            sender: this.localAddress,
            keyId: 1 + randomInt31(),
            iteration: 0,
            chainKey: randomBytesOf(32),
            signingPublicKey: toSerializedPublicKey(signingKeyPair.pubKey),
            signingPrivateKey: new Uint8Array(signingKeyPair.privKey),
            unusedMessageKeys: [],
        }
        this.ownKeys.set(groupId, record)
        this.notifyChanged()
        return record
    }

    /** Returns the own sender key of `groupId`, if one exists. */
    getSenderKey(groupId: string): SenderKeyRecord | undefined {
        return this.ownKeys.get(groupId)
    }

    /** Returns the sender key received from `sender` for `groupId`. */
    getReceivedSenderKey(groupId: string, sender: string): SenderKeyRecord | undefined {
        return this.receivedKeys.get(receiverKey(groupId, sender))
    }

    /**
     * Encrypts `plaintext` for `groupId`.
     *
     * The returned distribution message must be sent to every participant
     * that does not know the current sender key yet; the ciphertext is the
     * group message itself.
     *
     * @param groupId The group id.
     * @param plaintext The message body.
     */
    prepareGroupEncryption(groupId: string, plaintext: Uint8Array): GroupEncryptionResult {
        const record = this.ensureSenderKey(groupId)
        const signingPrivateKey = record.signingPrivateKey
        if (!signingPrivateKey) {
            throw new Error('sender key signing private key is missing')
        }

        // The distribution message carries the chain key *before* the current
        // message is derived, so that the receiver derives the same key.
        const distributionIteration = record.iteration
        const distributionChainKey = new Uint8Array(record.chainKey)

        const derived = deriveSenderKeyMessageKey(record.iteration, record.chainKey)
        record.chainKey = derived.nextChainKey
        record.iteration = derived.messageKey.iteration + 1
        this.notifyChanged()

        const distributionPayload = encode('SenderKeyDistributionMessage', {
            id: record.keyId,
            iteration: distributionIteration,
            chainKey: distributionChainKey,
            signingKey: record.signingPublicKey,
        })
        const distributionMessage = prependVersion(distributionPayload, SIGNAL_GROUP_VERSION)

        const encrypted = aesCbcEncryptFromSeed(derived.seed, plaintext)
        const messagePayload = encode('SenderKeyMessage', {
            id: record.keyId,
            iteration: derived.messageKey.iteration,
            ciphertext: encrypted,
        })
        const versionedContent = prependVersion(messagePayload, SIGNAL_GROUP_VERSION)
        const signature = xeddsaSign(signingPrivateKey, versionedContent)

        return {
            distributionMessage,
            ciphertext: concat(versionedContent, signature),
            keyId: record.keyId,
        }
    }

    /**
     * Stores a sender key distribution message received from `sender`.
     *
     * @param groupId The group the distribution belongs to.
     * @param sender Address of the sending device.
     * @param payload The versioned sender key distribution message.
     */
    processSenderKeyDistribution(
        groupId: string,
        sender: string,
        payload: Uint8Array,
    ): SenderKeyRecord {
        const distribution = parseSenderKeyDistribution(payload)
        const record: SenderKeyRecord = {
            groupId,
            sender,
            keyId: distribution.keyId,
            iteration: distribution.iteration,
            chainKey: distribution.chainKey,
            signingPublicKey: distribution.signingPublicKey,
            unusedMessageKeys: [],
        }
        this.receivedKeys.set(receiverKey(groupId, sender), record)
        this.notifyChanged()
        return record
    }

    /**
     * Decrypts a group message.
     *
     * @param groupId The group the message belongs to.
     * @param sender Address of the sending device.
     * @param ciphertext The versioned sender key message plus its signature.
     *
     * @returns The plaintext message.
     */
    decryptGroupMessage(groupId: string, sender: string, ciphertext: Uint8Array): Uint8Array {
        const record = this.receivedKeys.get(receiverKey(groupId, sender))
        if (!record) {
            throw new Error('missing sender key')
        }

        const parsed = parseSenderKeyMessage(ciphertext)
        if (parsed.keyId !== record.keyId) {
            throw new Error('sender key id mismatch')
        }

        const rawSigningKey = fromSerializedPublicKey(record.signingPublicKey)
        if (!xeddsaVerify(rawSigningKey, parsed.versionedContent, parsed.signature)) {
            throw new Error('invalid sender key signature')
        }

        const selected = selectSenderKeyMessageKey(record, parsed.iteration)
        const plaintext = aesCbcDecryptFromSeed(selected.messageKey.seed, parsed.ciphertext)
        // Only persist the advanced state after a successful decryption.
        this.receivedKeys.set(receiverKey(groupId, sender), selected.record)
        this.notifyChanged()
        return plaintext
    }

    /**
     * Exports the sender-key state.
     *
     * The chain key of a sender key advances with every message, and the
     * received keys are the only way to decrypt a group message at all. Both
     * have to survive a restart.
     */
    exportState(): SerializedSenderKeyState {
        const own: Record<string, SerializedSenderKeyRecord> = {}
        const received: Record<string, SerializedSenderKeyRecord> = {}
        for (const [groupId, record] of this.ownKeys) {
            own[groupId] = serializeSenderKeyRecord(record)
        }
        for (const [key, record] of this.receivedKeys) {
            received[key] = serializeSenderKeyRecord(record)
        }
        return { own, received }
    }

    /**
     * Restores the sender-key state from an export.
     *
     * The existing state is replaced, so importing fully restores the state
     * of the device.
     *
     * @param state The serialised state.
     */
    importState(state: SerializedSenderKeyState | undefined): void {
        this.ownKeys.clear()
        this.receivedKeys.clear()
        if (!state) return
        for (const [groupId, record] of Object.entries(state.own ?? {})) {
            this.ownKeys.set(groupId, deserializeSenderKeyRecord(record))
        }
        for (const [key, record] of Object.entries(state.received ?? {})) {
            this.receivedKeys.set(key, deserializeSenderKeyRecord(record))
        }
    }
}

// ─── Parsing helpers ──────────────────────────────────────────────────────────

/** A parsed sender key message. */
export interface ParsedSenderKeyMessage {
    /** Id of the sender key. */
    keyId: number
    /** Iteration of the message. */
    iteration: number
    /** The AES-CBC ciphertext. */
    ciphertext: Uint8Array
    /** The versioned message body the signature covers. */
    versionedContent: Uint8Array
    /** The XEdDSA signature. */
    signature: Uint8Array
}

/**
 * Parses a versioned sender key distribution message.
 */
export function parseSenderKeyDistribution(payload: Uint8Array): SenderKeyDistribution {
    if (payload.length < 2) {
        throw new Error('sender key distribution message is empty')
    }
    const version = payload[0]! >>> 4
    if (version !== SIGNAL_GROUP_VERSION) {
        throw new Error(`sender key distribution message has unsupported version ${version}`)
    }
    const decoded = decode('SenderKeyDistributionMessage', payload.subarray(1))
    if (
        decoded.id === undefined ||
        decoded.iteration === undefined ||
        decoded.chainKey === undefined ||
        decoded.signingKey === undefined
    ) {
        throw new Error('invalid sender key distribution message')
    }
    const chainKey = decoded.chainKey as Uint8Array
    if (chainKey.length !== 32) {
        throw new Error('sender key distribution chain key must be 32 bytes')
    }
    return {
        keyId: decoded.id as number,
        iteration: decoded.iteration as number,
        chainKey: new Uint8Array(chainKey),
        signingPublicKey: new Uint8Array(decoded.signingKey as Uint8Array),
    }
}

/**
 * Parses a versioned sender key message with its trailing signature.
 */
export function parseSenderKeyMessage(payload: Uint8Array): ParsedSenderKeyMessage {
    if (payload.length < 1 + SENDER_KEY_SIGNATURE_LENGTH) {
        throw new Error('sender key message is too short')
    }
    const version = payload[0]! >>> 4
    if (version !== SIGNAL_GROUP_VERSION) {
        throw new Error(`sender key message has unsupported version ${version}`)
    }
    const contentEnd = payload.length - SENDER_KEY_SIGNATURE_LENGTH
    const decoded = decode('SenderKeyMessage', payload.subarray(1, contentEnd))
    if (
        decoded.id === undefined ||
        decoded.iteration === undefined ||
        decoded.ciphertext === undefined
    ) {
        throw new Error('invalid sender key message')
    }
    return {
        keyId: decoded.id as number,
        iteration: decoded.iteration as number,
        ciphertext: decoded.ciphertext as Uint8Array,
        versionedContent: payload.subarray(0, contentEnd),
        signature: payload.subarray(contentEnd),
    }
}

/**
 * Selects the message key for `targetIteration`, deriving skipped keys.
 *
 * Out-of-order messages are supported: the keys of the skipped iterations
 * are retained until they are used or evicted.
 */
export function selectSenderKeyMessageKey(
    record: SenderKeyRecord,
    targetIteration: number,
): { messageKey: SenderKeyMessageKey; record: SenderKeyRecord } {
    const delta = targetIteration - record.iteration
    if (delta > FUTURE_MESSAGES_MAX) {
        throw new Error('sender key message is too far in the future')
    }

    const unused = record.unusedMessageKeys
    if (delta < 0) {
        const index = unused.findIndex((entry) => entry.iteration === targetIteration)
        if (index === -1) {
            throw new Error('sender key message iteration is stale')
        }
        const messageKey = unused[index]!
        const nextUnused = unused.slice()
        nextUnused.splice(index, 1)
        return {
            messageKey,
            record: { ...record, unusedMessageKeys: nextUnused },
        }
    }

    let chainKey = record.chainKey
    let derived = deriveSenderKeyMessageKey(record.iteration, chainKey)
    chainKey = derived.nextChainKey

    if (delta === 0) {
        return {
            messageKey: derived.messageKey,
            record: {
                ...record,
                iteration: targetIteration + 1,
                chainKey,
                unusedMessageKeys: unused,
            },
        }
    }

    const nextUnused = unused.slice()
    let overflow = delta + nextUnused.length - MAX_UNUSED_KEYS
    if (overflow > 0) {
        nextUnused.splice(0, overflow)
        overflow -= nextUnused.length
    }

    for (let iteration = record.iteration + 1; iteration <= targetIteration; iteration += 1) {
        if (overflow > 0) {
            overflow -= 1
        } else {
            nextUnused.push(derived.messageKey)
        }
        derived = deriveSenderKeyMessageKey(iteration, chainKey)
        chainKey = derived.nextChainKey
    }

    return {
        messageKey: derived.messageKey,
        record: {
            ...record,
            iteration: targetIteration + 1,
            chainKey,
            unusedMessageKeys: nextUnused,
        },
    }
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/** Builds the map key for a received sender key. */
function receiverKey(groupId: string, sender: string): string {
    return `${groupId}\u0000${sender}`
}

/** Returns a random 31-bit integer (used for sender key ids). */
function randomInt31(): number {
    const bytes = randomBytesOf(4)
    const value = ((bytes[0]! << 24) | (bytes[1]! << 16) | (bytes[2]! << 8) | bytes[3]!) >>> 0
    return value & 0x7fffffff
}

/**
 * Extracts the AES-CBC parameters from a seed.
 *
 * The first 16 bytes are the IV, the next 32 bytes the AES-256 key.
 */
function aesCbcParams(seed: Uint8Array): { key: Uint8Array; iv: Uint8Array } {
    if (seed.length < 48) {
        throw new Error('sender key message seed must be at least 48 bytes')
    }
    return {
        iv: seed.subarray(0, 16),
        key: seed.subarray(16, 48),
    }
}

/** Encrypts `plaintext` with the key material of a seed. */
function aesCbcEncryptFromSeed(seed: Uint8Array, plaintext: Uint8Array): Uint8Array {
    const { key, iv } = aesCbcParams(seed)
    return aesCbcEncrypt(key, iv, plaintext)
}

/** Decrypts `ciphertext` with the key material of a seed. */
function aesCbcDecryptFromSeed(seed: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    const { key, iv } = aesCbcParams(seed)
    return aesCbcDecrypt(key, iv, ciphertext)
}
