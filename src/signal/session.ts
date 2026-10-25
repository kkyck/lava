/**
 * Signal session state and the Double Ratchet implementation.
 *
 * The ratchet follows Signal's "half-double" variant as used by WhatsApp:
 *
 * - A session holds a root key, one *sending* chain and a list of
 *   *receiving* chains (one per remote ratchet key).
 * - Every message carries the sender's current ratchet key. When the key is
 *   new, the receiving side performs a DH ratchet and starts a new chain.
 * - Skipped message keys are retained so out-of-order delivery still works.
 */

import {
    aesCbcDecrypt,
    aesCbcEncrypt,
    concat,
    equalBytes,
    generateX25519KeyPair,
    hkdf,
    hkdfSplit,
    hmacSha256,
    prependVersion,
    toSerializedPublicKey,
    x25519,
} from '../crypto/primitives.js'
import { decode, encode } from '../proto/codec.js'
import {
    CHAIN_KEY_LABEL,
    FUTURE_MESSAGES_MAX,
    MAX_UNUSED_KEYS,
    MESSAGE_KEY_LABEL,
    SIGNAL_MAC_SIZE,
    SIGNAL_PREFIX,
    SIGNAL_VERSION,
    WHISPER_MESSAGE_KEYS_INFO,
    WHISPER_RATCHET_INFO,
    WHISPER_TEXT_INFO,
} from './constants.js'

/** A serialized (33-byte, `0x05`-prefixed) key pair. */
export interface SerializedKeyPair {
    /** 33-byte public key. */
    pubKey: Uint8Array
    /** 32-byte private key. */
    privKey: Uint8Array
}

/** A single message key with its counter. */
export interface MessageKey {
    /** Position of this message inside the chain. */
    index: number
    /** 32-byte AES key. */
    cipherKey: Uint8Array
    /** 32-byte HMAC key. */
    macKey: Uint8Array
    /** 16-byte AES-CBC initialisation vector. */
    iv: Uint8Array
}

/** A sending chain. */
export interface SendChain {
    /** The ratchet key pair used for this chain. */
    ratchetKey: SerializedKeyPair
    /** Counter of the next message. */
    nextMsgIndex: number
    /** Current chain key. */
    chainKey: Uint8Array
}

/** A receiving chain. */
export interface RecvChain {
    /** Public ratchet key of the remote side. */
    ratchetPubKey: Uint8Array
    /** Counter of the next expected message. */
    nextMsgIndex: number
    /** Current chain key. */
    chainKey: Uint8Array
    /** Skipped-ahead keys retained for out-of-order delivery. */
    unusedMsgKeys: MessageKey[]
}

/** Identity of a Signal address (one device). */
export interface SignalIdentity {
    /** Registration id of the device. */
    regId: number
    /** 33-byte identity public key. */
    pubKey: Uint8Array
    /** 32-byte identity private key. */
    privKey: Uint8Array
}

/** Information exchanged during the initial pre-key handshake. */
export interface InitialExchangeInfo {
    /** Id of the remote one-time pre-key that was used, if any. */
    remoteOneTimeId: number | null
    /** Id of the remote signed pre-key. */
    remoteSignedId: number
    /** Our one-time base key (public part). */
    localOneTimePubKey: Uint8Array
}

/** A complete Signal session. */
export interface SignalSession {
    /** Our identity. */
    local: SignalIdentity
    /** The remote identity. */
    remote: SignalIdentity
    /** Current root key. */
    rootKey: Uint8Array
    /** Receiving chains, newest last. */
    recvChains: RecvChain[]
    /** The current sending chain. */
    sendChain: SendChain
    /** Pre-key handshake metadata, cleared once the handshake completes. */
    initialExchangeInfo: InitialExchangeInfo | null
    /** Highest counter used on the previous sending chain. */
    prevSendChainHighestIndex: number
    /** The base key identifying this session. */
    aliceBaseKey: Uint8Array
}

/** A remote pre-key bundle. */
export interface PreKeyBundle {
    /** Registration id of the remote device. */
    regId: number
    /** 33-byte identity key. */
    identity: Uint8Array
    /** The signed pre-key. */
    signedKey: {
        /** Id of the signed pre-key. */
        id: number
        /** 33-byte public key. */
        publicKey: Uint8Array
    }
    /** Optional one-time pre-key. */
    oneTimeKey?: {
        /** Id of the one-time pre-key. */
        id: number
        /** 33-byte public key. */
        publicKey: Uint8Array
    } | null
    /** The remote ratchet key. */
    ratchetKey?: Uint8Array | null
}

/** The result of encrypting a Signal message. */
export interface EncryptedSignal {
    /** `msg` for a normal message, `pkmsg` for the first message of a session. */
    type: 'msg' | 'pkmsg'
    /** The encoded wire payload. */
    ciphertext: Uint8Array
}

/** A parsed inbound Signal message. */
export interface ParsedSignalMessage {
    /** The remote ratchet key that produced this message. */
    ratchetPubKey: Uint8Array
    /** Counter of this message. */
    counter: number
    /** Counter of the previous chain. */
    previousCounter: number
    /** The AES-CBC ciphertext. */
    ciphertext: Uint8Array
    /** Version byte + payload + MAC, as received. */
    versionContentMac: Uint8Array
}

/** A parsed inbound pre-key message. */
export interface ParsedPreKeyMessage extends ParsedSignalMessage {
    /** The remote identity that started the handshake. */
    remote: { regId: number; pubKey: Uint8Array }
    /** The base key the sender used. */
    sessionBaseKey: Uint8Array
    /** Id of our signed pre-key the sender picked. */
    localSignedPreKeyId: number
    /** Id of our one-time pre-key the sender picked, if any. */
    localOneTimeKeyId: number | null
}

/** Maximum number of receiving chains tracked simultaneously. */
const MAX_TRACKED_RECV_CHAINS = 4

// ─── Key helpers ─────────────────────────────────────────────────────────────

/** Generates a new X25519 key pair in Signal's serialized form. */
export function generateSerializedKeyPair(): SerializedKeyPair {
    const pair = generateX25519KeyPair()
    return { pubKey: toSerializedPublicKey(pair.publicKey), privKey: pair.privateKey }
}

/** Computes an X25519 shared secret with a serialized peer key. */
export function ecdh(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
    const raw = publicKey.length === 33 ? publicKey.subarray(1) : publicKey
    return x25519(privateKey, raw)
}

// ─── Session establishment ───────────────────────────────────────────────────

/**
 * Creates a session for an outgoing message.
 *
 * @param local Our identity.
 * @param remoteBundle The remote pre-key bundle.
 * @param localOneTimeBase Our freshly generated one-time base key.
 */
export function initiateSessionOutgoing(
    local: SignalIdentity,
    remoteBundle: PreKeyBundle,
    localOneTimeBase: SerializedKeyPair,
): SignalSession {
    const remoteIdentity = toSerializedPublicKey(remoteBundle.identity)
    const remoteSignedKey = toSerializedPublicKey(remoteBundle.signedKey.publicKey)
    const remoteOneTimeKey = remoteBundle.oneTimeKey
        ? toSerializedPublicKey(remoteBundle.oneTimeKey.publicKey)
        : null
    const remoteRatchetKey = toSerializedPublicKey(
        remoteBundle.ratchetKey ?? remoteBundle.signedKey.publicKey,
    )

    const signedDh = ecdh(local.privKey, remoteSignedKey)
    const identityDh = ecdh(localOneTimeBase.privKey, remoteIdentity)
    const baseDh = ecdh(localOneTimeBase.privKey, remoteSignedKey)
    const oneTimeDh = remoteOneTimeKey
        ? ecdh(localOneTimeBase.privKey, remoteOneTimeKey)
        : null

    const secret = concat(
        SIGNAL_PREFIX,
        signedDh,
        identityDh,
        baseDh,
        oneTimeDh ? oneTimeDh : new Uint8Array(0),
    )
    const [rootKey, chainKey] = hkdfSplit(secret, null, WHISPER_TEXT_INFO)

    const recvChain: RecvChain = {
        ratchetPubKey: remoteRatchetKey,
        nextMsgIndex: 0,
        chainKey,
        unusedMsgKeys: [],
    }
    const sendRatchet = generateSerializedKeyPair()
    const sendRatchetResult = calculateRatchet(rootKey, sendRatchet, remoteRatchetKey)

    return {
        local: { regId: local.regId, pubKey: local.pubKey, privKey: local.privKey },
        remote: { regId: remoteBundle.regId, pubKey: remoteIdentity, privKey: new Uint8Array(0) },
        rootKey: sendRatchetResult.rootKey,
        recvChains: [recvChain],
        sendChain: {
            ratchetKey: sendRatchet,
            nextMsgIndex: 0,
            chainKey: sendRatchetResult.chainKey,
        },
        initialExchangeInfo: {
            remoteOneTimeId: remoteBundle.oneTimeKey?.id ?? null,
            remoteSignedId: remoteBundle.signedKey.id,
            localOneTimePubKey: localOneTimeBase.pubKey,
        },
        prevSendChainHighestIndex: 0,
        aliceBaseKey: localOneTimeBase.pubKey,
    }
}

/**
 * Creates a session for an incoming pre-key message.
 *
 * @param local Our identity.
 * @param remote The remote identity.
 * @param sessionBaseKey The base key the sender used (33 bytes).
 * @param localKeys Our one-time, signed and ratchet keys.
 */
export function initiateSessionIncoming(
    local: SignalIdentity,
    remote: SignalIdentity,
    sessionBaseKey: Uint8Array,
    localKeys: {
        oneTime?: SerializedKeyPair | null
        signed: SerializedKeyPair
        ratchet: SerializedKeyPair
    },
): SignalSession {
    const baseKey = toSerializedPublicKey(sessionBaseKey)
    const remotePub = toSerializedPublicKey(remote.pubKey)

    const identityDh = ecdh(localKeys.signed.privKey, remotePub)
    const staticDh = ecdh(local.privKey, baseKey)
    const signedDh = ecdh(localKeys.signed.privKey, baseKey)
    const oneTimeDh = localKeys.oneTime ? ecdh(localKeys.oneTime.privKey, baseKey) : null

    const secret = concat(
        SIGNAL_PREFIX,
        identityDh,
        staticDh,
        signedDh,
        oneTimeDh ? oneTimeDh : new Uint8Array(0),
    )
    const [rootKey, chainKey] = hkdfSplit(secret, null, WHISPER_TEXT_INFO)

    return {
        local: { regId: local.regId, pubKey: local.pubKey, privKey: local.privKey },
        remote: { regId: remote.regId, pubKey: remotePub, privKey: new Uint8Array(0) },
        rootKey,
        recvChains: [],
        sendChain: {
            ratchetKey: localKeys.ratchet,
            nextMsgIndex: 0,
            chainKey,
        },
        initialExchangeInfo: null,
        prevSendChainHighestIndex: 0,
        aliceBaseKey: baseKey,
    }
}

/**
 * Performs one step of the DH ratchet.
 *
 * @param rootKey Current root key.
 * @param localRatchet Our ratchet key pair.
 * @param remoteRatchetPubKey The remote ratchet public key.
 */
export function calculateRatchet(
    rootKey: Uint8Array,
    localRatchet: SerializedKeyPair,
    remoteRatchetPubKey: Uint8Array,
): { rootKey: Uint8Array; chainKey: Uint8Array } {
    const sharedSecret = ecdh(localRatchet.privKey, remoteRatchetPubKey)
    const [nextRootKey, chainKey] = hkdfSplit(sharedSecret, rootKey, WHISPER_RATCHET_INFO)
    return { rootKey: nextRootKey, chainKey }
}

// ─── Message key derivation ──────────────────────────────────────────────────

/**
 * Derives the message key and the next chain key from a chain key.
 *
 * @param index Counter of the message being derived.
 * @param chainKey Current chain key.
 */
export function deriveMessageKey(
    index: number,
    chainKey: Uint8Array,
): { messageKey: MessageKey; nextChainKey: Uint8Array } {
    const nextChainRaw = hmacSha256(chainKey, CHAIN_KEY_LABEL)
    const messageInputKey = hmacSha256(chainKey, MESSAGE_KEY_LABEL)
    const nextChainKey = nextChainRaw.subarray(0, 32)
    const expanded = hkdf(messageInputKey, null, WHISPER_MESSAGE_KEYS_INFO, 80)
    return {
        nextChainKey,
        messageKey: {
            index,
            cipherKey: expanded.subarray(0, 32),
            macKey: expanded.subarray(32, 64),
            iv: expanded.subarray(64, 80),
        },
    }
}

/**
 * Selects the message key for `targetCounter`, deriving skipped keys.
 *
 * @param chain The receiving chain.
 * @param targetCounter The counter of the message being decrypted.
 */
export function selectMessageKey(
    chain: RecvChain,
    targetCounter: number,
): { messageKey: MessageKey; updatedChain: RecvChain } {
    const delta = targetCounter - chain.nextMsgIndex
    if (delta > FUTURE_MESSAGES_MAX) {
        throw new Error('signal: message too far in the future')
    }

    if (delta < 0) {
        const index = chain.unusedMsgKeys.findIndex((entry) => entry.index === targetCounter)
        if (index === -1) {
            throw new Error('signal: duplicate message')
        }
        const messageKey = chain.unusedMsgKeys[index]!
        const unusedMsgKeys = chain.unusedMsgKeys.slice()
        unusedMsgKeys.splice(index, 1)
        return { messageKey, updatedChain: { ...chain, unusedMsgKeys } }
    }

    let chainKey = chain.chainKey
    const first = deriveMessageKey(chain.nextMsgIndex, chainKey)
    let currentMessageKey = first.messageKey
    chainKey = first.nextChainKey

    if (delta === 0) {
        return {
            messageKey: currentMessageKey,
            updatedChain: {
                ratchetPubKey: chain.ratchetPubKey,
                nextMsgIndex: targetCounter + 1,
                chainKey,
                unusedMsgKeys: chain.unusedMsgKeys,
            },
        }
    }

    const nextUnused = chain.unusedMsgKeys.slice()
    let overflow = delta + nextUnused.length - MAX_UNUSED_KEYS
    if (overflow > 0) {
        nextUnused.splice(0, overflow)
        overflow -= nextUnused.length
    }
    for (let counter = chain.nextMsgIndex + 1; counter <= targetCounter; counter += 1) {
        if (overflow > 0) {
            overflow -= 1
        } else {
            nextUnused.push(currentMessageKey)
        }
        const derived = deriveMessageKey(counter, chainKey)
        currentMessageKey = derived.messageKey
        chainKey = derived.nextChainKey
    }

    return {
        messageKey: currentMessageKey,
        updatedChain: {
            ratchetPubKey: chain.ratchetPubKey,
            nextMsgIndex: targetCounter + 1,
            chainKey,
            unusedMsgKeys: nextUnused,
        },
    }
}

// ─── Encrypt / decrypt ───────────────────────────────────────────────────────

/**
 * Encrypts `plaintext` for the session.
 *
 * @param session The session to use.
 * @param plaintext The message body.
 */
export function encryptSignalMessage(
    session: SignalSession,
    plaintext: Uint8Array,
): { session: SignalSession; result: EncryptedSignal } {
    const { nextChainKey, messageKey } = deriveMessageKey(
        session.sendChain.nextMsgIndex,
        session.sendChain.chainKey,
    )
    const ciphertext = aesCbcEncrypt(messageKey.cipherKey, messageKey.iv, plaintext)
    const signalPayload = encode('SignalMessage', {
        ratchetKey: session.sendChain.ratchetKey.pubKey,
        counter: messageKey.index,
        previousCounter: session.prevSendChainHighestIndex,
        ciphertext,
    })

    const versionedLength = 1 + signalPayload.length
    const signalMessage = new Uint8Array(versionedLength + SIGNAL_MAC_SIZE)
    signalMessage[0] = ((SIGNAL_VERSION << 4) | SIGNAL_VERSION) & 0xff
    signalMessage.set(signalPayload, 1)
    const mac = hmacSha256(
        messageKey.macKey,
        concat(
            session.local.pubKey,
            session.remote.pubKey,
            signalMessage.subarray(0, versionedLength),
        ),
    )
    signalMessage.set(mac.subarray(0, SIGNAL_MAC_SIZE), versionedLength)

    let type: 'msg' | 'pkmsg' = 'msg'
    let output: Uint8Array = signalMessage
    if (session.initialExchangeInfo) {
        const preKeyPayload = encode('PreKeySignalMessage', {
            registrationId: session.local.regId,
            preKeyId: session.initialExchangeInfo.remoteOneTimeId ?? undefined,
            signedPreKeyId: session.initialExchangeInfo.remoteSignedId,
            baseKey: session.initialExchangeInfo.localOneTimePubKey,
            identityKey: session.local.pubKey,
            message: signalMessage,
        })
        type = 'pkmsg'
        output = prependVersion(preKeyPayload, SIGNAL_VERSION)
    }

    return {
        session: {
            ...session,
            sendChain: {
                ratchetKey: session.sendChain.ratchetKey,
                nextMsgIndex: messageKey.index + 1,
                chainKey: nextChainKey,
            },
            // The pre-key handshake is complete once the first message has
            // been sent; every following message is a plain `msg`.
            initialExchangeInfo: null,
        },
        result: { type, ciphertext: output },
    }
}

/**
 * Decrypts a Signal message using the current session.
 *
 * @param session The session to decrypt with.
 * @param parsed The parsed message.
 */
export function decryptSignalMessage(
    session: SignalSession,
    parsed: ParsedSignalMessage,
): { session: SignalSession; plaintext: Uint8Array } {
    const ratchetPubKey = toSerializedPublicKey(parsed.ratchetPubKey)

    let recvChainIndex = -1
    for (let index = 0; index < session.recvChains.length; index += 1) {
        const key = session.recvChains[index]!.ratchetPubKey
        if (equalBytes(key, ratchetPubKey)) {
            recvChainIndex = index
            break
        }
    }

    let selectedMessageKey: MessageKey
    let updatedSession: SignalSession

    if (recvChainIndex === -1) {
        // New remote ratchet key: perform the DH ratchet and start a chain.
        const recvRatchet = calculateRatchet(
            session.rootKey,
            session.sendChain.ratchetKey,
            ratchetPubKey,
        )
        const freshRecvChain: RecvChain = {
            ratchetPubKey,
            nextMsgIndex: 0,
            chainKey: recvRatchet.chainKey,
            unusedMsgKeys: [],
        }
        const selected = selectMessageKey(freshRecvChain, parsed.counter)
        const newSendRatchet = generateSerializedKeyPair()
        selectedMessageKey = selected.messageKey
        const sendRatchet = calculateRatchet(recvRatchet.rootKey, newSendRatchet, ratchetPubKey)
        const nextRecvChains = session.recvChains.slice(-MAX_TRACKED_RECV_CHAINS)
        nextRecvChains.push(selected.updatedChain)
        updatedSession = {
            ...session,
            rootKey: sendRatchet.rootKey,
            recvChains: nextRecvChains,
            sendChain: {
                ratchetKey: newSendRatchet,
                nextMsgIndex: 0,
                chainKey: sendRatchet.chainKey,
            },
            initialExchangeInfo: null,
            prevSendChainHighestIndex: Math.max(session.sendChain.nextMsgIndex - 1, 0),
        }
    } else {
        const chain = session.recvChains[recvChainIndex]!
        const selected = selectMessageKey(chain, parsed.counter)
        selectedMessageKey = selected.messageKey
        const nextRecvChains = session.recvChains.slice()
        nextRecvChains[recvChainIndex] = selected.updatedChain
        updatedSession = { ...session, recvChains: nextRecvChains }
    }

    // Verify the MAC before decrypting.
    const payloadWithoutMac = parsed.versionContentMac.subarray(
        0,
        parsed.versionContentMac.length - SIGNAL_MAC_SIZE,
    )
    const expectedMac = hmacSha256(
        selectedMessageKey.macKey,
        concat(session.remote.pubKey, session.local.pubKey, payloadWithoutMac),
    )
    const receivedMac = parsed.versionContentMac.subarray(
        parsed.versionContentMac.length - SIGNAL_MAC_SIZE,
    )
    if (!equalBytes(expectedMac.subarray(0, SIGNAL_MAC_SIZE), receivedMac)) {
        throw new Error('signal: invalid message mac')
    }

    const plaintext = aesCbcDecrypt(
        selectedMessageKey.cipherKey,
        selectedMessageKey.iv,
        parsed.ciphertext,
    )
    return { session: updatedSession, plaintext }
}

// ─── Serialisation ───────────────────────────────────────────────────────────

/**
 * Reads versioned content, validating the version and extracting the body.
 *
 * @param versionContent The versioned bytes.
 * @param expectedVersion The expected protocol version.
 * @param suffixLength Number of trailing bytes to exclude (e.g. the MAC).
 */
export function readVersionedContent(
    versionContent: Uint8Array,
    expectedVersion: number,
    suffixLength: number,
): Uint8Array {
    if (versionContent.length < 1) {
        throw new Error('signal: versioned content is empty')
    }
    const version = versionContent[0]! >>> 4
    if (version !== expectedVersion) {
        throw new Error(
            version < expectedVersion
                ? 'signal: legacy signal version'
                : `signal: unsupported signal version ${version}`,
        )
    }
    const bodyEnd = versionContent.length - suffixLength
    if (bodyEnd <= 1) {
        throw new Error('signal: invalid content length')
    }
    return versionContent.subarray(1, bodyEnd)
}

/**
 * Parses a normal (`msg`) Signal payload.
 *
 * @param versionContentMac Version byte + payload + MAC.
 */
export function deserializeSignalMessage(versionContentMac: Uint8Array): ParsedSignalMessage {
    const content = readVersionedContent(versionContentMac, SIGNAL_VERSION, SIGNAL_MAC_SIZE)
    const parsed = decode('SignalMessage', content)
    if (
        parsed.ratchetKey === undefined ||
        parsed.counter === undefined ||
        parsed.ciphertext === undefined
    ) {
        throw new Error('signal: invalid signal message')
    }
    return {
        ratchetPubKey: toSerializedPublicKey(parsed.ratchetKey as Uint8Array),
        counter: parsed.counter as number,
        previousCounter: (parsed.previousCounter as number) ?? 0,
        ciphertext: parsed.ciphertext as Uint8Array,
        versionContentMac,
    }
}

/**
 * Parses a pre-key (`pkmsg`) Signal payload.
 *
 * @param versionContent Version byte + `PreKeySignalMessage` body.
 */
export function deserializePreKeyMessage(versionContent: Uint8Array): ParsedPreKeyMessage {
    const content = readVersionedContent(versionContent, SIGNAL_VERSION, 0)
    const parsed = decode('PreKeySignalMessage', content)
    if (
        parsed.registrationId === undefined ||
        parsed.signedPreKeyId === undefined ||
        parsed.baseKey === undefined ||
        parsed.identityKey === undefined ||
        parsed.message === undefined
    ) {
        throw new Error('signal: invalid prekey signal message')
    }
    const signal = deserializeSignalMessage(parsed.message as Uint8Array)
    return {
        ...signal,
        remote: {
            regId: parsed.registrationId as number,
            pubKey: toSerializedPublicKey(parsed.identityKey as Uint8Array),
        },
        sessionBaseKey: toSerializedPublicKey(parsed.baseKey as Uint8Array),
        localSignedPreKeyId: parsed.signedPreKeyId as number,
        localOneTimeKeyId: (parsed.preKeyId as number | undefined) ?? null,
    }
}
