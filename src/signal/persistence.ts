/**
 * Serialisation of the Signal session state.
 *
 * The double ratchet state is the only part of a Signal session that cannot
 * be recreated from the key material: the root key, the chain keys and the
 * ratchet keys all evolve with every message. A device that forgets them
 * cannot decrypt the next message of an established conversation, so the
 * state has to survive a restart.
 *
 * The format is plain JSON with hex strings for the byte fields, which keeps
 * the credential snapshot readable and diffable.
 */

import type {
    InitialExchangeInfo,
    MessageKey,
    RecvChain,
    SendChain,
    SerializedKeyPair,
    SignalIdentity,
    SignalSession,
} from './session.js'
import type { SenderKeyMessageKey, SenderKeyRecord } from './group.js'
import { fromHex, toHex } from '../crypto/primitives.js'

/** The serialised form of a message key. */
export interface SerializedMessageKey {
    /** Position of the message inside the chain. */
    index: number
    /** 32-byte AES key, hex. */
    cipherKey: string
    /** 32-byte HMAC key, hex. */
    macKey: string
    /** 16-byte AES-CBC initialisation vector, hex. */
    iv: string
}

/** The serialised form of a receiving chain. */
export interface SerializedRecvChain {
    /** Public ratchet key of the remote side, hex. */
    ratchetPubKey: string
    /** Counter of the next expected message. */
    nextMsgIndex: number
    /** Current chain key, hex. */
    chainKey: string
    /** The keys retained for out-of-order delivery. */
    unusedMsgKeys: SerializedMessageKey[]
}

/** The serialised form of a sending chain. */
export interface SerializedSendChain {
    /** The ratchet key pair of the chain. */
    ratchetKey: {
        /** 33-byte public key, hex. */
        pubKey: string
        /** 32-byte private key, hex. */
        privKey: string
    }
    /** Counter of the next message. */
    nextMsgIndex: number
    /** Current chain key, hex. */
    chainKey: string
}

/** The serialised form of an identity. */
export interface SerializedSignalIdentity {
    /** Registration id of the device. */
    regId: number
    /** 33-byte identity public key, hex. */
    pubKey: string
    /** 32-byte identity private key, hex. */
    privKey: string
}

/** The serialised form of the pre-key handshake metadata. */
export interface SerializedInitialExchangeInfo {
    /** Id of the remote one-time pre-key that was used, if any. */
    remoteOneTimeId: number | null
    /** Id of the remote signed pre-key. */
    remoteSignedId: number
    /** Our one-time base key (public part), hex. */
    localOneTimePubKey: string
}

/** The serialised form of a Signal session. */
export interface SerializedSignalSession {
    /** Our identity. */
    local: SerializedSignalIdentity
    /** The remote identity. */
    remote: SerializedSignalIdentity
    /** Current root key, hex. */
    rootKey: string
    /** The receiving chains, newest last. */
    recvChains: SerializedRecvChain[]
    /** The current sending chain. */
    sendChain: SerializedSendChain
    /** The pre-key handshake metadata, when the handshake is not finished. */
    initialExchangeInfo: SerializedInitialExchangeInfo | null
    /** Highest counter used on the previous sending chain. */
    prevSendChainHighestIndex: number
    /** The base key identifying this session, hex. */
    aliceBaseKey: string
    /**
     * The sessions this one replaced, newest first.
     *
     * Only the outermost session carries them; the replaced sessions are
     * stored next to each other, not inside each other.
     */
    prevSessions?: SerializedSignalSession[]
}

/**
 * Serialises a message key.
 *
 * @param key The message key.
 */
export function serializeMessageKey(key: MessageKey): SerializedMessageKey {
    return {
        index: key.index,
        cipherKey: toHex(key.cipherKey),
        macKey: toHex(key.macKey),
        iv: toHex(key.iv),
    }
}

/**
 * Restores a message key.
 *
 * @param key The serialised message key.
 */
export function deserializeMessageKey(key: SerializedMessageKey): MessageKey {
    return {
        index: key.index,
        cipherKey: fromHex(key.cipherKey),
        macKey: fromHex(key.macKey),
        iv: fromHex(key.iv),
    }
}

/**
 * Serialises a receiving chain.
 *
 * @param chain The receiving chain.
 */
export function serializeRecvChain(chain: RecvChain): SerializedRecvChain {
    return {
        ratchetPubKey: toHex(chain.ratchetPubKey),
        nextMsgIndex: chain.nextMsgIndex,
        chainKey: toHex(chain.chainKey),
        unusedMsgKeys: chain.unusedMsgKeys.map(serializeMessageKey),
    }
}

/**
 * Restores a receiving chain.
 *
 * @param chain The serialised receiving chain.
 */
export function deserializeRecvChain(chain: SerializedRecvChain): RecvChain {
    return {
        ratchetPubKey: fromHex(chain.ratchetPubKey),
        nextMsgIndex: chain.nextMsgIndex,
        chainKey: fromHex(chain.chainKey),
        unusedMsgKeys: chain.unusedMsgKeys.map(deserializeMessageKey),
    }
}

/**
 * Serialises a sending chain.
 *
 * @param chain The sending chain.
 */
export function serializeSendChain(chain: SendChain): SerializedSendChain {
    return {
        ratchetKey: {
            pubKey: toHex(chain.ratchetKey.pubKey),
            privKey: toHex(chain.ratchetKey.privKey),
        },
        nextMsgIndex: chain.nextMsgIndex,
        chainKey: toHex(chain.chainKey),
    }
}

/**
 * Restores a sending chain.
 *
 * @param chain The serialised sending chain.
 */
export function deserializeSendChain(chain: SerializedSendChain): SendChain {
    return {
        ratchetKey: {
            pubKey: fromHex(chain.ratchetKey.pubKey),
            privKey: fromHex(chain.ratchetKey.privKey),
        },
        nextMsgIndex: chain.nextMsgIndex,
        chainKey: fromHex(chain.chainKey),
    }
}

/**
 * Serialises an identity.
 *
 * @param identity The identity.
 */
export function serializeIdentity(identity: SignalIdentity): SerializedSignalIdentity {
    return {
        regId: identity.regId,
        pubKey: toHex(identity.pubKey),
        privKey: toHex(identity.privKey),
    }
}

/**
 * Restores an identity.
 *
 * @param identity The serialised identity.
 */
export function deserializeIdentity(identity: SerializedSignalIdentity): SignalIdentity {
    return {
        regId: identity.regId,
        pubKey: fromHex(identity.pubKey),
        privKey: fromHex(identity.privKey),
    }
}

/**
 * Serialises the pre-key handshake metadata.
 *
 * @param info The metadata.
 */
export function serializeInitialExchangeInfo(
    info: InitialExchangeInfo | null,
): SerializedInitialExchangeInfo | null {
    if (!info) return null
    return {
        remoteOneTimeId: info.remoteOneTimeId,
        remoteSignedId: info.remoteSignedId,
        localOneTimePubKey: toHex(info.localOneTimePubKey),
    }
}

/**
 * Restores the pre-key handshake metadata.
 *
 * @param info The serialised metadata.
 */
export function deserializeInitialExchangeInfo(
    info: SerializedInitialExchangeInfo | null,
): InitialExchangeInfo | null {
    if (!info) return null
    return {
        remoteOneTimeId: info.remoteOneTimeId,
        remoteSignedId: info.remoteSignedId,
        localOneTimePubKey: fromHex(info.localOneTimePubKey),
    }
}

/**
 * Serialises a Signal session.
 *
 * @param session The session.
 */
export function serializeSignalSession(session: SignalSession): SerializedSignalSession {
    return serializeSession(session, true)
}

/**
 * Serialises one session.
 *
 * @param session The session.
 * @param withPrevious Whether the replaced sessions belong to this one.
 */
function serializeSession(
    session: SignalSession,
    withPrevious: boolean,
): SerializedSignalSession {
    return {
        local: serializeIdentity(session.local),
        remote: serializeIdentity(session.remote),
        rootKey: toHex(session.rootKey),
        recvChains: session.recvChains.map(serializeRecvChain),
        sendChain: serializeSendChain(session.sendChain),
        initialExchangeInfo: serializeInitialExchangeInfo(session.initialExchangeInfo),
        prevSendChainHighestIndex: session.prevSendChainHighestIndex,
        aliceBaseKey: toHex(session.aliceBaseKey),
        ...(withPrevious && session.prevSessions.length > 0
            ? { prevSessions: session.prevSessions.map((entry) => serializeSession(entry, false)) }
            : {}),
    }
}

/**
 * Restores a Signal session.
 *
 * @param session The serialised session.
 */
export function deserializeSignalSession(session: SerializedSignalSession): SignalSession {
    return deserializeSession(session, true)
}

/**
 * Restores one session.
 *
 * @param session The serialised session.
 * @param withPrevious Whether the replaced sessions belong to this one.
 */
function deserializeSession(
    session: SerializedSignalSession,
    withPrevious: boolean,
): SignalSession {
    return {
        local: deserializeIdentity(session.local),
        remote: deserializeIdentity(session.remote),
        rootKey: fromHex(session.rootKey),
        recvChains: session.recvChains.map(deserializeRecvChain),
        sendChain: deserializeSendChain(session.sendChain),
        initialExchangeInfo: deserializeInitialExchangeInfo(session.initialExchangeInfo),
        prevSendChainHighestIndex: session.prevSendChainHighestIndex,
        aliceBaseKey: fromHex(session.aliceBaseKey),
        prevSessions:
            withPrevious && session.prevSessions
                ? session.prevSessions.map((entry) => deserializeSession(entry, false))
                : [],
    }
}

/**
 * Serialises a key pair.
 *
 * @param keyPair The key pair.
 */
export function serializeKeyPair(keyPair: SerializedKeyPair): {
    /** 33-byte public key, hex. */
    pubKey: string
    /** 32-byte private key, hex. */
    privKey: string
} {
    return { pubKey: toHex(keyPair.pubKey), privKey: toHex(keyPair.privKey) }
}

// ─── Sender keys (group chats) ──────────────────────────────────────────────

/** The serialised form of a sender-key message key. */
export interface SerializedSenderKeyMessageKey {
    /** Position of the message inside the chain. */
    iteration: number
    /** 50-byte seed holding the IV and the AES-256 key, hex. */
    seed: string
}

/** The serialised form of a sender key. */
export interface SerializedSenderKeyRecord {
    /** The group the key belongs to. */
    groupId: string
    /** Address of the device that owns the key. */
    sender: string
    /** Id of the sender key. */
    keyId: number
    /** Iteration of the next message to be produced/consumed. */
    iteration: number
    /** Current chain key, hex. */
    chainKey: string
    /** Signing public key (33-byte serialized form), hex. */
    signingPublicKey: string
    /** Signing private key (32 bytes); only present on the sending side. */
    signingPrivateKey?: string
    /** The keys retained for messages that arrive out of order. */
    unusedMessageKeys: SerializedSenderKeyMessageKey[]
}

/** The serialised state of the sender-key manager. */
export interface SerializedSenderKeyState {
    /** The own sender keys, keyed by group id. */
    own: Record<string, SerializedSenderKeyRecord>
    /** The received sender keys, keyed by `groupId   sender`. */
    received: Record<string, SerializedSenderKeyRecord>
}

/**
 * Serialises a sender-key message key.
 *
 * @param key The message key.
 */
export function serializeSenderKeyMessageKey(
    key: SenderKeyMessageKey,
): SerializedSenderKeyMessageKey {
    return { iteration: key.iteration, seed: toHex(key.seed) }
}

/**
 * Restores a sender-key message key.
 *
 * @param key The serialised message key.
 */
export function deserializeSenderKeyMessageKey(
    key: SerializedSenderKeyMessageKey,
): SenderKeyMessageKey {
    return { iteration: key.iteration, seed: fromHex(key.seed) }
}

/**
 * Serialises a sender key.
 *
 * @param record The sender key.
 */
export function serializeSenderKeyRecord(record: SenderKeyRecord): SerializedSenderKeyRecord {
    return {
        groupId: record.groupId,
        sender: record.sender,
        keyId: record.keyId,
        iteration: record.iteration,
        chainKey: toHex(record.chainKey),
        signingPublicKey: toHex(record.signingPublicKey),
        ...(record.signingPrivateKey
            ? { signingPrivateKey: toHex(record.signingPrivateKey) }
            : {}),
        unusedMessageKeys: record.unusedMessageKeys.map(serializeSenderKeyMessageKey),
    }
}

/**
 * Restores a sender key.
 *
 * @param record The serialised sender key.
 */
export function deserializeSenderKeyRecord(record: SerializedSenderKeyRecord): SenderKeyRecord {
    return {
        groupId: record.groupId,
        sender: record.sender,
        keyId: record.keyId,
        iteration: record.iteration,
        chainKey: fromHex(record.chainKey),
        signingPublicKey: fromHex(record.signingPublicKey),
        ...(record.signingPrivateKey
            ? { signingPrivateKey: fromHex(record.signingPrivateKey) }
            : {}),
        unusedMessageKeys: record.unusedMessageKeys.map(deserializeSenderKeyMessageKey),
    }
}
