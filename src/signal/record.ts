/**
 * The Signal record structures.
 *
 * WhatsApp stores the double-ratchet state of a conversation and the group
 * sender keys in the protobuf formats the Signal protocol defines:
 * `RecordStructure` for the sessions and `SenderKeyRecordStructure` for the
 * sender keys. Every implementation of the protocol uses the very same
 * blobs, which makes them the natural interchange format when a device has
 * to take over a conversation that was started somewhere else.
 *
 * The decoders in this module turn those blobs into the in-memory shapes of
 * {@link SignalSession} and {@link SenderKeyRecord}; the encoders do the
 * reverse.
 *
 * The layout of the records is:
 *
 * ```text
 * RecordStructure
 *   currentSession   SessionStructure
 *   previousSessions SessionStructure[]
 *
 * SessionStructure
 *   localIdentityPublic   bytes   our identity key
 *   remoteIdentityPublic  bytes   the peer's identity key
 *   rootKey               bytes   the root of the ratchet
 *   previousCounter       uint32  highest counter of the previous chain
 *   senderChain           Chain   our sending chain
 *   receiverChains        Chain[] the peer's chains
 *   pendingPreKey         ...     the pre-key handshake, while it is open
 *   remoteRegistrationId  uint32
 *   localRegistrationId   uint32
 *   aliceBaseKey          bytes   the base key of the session
 * ```
 */

import { decode, encode } from '../proto/codec.js'
import type { RecvChain, SendChain, SignalSession } from './session.js'
import type { SenderKeyRecord } from './group.js'

/**
 * A decoded `RecordStructure`.
 *
 * The record holds the session that is currently in use plus the sessions
 * that were replaced by a re-key. A message that was encrypted with a
 * replaced session can still arrive late, so the previous sessions are kept
 * around for a while.
 */
export interface DecodedSignalRecord {
    /** The session that is currently in use. */
    session: SignalSession
    /** The replaced sessions, newest first. */
    previousSessions: SignalSession[]
}

// ─── Decoding ────────────────────────────────────────────────────────────────

/**
 * Decodes a `RecordStructure` blob into a Signal session.
 *
 * @param raw The `RecordStructure` blob.
 * @param localPrivateKey Our identity private key.
 *
 * The private half of our identity is not part of the record — it never
 * leaves the device — so it has to be supplied by the caller. It is only
 * needed to *start* a session; decrypting an established one does not use it.
 */
export function decodeSignalSessionRecord(
    raw: Uint8Array,
    localPrivateKey?: Uint8Array,
): DecodedSignalRecord {
    const decoded = decode('RecordStructure', raw)
    const current = requireRecord(decoded.currentSession, 'currentSession')
    const previous = asArray(decoded.previousSessions)
    const previousSessions = previous.map((entry, index) =>
        decodeSessionStructure(
            requireRecord(entry, `previousSessions[${index}]`),
            `previousSessions[${index}]`,
            localPrivateKey,
        ),
    )
    return {
        session: {
            ...decodeSessionStructure(current, 'currentSession', localPrivateKey),
            prevSessions: previousSessions,
        },
        previousSessions,
    }
}

/**
 * Decodes a `SenderKeyRecordStructure` blob into a sender key.
 *
 * The record may hold several states — one per generation of the sender
 * key — but only the newest one is returned, because a sender key is only
 * ever used for the messages that follow its distribution.
 *
 * @param raw The `SenderKeyRecordStructure` blob.
 * @param groupId The group the key belongs to.
 * @param sender The address of the device that owns the key.
 */
export function decodeSenderKeyRecord(
    raw: Uint8Array,
    groupId: string,
    sender: string,
): SenderKeyRecord {
    const states = decodeSenderKeyStates(raw)
    const state = states[states.length - 1]
    if (!state) throw new Error('signal record: the sender key has no state')
    return {
        groupId,
        sender,
        keyId: state.keyId,
        iteration: state.iteration,
        chainKey: state.chainKey,
        signingPublicKey: state.signingPublicKey,
        ...(state.signingPrivateKey ? { signingPrivateKey: state.signingPrivateKey } : {}),
        unusedMessageKeys: state.unusedMessageKeys,
    }
}

/**
 * Decodes every state of a `SenderKeyRecordStructure` blob.
 *
 * @param raw The `SenderKeyRecordStructure` blob.
 */
export function decodeSenderKeyStates(
    raw: Uint8Array,
): Omit<SenderKeyRecord, 'groupId' | 'sender'>[] {
    const decoded = decode('SenderKeyRecordStructure', raw)
    const states = asArray(decoded.senderKeyStates)
    return states.map((entry, index) => {
        const state = requireRecord(entry, `senderKeyStates[${index}]`)
        const chainKey = requireRecord(state.senderChainKey, `senderKeyStates[${index}].senderChainKey`)
        const signingKey = requireRecord(
            state.senderSigningKey,
            `senderKeyStates[${index}].senderSigningKey`,
        )
        const messageKeys = asArray(state.senderMessageKeys)
        return {
            keyId: optionalNumber(state.senderKeyId, 0),
            iteration: optionalNumber(chainKey.iteration, 0),
            chainKey: requireBytes(chainKey.seed, `senderKeyStates[${index}].senderChainKey.seed`),
            signingPublicKey: requireBytes(
                signingKey.public,
                `senderKeyStates[${index}].senderSigningKey.public`,
            ),
            ...(signingKey.private instanceof Uint8Array
                ? { signingPrivateKey: signingKey.private }
                : {}),
            unusedMessageKeys: messageKeys.map((entryKey, keyIndex) => {
                const key = requireRecord(entryKey, `senderKeyStates[${index}].senderMessageKeys[${keyIndex}]`)
                return {
                    iteration: optionalNumber(key.iteration, 0),
                    seed: requireBytes(
                        key.seed,
                        `senderKeyStates[${index}].senderMessageKeys[${keyIndex}].seed`,
                    ),
                }
            }),
        }
    })
}

// ─── Encoding ────────────────────────────────────────────────────────────────

/**
 * Encodes a Signal session into a `RecordStructure` blob.
 *
 * @param session The session.
 * @param previousSessions The replaced sessions, newest first.
 */
export function encodeSignalSessionRecord(
    session: SignalSession,
    previousSessions: SignalSession[] = session.prevSessions,
): Uint8Array {
    return encode('RecordStructure', {
        currentSession: encodeSessionStructure(session),
        ...(previousSessions.length > 0
            ? { previousSessions: previousSessions.map(encodeSessionStructure) }
            : {}),
    })
}

/**
 * Encodes a sender key into a `SenderKeyRecordStructure` blob.
 *
 * @param record The sender key.
 */
export function encodeSenderKeyRecord(record: SenderKeyRecord): Uint8Array {
    return encode('SenderKeyRecordStructure', {
        senderKeyStates: [
            {
                senderKeyId: record.keyId,
                senderChainKey: {
                    iteration: record.iteration,
                    seed: record.chainKey,
                },
                senderSigningKey: {
                    public: record.signingPublicKey,
                    ...(record.signingPrivateKey ? { private: record.signingPrivateKey } : {}),
                },
                senderMessageKeys: record.unusedMessageKeys.map((key) => ({
                    iteration: key.iteration,
                    seed: key.seed,
                })),
            },
        ],
    })
}

// ─── Internals ───────────────────────────────────────────────────────────────

/** Encodes one `SessionStructure`. */
function encodeSessionStructure(session: SignalSession): Record<string, unknown> {
    const exchange = session.initialExchangeInfo
    return {
        sessionVersion: 3,
        localIdentityPublic: session.local.pubKey,
        remoteIdentityPublic: session.remote.pubKey,
        rootKey: session.rootKey,
        previousCounter: session.prevSendChainHighestIndex,
        senderChain: {
            senderRatchetKey: session.sendChain.ratchetKey.pubKey,
            senderRatchetKeyPrivate: session.sendChain.ratchetKey.privKey,
            chainKey: {
                index: session.sendChain.nextMsgIndex,
                key: session.sendChain.chainKey,
            },
            messageKeys: [],
        },
        receiverChains: session.recvChains.map((chain) => ({
            senderRatchetKey: chain.ratchetPubKey,
            chainKey: {
                index: chain.nextMsgIndex,
                key: chain.chainKey,
            },
            messageKeys: chain.unusedMsgKeys.map((key) => ({
                index: key.index,
                cipherKey: key.cipherKey,
                macKey: key.macKey,
                iv: key.iv,
            })),
        })),
        ...(exchange
            ? {
                  pendingPreKey: {
                      ...(exchange.remoteOneTimeId !== null
                          ? { preKeyId: exchange.remoteOneTimeId }
                          : {}),
                      signedPreKeyId: exchange.remoteSignedId,
                      baseKey: exchange.localOneTimePubKey,
                  },
              }
            : {}),
        localRegistrationId: session.local.regId,
        remoteRegistrationId: session.remote.regId,
        ...(session.aliceBaseKey.length > 0 ? { aliceBaseKey: session.aliceBaseKey } : {}),
    }
}

/** Decodes one `SessionStructure`. */
function decodeSessionStructure(
    structure: Record<string, unknown>,
    field: string,
    localPrivateKey?: Uint8Array,
): SignalSession {
    const senderChain = requireRecord(structure.senderChain, `${field}.senderChain`)
    const pendingPreKey = structure.pendingPreKey
    const pending = pendingPreKey ? requireRecord(pendingPreKey, `${field}.pendingPreKey`) : undefined
    const exchange = pending
        ? {
              remoteOneTimeId:
                  typeof pending.preKeyId === 'number' ? pending.preKeyId : null,
              remoteSignedId: optionalNumber(pending.signedPreKeyId, 0),
              localOneTimePubKey: requireBytes(
                  pending.baseKey ?? new Uint8Array(0),
                  `${field}.pendingPreKey.baseKey`,
              ),
          }
        : null

    return {
        local: {
            regId: optionalNumber(structure.localRegistrationId, 0),
            pubKey: requireBytes(structure.localIdentityPublic, `${field}.localIdentityPublic`),
            privKey: localPrivateKey ? new Uint8Array(localPrivateKey) : new Uint8Array(0),
        },
        remote: {
            regId: optionalNumber(structure.remoteRegistrationId, 0),
            pubKey: requireBytes(structure.remoteIdentityPublic, `${field}.remoteIdentityPublic`),
            privKey: new Uint8Array(0),
        },
        rootKey: requireBytes(structure.rootKey, `${field}.rootKey`),
        recvChains: asArray(structure.receiverChains).map((entry, index) =>
            decodeRecvChain(
                requireRecord(entry, `${field}.receiverChains[${index}]`),
                `${field}.receiverChains[${index}]`,
            ),
        ),
        sendChain: decodeSendChain(senderChain, `${field}.senderChain`),
        initialExchangeInfo: exchange,
        prevSendChainHighestIndex: optionalNumber(structure.previousCounter, 0),
        aliceBaseKey:
            structure.aliceBaseKey instanceof Uint8Array
                ? structure.aliceBaseKey
                : new Uint8Array(0),
        prevSessions: [],
    }
}

/** Decodes one receiving chain. */
function decodeRecvChain(chain: Record<string, unknown>, field: string): RecvChain {
    const chainKey = requireRecord(chain.chainKey, `${field}.chainKey`)
    return {
        ratchetPubKey: requireBytes(chain.senderRatchetKey, `${field}.senderRatchetKey`),
        nextMsgIndex: optionalNumber(chainKey.index, 0),
        chainKey: requireBytes(chainKey.key, `${field}.chainKey.key`),
        unusedMsgKeys: asArray(chain.messageKeys).map((entry, index) => {
            const key = requireRecord(entry, `${field}.messageKeys[${index}]`)
            return {
                index: optionalNumber(key.index, 0),
                cipherKey: requireBytes(key.cipherKey, `${field}.messageKeys[${index}].cipherKey`),
                macKey: requireBytes(key.macKey, `${field}.messageKeys[${index}].macKey`),
                iv: requireBytes(key.iv, `${field}.messageKeys[${index}].iv`),
            }
        }),
    }
}

/** Decodes the sending chain. */
function decodeSendChain(chain: Record<string, unknown>, field: string): SendChain {
    const chainKey = requireRecord(chain.chainKey, `${field}.chainKey`)
    return {
        ratchetKey: {
            pubKey: requireBytes(chain.senderRatchetKey, `${field}.senderRatchetKey`),
            privKey: requireBytes(
                chain.senderRatchetKeyPrivate,
                `${field}.senderRatchetKeyPrivate`,
            ),
        },
        nextMsgIndex: optionalNumber(chainKey.index, 0),
        chainKey: requireBytes(chainKey.key, `${field}.chainKey.key`),
    }
}

/** Returns the value as a record, or throws. */
function requireRecord(value: unknown, field: string): Record<string, unknown> {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(`signal record: ${field} is missing`)
    }
    return value as Record<string, unknown>
}

/** Returns the value as bytes, or throws. */
function requireBytes(value: unknown, field: string): Uint8Array {
    if (!(value instanceof Uint8Array)) {
        throw new Error(`signal record: ${field} is missing`)
    }
    return value
}

/** Returns the value as a number, or the fallback. */
function optionalNumber(value: unknown, fallback: number): number {
    return typeof value === 'number' && Number.isFinite(value) ? value : fallback
}

/** Returns the value as an array, or an empty array. */
function asArray(value: unknown): unknown[] {
    return Array.isArray(value) ? value : []
}
