/**
 * The Signal session manager.
 *
 * Owns the device's key material, the per-peer double-ratchet sessions and
 * the per-group sender keys, and exposes the two operations the transport
 * needs:
 *
 * - {@link SignalSessionManager.encryptForPeer} — encrypt a payload for a
 *   device (direct chat) or a group.
 * - {@link SignalSessionManager.decryptFromPeer} — decrypt an inbound payload.
 */

import { concat, equalBytes } from '../crypto/primitives.js'
import { decode } from '../proto/codec.js'
import { SignalKeyStore } from './keys.js'
import {
    decryptSignalMessage,
    deserializePreKeyMessage,
    deserializeSignalMessage,
    ecdh,
    encryptSignalMessage,
    generateSerializedKeyPair,
    initiateSessionIncoming,
    initiateSessionOutgoing,
    type SerializedKeyPair,
    type SignalSession,
} from './session.js'
import { SenderKeyManager, type GroupEncryptionResult } from './group.js'
import { signalAddressKey, parseSignalAddressFromJid } from '../protocol/jid.js'
import {
    deserializeSignalSession,
    serializeSignalSession,
    type SerializedSignalSession,
} from './persistence.js'

/** A remote device's pre-key bundle. */
export interface RemoteKeyBundle {
    /** The device's registration id. */
    regId: number
    /** The device's identity public key (33 bytes, serialized). */
    identity: Uint8Array
    /** The device's signed pre-key. */
    signedKey: { id: number; publicKey: Uint8Array }
    /** The device's one-time pre-key, when one was available. */
    oneTimeKey?: { id: number; publicKey: Uint8Array } | null
}

/** Fetches the pre-key bundles of remote devices. */
export type PreKeyFetcher = (
    targets: { userJid: string; devices: { deviceId: number; registrationId?: number }[] }[],
) => Promise<{ deviceJid: string; bundle: RemoteKeyBundle }[]>

/** Options for {@link SignalSessionManager}. */
export interface SignalSessionManagerOptions {
    /** The key store holding this device's identity and pre-keys. */
    keyStore?: SignalKeyStore
    /** The sender-key manager used for group chats. */
    senderKeyManager?: SenderKeyManager
    /**
     * Called when a one-time pre-key is consumed.
     *
     * A one-time pre-key may only be used once, so the caller has to drop it
     * from its persistent storage when this fires.
     *
     * @param id The id of the consumed pre-key.
     */
    onPreKeyConsumed?: (id: number) => void
    /**
     * Called when a double-ratchet session changed.
     *
     * The ratchet state cannot be recreated from the key material, so the
     * caller has to persist it when this fires.
     */
    onSessionChanged?: () => void
    /**
     * Called when a group sender key changed.
     *
     * The chain key of a sender key advances with every group message and
     * the received keys are the only way to decrypt a group message at all,
     * so the caller has to persist them when this fires.
     */
    onSenderKeysChanged?: () => void
}

/** The result of encrypting for a peer. */
export interface EncryptedForPeer {
    /** The ciphertext to place in the `<enc>` node. */
    ciphertext: Uint8Array
    /** The `<enc type>` value: `msg`, `pkmsg` or `skmsg`. */
    encType: string
    /** The sender-key distribution message, for group chats. */
    distributionMessage?: Uint8Array
}

/** A decrypted inbound payload. */
export interface DecryptedFromPeer {
    /** The plaintext. */
    plaintext: Uint8Array
    /** The sender's device JID. */
    sender: string
    /** The sender's registration id. */
    registrationId: number
}

/**
 * Manages Signal sessions, keys and group sender keys.
 */
export class SignalSessionManager {
    /** The device's key material. */
    readonly keyStore: SignalKeyStore

    /** The group sender-key manager. */
    readonly senderKeyManager: SenderKeyManager

    /** The options the manager was created with. */
    private readonly options: SignalSessionManagerOptions

    /** Double-ratchet sessions, keyed by the canonical Signal address. */
    private readonly sessions = new Map<string, SignalSession>()

    /**
     * @param options The manager options.
     */
    constructor(options: SignalSessionManagerOptions = {}) {
        this.options = options
        this.keyStore = options.keyStore ?? new SignalKeyStore()
        this.senderKeyManager =
            options.senderKeyManager ??
            new SenderKeyManager({ onSenderKeysChanged: options.onSenderKeysChanged })
    }

    /**
     * Returns the session for an address, if one exists.
     *
     * @param address The Signal address (`user@server[:device]`).
     */
    getSession(address: string): SignalSession | undefined {
        return this.sessions.get(SignalSessionManager.addressKey(address))
    }

    /**
     * Stores a session for an address.
     *
     * @param address The Signal address.
     * @param session The session.
     */
    setSession(address: string, session: SignalSession): void {
        this.storeSession(SignalSessionManager.addressKey(address), session)
    }

    /** Removes the session for an address. */
    removeSession(address: string): void {
        this.sessions.delete(SignalSessionManager.addressKey(address))
    }

    /**
     * Stores a session under an already normalised key.
     *
     * Every write goes through here, so the persistence callback fires for
     * every change of the ratchet state.
     *
     * @param key The normalised address key.
     * @param session The session.
     */
    private storeSession(key: string, session: SignalSession): void {
        this.sessions.set(key, session)
        this.options.onSessionChanged?.()
    }

    /** Number of tracked sessions. */
    get sessionCount(): number {
        return this.sessions.size
    }

    /**
     * Exports every tracked session.
     *
     * The double ratchet state cannot be recreated from the key material, so
     * it has to survive a restart: a device that forgets it cannot decrypt
     * the next message of an established conversation.
     */
    exportSessions(): Record<string, SerializedSignalSession> {
        const out: Record<string, SerializedSignalSession> = {}
        for (const [address, session] of this.sessions) {
            out[address] = serializeSignalSession(session)
        }
        return out
    }

    /**
     * Restores the sessions from an export.
     *
     * The existing sessions are replaced, so importing fully restores the
     * state of the device.
     *
     * @param sessions The serialised sessions, keyed by address.
     */
    importSessions(sessions: Record<string, SerializedSignalSession> | undefined): void {
        this.sessions.clear()
        if (!sessions) return
        for (const [address, session] of Object.entries(sessions)) {
            this.sessions.set(address, deserializeSignalSession(session))
        }
    }

    /** The address key used to index sessions. */
    private static addressKey(address: string): string {
        return signalAddressKey(parseSignalAddressFromJid(address))
    }

    /**
     * Ensures a session exists for a peer, creating one from a pre-key bundle
     * when necessary.
     *
     * @param peerAddress The peer's device address.
     * @param bundle The peer's pre-key bundle.
     */
    ensureSession(peerAddress: string, bundle: RemoteKeyBundle): SignalSession {
        const key = SignalSessionManager.addressKey(peerAddress)
        const existing = this.sessions.get(key)
        if (existing) return existing

        const registration = this.keyStore.getRegistrationInfo()
        if (!registration) {
            throw new Error('signal: device is not registered')
        }
        const local: SignalIdentityLocal = {
            regId: registration.registrationId,
            pubKey: registration.identityKeyPair.pubKey,
            privKey: registration.identityKeyPair.privKey,
        }
        const baseKey = generateSerializedKeyPair()
        const session = initiateSessionOutgoing(
            local,
            {
                regId: bundle.regId,
                identity: bundle.identity,
                signedKey: bundle.signedKey,
                oneTimeKey: bundle.oneTimeKey ?? null,
            },
            baseKey,
        )
        this.storeSession(key, session)
        this.keyStore.setRemoteIdentity(key, bundle.identity)
        return session
    }

    /**
     * Encrypts a payload for a peer device.
     *
     * @param peerAddress The peer's device address.
     * @param plaintext The payload.
     */
    encryptForDevice(peerAddress: string, plaintext: Uint8Array): EncryptedForPeer {
        const key = SignalSessionManager.addressKey(peerAddress)
        const session = this.sessions.get(key)
        if (!session) {
            throw new Error(`signal: no session for ${peerAddress}`)
        }
        const result = encryptSignalMessage(session, plaintext)
        this.storeSession(key, result.session)
        return { ciphertext: result.result.ciphertext, encType: result.result.type }
    }

    /**
     * Encrypts a payload for a group chat.
     *
     * @param groupId The group's JID.
     * @param plaintext The payload.
     */
    encryptForGroup(groupId: string, plaintext: Uint8Array): EncryptedForPeer {
        const result = this.senderKeyManager.prepareGroupEncryption(groupId, plaintext)
        return {
            ciphertext: result.ciphertext,
            encType: 'skmsg',
            distributionMessage: result.distributionMessage,
        }
    }

    /**
     * Decrypts an inbound Signal payload.
     *
     * Handles both `msg` and `pkmsg` envelopes, creating the session on the
     * fly when a pre-key message arrives.
     *
     * The envelope type must be supplied by the caller: WhatsApp signals it
     * in the `<enc type="…">` stanza attribute, and it cannot be recovered
     * from the payload itself — both envelopes start with the same version
     * byte and a protobuf body whose field numbers overlap.
     *
     * @param senderAddress The sender's device address.
     * @param payload The raw ciphertext.
     * @param encType The `<enc type>` value: `msg` or `pkmsg`.
     */
    decryptFromDevice(
        senderAddress: string,
        payload: Uint8Array,
        encType: 'msg' | 'pkmsg' = 'msg',
    ): DecryptedFromPeer {
        const key = SignalSessionManager.addressKey(senderAddress)

        if (encType === 'pkmsg') {
            const preKey = deserializePreKeyMessage(payload)
            const registration = this.keyStore.getRegistrationInfo()
            if (!registration) {
                throw new Error('signal: device is not registered')
            }
            const signedPreKey = this.keyStore.getSignedPreKey(preKey.localSignedPreKeyId)
            if (!signedPreKey) {
                throw new Error(
                    `signal: signed pre-key ${preKey.localSignedPreKeyId} is not available`,
                )
            }
            const oneTime =
                preKey.localOneTimeKeyId !== null
                    ? this.keyStore.consumePreKey(preKey.localOneTimeKeyId)
                    : undefined
            if (oneTime) this.options.onPreKeyConsumed?.(oneTime.keyId)
            const session = initiateSessionIncoming(
                {
                    regId: registration.registrationId,
                    pubKey: registration.identityKeyPair.pubKey,
                    privKey: registration.identityKeyPair.privKey,
                },
                {
                    regId: preKey.remote.regId,
                    pubKey: preKey.remote.pubKey,
                    privKey: new Uint8Array(0),
                },
                preKey.sessionBaseKey,
                {
                    oneTime: oneTime
                        ? { pubKey: oneTime.keyPair.pubKey, privKey: oneTime.keyPair.privKey }
                        : null,
                    signed: {
                        pubKey: signedPreKey.keyPair.pubKey,
                        privKey: signedPreKey.keyPair.privKey,
                    },
                    ratchet: {
                        pubKey: signedPreKey.keyPair.pubKey,
                        privKey: signedPreKey.keyPair.privKey,
                    },
                },
            )
            const result = decryptSignalMessage(session, preKey)
            this.storeSession(key, result.session)
            this.keyStore.setRemoteIdentity(key, preKey.remote.pubKey)
            return {
                plaintext: result.plaintext,
                sender: senderAddress,
                registrationId: preKey.remote.regId,
            }
        }

        const session = this.sessions.get(key)
        if (!session) {
            throw new Error(`signal: no session for ${senderAddress}`)
        }
        const parsed = deserializeSignalMessage(payload)
        const result = decryptSignalMessage(session, parsed)
        this.storeSession(key, result.session)
        return {
            plaintext: result.plaintext,
            sender: senderAddress,
            registrationId: session.remote.regId,
        }
    }

    /**
     * Decrypts an inbound group payload.
     *
     * @param groupId The group's JID.
     * @param sender The sender's device address.
     * @param payload The raw ciphertext.
     */
    decryptFromGroup(
        groupId: string,
        sender: string,
        payload: Uint8Array,
    ): DecryptedFromPeer {
        const plaintext = this.senderKeyManager.decryptGroupMessageForParticipant(
            groupId,
            sender,
            payload,
        )
        return { plaintext, sender, registrationId: 0 }
    }

    /**
     * Processes an inbound sender-key distribution message.
     *
     * @param groupId The group's JID.
     * @param sender The sender's device address.
     * @param payload The distribution message bytes.
     */
    processSenderKeyDistribution(
        groupId: string,
        sender: string,
        payload: Uint8Array,
    ): void {
        this.senderKeyManager.processSenderKeyDistribution(groupId, sender, payload)
    }
}

/** The local identity used when establishing a session. */
interface SignalIdentityLocal {
    regId: number
    pubKey: Uint8Array
    privKey: Uint8Array
}

/** Re-exported helpers. */
export { ecdh, equalBytes, concat, generateSerializedKeyPair, decode }
export type { SignalSession, SerializedKeyPair, GroupEncryptionResult }
