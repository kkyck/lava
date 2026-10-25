/**
 * The WhatsApp client.
 *
 * {@link WaClient} owns everything: the credentials, the Signal key material,
 * the transport and the node router. It exposes small, focused sub-APIs
 * (`client.message`, `client.group`, `client.call`, …) and emits events for
 * everything that happens asynchronously.
 *
 * ```ts
 * const client = new WaClient({ transport: 'mobile' })
 * client.on('message', (m) => console.log(m.text))
 * await client.connect()
 * await client.message.send('6281234567890@s.whatsapp.net', 'Hello')
 * ```
 */

import { EventEmitter } from 'node:events'

import {
    FileCredentialStore,
    MemoryCredentialStore,
    fromBase64,
    toBase64,
    type CredentialSnapshot,
    type CredentialStore,
} from './auth/credentials.js'
import { completeCompanionFinish, createCompanionHello } from './auth/pairing.js'
import { generateX25519KeyPair, toSerializedPublicKey } from './crypto/primitives.js'
import { createSilentLogger, type WaLogger } from './logger.js'
import {
    collectInboundEncryptions,
    decodeMessageBody,
    extractSenderKeyDistribution,
    prepareOutboundPlaintext,
    resolveInboundMessageKey,
    summarizeMessageBody,
    stripInboundPadding,
    type InboundMessageKey,
} from './message/codec.js'
import {
    buildTextContent,
    buildReactionContent,
    buildRevokeContent,
    buildLocationContent,
    buildContactContent,
    buildPollContent,
    resolveOutboundMessageAttrs,
    type MessageContent,
    type MessageKey,
} from './protocol/message.js'
import {
    computePhashV2,
} from './protocol/phash.js'
import {
    HOST_DOMAIN,
    buildDeviceJid,
    getLoginIdentity,
    isGroupJid,
    parsePhoneJid,
    splitJid,
    toUserJid,
} from './protocol/jid.js'
import {
    WA_DEFAULTS,
    WA_IQ_TYPES,
    WA_MESSAGE_TAGS,
    WA_NODE_TAGS,
    WA_NOTIFICATION_TYPES,
    WA_XMLNS,
} from './protocol/constants.js'
import {
    buildDeviceListUsyncIq,
    DeviceListStore,
    parseDeviceListResponse,
    type DeviceEntry,
} from './signal/device-list.js'
import {
    buildMissingPreKeysFetchIq,
    buildPreKeyUploadIq,
    buildSignedPreKeyRotateIq,
    parseMissingPreKeysResponse,
    SIGNAL_UPLOAD_PREKEYS_COUNT,
} from './signal/api.js'
import {
    buildDigestIq,
    parseDigestResponse,
    validateKeyBundleDigest,
    type DigestValidation,
    type SignalDigest,
} from './signal/digest.js'
import {
    SignalKeyStore,
    generatePreKeyPair,
    generateRegistrationInfo,
    generateSignedPreKey,
    MAX_RETAINED_PRE_KEYS,
} from './signal/keys.js'
import { SignalSessionManager } from './signal/manager.js'
import {
    MediaConnectionCache,
    downloadMedia,
    uploadMedia,
    type MediaHttpHandler,
    type MediaTransferOptions,
    type WaMediaUpload,
} from './media/transfer.js'
import {
    buildMediaContent,
    resolveMediaPayload,
    type MediaPayload,
    type WaMediaType,
} from './protocol/media.js'
import type { BinaryNode } from './transport/binary/types.js'
import {
    DEFAULT_ANDROID_PROFILE,
    DEFAULT_WEB_VERSION,
    buildDeviceProps,
    buildLoginPayload,
    buildMobileLoginPayload,
    buildMobileRegistrationPayload,
    buildRegistrationPayload,
    type DeviceProfile,
} from './transport/client-payload.js'
import { DeviceProps_PlatformType } from './proto/enums.js'
import { MobileTransport } from './transport/mobile.js'
import { WebTransport } from './transport/web.js'
import type { NoiseSessionConfig } from './transport/noise-session.js'
import type { TransportHandlers } from './transport/types.js'
import {
    buildAckNode,
    buildNotificationAckNode,
    buildReceiptNode,
} from './transport/node/builders/global.js'
import {
    buildCompanionFinishRequestNode,
    buildCompanionHelloRequestNode,
    buildGetCountryCodeRequestNode,
    WA_COMPANION_PLATFORM_ID,
    WA_SIGNALING,
} from './transport/node/builders/pairing.js'
import {
    buildDirectMessageFanoutNode,
    buildGroupSenderKeyMessageNode,
    type EncryptedParticipant,
} from './transport/node/builders/message.js'
import {
    buildCallAcceptNode,
    buildCallOfferNode,
    buildCallRejectNode,
    buildCallTerminateNode,
    buildChatStateNode,
    buildCreateGroupIq,
    buildGetPrivacyDisallowedListIq,
    buildGetPrivacySettingsIq,
    buildGroupParticipantChangeIq,
    buildLeaveGroupIq,
    buildPresenceNode,
    buildSetGroupSubjectIq,
    buildSetPrivacyCategoryIq,
    buildSetPrivacyDisallowedListIq,
    buildSetPushNameIq,
    buildSetStatusIq,
    buildUsyncIq,
} from './transport/node/builders.js'
import {
    decodeNodeContentBytes,
    findNodeChild,
    getNodeChildrenByTag,
    getNodeText,
} from './transport/node/helpers.js'
import { assertIqResult, parseIqError } from './transport/node/query.js'
import { generateMessageId, generateRandomId } from './util/message-id.js'
import { buildWhatsAppQrPayload } from './qr/whatsapp.js'

/** The transport a client runs on. */
export type WaTransportMode = 'mobile' | 'web'

/** The connection states a client moves through. */
export type WaConnectionState =
    | 'disconnected'
    | 'connecting'
    | 'pairing'
    | 'connected'
    | 'closing'

/**
 * The transport abstraction the client talks to.
 *
 * The two built-in transports — the native mobile (WAP) one and the
 * WhatsApp Web one — both implement it, and a custom transport (a proxy, a
 * tunnelled socket, a test double) can be plugged in through
 * {@link WaClientOptions.transportFactory}.
 */
export interface WaTransport {
    /** Starts the transport and performs the Noise handshake. */
    start(): Promise<void>
    /** Sends a stanza. */
    send(node: BinaryNode): void
    /** Sends an IQ and waits for the matching response. */
    query(node: BinaryNode, timeoutMs?: number): Promise<BinaryNode>
    /** Returns the server's static key, once the handshake completed. */
    getServerStaticKey(): Uint8Array | null
    /** Closes the transport. */
    close(): void
}

/**
 * Builds the transport the client should use.
 *
 * @param context The Noise configuration and the stanza handlers.
 */
export type WaTransportFactory = (context: {
    /** The Noise configuration, including the client payload. */
    noise: Omit<NoiseSessionConfig, 'sendWire'>
    /** The stanza handlers the transport has to call. */
    handlers: TransportHandlers
}) => WaTransport

/** Configuration for {@link WaClient}. */
export interface WaClientOptions {
    /** The transport to use; `mobile` (the native WAP API) by default. */
    transport?: WaTransportMode
    /** Where the session is persisted; an in-memory store by default. */
    credentials?: CredentialStore
    /** The device profile reported to the server. */
    deviceProfile?: DeviceProfile
    /** The push name shown to other users. */
    pushName?: string
    /** The logger; a silent logger by default. */
    logger?: WaLogger
    /** The mobile transport host. */
    mobileHost?: string
    /** The mobile transport port. */
    mobilePort?: number
    /** The WhatsApp Web socket URL. */
    webSocketUrl?: string
    /** Whether the client should reconnect automatically. */
    autoReconnect?: boolean
    /** The delay between reconnect attempts, in milliseconds. */
    reconnectDelayMs?: number
    /**
     * How many one-time pre-keys are generated and uploaded per batch.
     *
     * The official clients upload a batch of 812, which is also the default.
     */
    preKeyCount?: number
    /**
     * The HTTP handler used for media transfers.
     *
     * The default one talks to the real WhatsApp CDN; override it to route
     * the traffic through a proxy or to serve the media from a test double.
     */
    mediaHttp?: MediaHttpHandler
    /** The timeout of a media transfer, in milliseconds. */
    mediaTimeoutMs?: number
    /** Builds the transport; overrides the built-in ones when set. */
    transportFactory?: WaTransportFactory
}

/** The options of a media message. */
export interface WaMediaMessageOptions {
    /** The media kind. */
    type: WaMediaType
    /** The MIME type of the file. */
    mimetype: string
    /** The caption that goes with the file. */
    caption?: string
    /** The JPEG thumbnail. */
    jpegThumbnail?: Uint8Array
    /** The PNG thumbnail (stickers). */
    pngThumbnail?: Uint8Array
    /** The width of the file, in pixels. */
    width?: number
    /** The height of the file, in pixels. */
    height?: number
    /** The duration of the file, in seconds. */
    seconds?: number
    /** The file name (documents). */
    fileName?: string
    /** The document title (documents). */
    title?: string
    /** The number of pages (documents). */
    pageCount?: number
    /** Whether the audio is a push-to-talk voice note. */
    ptt?: boolean
    /** Whether the video plays as a GIF. */
    gifPlayback?: boolean
    /** Whether the sticker is animated. */
    isAnimated?: boolean
    /** The length of the sticker's first frame. */
    firstFrameLength?: number
}

/** An inbound message, as handed to the `message` event. */
export interface WaInboundMessage {
    /** The chat the message belongs to. */
    jid: string
    /** The message id. */
    id: string
    /** Whether the message was sent by this account. */
    fromMe: boolean
    /** The sender's push name. */
    pushName?: string
    /** The sender's participant JID, for group messages. */
    participant?: string
    /** The message body. */
    message: MessageContent
    /** The content type (`conversation`, `extendedTextMessage`, …). */
    type?: string
    /** The plain text, when the message carries one. */
    text?: string
    /** The id of the quoted message, when the message is a reply. */
    quotedId?: string
    /** The reaction emoji, when the message is a reaction. */
    reaction?: string
    /** Whether the message revokes another one. */
    revoked?: boolean
    /** The Unix timestamp of the message. */
    timestamp?: number
}

/** An acknowledgement of a message that was sent. */
export interface WaMessageAck {
    /** The message id. */
    id: string
    /** The chat the message was sent to. */
    jid: string
    /** The error code, when the server rejected the message. */
    error?: string
    /** The stanza type. */
    type?: string
}

/** A delivery or read receipt. */
export interface WaReceipt {
    /** The message id. */
    id: string
    /** The chat the receipt came from. */
    jid: string
    /** The receipt type (`delivery`, `read`, `read-self`, …). */
    type: string
    /** The participant, for group receipts. */
    participant?: string
}

/** An inbound or outbound call. */
export interface WaCallEvent {
    /** The call id. */
    id: string
    /** The peer. */
    jid: string
    /** Whether the call is a video call. */
    video: boolean
    /** The call direction. */
    direction: 'incoming' | 'outgoing'
    /** The call state. */
    status: 'offer' | 'accept' | 'reject' | 'terminate'
}

/** The credentials of the current session. */
export interface WaSessionInfo {
    /** The account's own JID, once the device is paired. */
    meJid?: string
    /** The account's LID, once it is known. */
    meLid?: string
    /** The push name shown to other users. */
    pushName?: string
    /** The transport the session was created for. */
    transport: WaTransportMode
    /** Whether the device is paired. */
    paired: boolean
}

/**
 * The WhatsApp client.
 *
 * The client is an {@link EventEmitter}; the events it emits are documented
 * on {@link WaClient}.
 */
export class WaClient extends EventEmitter {
    /** Emitted with `{ qr, ttlMs }` when a QR code has to be scanned. */
    static readonly AUTH_QR = 'auth_qr'
    /** Emitted with `{ code }` when a pairing code is available. */
    static readonly AUTH_PAIRING_CODE = 'auth_pairing_code'
    /** Emitted with `{ meJid, meLid }` once the device is paired. */
    static readonly AUTH_PAIRED = 'auth_paired'
    /** Emitted with `{ state }` whenever the connection state changes. */
    static readonly CONNECTION = 'connection'
    /** Emitted with a {@link WaInboundMessage} for every inbound message. */
    static readonly MESSAGE = 'message'
    /** Emitted with a {@link WaMessageAck} for every acknowledgement. */
    static readonly MESSAGE_ACK = 'message_ack'
    /** Emitted with a {@link WaReceipt} for every receipt. */
    static readonly RECEIPT = 'receipt'
    /** Emitted with a {@link WaCallEvent} for every call transition. */
    static readonly CALL = 'call'
    /** Emitted with an `Error` for every recoverable failure. */
    static readonly ERROR = 'error'

    private readonly options: WaClientOptions
    private readonly logger: WaLogger
    private readonly store: CredentialStore
    private readonly keyStore: SignalKeyStore
    private readonly signal: SignalSessionManager
    private readonly deviceList = new DeviceListStore()
    private readonly mediaConn = new MediaConnectionCache()

    private credentials: CredentialSnapshot | null = null
    private transport: WaTransport | null = null
    private state: WaConnectionState = 'disconnected'
    private reconnectTimer: NodeJS.Timeout | null = null
    private stopping = false

    /** The tail of the credential write queue. */
    private credentialWrite: Promise<void> = Promise.resolve()

    /** The active pairing session, if any. */
    private pairing: {
        pairingCode: string
        phoneJid: string
        ref: string
        createdAtSeconds: number
        companionEphemeralPrivateKey: Uint8Array
        companionEphemeralPublicKey: Uint8Array
        finished: boolean
    } | null = null

    /** The QR references handed out by the server. */
    private qrRefs: string[] = []
    private qrRefIndex = 0

    /**
     * @param options The client options.
     */
    constructor(options: WaClientOptions = {}) {
        super()
        this.options = options
        this.logger = options.logger ?? createSilentLogger()
        this.store = options.credentials ?? new MemoryCredentialStore()
        this.keyStore = new SignalKeyStore()
        this.signal = new SignalSessionManager({
            keyStore: this.keyStore,
            // A one-time pre-key may only be used once, so it is dropped from
            // the persistent snapshot as soon as it is consumed.
            onPreKeyConsumed: (id) => {
                this.forgetPreKey(id)
            },
        })
    }

    /**
     * Drops a consumed one-time pre-key from the persistent snapshot.
     *
     * @param id The id of the consumed pre-key.
     */
    private forgetPreKey(id: number): void {
        const snapshot = this.credentials
        if (!snapshot) return
        if (!snapshot.preKeys.some((record) => record.id === id)) return
        void this.persistPreKeyPool().catch((error: unknown) => {
            this.emit(
                WaClient.ERROR,
                error instanceof Error ? error : new Error(String(error)),
            )
        })
    }

    /** The current connection state. */
    getState(): WaConnectionState {
        return this.state
    }

    /** The account's own JID, once known. */
    getMeJid(): string | undefined {
        return this.credentials?.meJid
    }

    /** The Signal session manager (advanced use). */
    get signalManager(): SignalSessionManager {
        return this.signal
    }

    /**
     * Returns a snapshot of the current session.
     */
    getSession(): WaSessionInfo {
        return {
            ...(this.credentials?.meJid ? { meJid: this.credentials.meJid } : {}),
            ...(this.credentials?.meLid ? { meLid: this.credentials.meLid } : {}),
            ...(this.credentials?.pushName ? { pushName: this.credentials.pushName } : {}),
            transport: this.options.transport ?? 'mobile',
            paired: Boolean(this.credentials?.meJid),
        }
    }

    // ── Lifecycle ────────────────────────────────────────────────────────────

    /**
     * Connects to WhatsApp.
     *
     * The call resolves as soon as the Noise handshake succeeded and the
     * client payload was accepted; pairing continues in the background and
     * completes through the {@link WaClient.AUTH_PAIRED} event.
     */
    async connect(): Promise<void> {
        if (this.state === 'connected' || this.state === 'connecting') return
        this.stopping = false
        this.setState('connecting')

        const credentials = await this.ensureCredentials()
        const payload = this.buildNoisePayload(credentials)
        const transport = this.createTransport(credentials, payload)
        this.transport = transport

        try {
            await transport.start()
        } catch (error) {
            this.transport = null
            this.setState('disconnected')
            throw error
        }

        const serverStaticKey = transport.getServerStaticKey()
        if (serverStaticKey) {
            await this.updateCredentials({
                serverStaticKey: toBase64(serverStaticKey),
            })
        }

        this.setState(credentials.meJid ? 'connected' : 'pairing')
        await this.afterConnect()
    }

    /**
     * Closes the connection.
     */
    async disconnect(): Promise<void> {
        this.stopping = true
        if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer)
            this.reconnectTimer = null
        }
        this.setState('closing')
        this.transport?.close()
        this.transport = null
        this.setState('disconnected')
    }

    /** Emits the connection state and updates the internal state. */
    private setState(state: WaConnectionState): void {
        if (this.state === state) return
        this.state = state
        this.emit(WaClient.CONNECTION, { state })
    }

    /**
     * Runs the post-connect chores: pre-key upload and the initial device
     * list sync.
     */
    private async afterConnect(): Promise<void> {
        if (!this.credentials?.meJid) {
            // A companion device has to pair before it can do anything else.
            return
        }
        try {
            await this.uploadPreKeys()
        } catch (error) {
            this.emit(WaClient.ERROR, error)
        }
    }

    /**
     * Creates the transport for the configured mode.
     *
     * @param credentials The credentials.
     * @param payload The Noise handshake payload.
     */
    private createTransport(
        credentials: CredentialSnapshot,
        payload: Uint8Array,
    ): WaTransport {
        const noise = {
            clientStaticKeyPair: {
                publicKey: fromBase64(credentials.noiseKeyPair.pub),
                privateKey: fromBase64(credentials.noiseKeyPair.priv),
            },
            payload,
            ...(credentials.serverStaticKey
                ? { serverStaticKey: fromBase64(credentials.serverStaticKey) }
                : {}),
        }
        const handlers = {
            onNode: (node: BinaryNode) => {
                this.handleNode(node)
            },
            onClose: (error?: Error) => {
                this.handleClose(error)
            },
            onError: (error: Error) => {
                this.emit(WaClient.ERROR, error)
            },
        }

        if (this.options.transportFactory) {
            return this.options.transportFactory({ noise, handlers })
        }

        if ((this.options.transport ?? 'mobile') === 'web') {
            return new WebTransport({
                noise,
                handlers,
                ...(this.options.webSocketUrl ? { url: this.options.webSocketUrl } : {}),
            })
        }
        return new MobileTransport({
            noise,
            handlers,
            ...(this.options.mobileHost ? { host: this.options.mobileHost } : {}),
            ...(this.options.mobilePort ? { port: this.options.mobilePort } : {}),
        })
    }

    /**
     * Builds the Noise handshake payload.
     *
     * A paired device sends a *login* payload; an unpaired one sends a
     * *registration* payload that carries the Signal identity.
     *
     * @param credentials The credentials.
     */
    private buildNoisePayload(credentials: CredentialSnapshot): Uint8Array {
        const profile = this.options.deviceProfile ?? DEFAULT_ANDROID_PROFILE
        const mode = this.options.transport ?? 'mobile'
        const registration = this.keyStore.getRegistrationInfo()
        const signedPreKey = this.keyStore.getSignedPreKey()

        if (credentials.meJid) {
            const identity = getLoginIdentity(credentials.meJid)
            if (mode === 'web') {
                return buildLoginPayload({
                    username: identity.username,
                    device: identity.device,
                    ...(credentials.pushName ? { pushName: credentials.pushName } : {}),
                    versionBase: profile.appVersion ?? DEFAULT_WEB_VERSION,
                    loginCounter: credentials.loginCounter ?? 0,
                })
            }
            return buildMobileLoginPayload({
                username: identity.username,
                device: identity.device,
                deviceProfile: profile,
                ...(credentials.pushName ? { pushName: credentials.pushName } : {}),
            })
        }

        if (!registration) throw new Error('client: the device has no Signal identity')
        if (!signedPreKey) throw new Error('client: the device has no signed pre-key')

        if (mode === 'web') {
            return buildRegistrationPayload({
                device: 0,
                registrationId: registration.registrationId,
                identityKey: registration.identityKeyPair.pubKey,
                signedPreKeyId: signedPreKey.keyId,
                signedPreKey: signedPreKey.keyPair.pubKey,
                signedPreKeySignature: signedPreKey.signature,
                ...(credentials.pushName ? { pushName: credentials.pushName } : {}),
                versionBase: profile.appVersion ?? DEFAULT_WEB_VERSION,
                deviceProps: buildDeviceProps(profile, DeviceProps_PlatformType.DESKTOP),
            })
        }
        return buildMobileRegistrationPayload({
            device: 0,
            deviceProfile: profile,
            registrationId: registration.registrationId,
            identityKey: registration.identityKeyPair.pubKey,
            signedPreKeyId: signedPreKey.keyId,
            signedPreKey: signedPreKey.keyPair.pubKey,
            signedPreKeySignature: signedPreKey.signature,
            deviceProps: buildDeviceProps(profile),
            ...(credentials.pushName ? { pushName: credentials.pushName } : {}),
        })
    }

    /**
     * Loads the credentials, creating them when they are missing.
     */
    private async ensureCredentials(): Promise<CredentialSnapshot> {
        const existing = await this.store.load()
        if (existing) {
            this.credentials = existing
            this.restoreSignalKeys(existing)
            return existing
        }

        const noiseKeyPair = generateX25519KeyPair()
        const registration = generateRegistrationInfo()
        this.keyStore.setRegistrationInfo(registration)

        // The pre-key ids are handed out sequentially, like the official
        // clients do, so they are unique and always fit the three byte
        // field the protocol uses for them.
        //
        // Signed pre-keys live in their own id namespace — the official
        // clients track them separately (`signal_last_spk_id` versus
        // `signal_next_pk_id`) — so a signed pre-key may reuse the number
        // of a one-time pre-key without any ambiguity.
        const signedPreKey = generateSignedPreKey(
            this.keyStore.allocateSignedPreKeyId(),
            registration.identityKeyPair.privKey,
        )
        this.keyStore.setSignedPreKey(signedPreKey)

        // The pool is filled with a full batch of pre-keys, exactly like the
        // official clients do before the first upload.
        const preKeyCount = this.options.preKeyCount ?? SIGNAL_UPLOAD_PREKEYS_COUNT
        this.keyStore.getOrGenPreKeys(preKeyCount, generatePreKeyPair)

        const snapshot: CredentialSnapshot = {
            version: 1,
            noiseKeyPair: { pub: toBase64(noiseKeyPair.publicKey), priv: toBase64(noiseKeyPair.privateKey) },
            identityKeyPair: {
                pub: toBase64(registration.identityKeyPair.pubKey),
                priv: toBase64(registration.identityKeyPair.privKey),
            },
            registrationId: registration.registrationId,
            signedPreKey: {
                id: signedPreKey.keyId,
                keyPair: {
                    pub: toBase64(signedPreKey.keyPair.pubKey),
                    priv: toBase64(signedPreKey.keyPair.privKey),
                },
                signature: toBase64(signedPreKey.signature),
            },
            preKeys: this.serializePreKeys(),
            firstUnuploadedPreKeyId: this.keyStore.getFirstUnuploadedPreKeyId(),
            nextPreKeyId: this.keyStore.getNextPreKeyId(),
            nextSignedPreKeyId: this.keyStore.getNextSignedPreKeyId(),
            serverHasPreKeys: this.keyStore.getServerHasPreKeys(),
            transport: this.options.transport ?? 'mobile',
        }
        await this.store.save(snapshot)
        this.credentials = snapshot
        return snapshot
    }

    /**
     * Restores the Signal key material from a credential snapshot.
     *
     * @param snapshot The snapshot.
     */
    private restoreSignalKeys(snapshot: CredentialSnapshot): void {
        if (!this.keyStore.getRegistrationInfo()) {
            this.keyStore.setRegistrationInfo({
                registrationId: snapshot.registrationId,
                identityKeyPair: {
                    pubKey: fromBase64(snapshot.identityKeyPair.pub),
                    privKey: fromBase64(snapshot.identityKeyPair.priv),
                },
            })
        }
        if (!this.keyStore.getSignedPreKey()) {
            this.keyStore.setSignedPreKey({
                keyId: snapshot.signedPreKey.id,
                keyPair: {
                    pubKey: fromBase64(snapshot.signedPreKey.keyPair.pub),
                    privKey: fromBase64(snapshot.signedPreKey.keyPair.priv),
                },
                signature: fromBase64(snapshot.signedPreKey.signature),
            })
        }
        for (const record of snapshot.preKeys) {
            if (this.keyStore.getPreKey(record.id)) continue
            this.keyStore.addPreKey({
                keyId: record.id,
                keyPair: {
                    pubKey: fromBase64(record.keyPair.pub),
                    privKey: fromBase64(record.keyPair.priv),
                },
            })
        }
        // The pre-key id counter must never go back, or an id that was
        // already handed out would be used twice.
        if (snapshot.nextPreKeyId !== undefined) {
            this.keyStore.setNextPreKeyId(snapshot.nextPreKeyId)
        }
        // Signed pre-keys have their own counter, so it is restored
        // separately.
        if (snapshot.nextSignedPreKeyId !== undefined) {
            this.keyStore.setNextSignedPreKeyId(snapshot.nextSignedPreKeyId)
        }
        // The upload cursor tells the client which pre-keys the server has
        // not seen yet.
        if (snapshot.firstUnuploadedPreKeyId !== undefined) {
            this.keyStore.setFirstUnuploadedPreKeyId(snapshot.firstUnuploadedPreKeyId)
        }
        // While the server holds a batch of our pre-keys there is no need to
        // upload another one.
        this.keyStore.setServerHasPreKeys(snapshot.serverHasPreKeys === true)
    }

    /**
     * Serialises the pre-key pool of the key store.
     *
     * @returns The pre-keys, oldest id first.
     */
    private serializePreKeys(): { id: number; keyPair: { pub: string; priv: string } }[] {
        return this.keyStore.listPreKeys().map((record) => ({
            id: record.keyId,
            keyPair: {
                pub: toBase64(record.keyPair.pubKey),
                priv: toBase64(record.keyPair.privKey),
            },
        }))
    }

    /**
     * Merges changes into the credential snapshot and persists it.
     *
     * The writes are queued: two overlapping writes would otherwise race and
     * the slower one could overwrite the newer snapshot. That would lose a
     * pre-key that the server already knows about, and the device would no
     * longer be able to decrypt the session that uses it.
     *
     * @param changes The fields to update. A function is evaluated right
     *                before the write, so it always sees the current state.
     */
    private async updateCredentials(
        changes:
            | Partial<CredentialSnapshot>
            | (() => Partial<CredentialSnapshot>),
    ): Promise<CredentialSnapshot> {
        const run = async (): Promise<CredentialSnapshot> => {
            const current = this.credentials ?? (await this.ensureCredentials())
            const patch = typeof changes === 'function' ? changes() : changes
            const next: CredentialSnapshot = { ...current, ...patch }
            this.credentials = next
            await this.store.save(next)
            return next
        }

        const pending = this.credentialWrite.then(run, run)
        this.credentialWrite = pending.then(
            () => undefined,
            () => undefined,
        )
        return pending
    }

    /**
     * Persists the current pre-key pool together with its counters.
     *
     * The pool is read right before the write, so a pre-key that is consumed
     * while another write is in flight is never resurrected.
     *
     * @param changes Extra fields to update.
     */
    private async persistPreKeyPool(
        changes: Partial<CredentialSnapshot> = {},
    ): Promise<CredentialSnapshot> {
        return this.updateCredentials(() => ({
            ...changes,
            preKeys: this.serializePreKeys(),
            firstUnuploadedPreKeyId: this.keyStore.getFirstUnuploadedPreKeyId(),
            nextPreKeyId: this.keyStore.getNextPreKeyId(),
        }))
    }

    // ── Node routing ─────────────────────────────────────────────────────────

    /**
     * Routes an inbound node.
     *
     * @param node The node.
     */
    private handleNode(node: BinaryNode): void {
        switch (node.tag) {
            case WA_NODE_TAGS.SUCCESS:
                this.handleSuccess(node)
                return
            case WA_MESSAGE_TAGS.MESSAGE:
                void this.handleMessage(node)
                return
            case WA_MESSAGE_TAGS.RECEIPT:
                this.handleReceipt(node)
                return
            case WA_NODE_TAGS.ACK:
                this.handleAck(node)
                return
            case WA_NODE_TAGS.IQ:
                void this.handleIq(node)
                return
            case WA_NODE_TAGS.NOTIFICATION:
                void this.handleNotification(node)
                return
            default:
                return
        }
    }

    /**
     * Handles the `<success>` stanza the server sends after a successful
     * handshake.
     *
     * @param node The stanza.
     */
    private handleSuccess(node: BinaryNode): void {
        const props = findNodeChild(node, WA_NODE_TAGS.PROPS)
        const meJid = props?.attrs.jid ?? node.attrs.jid
        const meLid = props?.attrs.lid
        const pushName = props?.attrs.pushname ?? props?.attrs.name

        void this.updateCredentials({
            ...(meJid ? { meJid } : {}),
            ...(meLid ? { meLid } : {}),
            ...(pushName ? { pushName } : {}),
            lastSuccessTs: Date.now(),
            loginCounter: (this.credentials?.loginCounter ?? 0) + 1,
        }).then(() => {
            this.setState('connected')
            if (meJid) {
                this.emit(WaClient.AUTH_PAIRED, { meJid, meLid })
            }
            void this.afterConnect()
        })
    }

    /**
     * Handles a `<notification>` stanza.
     *
     * @param node The stanza.
     */
    private async handleNotification(node: BinaryNode): Promise<void> {
        const linkCode = findNodeChild(node, WA_NODE_TAGS.LINK_CODE_COMPANION_REG)
        if (linkCode?.attrs.stage === WA_SIGNALING.LINK_CODE_STAGE_PRIMARY_HELLO) {
            await this.handlePrimaryHello(linkCode)
            return
        }
        if (linkCode?.attrs.stage === WA_SIGNALING.COMPANION_REG_REFRESH_NOTIFICATION) {
            // The server asks the companion to refresh its pairing code.
            return
        }

        // The Signal housekeeping notification. The server tells the client
        // that its pool of our pre-keys is running low with a `<count/>`
        // child; the client then uploads a fresh batch. A `<digest/>` child
        // means the server wants the key bundle validated.
        if (node.attrs.type === WA_NOTIFICATION_TYPES.ENCRYPT) {
            this.send(
                buildNotificationAckNode(
                    node.attrs.id,
                    node.attrs.from ?? HOST_DOMAIN,
                    node.attrs.type,
                    node.attrs.participant,
                ),
            )
            if (findNodeChild(node, WA_NODE_TAGS.COUNT)) {
                await this.handlePreKeyLowNotification()
                return
            }
            if (findNodeChild(node, WA_NODE_TAGS.DIGEST)) {
                await this.handleDigestNotification()
            }
            return
        }

        this.send(
            buildNotificationAckNode(
                node.attrs.id,
                node.attrs.from ?? HOST_DOMAIN,
                node.attrs.type ?? WA_NODE_TAGS.NOTIFICATION,
                node.attrs.participant,
            ),
        )
    }

    /**
     * Reacts to the server running low on our pre-keys.
     *
     * The flag that tells the client that the server holds a batch of our
     * pre-keys is cleared and a fresh batch is uploaded right away.
     */
    private async handlePreKeyLowNotification(): Promise<void> {
        this.keyStore.setServerHasPreKeys(false)
        await this.persistPreKeyPool({ serverHasPreKeys: false })
        try {
            await this.uploadPreKeys()
        } catch (error) {
            this.emit(WaClient.ERROR, error)
        }
    }

    /**
     * Reacts to the server asking for a key-bundle validation.
     *
     * The digest the server holds is compared with the local state. When the
     * two do not match, the pre-keys drifted and a fresh batch is uploaded.
     */
    private async handleDigestNotification(): Promise<void> {
        try {
            await this.validateDigestAndRecoverPreKeys()
        } catch (error) {
            this.emit(WaClient.ERROR, error)
        }
    }

    /**
     * Validates the local key bundle against the digest the server holds.
     *
     * The server keeps a digest of the key bundle it holds for this device.
     * Comparing it with the local state detects a drift — a crash in the
     * middle of an upload, for example — which is repaired by uploading a
     * fresh batch of pre-keys.
     */
    async validateDigestAndRecoverPreKeys(): Promise<DigestValidation> {
        const registration = this.keyStore.getRegistrationInfo()
        const signedPreKey = this.keyStore.getSignedPreKey()
        if (!registration || !signedPreKey) {
            return { valid: false, reason: 'missing_local_state', preKeyCount: 0, shouldReupload: false }
        }

        let response: BinaryNode
        try {
            response = await this.query(buildDigestIq())
        } catch (error) {
            this.emit(WaClient.ERROR, error)
            return {
                valid: false,
                reason: 'missing_remote_digest',
                preKeyCount: 0,
                shouldReupload: true,
            }
        }

        // The server does not know this device (yet): the client has to
        // upload its pre-keys.
        if (response.attrs.type === WA_IQ_TYPES.ERROR) {
            await this.recoverPreKeys()
            return {
                valid: false,
                reason: 'missing_remote_digest',
                preKeyCount: 0,
                shouldReupload: true,
            }
        }
        if (response.attrs.type !== WA_IQ_TYPES.RESULT) {
            return {
                valid: false,
                reason: 'invalid_response',
                preKeyCount: 0,
                shouldReupload: false,
            }
        }

        let digest: SignalDigest
        try {
            digest = parseDigestResponse(response)
        } catch (error) {
            this.emit(WaClient.ERROR, error)
            return {
                valid: false,
                reason: 'invalid_response',
                preKeyCount: 0,
                shouldReupload: false,
            }
        }

        const validation = validateKeyBundleDigest(
            digest,
            registration,
            signedPreKey,
            (id) => this.keyStore.getPreKey(id),
        )
        if (validation.shouldReupload) {
            await this.recoverPreKeys()
        }
        return validation
    }

    /**
     * Uploads a fresh batch of pre-keys after a digest mismatch.
     */
    private async recoverPreKeys(): Promise<void> {
        this.keyStore.setServerHasPreKeys(false)
        await this.persistPreKeyPool({ serverHasPreKeys: false })
        await this.uploadPreKeys()
    }

    /**
     * Handles an inbound `<iq>` stanza.
     *
     * @param node The stanza.
     */
    private async handleIq(node: BinaryNode): Promise<void> {
        if (node.attrs.type !== WA_IQ_TYPES.SET) return

        const pairDevice = findNodeChild(node, WA_NODE_TAGS.PAIR_DEVICE)
        if (pairDevice) {
            this.handlePairDevice(pairDevice)
            return
        }
        const pairSuccess = findNodeChild(node, WA_NODE_TAGS.PAIR_SUCCESS)
        if (pairSuccess) {
            await this.handlePairSuccess(node, pairSuccess)
            return
        }
    }

    /**
     * Handles the `<pair-device>` stanza that carries the QR references.
     *
     * @param node The stanza.
     */
    private handlePairDevice(node: BinaryNode): void {
        const refs = getNodeChildrenByTag(node, WA_NODE_TAGS.REF)
            .map((ref) => getNodeText(ref))
            .filter((ref) => ref.length > 0)
        if (refs.length === 0) return
        this.qrRefs = refs
        this.qrRefIndex = 0
        this.emitNextQr()
    }

    /**
     * Emits the next QR payload.
     */
    private emitNextQr(): void {
        const ref = this.qrRefs[this.qrRefIndex]
        if (ref === undefined) return
        this.qrRefIndex += 1
        const credentials = this.credentials
        if (!credentials) return
        const remaining = this.qrRefs.length - this.qrRefIndex
        const ttlMs =
            remaining >= 5 ? WA_DEFAULTS.QR_INITIAL_TTL_MS : WA_DEFAULTS.QR_ROTATION_TTL_MS
        this.emit(WaClient.AUTH_QR, {
            qr: this.buildQrPayload(ref, credentials),
            ttlMs,
        })
    }

    /**
     * Builds the QR payload the phone scans.
     *
     * The payload is a comma-separated list:
     * `ref,noisePubKey,identityPubKey,advSecret,platform`.
     *
     * @param ref The pairing reference.
     * @param credentials The credentials.
     */
    private buildQrPayload(ref: string, credentials: CredentialSnapshot): string {
        return buildWhatsAppQrPayload({
            ref,
            noisePublicKey: fromBase64(credentials.noiseKeyPair.pub),
            identityPublicKey: fromBase64(credentials.identityKeyPair.pub),
            advSecret: credentials.advSecretKey
                ? fromBase64(credentials.advSecretKey)
                : new Uint8Array(32),
            devicePlatform: this.options.deviceProfile?.device ?? 'Desktop',
        })
    }

    /**
     * Handles the `primary_hello` notification: the phone scanned the QR
     * code (or the user typed the pairing code) and the server forwards the
     * phone's ephemeral key.
     *
     * @param linkCode The `<link_code_companion_reg>` node.
     */
    private async handlePrimaryHello(linkCode: BinaryNode): Promise<void> {
        const pairing = this.pairing
        if (!pairing) return

        const refNode = findNodeChild(linkCode, WA_NODE_TAGS.LINK_CODE_PAIRING_REF)
        const wrappedNode = findNodeChild(
            linkCode,
            WA_NODE_TAGS.LINK_CODE_PAIRING_WRAPPED_PRIMARY_EPHEMERAL_PUB,
        )
        const identityNode = findNodeChild(linkCode, WA_NODE_TAGS.PRIMARY_IDENTITY_PUB)
        if (!refNode || !wrappedNode || !identityNode) {
            throw new Error('pairing: primary_hello is missing fields')
        }
        const ref = getNodeText(refNode)
        if (ref !== pairing.ref) return

        const nowSeconds = Math.floor(Date.now() / 1000)
        if (nowSeconds - pairing.createdAtSeconds > WA_DEFAULTS.PAIRING_CODE_MAX_AGE_SECONDS) {
            throw new Error('pairing: the pairing code expired')
        }

        const credentials = this.credentials
        if (!credentials) throw new Error('pairing: no credentials')
        const registration = this.keyStore.getRegistrationInfo()
        if (!registration) throw new Error('pairing: no Signal identity')

        const finish = await completeCompanionFinish({
            pairingCode: pairing.pairingCode,
            companionEphemeralPrivateKey: pairing.companionEphemeralPrivateKey,
            identityKeyPair: registration.identityKeyPair,
            wrappedPrimaryEphemeralPub: decodeNodeContentBytes(
                wrappedNode.content,
                'primary_hello.wrapped_primary_ephemeral_pub',
            ),
            primaryIdentityPub: decodeNodeContentBytes(
                identityNode.content,
                'primary_hello.primary_identity_pub',
            ),
        })

        await this.updateCredentials({ advSecretKey: toBase64(finish.advSecret) })

        const result = await this.query(
            buildCompanionFinishRequestNode({
                phoneJid: pairing.phoneJid,
                wrappedKeyBundle: finish.wrappedKeyBundle,
                companionIdentityPublic: finish.companionIdentityPublic,
                ref,
            }),
        )
        assertIqResult(result, 'companion finish')
        pairing.finished = true
    }

    /**
     * Handles the `<pair-success>` stanza: the server confirms the pairing
     * and hands out the account identity.
     *
     * @param iqNode The IQ stanza.
     * @param pairSuccess The `<pair-success>` node.
     */
    private async handlePairSuccess(
        iqNode: BinaryNode,
        pairSuccess: BinaryNode,
    ): Promise<void> {
        const deviceNode = findNodeChild(pairSuccess, 'device')
        const platformNode = findNodeChild(pairSuccess, WA_NODE_TAGS.PLATFORM)
        if (!deviceNode || !platformNode) {
            throw new Error('pairing: pair-success is missing the device or platform node')
        }
        const meJid = deviceNode.attrs.jid
        const meLid = deviceNode.attrs.lid
        await this.updateCredentials({
            ...(meJid ? { meJid } : {}),
            ...(meLid ? { meLid } : {}),
            transport: this.options.transport ?? 'mobile',
            loginCounter: 0,
        })
        this.setState('connected')
        this.emit(WaClient.AUTH_PAIRED, { meJid, meLid })
        void this.afterConnect()
    }

    /**
     * Handles an inbound `<message>` stanza.
     *
     * The official clients deliver the encrypted payload as a **top-level**
     * `<enc>` child of the stanza; the sender is the `participant`
     * attribute for group chats and the `from` attribute for direct chats.
     *
     * @param node The stanza.
     */
    private async handleMessage(node: BinaryNode): Promise<void> {
        const meJid = this.credentials?.meJid
        const sender = node.attrs.participant ?? node.attrs.from
        const encryptions = collectInboundEncryptions(node)

        for (const encryption of encryptions) {
            if (encryption.encType === 'skmsg') {
                // A group message: the payload is encrypted with the group's
                // sender key.
                if (!sender) continue
                try {
                    const decrypted = this.signal.decryptFromGroup(
                        node.attrs.from ?? '',
                        sender,
                        encryption.ciphertext,
                    )
                    const body = decodeMessageBody(stripInboundPadding(decrypted.plaintext))
                    await this.emitInboundMessage(node, sender, body, meJid)
                } catch (error) {
                    this.emit(WaClient.ERROR, error)
                }
                continue
            }

            if (encryption.encType !== 'msg' && encryption.encType !== 'pkmsg') continue
            if (!sender) continue

            // The stanza does not carry the sender's device id, so the
            // session is looked up by the sender's user address. When the
            // peer runs more than one device, every known device address is
            // tried as well.
            let lastError: unknown
            let decryptedMessage: { plaintext: Uint8Array } | undefined
            for (const address of this.senderAddresses(sender, encryption.deviceJid)) {
                try {
                    decryptedMessage = this.signal.decryptFromDevice(
                        address,
                        encryption.ciphertext,
                        encryption.encType,
                    )
                    lastError = undefined
                    break
                } catch (error) {
                    lastError = error
                }
            }

            if (!decryptedMessage) {
                if (lastError) this.emit(WaClient.ERROR, lastError)
                continue
            }

            try {
                const body = decodeMessageBody(stripInboundPadding(decryptedMessage.plaintext))
                await this.emitInboundMessage(node, sender, body, meJid)
            } catch (error) {
                this.emit(WaClient.ERROR, error)
            }
        }

        // Acknowledge the message so the server stops resending it.
        this.send(
            buildAckNode(node.attrs.id ?? '', node.attrs.from ?? HOST_DOMAIN, {
                type: node.attrs.type,
                ...(node.attrs.participant ? { participant: node.attrs.participant } : {}),
            }),
        )
    }

    /**
     * Returns the device addresses a payload may have been encrypted for.
     *
     * The stanza only names the sender's user, so the primary address comes
     * first; the remaining devices the peer is known to run are tried as
     * fallbacks.
     *
     * @param sender The sender's address, as named by the stanza.
     * @param addressedDeviceJid The device the payload was addressed to, if
     *   the server used the fan-out shape.
     */
    private senderAddresses(sender: string, addressedDeviceJid?: string): string[] {
        const addresses: string[] = []
        if (addressedDeviceJid) addresses.push(addressedDeviceJid)
        if (!addresses.includes(sender)) addresses.push(sender)

        const userJid = toUserJid(sender)
        const known = this.deviceList.get(userJid)
        if (known) {
            for (const device of known) {
                if (!addresses.includes(device.jid)) addresses.push(device.jid)
            }
        }
        return addresses
    }

    /**
     * Emits an inbound message.
     *
     * @param node The stanza.
     * @param senderDeviceJid The device the payload was addressed to.
     * @param body The decoded message body.
     * @param meJid The account's own JID.
     */
    private async emitInboundMessage(
        node: BinaryNode,
        senderDeviceJid: string,
        body: MessageContent,
        meJid: string | undefined,
    ): Promise<void> {
        const distribution = extractSenderKeyDistribution(body)
        if (distribution) {
            try {
                this.signal.processSenderKeyDistribution(
                    distribution.groupId,
                    senderDeviceJid,
                    distribution.payload,
                )
            } catch (error) {
                this.emit(WaClient.ERROR, error)
            }
            // A distribution-only message carries no user-visible content.
            return
        }

        const key = resolveInboundMessageKey(node, senderDeviceJid, meJid, this.credentials?.meLid)
        const summary = summarizeMessageBody(body)
        const event: WaInboundMessage = {
            jid: key.remoteJid,
            id: key.id,
            fromMe: key.fromMe,
            ...(key.pushName ? { pushName: key.pushName } : {}),
            ...(key.participant ? { participant: key.participant } : {}),
            message: body,
            ...(summary.type ? { type: summary.type } : {}),
            ...(summary.text !== undefined ? { text: summary.text } : {}),
            ...(summary.quotedId !== undefined ? { quotedId: summary.quotedId } : {}),
            ...(summary.reaction !== undefined ? { reaction: summary.reaction } : {}),
            ...(summary.revoked !== undefined ? { revoked: summary.revoked } : {}),
            ...(node.attrs.t ? { timestamp: Number.parseInt(node.attrs.t, 10) } : {}),
        }
        this.emit(WaClient.MESSAGE, event)
    }

    /**
     * Handles an inbound `<receipt>` stanza.
     *
     * @param node The stanza.
     */
    private handleReceipt(node: BinaryNode): void {
        const event: WaReceipt = {
            id: node.attrs.id ?? '',
            jid: node.attrs.from ?? '',
            type: node.attrs.type ?? '',
            ...(node.attrs.participant ? { participant: node.attrs.participant } : {}),
        }
        this.emit(WaClient.RECEIPT, event)
    }

    /**
     * Handles an inbound `<ack>` stanza.
     *
     * @param node The stanza.
     */
    private handleAck(node: BinaryNode): void {
        const event: WaMessageAck = {
            id: node.attrs.id ?? '',
            jid: node.attrs.from ?? '',
            ...(node.attrs.error ? { error: node.attrs.error } : {}),
            ...(node.attrs.type ? { type: node.attrs.type } : {}),
        }
        this.emit(WaClient.MESSAGE_ACK, event)
    }

    /**
     * Handles the connection closing.
     *
     * @param error The reason.
     */
    private handleClose(error?: Error): void {
        if (this.state !== 'closing') this.setState('disconnected')
        if (this.stopping) return
        if (this.options.autoReconnect !== true) return
        const delay = this.options.reconnectDelayMs ?? WA_DEFAULTS.RECONNECT_INTERVAL_MS
        if (this.reconnectTimer) return
        this.reconnectTimer = setTimeout(() => {
            this.reconnectTimer = null
            void this.connect().catch((reconnectError: unknown) => {
                this.emit(
                    WaClient.ERROR,
                    reconnectError instanceof Error ? reconnectError : new Error(String(reconnectError)),
                )
            })
        }, delay)
        this.reconnectTimer.unref?.()
    }

    // ── Transport helpers ────────────────────────────────────────────────────

    /**
     * Sends a node.
     *
     * @param node The node.
     */
    private send(node: BinaryNode): void {
        this.transport?.send(node)
    }

    /**
     * Sends an IQ and waits for the response.
     *
     * @param node The IQ node.
     * @param timeoutMs The response timeout.
     */
    private async query(
        node: BinaryNode,
        timeoutMs: number = WA_DEFAULTS.IQ_TIMEOUT_MS,
    ): Promise<BinaryNode> {
        if (!this.transport) throw new Error('client: not connected')
        return this.transport.query(node, timeoutMs)
    }

    // ── Public API ───────────────────────────────────────────────────────────

    /** The authentication API. */
    readonly auth = {
        /**
         * Requests a pairing code for the given phone number.
         *
         * @param phoneNumber The phone number, in any format.
         * @param options The options.
         */
        requestPairingCode: async (
            phoneNumber: string,
            options: { customCode?: string; showPushNotification?: boolean } = {},
        ): Promise<string> => {
            const credentials = this.credentials ?? (await this.ensureCredentials())
            const phoneJid = parsePhoneJid(phoneNumber)
            const hello = await createCompanionHello(
                options.customCode !== undefined ? { customCode: options.customCode } : {},
            )
            await this.updateCredentials({
                advSecretKey: toBase64(new Uint8Array(32)),
            })
            const response = await this.query(
                buildCompanionHelloRequestNode({
                    phoneJid,
                    wrappedCompanionEphemeralPub: hello.wrappedCompanionEphemeralPub,
                    companionServerAuthKeyPub: fromBase64(credentials.noiseKeyPair.pub),
                    companionPlatformId:
                        (this.options.transport ?? 'mobile') === 'web'
                            ? WA_COMPANION_PLATFORM_ID.WEB
                            : WA_COMPANION_PLATFORM_ID.ANDROID,
                    companionPlatformDisplay: this.options.deviceProfile?.device ?? 'Desktop',
                    shouldShowPushNotification: options.showPushNotification !== false,
                }),
            )
            assertIqResult(response, 'companion hello')
            const linkCode = findNodeChild(response, WA_NODE_TAGS.LINK_CODE_COMPANION_REG)
            const refNode = linkCode
                ? findNodeChild(linkCode, WA_NODE_TAGS.LINK_CODE_PAIRING_REF)
                : undefined
            if (!refNode) throw new Error('pairing: the server sent no pairing reference')
            const ref = getNodeText(refNode)
            this.pairing = {
                pairingCode: hello.pairingCode,
                phoneJid,
                ref,
                createdAtSeconds: Math.floor(Date.now() / 1000),
                companionEphemeralPrivateKey: hello.companionEphemeralPrivateKey,
                companionEphemeralPublicKey: hello.companionEphemeralPublicKey,
                finished: false,
            }
            this.emit(WaClient.AUTH_PAIRING_CODE, { code: hello.pairingCode })
            return hello.pairingCode
        },

        /**
         * Fetches the country code the server derives from the phone number.
         */
        fetchCountryCode: async (): Promise<string> => {
            const response = await this.query(buildGetCountryCodeRequestNode())
            assertIqResult(response, 'country code')
            const country = findNodeChild(response, WA_NODE_TAGS.COUNTRY_CODE)
            const iso = country?.attrs.iso
            if (!iso) throw new Error('pairing: the server sent no country code')
            return iso
        },

        /**
         * Returns the credentials of the current session.
         */
        getCurrentCredentials: (): WaSessionInfo => this.getSession(),

        /**
         * Removes the stored credentials, unpairing the device.
         */
        logout: async (): Promise<void> => {
            await this.store.clear()
            this.credentials = null
            this.setState('disconnected')
        },
    }

    /**
     * The media API.
     *
     * Media files are uploaded to the WhatsApp CDN, encrypted with a
     * per-file key, and referenced from the message stanza. A download does
     * the reverse: the CDN is asked for the encrypted bytes, which are then
     * decrypted and verified locally.
     */
    readonly media = {
        /**
         * Encrypts a media file and uploads it to the WhatsApp CDN.
         *
         * @param data The media bytes.
         * @param options The media kind and its MIME type.
         */
        upload: async (
            data: Uint8Array,
            options: { type: WaMediaType; mimetype: string },
        ): Promise<WaMediaUpload> => {
            const conn = await this.mediaConn.get(this.mediaTransferOptions())
            return uploadMedia({ ...this.mediaTransferOptions(), conn }, {
                data,
                type: options.type,
                mimetype: options.mimetype,
            })
        },

        /**
         * Downloads and decrypts the media of a message.
         *
         * @param source The inbound message, the raw message body, or a
         *               media payload that was extracted earlier.
         */
        download: async (
            source: WaInboundMessage | MessageContent | MediaPayload,
        ): Promise<Uint8Array> => {
            const payload = this.resolveMediaPayload(source)
            if (!payload) throw new Error('client: the message carries no downloadable media')
            return downloadMedia(this.mediaTransferOptions(), payload)
        },
    }

    /**
     * Builds the options of a media transfer.
     */
    private mediaTransferOptions(): MediaTransferOptions {
        return {
            query: (node, timeoutMs) => this.query(node, timeoutMs),
            ...(this.options.mediaHttp ? { http: this.options.mediaHttp } : {}),
            ...(this.options.mediaTimeoutMs !== undefined
                ? { timeoutMs: this.options.mediaTimeoutMs }
                : {}),
        }
    }

    /**
     * Extracts the media payload of a message, an inbound message, or an
     * already extracted payload.
     *
     * @param source The source.
     */
    private resolveMediaPayload(
        source: WaInboundMessage | MessageContent | MediaPayload,
    ): MediaPayload | undefined {
        if (source && typeof source === 'object' && 'message' in source) {
            return resolveMediaPayload((source as WaInboundMessage).message)
        }
        if (source && typeof source === 'object' && 'mediaType' in source) {
            return source as MediaPayload
        }
        return resolveMediaPayload(source as MessageContent)
    }

    /** The messaging API. */
    readonly message = {
        /**
         * Sends a text message.
         *
         * @param to The recipient.
         * @param text The message text.
         * @param options The options.
         */
        send: async (
            to: string,
            text: string,
            options: {
                quote?: MessageKey
                mentionedJid?: string[]
                linkPreview?: {
                    url: string
                    title?: string
                    description?: string
                    jpegThumbnail?: Uint8Array
                }
            } = {},
        ): Promise<string> => {
            // `buildTextContent` calls the quoted message `quoted`, while the
            // public API calls it `quote` — map one onto the other so a
            // quote is never silently dropped.
            const body = buildTextContent(text, {
                ...(options.quote ? { quoted: options.quote } : {}),
                ...(options.mentionedJid ? { mentionedJid: options.mentionedJid } : {}),
                ...(options.linkPreview ? { linkPreview: options.linkPreview } : {}),
            })
            return this.sendBody(to, body)
        },

        /**
         * Sends a pre-built message body.
         *
         * @param to The recipient.
         * @param body The message body.
         */
        sendBody: (to: string, body: MessageContent): Promise<string> => this.sendBody(to, body),

        /**
         * Reacts to a message.
         *
         * @param to The chat the message is in.
         * @param target The reacted-to message.
         * @param emoji The reaction; an empty string removes the reaction.
         */
        react: async (to: string, target: MessageKey, emoji: string): Promise<string> => {
            return this.sendBody(to, buildReactionContent(target, emoji))
        },

        /**
         * Revokes (deletes for everyone) a message.
         *
         * @param to The chat the message is in.
         * @param target The revoked message.
         */
        revoke: async (to: string, target: MessageKey): Promise<string> => {
            return this.sendBody(to, buildRevokeContent(target))
        },

        /**
         * Sends a location.
         *
         * @param to The recipient.
         * @param location The location.
         */
        sendLocation: async (
            to: string,
            location: Parameters<typeof buildLocationContent>[0],
        ): Promise<string> => {
            return this.sendBody(to, buildLocationContent(location))
        },

        /**
         * Sends a contact (vCard).
         *
         * @param to The recipient.
         * @param contact The contact.
         */
        sendContact: async (
            to: string,
            contact: { displayName: string; vcard: string },
        ): Promise<string> => {
            return this.sendBody(to, buildContactContent(contact))
        },

        /**
         * Uploads a media file and sends it.
         *
         * The file is encrypted with a fresh media key and uploaded to the
         * WhatsApp CDN first; the message stanza then only carries the
         * metadata (the key, the hashes and the CDN path).
         *
         * @param to The recipient.
         * @param data The media bytes.
         * @param options The media kind and its metadata.
         */
        sendMedia: async (
            to: string,
            data: Uint8Array,
            options: WaMediaMessageOptions,
        ): Promise<string> => {
            const upload = await this.media.upload(data, {
                type: options.type,
                mimetype: options.mimetype,
            })
            const body = buildMediaContent(options.type, {
                url: upload.url,
                directPath: upload.directPath,
                mediaKey: upload.mediaKey,
                fileSha256: upload.fileSha256,
                fileEncSha256: upload.fileEncSha256,
                fileLength: upload.fileLength,
                mediaKeyTimestamp: upload.mediaKeyTimestamp,
                mimetype: options.mimetype,
                ...(options.caption !== undefined ? { caption: options.caption } : {}),
                ...(options.jpegThumbnail !== undefined
                    ? { jpegThumbnail: options.jpegThumbnail }
                    : {}),
                ...(options.pngThumbnail !== undefined
                    ? { pngThumbnail: options.pngThumbnail }
                    : {}),
                ...(options.width !== undefined ? { width: options.width } : {}),
                ...(options.height !== undefined ? { height: options.height } : {}),
                ...(options.seconds !== undefined ? { seconds: options.seconds } : {}),
                ...(options.fileName !== undefined ? { fileName: options.fileName } : {}),
                ...(options.title !== undefined ? { title: options.title } : {}),
                ...(options.pageCount !== undefined ? { pageCount: options.pageCount } : {}),
                ...(options.ptt !== undefined ? { ptt: options.ptt } : {}),
                ...(options.gifPlayback !== undefined
                    ? { gifPlayback: options.gifPlayback }
                    : {}),
                ...(options.isAnimated !== undefined
                    ? { isAnimated: options.isAnimated }
                    : {}),
                ...(options.firstFrameLength !== undefined
                    ? { firstFrameLength: options.firstFrameLength }
                    : {}),
            })
            return this.sendBody(to, body)
        },

        /**
         * Creates a poll.
         *
         * @param to The recipient.
         * @param poll The poll.
         */
        createPoll: async (
            to: string,
            poll: Parameters<typeof buildPollContent>[0],
        ): Promise<string> => {
            return this.sendBody(to, buildPollContent(poll))
        },

        /**
         * Marks a chat as read.
         *
         * WhatsApp expects the receipt to carry the id of the last message
         * that is being marked as read, so pass the id of the newest message
         * in the chat. Without it the receipt is sent with an empty id,
         * which the server accepts but treats as "nothing was read".
         *
         * @param to The chat.
         * @param options The options.
         */
        read: async (
            to: string,
            options: {
                /** The id of the last message that is marked as read. */
                id?: string
                /** The participant, for group chats. */
                participant?: string
                /** Whether the receipt is about this device only. */
                self?: boolean
            } = {},
        ): Promise<void> => {
            const type = options.self ? 'read-self' : 'read'
            this.send(
                buildReceiptNode(options.id ?? '', to, type, {
                    ...(options.participant ? { participant: options.participant } : {}),
                }),
            )
        },
    }

    /** The group API. */
    readonly group = {
        /**
         * Creates a group.
         *
         * @param subject The group subject.
         * @param participants The initial members.
         * @param description The optional description.
         */
        create: async (
            subject: string,
            participants: string[],
            description?: string,
        ): Promise<BinaryNode> => {
            return this.query(buildCreateGroupIq(subject, participants, description))
        },

        /**
         * Adds members to a group.
         *
         * @param groupJid The group.
         * @param participants The new members.
         */
        addParticipants: async (groupJid: string, participants: string[]): Promise<BinaryNode> => {
            return this.query(buildGroupParticipantChangeIq(groupJid, 'add', participants))
        },

        /**
         * Removes members from a group.
         *
         * @param groupJid The group.
         * @param participants The removed members.
         */
        removeParticipants: async (groupJid: string, participants: string[]): Promise<BinaryNode> => {
            return this.query(buildGroupParticipantChangeIq(groupJid, 'remove', participants))
        },

        /**
         * Promotes members to admin.
         *
         * @param groupJid The group.
         * @param participants The promoted members.
         */
        promoteParticipants: async (
            groupJid: string,
            participants: string[],
        ): Promise<BinaryNode> => {
            return this.query(buildGroupParticipantChangeIq(groupJid, 'promote', participants))
        },

        /**
         * Demotes admins to members.
         *
         * @param groupJid The group.
         * @param participants The demoted admins.
         */
        demoteParticipants: async (
            groupJid: string,
            participants: string[],
        ): Promise<BinaryNode> => {
            return this.query(buildGroupParticipantChangeIq(groupJid, 'demote', participants))
        },

        /**
         * Leaves one or more groups.
         *
         * @param groupJids The groups.
         */
        leave: async (groupJids: string[]): Promise<BinaryNode> => {
            return this.query(buildLeaveGroupIq(groupJids))
        },

        /**
         * Changes the subject of a group.
         *
         * @param groupJid The group.
         * @param subject The new subject.
         */
        setSubject: async (groupJid: string, subject: string): Promise<BinaryNode> => {
            return this.query(buildSetGroupSubjectIq(groupJid, subject))
        },
    }

    /** The profile API. */
    readonly profile = {
        /**
         * Changes the push name shown to other users.
         *
         * @param pushName The new push name.
         */
        setPushName: async (pushName: string): Promise<BinaryNode> => {
            const result = await this.query(buildSetPushNameIq(pushName))
            await this.updateCredentials({ pushName })
            return result
        },

        /**
         * Changes the "about" text.
         *
         * @param text The new text.
         */
        setStatus: async (text: string): Promise<BinaryNode> => {
            return this.query(buildSetStatusIq(text))
        },

        /**
         * Looks up the profile of a user.
         *
         * @param jid The user.
         */
        get: async (jid: string): Promise<BinaryNode> => {
            const sid = generateRandomId()
            return this.query(
                buildUsyncIq({
                    sid,
                    users: [{ jid }],
                    queryProtocolNodes: [
                        { tag: WA_NODE_TAGS.CONTACT, attrs: {} },
                        { tag: WA_NODE_TAGS.PUSHNAME, attrs: {} },
                        { tag: WA_NODE_TAGS.STATUS, attrs: {} },
                    ],
                }),
            )
        },
    }

    /** The presence API. */
    readonly presence = {
        /**
         * Publishes the available presence.
         *
         * @param name The push name.
         */
        available: (name?: string): void => {
            this.send(buildPresenceNode('available', name))
        },

        /**
         * Publishes the unavailable presence.
         */
        unavailable: (): void => {
            this.send(buildPresenceNode('unavailable'))
        },

        /**
         * Sends a chat state (typing indicator).
         *
         * @param to The recipient.
         * @param state The state.
         */
        chatState: (to: string, state: 'composing' | 'paused'): void => {
            this.send(buildChatStateNode(to, state))
        },
    }

    /** The privacy API. */
    readonly privacy = {
        /**
         * Reads the privacy settings.
         */
        getSettings: async (): Promise<BinaryNode> => {
            return this.query(buildGetPrivacySettingsIq())
        },

        /**
         * Changes a privacy category.
         *
         * @param category The category (`last`, `online`, `profile`, …).
         * @param value The value (`all`, `contacts`, `none`, …).
         */
        setCategory: async (category: string, value: string): Promise<BinaryNode> => {
            return this.query(buildSetPrivacyCategoryIq(category, value))
        },

        /**
         * Reads the block list.
         *
         * @param category The list category.
         */
        getBlocked: async (category = 'blocklist'): Promise<BinaryNode> => {
            return this.query(buildGetPrivacyDisallowedListIq(category))
        },

        /**
         * Blocks or unblocks users.
         *
         * @param category The list category.
         * @param jids The users.
         * @param dhash The version stamp from the last read.
         */
        setBlocked: async (
            category: string,
            jids: string[],
            dhash?: string,
        ): Promise<BinaryNode> => {
            return this.query(buildSetPrivacyDisallowedListIq(category, jids, dhash))
        },
    }

    /** The call API. */
    readonly call = {
        /**
         * Places a call.
         *
         * @param to The callee.
         * @param options The options.
         */
        offer: async (
            to: string,
            options: { video?: boolean; media?: { sdp?: string; transport?: Uint8Array } } = {},
        ): Promise<string> => {
            const meJid = this.credentials?.meJid ?? ''
            const callId = generateRandomId(12)
            this.send(
                buildCallOfferNode(to, callId, meJid, {
                    ...(options.video !== undefined ? { video: options.video } : {}),
                    ...(options.media ? { media: options.media } : {}),
                }),
            )
            this.emit(WaClient.CALL, {
                id: callId,
                jid: to,
                video: options.video === true,
                direction: 'outgoing',
                status: 'offer',
            })
            return callId
        },

        /**
         * Answers a call.
         *
         * @param to The peer.
         * @param callId The call id.
         * @param options The options.
         */
        accept: async (
            to: string,
            callId: string,
            options: { video?: boolean; media?: { sdp?: string; transport?: Uint8Array } } = {},
        ): Promise<void> => {
            const meJid = this.credentials?.meJid ?? ''
            this.send(
                buildCallAcceptNode(to, callId, meJid, {
                    ...(options.video !== undefined ? { video: options.video } : {}),
                    ...(options.media ? { media: options.media } : {}),
                }),
            )
        },

        /**
         * Rejects a call.
         *
         * @param to The peer.
         * @param callId The call id.
         * @param reason The optional reason.
         */
        reject: async (to: string, callId: string, reason?: string): Promise<void> => {
            const meJid = this.credentials?.meJid ?? ''
            this.send(buildCallRejectNode(to, callId, meJid, reason))
        },

        /**
         * Ends a call.
         *
         * @param to The peer.
         * @param callId The call id.
         */
        terminate: async (to: string, callId: string): Promise<void> => {
            const meJid = this.credentials?.meJid ?? ''
            this.send(buildCallTerminateNode(to, callId, meJid))
        },
    }

    // ── Message dispatch ─────────────────────────────────────────────────────

    /**
     * Generates the id of the next outgoing message.
     *
     * The format depends on the transport: the mobile API uses the 32
     * character `0xac`-prefixed ids, WhatsApp Web uses the 22 character
     * `3EB0`-prefixed ones.
     */
    private nextMessageId(): string {
        const format = (this.options.transport ?? 'mobile') === 'mobile' ? 'mobile' : 'web'
        return generateMessageId(this.credentials?.meJid ?? '', format)
    }

    /**
     * Encrypts and sends a message body.
     *
     * @param to The recipient.
     * @param body The message body.
     * @returns The id of the sent message.
     */
    private async sendBody(to: string, body: MessageContent): Promise<string> {
        const transport = this.transport
        if (!transport) throw new Error('client: not connected')
        const meJid = this.credentials?.meJid
        if (!meJid) throw new Error('client: the device is not paired yet')

        const id = this.nextMessageId()
        const plaintext = prepareOutboundPlaintext(body)
        const attrs = resolveOutboundMessageAttrs(body)

        if (isGroupJid(to)) {
            await this.sendGroupMessage(to, id, plaintext, attrs)
        } else {
            await this.sendDirectMessage(to, id, plaintext, attrs)
        }
        return id
    }

    /**
     * Sends a direct message, fanning the ciphertext out to every device of
     * the recipient.
     *
     * @param to The recipient.
     * @param id The message id.
     * @param plaintext The padded plaintext.
     * @param attrs The stanza attributes.
     */
    private async sendDirectMessage(
        to: string,
        id: string,
        plaintext: Uint8Array,
        attrs: ReturnType<typeof resolveOutboundMessageAttrs>,
    ): Promise<void> {
        const devices = await this.resolveDevices(to)
        if (devices.length === 0) throw new Error(`client: no devices known for ${to}`)

        const participants: EncryptedParticipant[] = []
        for (const device of devices) {
            const session = await this.ensureSignalSession(device.jid)
            const encrypted = this.signal.encryptForDevice(device.jid, plaintext)
            participants.push({
                jid: device.jid,
                encType: encrypted.encType,
                ciphertext: encrypted.ciphertext,
            })
            void session
        }

        this.send(
            buildDirectMessageFanoutNode(
                {
                    to,
                    type: attrs.typeAttr,
                    id,
                    ...(attrs.mediatype ? { mediatype: attrs.mediatype } : {}),
                    ...(attrs.edit ? { edit: attrs.edit } : {}),
                    ...(attrs.decryptFail ? { decryptFail: attrs.decryptFail } : {}),
                    ...(attrs.metaAttrs ? { additionalAttributes: attrs.metaAttrs } : {}),
                },
                participants,
            ),
        )
    }

    /**
     * Sends a group message.
     *
     * @param groupJid The group.
     * @param id The message id.
     * @param plaintext The padded plaintext.
     * @param attrs The stanza attributes.
     */
    private async sendGroupMessage(
        groupJid: string,
        id: string,
        plaintext: Uint8Array,
        attrs: ReturnType<typeof resolveOutboundMessageAttrs>,
    ): Promise<void> {
        const devices = await this.resolveGroupDevices(groupJid)
        if (devices.length === 0) {
            throw new Error(`client: no devices known for ${groupJid}`)
        }

        const group = this.signal.encryptForGroup(groupJid, plaintext)
        const distribution = group.distributionMessage
        if (!distribution) throw new Error('client: no sender key distribution was produced')

        const participants: EncryptedParticipant[] = []
        const phashTargets: string[] = []
        for (const device of devices) {
            await this.ensureSignalSession(device.jid)
            const encrypted = this.signal.encryptForDevice(device.jid, distribution)
            participants.push({
                jid: device.jid,
                encType: encrypted.encType,
                ciphertext: encrypted.ciphertext,
            })
            phashTargets.push(device.jid)
        }
        const meJid = this.credentials?.meJid
        if (meJid) phashTargets.push(meJid)

        this.send(
            buildGroupSenderKeyMessageNode(
                {
                    to: groupJid,
                    type: attrs.typeAttr,
                    id,
                    phash: computePhashV2(phashTargets),
                    ...(attrs.mediatype ? { mediatype: attrs.mediatype } : {}),
                    ...(attrs.edit ? { edit: attrs.edit } : {}),
                    ...(attrs.decryptFail ? { decryptFail: attrs.decryptFail } : {}),
                    ...(attrs.metaAttrs ? { additionalAttributes: attrs.metaAttrs } : {}),
                },
                participants,
                group.ciphertext,
            ),
        )
    }

    /**
     * Resolves the devices of a user, querying the server when the cache
     * misses.
     *
     * @param userJid The user.
     */
    private async resolveDevices(userJid: string): Promise<DeviceEntry[]> {
        const cached = this.deviceList.get(userJid)
        if (cached) return cached
        const entries = await this.queryDeviceLists([userJid])
        return entries.find((entry) => entry.userJid === toUserJid(userJid))?.devices ?? []
    }

    /**
     * Resolves the devices of every member of a group.
     *
     * @param groupJid The group.
     */
    private async resolveGroupDevices(groupJid: string): Promise<DeviceEntry[]> {
        const participants = await this.queryGroupParticipants(groupJid)
        if (participants.length === 0) return []
        const entries = await this.queryDeviceLists(participants)
        const out: DeviceEntry[] = []
        for (const entry of entries) out.push(...entry.devices)
        return out
    }

    /**
     * Queries the device lists of a set of users.
     *
     * @param jids The users.
     */
    private async queryDeviceLists(jids: string[]): Promise<
        { userJid: string; devices: DeviceEntry[]; updatedAtMs: number }[]
    > {
        if (jids.length === 0) return []
        const unique = [...new Set(jids.map((jid) => toUserJid(jid)))]
        const sid = generateRandomId()
        const response = await this.query(buildDeviceListUsyncIq(unique, sid))
        assertIqResult(response, 'device list')
        const parsed = parseDeviceListResponse(response, unique)
        for (const entry of parsed) this.deviceList.set(entry)
        return parsed
    }

    /**
     * Reads the participant list of a group.
     *
     * @param groupJid The group.
     */
    private async queryGroupParticipants(groupJid: string): Promise<string[]> {
        const sid = generateRandomId()
        const response = await this.query(
            buildUsyncIq({
                sid,
                users: [{ jid: groupJid }],
                queryProtocolNodes: [
                    {
                        tag: 'participants',
                        attrs: {},
                        content: [{ tag: 'participant', attrs: {} }],
                    },
                ],
            }),
        )
        assertIqResult(response, 'group participants')
        const usync = findNodeChild(response, WA_NODE_TAGS.USYNC)
        const list = usync ? findNodeChild(usync, WA_NODE_TAGS.LIST) : undefined
        if (!list) return []
        const out: string[] = []
        for (const userNode of getNodeChildrenByTag(list, WA_NODE_TAGS.USER)) {
            const participants = findNodeChild(userNode, 'participants')
            if (!participants) continue
            for (const participant of getNodeChildrenByTag(participants, WA_NODE_TAGS.PARTICIPANT)) {
                const jid = participant.attrs.jid
                if (jid) out.push(jid)
            }
        }
        return out
    }

    /**
     * Makes sure a Signal session exists for a device, fetching the pre-key
     * bundle when necessary.
     *
     * @param deviceJid The device JID.
     */
    private async ensureSignalSession(deviceJid: string): Promise<void> {
        if (this.signal.getSession(deviceJid)) return
        const userJid = toUserJid(deviceJid)
        const devices = await this.resolveDevices(userJid)
        const device = devices.find((entry) => entry.jid === deviceJid)
        const deviceId = device?.deviceId ?? 0

        const response = await this.query(
            buildMissingPreKeysFetchIq([
                {
                    userJid,
                    devices: [{ deviceId }],
                },
            ]),
        )
        assertIqResult(response, 'prekey fetch')
        const results = parseMissingPreKeysResponse(response, [{ userJid, devices: [] }])
        const bundle = results[0]?.devices?.[0]?.bundle
        if (!bundle) throw new Error(`client: no pre-key bundle for ${deviceJid}`)
        this.signal.ensureSession(deviceJid, {
            regId: bundle.regId,
            identity: bundle.identity,
            signedKey: bundle.signedKey,
            oneTimeKey: bundle.oneTimeKey ?? null,
        })
    }

    /**
     * Uploads the one-time pre-keys and rotates the signed pre-key when it is
     * too old.
     *
     * The uploaded pre-keys stay in the credential store: the server keeps
     * handing them out, and the device must still be able to decrypt the
     * pre-key message that uses them. Only the upload cursor moves forward,
     * so a pre-key is never uploaded twice.
     *
     * The whole batch is uploaded in a single `<iq>`, exactly like the
     * official client does (`WAWebUploadPreKeysJob`), and the server is
     * told that it now holds a batch of our pre-keys. As long as that is
     * the case, no further batch is uploaded — the server tells the client
     * when its pool runs low with an `<notification type="encrypt">` stanza.
     */
    private async uploadPreKeys(): Promise<void> {
        const registration = this.keyStore.getRegistrationInfo()
        const signedPreKey = this.keyStore.getSignedPreKey()
        if (!registration || !signedPreKey) return

        // The server still holds a batch of our pre-keys, so there is
        // nothing to upload yet.
        if (this.keyStore.getServerHasPreKeys()) return

        const count = this.options.preKeyCount ?? SIGNAL_UPLOAD_PREKEYS_COUNT
        const preKeys = this.keyStore.getOrGenPreKeys(count, generatePreKeyPair)
        if (preKeys.length === 0) return

        // A rejected upload must not move the cursor: the same pre-keys are
        // uploaded again on the next attempt.
        const response = await this.query(buildPreKeyUploadIq(registration, signedPreKey, preKeys))
        assertIqResult(response, 'prekey upload')

        // The upload succeeded: the cursor moves past the last uploaded
        // pre-key and the server is marked as holding a batch.
        const lastId = preKeys[preKeys.length - 1]!.keyId
        this.keyStore.markKeyAsUploaded(lastId)
        this.keyStore.setServerHasPreKeys(true)

        // A long-lived device would pile up pre-keys forever, so the pool is
        // bounded. The oldest uploaded keys are dropped first.
        this.keyStore.prunePreKeys(MAX_RETAINED_PRE_KEYS)

        await this.persistPreKeyPool({ serverHasPreKeys: true })
    }

    /**
     * Rotates the signed pre-key.
     *
     * When the server rejects the new signed pre-key, the key bundle is
     * validated against the digest the server holds — exactly like the
     * official client does (`WAWebRotateKeyJob` → `maybeDigestKey`).
     */
    async rotateSignedPreKey(): Promise<void> {
        const registration = this.keyStore.getRegistrationInfo()
        if (!registration) return
        const record = generateSignedPreKey(
            this.keyStore.allocateSignedPreKeyId(),
            registration.identityKeyPair.privKey,
        )
        this.keyStore.rotateSignedPreKey(record)

        let response: BinaryNode | null = null
        try {
            response = await this.query(buildSignedPreKeyRotateIq(record))
        } catch (error) {
            this.emit(WaClient.ERROR, error)
        }

        if (response && response.attrs.type === WA_IQ_TYPES.RESULT) {
            await this.updateCredentials({
                signedPreKey: {
                    id: record.keyId,
                    keyPair: {
                        pub: toBase64(record.keyPair.pubKey),
                        priv: toBase64(record.keyPair.privKey),
                    },
                    signature: toBase64(record.signature),
                },
                nextSignedPreKeyId: this.keyStore.getNextSignedPreKeyId(),
            })
            return
        }

        // The server did not accept the new signed pre-key. The key bundle
        // is validated against the server's digest, which tells us whether
        // the local state drifted.
        await this.updateCredentials({
            signedPreKey: {
                id: record.keyId,
                keyPair: {
                    pub: toBase64(record.keyPair.pubKey),
                    priv: toBase64(record.keyPair.privKey),
                },
                signature: toBase64(record.signature),
            },
            nextSignedPreKeyId: this.keyStore.getNextSignedPreKeyId(),
        })
        if (!this.shouldDigestAfterRotateError(response)) return
        await this.validateDigestAndRecoverPreKeys().catch((error: unknown) => {
            this.emit(
                WaClient.ERROR,
                error instanceof Error ? error : new Error(String(error)),
            )
        })
    }

    /**
     * Decides whether a failed signed pre-key rotation needs a digest check.
     *
     * The official client only validates the key bundle when the server
     * rejected the key (`409`) or answered with an error it does not know
     * (`WAWebRotateKeyJob`). A malformed request (`406`) is the client's own
     * fault and a server error (`5xx`) is worth retrying later, so neither
     * of them triggers a digest check.
     *
     * @param response The failed response, when there is one.
     */
    private shouldDigestAfterRotateError(response: BinaryNode | null): boolean {
        if (!response) return true
        const error = parseIqError(response)
        if (error.numericCode === 406) return false
        if (error.numericCode !== undefined && error.numericCode >= 500) return false
        return true
    }
}

/** Re-exported for convenience. */
export { FileCredentialStore, MemoryCredentialStore }
