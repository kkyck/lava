/**
 * The WhatsApp client.
 *
 * {@link LavaClient} owns everything: the credentials, the Signal key material,
 * the transport and the node router. It exposes small, focused sub-APIs
 * (`client.message`, `client.group`, `client.call`, …) and emits events for
 * everything that happens asynchronously.
 *
 * ```ts
 * const client = new LavaClient({ transport: 'mobile' })
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
import {
    LavaRegistration,
    canonicalPhoneNumber,
    describeRegistrationFailure,
    type LavaCodeRequest,
    type LavaNumberStatus,
    type LavaRegistrationOptions,
    type LavaRegistrationResult,
    type LavaRegistrationSession,
} from './auth/registration.js'
import { completeCompanionFinish, createCompanionHello } from './auth/pairing.js'
import {
    AppStateSyncClient,
    type AppStateExternalBlob,
    type AppStatePendingMutation,
    type AppStateSyncOptions,
    type AppStateSyncResult,
} from './appstate/sync.js'
import { AppStateStore, type AppStateStoreSnapshot } from './appstate/store.js'
import { toHex, generateX25519KeyPair, toSerializedPublicKey } from './crypto/primitives.js'
import { randomBytesOf } from './crypto/primitives.js'
import { hostOsName } from './util/host.js'
import { QrFlow } from './qr/flow.js'
import { createSilentLogger, type WaLogger } from './logger.js'
import {
    collectInboundEncryptions,
    decodeMessageBody,
    extractSenderKeyDistribution,
    hasMessageContent,
    prepareOutboundPlaintext,
    prepareSenderKeyDistributionPayload,
    resolveInboundMessageKey,
    summarizeMessageBody,
    stripInboundPadding,
    type InboundMessageKey,
} from './message/codec.js'
import {
    PROTOCOL_MESSAGE_TYPE,
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
    isLidJid,
    normalizeDeviceJid,
    parsePhoneJid,
    parseSignalAddressFromJid,
    splitJid,
    toUserJid,
    type JidParts,
} from './protocol/jid.js'
import {
    WA_DEFAULTS,
    WA_IQ_TYPES,
    WA_MESSAGE_TAGS,
    WA_MESSAGE_TYPES,
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
    selectPreKeyBundle,
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
    generateMediaId,
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
    DEFAULT_IOS_PROFILE,
    DEFAULT_WEB_PROFILE,
    DEFAULT_WEB_VERSION,
    buildDeviceProps,
    buildLoginPayload,
    buildMobileLoginPayload,
    buildMobileRegistrationPayload,
    buildRegistrationPayload,
    type DeviceProfile,
} from './transport/client-payload.js'
import { DeviceProps_PlatformType } from './proto/enums.js'
import { KeepAlive } from './transport/keepalive.js'
import { MobileTransport } from './transport/mobile.js'
import { WebTransport } from './transport/web.js'
import type { NoiseSessionConfig } from './transport/noise-session.js'
import type { TransportHandlers } from './transport/types.js'
import {
    buildAckNode,
    buildIqResultNode,
    buildNotificationAckNode,
    buildReceiptNode,
    buildRetryReceiptNode,
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
    buildRetryMessageNode,
    type EncryptedParticipant,
} from './transport/node/builders/message.js'
import {
    buildCallAcceptNode,
    buildCallOfferNode,
    buildCallRejectNode,
    buildCallTerminateNode,
    buildChatStateNode,
    buildCreateGroupIq,
    buildGetGroupMetadataIq,
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
    getFirstNodeChild,
    getNodeChildrenByTag,
    getNodeText,
} from './transport/node/helpers.js'
import { assertIqResult, parseIqError } from './transport/node/query.js'
import { generateMessageId, generateRandomId } from './util/message-id.js'
import { buildWhatsAppQrPayload } from './qr/whatsapp.js'
import {
    GroupMetadataCache,
    parseGroupMetadata,
    parseGroupParticipants,
    resolveGroupAddressingMode,
} from './protocol/group.js'
import type { GroupMetadata, GroupParticipant } from './protocol/group.js'
import { parseRetryReceipt } from './protocol/retry.js'
import type { RetryRequest } from './protocol/retry.js'
import { parseFailureNode } from './protocol/failure.js'
import {
    WA_CALL_RECEIPT_PAYLOADS,
    WA_CALL_STATUS,
    parseCallKey,
    parseCallNode,
} from './protocol/call.js'
import type { WaFailure } from './protocol/failure.js'
import { OutboundMessageCache } from './message/outbound-cache.js'

/** The transport a client runs on. */
export type WaTransportMode = 'mobile' | 'web'

/**
 * The number of times a single stanza may be asked to be resent.
 *
 * A message that cannot be decrypted once will not become decryptable by
 * asking again, so the retries stop after a few attempts.
 */
const MAX_RETRY_COUNT = 3

/**
 * The number of times a peer may ask for a message to be sent again.
 *
 * A message that could not be decrypted once will not become decryptable by
 * asking again and again, so the answers stop after a few attempts.
 */
const MAX_REMOTE_RETRY_COUNT = 3

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
 * {@link LavaClientOptions.transportFactory}.
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

/** Configuration for {@link LavaClient}. */
export interface LavaClientOptions {
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
 * on {@link LavaClient}.
 */
export class LavaClient extends EventEmitter {
    /** Emitted with `{ qr, ttlMs }` when a QR code has to be scanned. */
    static readonly AUTH_QR = 'auth_qr'
    /** Emitted with `{ code }` when a pairing code is available. */
    static readonly AUTH_PAIRING_CODE = 'auth_pairing_code'
    /** Emitted with `{ meJid, meLid }` once the device is paired. */
    static readonly AUTH_PAIRED = 'auth_paired'
    /** Emitted with `{ phoneNumber, method, length, wait }` when a code is sent. */
    static readonly AUTH_REGISTRATION_CODE = 'auth_registration_code'
    /** Emitted with `{ meJid }` once a phone number has been claimed. */
    static readonly AUTH_REGISTERED = 'auth_registered'
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
    /** Emitted with a {@link WaFailure} when the server refuses the session. */
    static readonly FAILURE = 'failure'
    /** Emitted when the server ended the session and the device has to pair again. */
    static readonly LOGOUT = 'logout'
    /** Emitted with an `Error` for every recoverable failure. */
    static readonly ERROR = 'error'

    private readonly options: LavaClientOptions
    private readonly logger: WaLogger
    private readonly store: CredentialStore
    private readonly keyStore: SignalKeyStore
    private readonly signal: SignalSessionManager
    private readonly deviceList = new DeviceListStore()
    private readonly groupParticipants = new GroupMetadataCache()
    private readonly outboundMessages = new OutboundMessageCache()
    private readonly resendCounts = new Map<string, number>()
    private readonly mediaConn = new MediaConnectionCache()
    private readonly appStateStore = new AppStateStore()
    private readonly pendingAppState: AppStatePendingMutation[] = []

    private credentials: CredentialSnapshot | null = null
    private transport: WaTransport | null = null
    private keepAlive: KeepAlive | null = null
    private state: WaConnectionState = 'disconnected'
    private reconnectTimer: NodeJS.Timeout | null = null
    private stopping = false
    /** The registration in progress, when a code was asked for. */
    private registrationSession: LavaRegistrationSession | undefined

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

    /**
     * The QR references handed out by the server and the rotation between
     * them.
     */
    private readonly qrFlow = new QrFlow({
        buildQr: (ref) => {
            const credentials = this.credentials
            return credentials ? this.buildQrPayload(ref, credentials) : ''
        },
        emitQr: (qr, ttlMs) => {
            if (!qr) return
            this.emit(LavaClient.AUTH_QR, { qr, ttlMs })
        },
    })

    /** The stanzas a retry receipt was already sent for. */
    private readonly retryCounts = new Map<string, number>()

    /**
     * @param options The client options.
     */
    constructor(options: LavaClientOptions = {}) {
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
            // The ratchet state cannot be recreated from the key material, so
            // it is persisted as soon as it changes.
            onSessionChanged: () => {
                this.persistSessions()
            },
            // The sender keys of the group chats advance with every message,
            // so they are persisted as soon as they change too.
            onSenderKeysChanged: () => {
                this.persistSenderKeys()
            },
        })
    }

    /**
     * Reports a recoverable failure.
     *
     * The `error` event is special in Node: emitting it without a listener
     * throws. A library must not take the whole application down because the
     * user did not subscribe to the event, so the failure is only emitted
     * when somebody is listening and logged otherwise.
     *
     * @param error The failure.
     */
    private emitError(error: unknown): void {
        const failure = error instanceof Error ? error : new Error(String(error))
        if (this.listenerCount(LavaClient.ERROR) > 0) {
            this.emit(LavaClient.ERROR, failure)
            return
        }
        this.logger.log({
            level: 'warn',
            message: `unhandled client error: ${failure.message}`,
        })
    }

    /**
     * Runs a task in the background.
     *
     * A promise that nobody waits for ends the process in Node when it is
     * rejected, so every background task of the library goes through here:
     * a failure is reported like any other recoverable failure instead of
     * taking the host application down.
     *
     * @param task The task.
     */
    private background(task: Promise<unknown>): void {
        void task.catch((error: unknown) => {
            this.emitError(error)
        })
    }

    /**
     * Writes a debug record.
     *
     * @param message The message.
     * @param fields Additional structured fields.
     */
    private logDebug(message: string, fields?: Record<string, unknown>): void {
        this.logger.log({
            level: 'debug',
            message,
            ...(fields ? { fields } : {}),
        })
    }

    /**
     * Persists the double-ratchet sessions.
     *
     * The write is queued with the other credential writes, so two
     * overlapping writes cannot overwrite each other.
     */
    private persistSessions(): void {
        if (!this.credentials) return
        const sessions = this.signal.exportSessions()
        void this.updateCredentials({ sessions }).catch((error: unknown) => {
            this.emitError(error)
        })
    }

    /**
     * Persists the sender keys of the group chats.
     *
     * The write is queued with the other credential writes, so two
     * overlapping writes cannot overwrite each other.
     */
    private persistSenderKeys(): void {
        if (!this.credentials) return
        const senderKeys = this.signal.senderKeyManager.exportState()
        void this.updateCredentials({ senderKeys }).catch((error: unknown) => {
            this.emitError(error)
        })
    }

    /**
     * Restores the cached group memberships of a snapshot.
     *
     * The group server refuses a client that asks for the member list of the
     * same group over and over, so the membership has to survive a restart.
     *
     * @param snapshot The snapshot to restore from.
     */
    private restoreGroupMetadata(snapshot: CredentialSnapshot): void {
        for (const [groupJid, entry] of Object.entries(snapshot.groupMetadata ?? {})) {
            this.groupParticipants.restore(groupJid, entry)
        }
    }

    /**
     * Persists the cached group memberships.
     *
     * The write is queued with the other credential writes, so two
     * overlapping writes cannot overwrite each other.
     */
    private persistGroupMetadata(): void {
        if (!this.credentials) return
        const groupMetadata = this.groupParticipants.snapshot()
        void this.updateCredentials({ groupMetadata }).catch((error: unknown) => {
            this.emitError(error)
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
                LavaClient.ERROR,
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
     * completes through the {@link LavaClient.AUTH_PAIRED} event.
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
        this.startKeepAlive(transport)
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
        this.stopKeepAlive()
        this.qrFlow.clear()
        this.setState('closing')
        this.transport?.close()
        this.transport = null
        this.setState('disconnected')
    }

    /**
     * Starts the keepalive of a transport.
     *
     * WhatsApp closes a socket that stays silent, so the client pings the
     * server every few seconds. A ping that never comes back proves that the
     * socket is dead, and the connection is re-established.
     *
     * @param transport The transport to keep alive.
     */
    private startKeepAlive(transport: WaTransport): void {
        this.stopKeepAlive()
        const keepAlive = new KeepAlive({
            query: (node, timeoutMs) => transport.query(node, timeoutMs),
            onFailure: (error) => {
                this.warn('keepalive: the ping failed, the socket is dead', error)
                // The socket is gone: close it and let the reconnect logic
                // open a fresh one.
                transport.close()
                this.handleClose(error)
            },
            onClockSkewMs: (skewMs) => {
                this.logDebug('keepalive: the clock skew', { skewMs })
            },
        })
        this.keepAlive = keepAlive
        keepAlive.start()
    }

    /** Stops the keepalive. */
    private stopKeepAlive(): void {
        if (!this.keepAlive) return
        this.keepAlive.stop()
        this.keepAlive = null
    }

    /** Emits the connection state and updates the internal state. */
    private setState(state: WaConnectionState): void {
        if (this.state === state) return
        this.state = state
        this.emit(LavaClient.CONNECTION, { state })
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
            this.emitError(error)
        }
        // The app state of the account is synchronised in the background:
        // a device that never syncs looks different from the official ones.
        void this.appState
            .sync()
            .catch((error: unknown) => {
                this.warn('app-state: the initial sync failed', error)
            })
    }

    /**
     * Reports a problem that does not stop the client.
     *
     * @param message The message.
     * @param error The cause.
     */
    private warn(message: string, error?: unknown): void {
        this.logger.log({
            level: 'warn',
            message,
            ...(error !== undefined
                ? { fields: { error: error instanceof Error ? error.message : String(error) } }
                : {}),
        })
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
                this.emitError(error)
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
        const profile = this.resolveDeviceProfile(credentials.deviceInfo)
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
     * Resolves the device profile the handshake announces.
     *
     * A device keeps the same fingerprint for its whole life: the app
     * version, the model and the build number are written into the account
     * when the device is registered, and the server compares the login
     * payload against them. A device that suddenly announces another model
     * looks like a new device that took over an old one.
     *
     * So the profile stored with the session wins over the default, and only
     * an explicitly configured profile overrides the stored one.
     *
     * The default depends on the transport: the mobile transport announces
     * a phone, the web transport announces a browser. The server refuses a
     * client it considers too old with the reason 405, so the default
     * version always has to be one the server still accepts.
     *
     * @param stored The stored device profile, when the session has one.
     */
    private resolveDeviceProfile(
        stored?: CredentialSnapshot['deviceInfo'],
    ): DeviceProfile {
        if (this.options.deviceProfile) return this.options.deviceProfile
        const mode = this.options.transport ?? 'mobile'
        if (mode === 'web') {
            // WhatsApp Web does not keep a phone fingerprint.
            return { ...DEFAULT_WEB_PROFILE }
        }
        if (!stored) return DEFAULT_ANDROID_PROFILE
        const fallback =
            stored.os === 'ios' ? DEFAULT_IOS_PROFILE : DEFAULT_ANDROID_PROFILE
        return {
            ...fallback,
            os: stored.os ?? fallback.os,
            appVersion: stored.appVersion ?? fallback.appVersion,
            device: stored.device ?? fallback.device,
            osVersion: stored.osVersion ?? fallback.osVersion,
            osBuildNumber: stored.osBuildNumber ?? fallback.osBuildNumber,
            manufacturer: stored.manufacturer ?? fallback.manufacturer,
            ...(stored.deviceBoard !== undefined ? { deviceBoard: stored.deviceBoard } : {}),
            ...(stored.mcc !== undefined ? { mcc: stored.mcc } : {}),
            ...(stored.mnc !== undefined ? { mnc: stored.mnc } : {}),
        }
    }

    /**
     * Loads the credentials, creating them when they are missing.
     */
    private async ensureCredentials(): Promise<CredentialSnapshot> {
        const existing = await this.store.load()
        if (existing) {
            this.credentials = existing
            this.restoreSignalKeys(existing)
            this.restoreGroupMetadata(existing)
            return existing
        }

        const profile = this.resolveDeviceProfile()

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
            ...(this.options.transport === 'web'
                ? {}
                : { deviceInfo: this.deviceInfoFromProfile(profile) }),
        }
        await this.store.save(snapshot)
        this.credentials = snapshot
        return snapshot
    }

    /**
     * Extracts the persistent part of a device profile.
     *
     * The fingerprint of a device has to survive a restart, so it is written
     * into the credential snapshot and read back when the session resumes.
     *
     * @param profile The device profile.
     */
    private deviceInfoFromProfile(profile: DeviceProfile): NonNullable<
        CredentialSnapshot['deviceInfo']
    > {
        return {
            appVersion: profile.appVersion ?? DEFAULT_ANDROID_PROFILE.appVersion ?? '',
            device: profile.device,
            osVersion: profile.osVersion,
            osBuildNumber: profile.osBuildNumber,
            manufacturer: profile.manufacturer,
            os: profile.os,
            ...(profile.deviceBoard !== undefined ? { deviceBoard: profile.deviceBoard } : {}),
            ...(profile.mcc !== undefined ? { mcc: profile.mcc } : {}),
            ...(profile.mnc !== undefined ? { mnc: profile.mnc } : {}),
        }
    }

    /**
     * Restores the Signal key material from a credential snapshot.
     *
     * @param snapshot The snapshot.
     */
    private restoreSignalKeys(snapshot: CredentialSnapshot): void {
        // The sender keys name their owner, so the address of the local
        // device has to be known before the first group message.
        if (snapshot.meJid) {
            this.signal.senderKeyManager.setLocalAddresses(
                snapshot.meJid,
                snapshot.meLid,
            )
        }
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
        // The app-state store is restored as well, so the client keeps the
        // collection state it had before the restart.
        if (snapshot.appState) {
            this.appStateStore.mergeSnapshot(snapshot.appState)
        }
        // The double-ratchet sessions are restored too: the ratchet state
        // cannot be recreated from the key material, so without it the next
        // message of an established conversation could not be decrypted.
        this.signal.importSessions(snapshot.sessions)
        // The sender keys of the group chats are restored as well: they are
        // the only way to decrypt an inbound group message.
        this.signal.senderKeyManager.importState(snapshot.senderKeys)
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
                this.background(this.handleMessage(node))
                return
            case WA_MESSAGE_TAGS.RECEIPT:
                this.handleReceipt(node)
                return
            case WA_NODE_TAGS.ACK:
                this.handleAck(node)
                return
            case WA_NODE_TAGS.IQ:
                this.background(this.handleIq(node))
                return
            case WA_NODE_TAGS.CALL:
                this.handleCall(node)
                return
            case WA_NODE_TAGS.NOTIFICATION:
                this.background(this.handleNotification(node))
                return
            case WA_NODE_TAGS.FAILURE:
                this.handleFailure(node)
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

        this.background(
            this.updateCredentials({
                ...(meJid ? { meJid } : {}),
                ...(meLid ? { meLid } : {}),
                ...(pushName ? { pushName } : {}),
                lastSuccessTs: Date.now(),
                loginCounter: (this.credentials?.loginCounter ?? 0) + 1,
            }).then(() => {
                this.setState('connected')
                if (meJid) {
                    this.emit(LavaClient.AUTH_PAIRED, { meJid, meLid })
                }
                return this.afterConnect()
            }),
        )
    }

    /**
     * Handles a `<call>` stanza.
     *
     * The peer waits for an answer before it considers the call delivered,
     * so the stanza is answered first: an offer, an accept, a reject and a
     * re-key are answered with a receipt that carries the payload back, every
     * other payload with a plain acknowledgement.
     *
     * @param node The stanza.
     */
    private handleCall(node: BinaryNode): void {
        const call = parseCallNode(node)
        const peer = node.attrs.from ?? node.attrs.participant ?? ''
        const stanzaId = node.attrs.id
        const payload = getFirstNodeChild(node)

        if (stanzaId && payload && WA_CALL_RECEIPT_PAYLOADS.has(call.type)) {
            this.send(
                buildReceiptNode(stanzaId, peer, '', {
                    ...(this.deriveCallReceiptFrom(peer) !== undefined
                        ? { from: this.deriveCallReceiptFrom(peer) }
                        : {}),
                    content: [
                        {
                            tag: payload.tag,
                            attrs: {
                                ...(call.callId !== undefined ? { 'call-id': call.callId } : {}),
                                ...(call.creator !== undefined
                                    ? { 'call-creator': call.creator }
                                    : {}),
                            },
                        },
                    ],
                }),
            )
        } else if (stanzaId && peer) {
            this.send(
                buildAckNode(stanzaId, peer, {
                    type: payload?.tag ?? WA_NODE_TAGS.CALL,
                    class: WA_MESSAGE_TYPES.ACK_CLASS_CALL,
                }),
            )
        }

        const status = WA_CALL_STATUS[call.type]
        if (!status) return
        this.emit(LavaClient.CALL, {
            id: call.callId ?? stanzaId ?? '',
            jid: call.creator ?? peer,
            video: call.video,
            direction: 'incoming',
            status,
        })
    }

    /**
     * Derives the address a call receipt is sent from.
     *
     * The receipt has to name the address the peer addressed: a peer that
     * called a LID address gets a receipt from the LID address of this
     * device, a peer that called a phone-number address gets one from the
     * phone-number address.
     *
     * @param peer The address of the peer.
     * @returns The address of this device, when it is known.
     */
    private deriveCallReceiptFrom(peer: string): string | undefined {
        const meJid = this.credentials?.meJid
        const meLid = this.credentials?.meLid
        try {
            if (isLidJid(peer)) {
                return meLid ? normalizeDeviceJid(meLid) : undefined
            }
            return meJid ? toUserJid(meJid) : undefined
        } catch {
            // A malformed address is no reason to drop the receipt.
            return undefined
        }
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
        if (linkCode?.attrs.stage === WA_SIGNALING.LINK_CODE_STAGE_REFRESH_CODE) {
            // The server asks for a fresh pairing code.
            this.send(
                buildNotificationAckNode(
                    node.attrs.id,
                    node.attrs.from ?? HOST_DOMAIN,
                    node.attrs.type ?? WA_NODE_TAGS.NOTIFICATION,
                    node.attrs.participant,
                ),
            )
            this.qrFlow.refreshCurrentQr()
            return
        }
        /**
         * The server asks the companion to rotate its pairing code. The
         * attestation secret is rotated first, so the acknowledgement and the
         * new QR code always describe the same state.
         */
        if (
            findNodeChild(node, WA_SIGNALING.COMPANION_REG_REFRESH_NOTIFICATION) !== undefined ||
            findNodeChild(node, 'pair-device-rotate-qr') !== undefined
        ) {
            await this.rotateAdvSecret()
            this.send(
                buildNotificationAckNode(
                    node.attrs.id,
                    node.attrs.from ?? HOST_DOMAIN,
                    WA_SIGNALING.COMPANION_REG_REFRESH_NOTIFICATION,
                    node.attrs.participant,
                ),
            )
            this.qrFlow.refreshCurrentQr()
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
            this.emitError(error)
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
            this.emitError(error)
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
            this.emitError(error)
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
            this.emitError(error)
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
        /**
         * The server pings the client with an `<iq type="get">` carrying the
         * `w:p` (or `urn:xmpp:ping`) namespace. The client has to answer it,
         * or the server considers the client gone and drops the socket.
         */
        if (
            node.attrs.type === WA_IQ_TYPES.GET &&
            (node.attrs.xmlns === WA_XMLNS.WHATSAPP_PING ||
                node.attrs.xmlns === WA_XMLNS.XMPP_PING)
        ) {
            this.send(buildIqResultNode(node))
            return
        }

        if (node.attrs.type !== WA_IQ_TYPES.SET) return

        const pairDevice = findNodeChild(node, WA_NODE_TAGS.PAIR_DEVICE)
        if (pairDevice) {
            await this.handlePairDevice(node, pairDevice)
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
     * @param iqNode The IQ stanza the references arrived in.
     * @param node The `<pair-device>` node.
     */
    private async handlePairDevice(iqNode: BinaryNode, node: BinaryNode): Promise<void> {
        const refs = getNodeChildrenByTag(node, WA_NODE_TAGS.REF)
            .map((ref) => getNodeText(ref))
            .filter((ref) => ref.length > 0)
        if (refs.length === 0) return
        /**
         * The advanced device attestation secret is rotated with every set of
         * references, so a leaked QR cannot be replayed against a later one.
         * The rotation happens before the request is answered, so the answer
         * and the QR always describe the same state.
         */
        await this.rotateAdvSecret()
        /**
         * The server expects an `<iq type="result">` in reply to the
         * `pair-device` request. Without it the request stays unanswered and
         * the server closes the socket.
         */
        this.send(buildIqResultNode(iqNode))
        this.qrFlow.setRefs(refs)
    }

    /**
     * Replaces the advanced device attestation secret with a fresh one.
     */
    private async rotateAdvSecret(): Promise<void> {
        await this.updateCredentials({ advSecretKey: toBase64(randomBytesOf(32)) })
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
            devicePlatform: WA_COMPANION_PLATFORM_ID.ELECTRON,
        })
    }

    /**
     * The name the phone shows for this client while pairing.
     *
     * The official client sends the name of the program and the system it
     * runs on, e.g. `Chrome (Linux)`.
     *
     * @returns The display name.
     */
    private companionPlatformDisplay(): string {
        const profile = this.options.deviceProfile
        /**
         * The linking protocol belongs to the web client, so the phone shows
         * the program that links — not the phone it impersonates on the
         * message API. A desktop client therefore announces itself as the
         * desktop app, together with the system it runs on.
         */
        const device = profile?.propsOs ? profile.device : 'Desktop'
        const os = profile?.propsOs ?? hostOsName()
        return `${device} (${os})`
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
        if (meJid) {
            // The sender keys name their owner.
            this.signal.senderKeyManager.setLocalAddresses(meJid, meLid)
        }
        await this.updateCredentials({
            ...(meJid ? { meJid } : {}),
            ...(meLid ? { meLid } : {}),
            transport: this.options.transport ?? 'mobile',
            loginCounter: 0,
        })
        this.setState('connected')
        this.emit(LavaClient.AUTH_PAIRED, { meJid, meLid })
        this.background(this.afterConnect())
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
        /**
         * WhatsApp names a peer by its LID, but the stanza carries the
         * phone-number address of the same peer next to it. The Signal state
         * may be stored under either of the two, so both are tried.
         */
        const alternateSender = node.attrs.participant_pn ?? node.attrs.sender_pn

        let decrypted = false

        for (const encryption of encryptions) {
            if (encryption.encType === 'skmsg') {
                // A group message: the payload is encrypted with the group's
                // sender key.
                if (!sender) continue

                let plaintext: Uint8Array | undefined
                let failure: unknown
                // The sender key may be stored under the phone-number address
                // of the participant instead of its LID address.
                for (const address of [sender, alternateSender]) {
                    if (!address) continue
                    try {
                        plaintext = this.signal.decryptFromGroup(
                            node.attrs.from ?? '',
                            address,
                            encryption.ciphertext,
                        ).plaintext
                        break
                    } catch (error) {
                        failure ??= error
                    }
                }

                if (!plaintext) {
                    if (failure) this.emitError(failure)
                    continue
                }

                // The payload was read, so the server must not resend it,
                // even when the message itself cannot be handled.
                decrypted = true
                try {
                    const body = decodeMessageBody(stripInboundPadding(plaintext))
                    await this.emitInboundMessage(node, sender, body, meJid)
                } catch (error) {
                    this.emitError(error)
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
            for (const address of this.senderAddresses(
                sender,
                encryption.deviceJid,
                alternateSender,
            )) {
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
                if (lastError) this.emitError(lastError)
                continue
            }

            // The payload was read, so the server must not resend it, even
            // when the message itself cannot be handled.
            decrypted = true
            try {
                const body = decodeMessageBody(stripInboundPadding(decryptedMessage.plaintext))
                await this.emitInboundMessage(node, sender, body, meJid)
            } catch (error) {
                this.emitError(error)
            }
        }

        if (encryptions.length > 0 && !decrypted) {
            // Nothing could be decrypted: the payload was encrypted with a key
            // this device does not have. Asking the server to send the
            // message again makes it re-encrypt it for a key this device
            // knows.
            this.sendRetryReceipt(node)
            return
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
     * Asks the server to send an undecryptable message again.
     *
     * The retry counter of the stanza is raised with every attempt, so the
     * server can tell a first attempt from a repeated one. A stanza is only
     * asked for a few times: a message that cannot be decrypted once will not
     * become decryptable by asking again, and an endless retry loop would
     * keep the server busy.
     */
    private sendRetryReceipt(node: BinaryNode): void {
        const id = node.attrs.id
        const to = node.attrs.from
        if (!id || !to) return

        // The server repeats the stanza with a rising retry counter; when it
        // does not, the counter of the last attempt is used.
        const retryNode = findNodeChild(node, 'retry')
        const stanzaCount = Number.parseInt(retryNode?.attrs.count ?? '', 10)
        const previous = Number.isSafeInteger(stanzaCount) && stanzaCount > 0
            ? stanzaCount
            : (this.retryCounts.get(id) ?? 0)
        const count = previous + 1
        if (count > MAX_RETRY_COUNT) return
        this.retryCounts.set(id, count)

        this.send(
            buildRetryReceiptNode(id, to, count, {
                ...(node.attrs.participant ? { participant: node.attrs.participant } : {}),
                ...(node.attrs.t ? { t: node.attrs.t } : {}),
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
     * @param alternateSender The phone-number address of the sender, when the
     *   stanza carries one.
     */
    private senderAddresses(
        sender: string,
        addressedDeviceJid?: string,
        alternateSender?: string,
    ): string[] {
        const addresses: string[] = []
        if (addressedDeviceJid) addresses.push(addressedDeviceJid)
        if (!addresses.includes(sender)) addresses.push(sender)
        if (alternateSender && !addresses.includes(alternateSender)) {
            addresses.push(alternateSender)
        }

        const userJid = toUserJid(sender)
        const known = this.deviceList.get(userJid)
        if (known) {
            for (const device of known) {
                if (!addresses.includes(device.jid)) addresses.push(device.jid)
            }
        }

        /**
         * A stanza names the sender by its user address, so the payload may
         * have been encrypted for any of the devices the peer runs. Every
         * device this device has a session with is therefore a candidate —
         * and the only ones that can work, because a session is needed to
         * decrypt a payload at all.
         */
        for (const address of this.signal.sessionAddresses(parseSignalAddressFromJid(sender).user)) {
            if (!addresses.includes(address)) addresses.push(address)
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
                this.emitError(error)
            }
            // A body that carries nothing but the distribution has no
            // user-visible content; a group message carries the distribution
            // *and* the message itself.
            if (!hasMessageContent(body)) return
        }

        await this.handleProtocolMessage(body, senderDeviceJid)

        const key = resolveInboundMessageKey(node, senderDeviceJid, meJid, this.credentials?.meLid)
        const summary = summarizeMessageBody(body)
        this.emitModernCall(body, key.remoteJid)
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
        this.emit(LavaClient.MESSAGE, event)
    }

    /**
     * Announces a call that arrives as an ordinary message.
     *
     * The modern protocol sends a call offer as a message whose body carries
     * a `call` field with the serialised key of the call. The key names the
     * chat the call takes place in and whether this device called.
     *
     * @param body The message body.
     * @param remoteJid The chat the message came from.
     */
    private emitModernCall(body: MessageContent, remoteJid: string): void {
        const call = body.call as Record<string, unknown> | undefined
        if (!call) return
        const raw = call.callKey
        if (!(raw instanceof Uint8Array)) return
        const key = parseCallKey(raw)
        this.emit(LavaClient.CALL, {
            id: key.id ?? '',
            jid: key.chatJid ?? remoteJid,
            video: false,
            direction: key.fromMe === true ? 'outgoing' : 'incoming',
            status: 'offer',
        })
    }

    /**
     * Handles a protocol message that is not user visible.
     *
     * The app-state key share and the key request are the two the library
     * acts on: they move the sync keys between the devices of an account.
     *
     * @param body The message body.
     * @param senderDeviceJid The device the message came from.
     */
    private async handleProtocolMessage(
        body: MessageContent,
        senderDeviceJid: string,
    ): Promise<void> {
        const protocol = body.protocolMessage as Record<string, unknown> | undefined
        if (!protocol) return

        const share = protocol.appStateSyncKeyShare as Record<string, unknown> | undefined
        if (share) {
            const imported = this.importAppStateKeys(share)
            if (imported > 0) {
                // The peer may have sent a key the client was missing, so a
                // sync round can now make progress.
                void this.appState
                    .sync()
                    .catch((error: unknown) => {
                        this.emit(
                            LavaClient.ERROR,
                            error instanceof Error ? error : new Error(String(error)),
                        )
                    })
            }
            return
        }

        const request = protocol.appStateSyncKeyRequest as Record<string, unknown> | undefined
        if (request) {
            await this.answerAppStateKeyRequest(request, senderDeviceJid)
        }
    }

    /**
     * Imports the sync keys of a key share.
     *
     * @param share The key share.
     * @returns The number of keys that were new.
     */
    private importAppStateKeys(share: Record<string, unknown>): number {
        const keys = share.keys
        if (!Array.isArray(keys)) return 0
        const imported: {
            keyId: Uint8Array
            keyData: Uint8Array
            timestamp: number
        }[] = []
        for (const item of keys) {
            const record = item as Record<string, unknown>
            const keyId = (record.keyId as Record<string, unknown> | undefined)?.keyId
            const keyData = (record.keyData as Record<string, unknown> | undefined)?.keyData
            if (!(keyId instanceof Uint8Array)) continue
            if (!(keyData instanceof Uint8Array)) continue
            const timestamp = (record.keyData as Record<string, unknown> | undefined)?.timestamp
            imported.push({
                keyId,
                keyData,
                timestamp: typeof timestamp === 'number' ? timestamp : Date.now(),
            })
        }
        if (imported.length === 0) return 0
        const added = this.appStateStore.upsertKeys(imported)
        if (added > 0) {
            void this.persistAppState().catch(() => undefined)
        }
        return added
    }

    /**
     * Answers a request for sync keys.
     *
     * @param request The request.
     * @param senderDeviceJid The device that asked.
     */
    private async answerAppStateKeyRequest(
        request: Record<string, unknown>,
        senderDeviceJid: string,
    ): Promise<void> {
        const entries = request.keyIds
        if (!Array.isArray(entries)) return
        const wanted = new Set<string>()
        for (const entry of entries) {
            const keyId = (entry as Record<string, unknown> | undefined)?.keyId
            if (keyId instanceof Uint8Array) wanted.add(toHex(keyId))
        }
        if (wanted.size === 0) return
        const keys = this.appStateStore
            .listKeys()
            .filter((key) => wanted.has(toHex(key.keyId)))
            .map((key) => ({
                keyId: { keyId: key.keyId },
                keyData: { keyData: key.keyData, timestamp: key.timestamp },
            }))
        if (keys.length === 0) return
        try {
            await this.sendBody(senderDeviceJid, {
                protocolMessage: {
                    type: PROTOCOL_MESSAGE_TYPE.APP_STATE_SYNC_KEY_SHARE,
                    appStateSyncKeyShare: { keys },
                },
            })
        } catch (error) {
            this.emit(
                LavaClient.ERROR,
                error instanceof Error ? error : new Error(String(error)),
            )
        }
    }

    /**
     * Handles an inbound `<receipt>` stanza.
     *
     * A receipt of the type `retry` is not a status report: it says that the
     * peer could not decrypt the message and asks for it to be sent again.
     * Such a receipt is answered right away.
     *
     * @param node The stanza.
     */
    private handleReceipt(node: BinaryNode): void {
        /**
         * The protocol work comes first: a listener that throws must not
         * keep the library from answering a peer.
         */
        const request = parseRetryReceipt(node)
        if (request) {
            this.background(this.handleRetryRequest(request))
        }

        const event: WaReceipt = {
            id: node.attrs.id ?? '',
            jid: node.attrs.from ?? '',
            type: node.attrs.type ?? '',
            ...(node.attrs.participant ? { participant: node.attrs.participant } : {}),
        }
        this.emit(LavaClient.RECEIPT, event)
    }

    /**
     * Answers a retry request of a peer.
     *
     * The peer could not decrypt a message of ours and asks for it to be
     * sent again. The answer is the very same message, encrypted for the
     * device that asked — this time with a key the device knows.
     *
     * The request is ignored when the message is not known any more, when it
     * was asked for too often, or when the peer is not the recipient of the
     * message: a peer that was never sent a message has no business asking
     * for it.
     *
     * @param request The request.
     */
    private async handleRetryRequest(request: RetryRequest): Promise<void> {
        try {
            if (request.retryCount > MAX_REMOTE_RETRY_COUNT) {
                this.logDebug('retry request ignored: the retry limit was reached')
                return
            }

            const outbound = this.outboundMessages.get(request.originalMsgId)
            if (!outbound) {
                this.logDebug('retry request ignored: the message is unknown')
                return
            }

            const requesterJid = request.participant ?? request.from
            if (!requesterJid) return

            if (!this.isRetryRequesterAllowed(outbound, requesterJid)) {
                this.logDebug('retry request ignored: the requester is not the recipient')
                return
            }

            /**
             * The peer counts the retries itself, but a peer that always
             * claims to be the first attempt must not keep the client busy
             * either.
             */
            const counterKey = `${request.originalMsgId}|${requesterJid}`
            const attempts = (this.resendCounts.get(counterKey) ?? 0) + 1
            if (attempts > MAX_REMOTE_RETRY_COUNT) {
                this.logDebug('retry request ignored: the device asked too often', {
                    id: request.originalMsgId,
                    requester: requesterJid,
                })
                return
            }
            this.resendCounts.set(counterKey, attempts)

            const address = parseSignalAddressFromJid(requesterJid)
            await this.prepareRetrySession(request, requesterJid)

            const encrypted = this.signal.encryptForDevice(requesterJid, outbound.plaintext)

            if (outbound.isGroup) {
                /**
                 * The device could not read the message, so it did not get the
                 * sender key either. The next message has to carry the
                 * distribution again.
                 */
                this.signal.senderKeyManager.forgetDistribution(outbound.to, address)
            }

            this.send(
                buildRetryMessageNode(
                    {
                        to: outbound.isGroup ? outbound.to : requesterJid,
                        type: outbound.type,
                        id: request.originalMsgId,
                        ...(outbound.mediatype ? { mediatype: outbound.mediatype } : {}),
                    },
                    encrypted.encType,
                    encrypted.ciphertext,
                    request.retryCount,
                    outbound.isGroup ? requesterJid : undefined,
                ),
            )
            this.logDebug('retry request answered', {
                id: request.originalMsgId,
                requester: requesterJid,
            })
        } catch (error) {
            this.emitError(error)
        }
    }

    /**
     * Decides whether a peer may ask for a message to be sent again.
     *
     * A peer may only ask for a message that was addressed to it. The one
     * exception is our own other devices: they receive the messages of the
     * account as well.
     *
     * @param outbound The message.
     * @param requesterJid The device that asked.
     */
    private isRetryRequesterAllowed(
        outbound: { to: string; isGroup: boolean },
        requesterJid: string,
    ): boolean {
        if (outbound.isGroup) {
            // Every member of a group may ask for the messages of the group.
            const members = this.groupParticipants.get(outbound.to)?.participants
            if (!members || members.length === 0) return true
            const requesterUser = toUserJid(requesterJid)
            return members.some(
                (member) =>
                    toUserJid(member.jid) === requesterUser ||
                    (member.phoneJid ? toUserJid(member.phoneJid) === requesterUser : false),
            )
        }

        const meJid = this.credentials?.meJid
        const requesterUser = toUserJid(requesterJid)
        if (toUserJid(outbound.to) === requesterUser) return true
        return meJid ? toUserJid(meJid) === requesterUser : false
    }

    /**
     * Makes sure a session with the device that asked for a retry exists.
     *
     * The peer usually sends its key bundle along with the request, so the
     * session can be rebuilt without asking the server. A peer that re-uses
     * the registration id of another device invalidates the old session: the
     * keys of the new device are needed to talk to it.
     *
     * @param request The request.
     * @param requesterJid The device that asked.
     * @param address The address of the device.
     */
    private async prepareRetrySession(
        request: RetryRequest,
        requesterJid: string,
    ): Promise<void> {
        const bundle = request.keyBundle
        const session = this.signal.getSession(requesterJid)

        /**
         * A peer that re-uses the registration id of another device
         * invalidates the old session: the keys of the new device are
         * needed to talk to it.
         */
        if (session && request.regId && session.remote.regId !== request.regId) {
            this.signal.removeSession(requesterJid)
        }

        if (bundle) {
            // The peer sent its keys along with the request, so the session
            // can be rebuilt without asking the server.
            this.signal.ensureSession(requesterJid, {
                regId: request.regId ?? 0,
                identity: bundle.identity,
                signedKey: bundle.signedKey,
                oneTimeKey: bundle.oneTimeKey ?? null,
            })
            return
        }

        await this.ensureSignalSession(requesterJid)
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
        this.emit(LavaClient.MESSAGE_ACK, event)
    }

    /**
     * Handles a `<failure/>` stanza.
     *
     * The server refuses a session with a `<failure/>` stanza and closes the
     * socket right after it. The reason decides what happens to the
     * session: a reason that ends the session for good clears the stored
     * credentials, because a device whose credentials the server rejects
     * has to pair again; a reason that only interrupts the connection keeps
     * them, so the client may connect again.
     *
     * @param node The stanza.
     */
    private handleFailure(node: BinaryNode): void {
        const failure = parseFailureNode(node)
        this.emit(LavaClient.FAILURE, failure)
        this.logger.log({
            level: 'warn',
            message: `the server refused the session (reason ${failure.reason ?? 'unknown'})`,
            fields: {
                ...(failure.reason !== undefined ? { reason: failure.reason } : {}),
                ...(failure.code !== undefined ? { code: failure.code } : {}),
                ...(failure.location ? { location: failure.location } : {}),
            },
        })

        if (failure.logout) {
            // The credentials are worthless. The device has to pair again,
            // so the stored ones are removed and no reconnect is attempted.
            this.stopping = true
            this.background(this.endSession(failure))
            return
        }

        if (failure.disconnect) {
            // The credentials stay valid: the connection may be re-established.
            this.transport?.close()
            return
        }

        // An unknown reason says nothing about the session. The server
        // closes the socket anyway, and the close handler takes it from
        // there.
    }

    /**
     * Ends a session the server refused for good.
     *
     * The connection is closed, the stored credentials are removed and the
     * client reports the end of the session with the `logout` event.
     *
     * @param failure The failure the server reported.
     */
    private async endSession(failure: WaFailure): Promise<void> {
        this.transport?.close()
        this.transport = null
        try {
            await this.store.clear()
        } catch (error) {
            this.emitError(error)
        }
        this.credentials = null
        this.setState('disconnected')
        this.emit(LavaClient.LOGOUT, failure)
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
                    LavaClient.ERROR,
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
                // The attestation secret is rotated with every pairing
                // attempt, the way the official client does it.
                advSecretKey: toBase64(randomBytesOf(32)),
            })
            const response = await this.query(
                buildCompanionHelloRequestNode({
                    phoneJid,
                    wrappedCompanionEphemeralPub: hello.wrappedCompanionEphemeralPub,
                    companionServerAuthKeyPub: fromBase64(credentials.noiseKeyPair.pub),
                    companionPlatformId: WA_COMPANION_PLATFORM_ID.ELECTRON,
                    companionPlatformDisplay: this.companionPlatformDisplay(),
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
            this.emit(LavaClient.AUTH_PAIRING_CODE, { code: hello.pairingCode })
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
     * The phone-number registration API.
     *
     * Registering a number is the *mobile primary* way into an account: the
     * library claims the number itself instead of attaching to somebody
     * else's phone as a companion. The server verifies the number out of band
     * — by SMS or by a voice call — and the account's whole state is pushed to
     * the library afterwards.
     *
     * ```ts
     * const client = new LavaClient({ transport: 'mobile' })
     * await client.registration.requestCode('+6281234567890')
     * await client.registration.confirm('123456')
     * await client.connect()
     * ```
     */
    readonly registration = {
        /**
         * Asks the server for a verification code for a phone number.
         *
         * The `/exist` endpoint is consulted first, but only to catch the
         * one case the caller cannot recover from: a number that is already
         * an account. The endpoint answers most requests with a refusal that
         * says nothing about the number, so the truth comes from the code
         * request itself.
         *
         * @param phoneNumber The phone number, in international format.
         * @param options The options.
         */
        requestCode: async (
            phoneNumber: string,
            options: LavaRegistrationOptions = {},
        ): Promise<LavaCodeRequest> => {
            const session = await this.createRegistrationSession(phoneNumber, options)
            const status = await LavaRegistration.checkNumber(session, options)
            if (status.registered) {
                throw new Error(
                    'lava: the number is already an account — ' +
                        'pair as a companion device instead of registering it',
                )
            }
            const request = await LavaRegistration.requestCode(
                session,
                options.method ?? 'sms',
                options,
            )
            if (!request.ok) {
                throw new Error(
                    `lava: the server refused to send a code — ` +
                        `${describeRegistrationFailure(request.reason)}`,
                )
            }
            this.registrationSession = session
            // The code arrives by SMS, which can take minutes: the material
            // of the registration has to outlive the process that asked for
            // it, or the code could never be handed back.
            await this.updateCredentials({
                registration: {
                    phoneNumber: session.phoneNumber,
                    ...LavaRegistration.materialOf(session),
                    ...(request.method !== undefined ? { codeMethod: request.method } : {}),
                },
            })
            this.emit(LavaClient.AUTH_REGISTRATION_CODE, {
                phoneNumber: session.phoneNumber,
                method: request.method,
                ...(request.length !== undefined ? { length: request.length } : {}),
                ...(request.wait !== undefined ? { wait: request.wait } : {}),
            })
            return request
        },

        /**
         * Hands the verification code back and claims the number.
         *
         * @param code The code the user received.
         * @param options The options.
         */
        confirm: async (
            code: string,
            options: LavaRegistrationOptions = {},
        ): Promise<LavaRegistrationResult> => {
            const session = this.registrationSession ?? (await this.restoreRegistrationSession())
            if (!session) {
                throw new Error('lava: no code was requested for this session')
            }
            const result = await LavaRegistration.submitCode(session, code, options)
            if (!result.ok) {
                throw new Error(
                    `lava: the server refused the code — ` +
                        `${describeRegistrationFailure(result.reason)}`,
                )
            }
            const canonical = result.canonicalNumber ?? session.nationalNumber
            const meJid = `${canonical}@s.whatsapp.net`
            // The sender keys name their owner.
            this.signal.senderKeyManager.setLocalAddress(meJid)
            // The account was claimed as the device the registration
            // described, so the connection has to announce the very same
            // device — otherwise the server sees two different phones.
            await this.updateCredentials({
                meJid,
                transport: 'mobile',
                deviceInfo: this.deviceInfoFromRegistration(session),
                registration: undefined,
            })
            this.registrationSession = undefined
            this.emit(LavaClient.AUTH_REGISTERED, { meJid })
            return result
        },

        /**
         * Asks the server whether a number is already an account.
         *
         * The answer is advisory: the endpoint refuses most requests with an
         * answer that says nothing about the number. `conclusive` reports
         * whether the server actually ruled on it.
         *
         * @param phoneNumber The phone number, in international format.
         * @param options The options.
         */
        status: async (
            phoneNumber: string,
            options: LavaRegistrationOptions = {},
        ): Promise<LavaNumberStatus> => {
            const session = await this.createRegistrationSession(phoneNumber, options)
            return LavaRegistration.checkNumber(session, options)
        },
    }

    /**
     * Builds the registration session of a phone number.
     *
     * The identity material comes from the same key store the connection
     * uses, so the number is claimed by exactly the device that later logs
     * in with it.
     *
     * The platform follows the profile the client was given, so that the
     * registration and the connection describe the same phone. A client
     * without a profile registers as an iPhone: the token an Android
     * registration carries is derived from the signed application package,
     * which no library can reproduce — so an Android registration has to
     * bring its own token.
     *
     * @param phoneNumber The phone number, in international format.
     * @param options The options.
     */
    private async createRegistrationSession(
        phoneNumber: string,
        options: LavaRegistrationOptions,
    ): Promise<LavaRegistrationSession> {
        const credentials = this.credentials ?? (await this.ensureCredentials())
        const registration = this.keyStore.getRegistrationInfo()
        const signedPreKey = this.keyStore.getSignedPreKey()
        if (!registration || !signedPreKey) {
            throw new Error('lava: the device has no Signal identity to register with')
        }
        const profile = this.options.deviceProfile ?? DEFAULT_IOS_PROFILE
        // A registration that is already under way has to look like the very
        // same device, so its material is carried over.
        const stored = credentials.registration
        const canonical = canonicalPhoneNumber(phoneNumber)
        const material =
            options.material ?? (stored?.phoneNumber === canonical ? stored : undefined)
        return LavaRegistration.createSession(
            phoneNumber,
            {
                noiseKeyPair: credentials.noiseKeyPair,
                identityKeyPair: credentials.identityKeyPair,
                registrationId: registration.registrationId,
                signedPreKey: {
                    id: signedPreKey.keyId,
                    keyPair: {
                        pub: toBase64(signedPreKey.keyPair.pubKey),
                        priv: toBase64(signedPreKey.keyPair.privKey),
                    },
                    signature: toBase64(signedPreKey.signature),
                },
            },
            {
                ...options,
                ...(material !== undefined ? { material } : {}),
                appVersion: options.appVersion ?? profile.appVersion,
                device: {
                    os: options.device?.os ?? profile.os,
                    model: options.device?.model ?? profile.device,
                    osVersion: options.device?.osVersion ?? profile.osVersion,
                    osBuildNumber: options.device?.osBuildNumber ?? profile.osBuildNumber,
                    manufacturer: options.device?.manufacturer ?? profile.manufacturer,
                    appVersion: options.appVersion ?? profile.appVersion ?? '',
                    ...(options.device?.ram !== undefined ? { ram: options.device.ram } : {}),
                },
            },
        )
    }

    /**
     * Rebuilds the registration that is under way.
     *
     * The verification code arrives by SMS, which can take minutes — by the
     * time it does, the process that asked for it may be gone. The session
     * is therefore rebuilt from the material that was kept.
     *
     * @returns The registration session, when there is one.
     */
    private async restoreRegistrationSession(): Promise<LavaRegistrationSession | undefined> {
        const credentials = this.credentials ?? (await this.ensureCredentials())
        const stored = credentials.registration
        if (!stored) return undefined
        return this.createRegistrationSession(stored.phoneNumber, {
            material: {
                deviceId: stored.deviceId,
                identityId: stored.identityId,
                advertisingId: stored.advertisingId,
                installId: stored.installId,
                accessSessionId: stored.accessSessionId,
            },
        })
    }

    /**
     * Extracts the device a registration described.
     *
     * The device has to survive the registration: the account was claimed as
     * that phone, so the connection announces it.
     *
     * @param session The registration session.
     */
    private deviceInfoFromRegistration(
        session: LavaRegistrationSession,
    ): NonNullable<CredentialSnapshot['deviceInfo']> {
        return {
            appVersion: session.device.appVersion,
            device: session.device.model,
            osVersion: session.device.osVersion,
            osBuildNumber: session.device.osBuildNumber ?? '',
            manufacturer: session.device.manufacturer,
            os: session.device.os,
        }
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
                mediaId: generateMediaId(),
            })
        },

        /**
         * Downloads and decrypts the media of a message.
         *
         * @param source The inbound message, the raw message body, or a
         *               media payload that was extracted earlier.
         */
        download: async (
            source: WaInboundMessage | MessageContent | MediaPayload | WaMediaUpload,
        ): Promise<Uint8Array> => {
            const payload = this.resolveMediaPayload(source)
            if (!payload) throw new Error('client: the message carries no downloadable media')
            // The media connection names the CDN hosts that serve the file.
            // When it cannot be fetched the well known hosts are used.
            const conn = await this.mediaConn
                .get(this.mediaTransferOptions())
                .catch(() => null)
            return downloadMedia(
                {
                    ...this.mediaTransferOptions(),
                    ...(conn ? { conn } : {}),
                },
                payload,
            )
        },
    }

    /** The app-state API. */
    readonly appState = {
        /**
         * Runs a sync round.
         *
         * The server answers with the state of every requested collection:
         * either a snapshot (the whole collection) or the patches that
         * happened since the version the device already had.
         *
         * @param options The options.
         */
        sync: async (options: AppStateSyncOptions = {}): Promise<AppStateSyncResult> => {
            const client = this.appStateClient()
            const pending = this.pendingAppState.splice(0, this.pendingAppState.length)
            const result = await client.sync({
                ...options,
                pendingMutations: [...(options.pendingMutations ?? []), ...pending],
            })
            // The changes of a collection that the server did not accept
            // stay pending, so the next round pushes them again.
            const accepted = new Set(
                result.collections
                    .filter((entry) => entry.uploaded)
                    .map((entry) => entry.collection),
            )
            for (const mutation of pending) {
                if (!accepted.has(mutation.collection)) {
                    this.pendingAppState.push(mutation)
                }
            }
            await this.persistAppState()
            return result
        },

        /**
         * Records a change that the next sync round pushes to the server.
         *
         * @param collection The collection.
         * @param index The index of the record.
         * @param value The value of the record.
         */
        set: (
            collection: string,
            index: string,
            value: Record<string, unknown>,
            version = 1,
        ): void => {
            this.pendingAppState.push({ collection, operation: 'set', index, value, version })
        },

        /**
         * Records the removal of a record, which the next sync round pushes
         * to the server.
         *
         * @param collection The collection.
         * @param index The index of the record.
         */
        remove: (collection: string, index: string, version = 1): void => {
            this.pendingAppState.push({ collection, operation: 'remove', index, version })
        },

        /**
         * Lists the sync keys the device knows about.
         */
        keys: () =>
            this.appStateStore.listKeys().map((key) => ({
                keyId: toHex(key.keyId),
                keyData: toHex(key.keyData),
                timestamp: key.timestamp,
            })),

        /**
         * Returns the state of a collection.
         *
         * @param collection The collection.
         */
        state: (collection: string) => {
            const state = this.appStateStore.getCollectionState(collection)
            return {
                initialized: state.initialized,
                version: state.version,
                hash: toHex(state.hash),
                records: state.indexValueMap.size,
            }
        },

        /**
         * Shares the sync keys with another device of the account.
         *
         * @param to The device to share with.
         * @param keyIds The ids of the keys to share; every known key by
         *   default.
         */
        share: async (to: string, keyIds?: readonly Uint8Array[]): Promise<string> => {
            const wanted = keyIds
                ? keyIds.map((id) => toHex(id))
                : this.appStateStore.listKeys().map((key) => toHex(key.keyId))
            const keys = this.appStateStore
                .listKeys()
                .filter((key) => wanted.includes(toHex(key.keyId)))
                .map((key) => ({
                    keyId: { keyId: key.keyId },
                    keyData: {
                        keyData: key.keyData,
                        timestamp: key.timestamp,
                    },
                }))
            return this.sendBody(to, {
                protocolMessage: {
                    type: PROTOCOL_MESSAGE_TYPE.APP_STATE_SYNC_KEY_SHARE,
                    appStateSyncKeyShare: { keys },
                },
            })
        },

        /**
         * Asks another device of the account for sync keys.
         *
         * @param to The device to ask.
         * @param keyIds The ids of the keys that are missing.
         */
        request: async (to: string, keyIds: readonly Uint8Array[]): Promise<string> => {
            return this.sendBody(to, {
                protocolMessage: {
                    type: PROTOCOL_MESSAGE_TYPE.APP_STATE_SYNC_KEY_REQUEST,
                    appStateSyncKeyRequest: {
                        keyIds: keyIds.map((keyId) => ({ keyId })),
                    },
                },
            })
        },
    }

    /**
     * Builds the app-state sync client.
     *
     * The client is rebuilt whenever the connection changes, because it
     * holds a reference to the transport.
     */
    private appStateClient(): AppStateSyncClient {
        return new AppStateSyncClient({
            query: (node, timeoutMs) => this.query(node, timeoutMs),
            store: this.appStateStore,
            getMeJid: () => this.credentials?.meJid,
            mobilePrimary: (this.options.transport ?? 'mobile') === 'mobile',
            logger: this.logger,
            onMissingKeys: (keyIds) => this.requestAppStateKeys(keyIds),
            downloadExternalBlob: async (
                _collection: string,
                _kind: 'snapshot' | 'patch',
                reference: AppStateExternalBlob,
            ) => {
                const conn = await this.mediaConn
                    .get(this.mediaTransferOptions())
                    .catch(() => null)
                return downloadMedia(
                    {
                        ...this.mediaTransferOptions(),
                        ...(conn ? { conn } : {}),
                    },
                    {
                        // The official client stores both the snapshot and
                        // the external patch under the same media type.
                        mediaType: 'md-app-state',
                        directPath: reference.directPath,
                        mediaKey: reference.mediaKey,
                        ...(reference.fileSha256 ? { fileSha256: reference.fileSha256 } : {}),
                        ...(reference.fileEncSha256
                            ? { fileEncSha256: reference.fileEncSha256 }
                            : {}),
                    },
                )
            },
        })
    }

    /**
     * Asks the other devices of the account for the sync keys that are
     * missing.
     *
     * The devices of an account share their keys with each other, so a
     * device that joins later can ask for the ones it does not have yet.
     *
     * @param keyIds The ids of the keys that are missing.
     */
    private async requestAppStateKeys(keyIds: readonly Uint8Array[]): Promise<void> {
        const devices = this.ownAccountDevices()
        if (devices.length === 0) return
        for (const device of devices) {
            try {
                await this.appState.request(device, keyIds)
            } catch (error) {
                this.warn('app-state: the request for a sync key failed', error)
            }
        }
    }

    /**
     * Lists the other devices of the account.
     *
     * The device index of the paired JID names the device itself, so the
     * other devices are the ones around it.
     *
     * @returns The device JIDs of the account.
     */
    private ownAccountDevices(): string[] {
        const meJid = this.credentials?.meJid
        if (!meJid) return []
        const match = /^(.*?):(\d+)@(.*)$/.exec(meJid)
        if (!match) return []
        const [, user, device, server] = match
        const index = Number.parseInt(device!, 10)
        if (!Number.isSafeInteger(index)) return []
        const devices: string[] = []
        // The account holds at most a handful of linked devices; the
        // official client uses the same window when it looks for a peer.
        for (let i = 0; i <= 5; i++) {
            if (i === index) continue
            devices.push(`${user}:${i}@${server}`)
        }
        return devices
    }

    /**
     * Persists the app-state store.
     *
     * The sync keys and the collection state have to survive a restart, or
     * the client would ask the server for a fresh snapshot every time.
     */
    private async persistAppState(): Promise<void> {
        await this.updateCredentials(() => ({
            appState: this.appStateStore.toSnapshot(),
        }))
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
        source: WaInboundMessage | MessageContent | MediaPayload | WaMediaUpload,
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

        /**
         * Reads the metadata of a group.
         *
         * The metadata holds the settings of the group and the list of its
         * members.
         *
         * @param groupJid The group.
         */
        metadata: async (groupJid: string): Promise<GroupMetadata> => {
            const cached = this.groupParticipants.get(groupJid)
            if (cached) return cached
            const response = await this.query(buildGetGroupMetadataIq(groupJid))
            assertIqResult(response, 'group metadata')
            const metadata = parseGroupMetadata(response)
            this.groupParticipants.set(groupJid, metadata)
            this.persistGroupMetadata()
            return metadata
        },

        /**
         * Reads the members of a group.
         *
         * @param groupJid The group.
         */
        participants: async (groupJid: string): Promise<GroupParticipant[]> => {
            return this.queryGroupParticipants(groupJid)
        },

        /**
         * Drops the cached membership of a group.
         *
         * The next read asks the group server again. The server refuses a
         * client that queries the same group too often, so the membership is
         * only refreshed when it is really needed.
         *
         * @param groupJid The group.
         */
        refresh: (groupJid: string): void => {
            this.groupParticipants.invalidate(groupJid)
            this.persistGroupMetadata()
        },

        /**
         * Starts a new generation of the sender key of a group.
         *
         * The group is re-keyed: a fresh key id, a fresh chain key and a
         * fresh signing key pair. The generation it replaces is kept, so a
         * message that was encrypted with it can still be read. The new
         * generation is announced to the members with the next message.
         *
         * @param groupJid The group.
         * @returns The id of the new sender key.
         */
        rotateSenderKey: (groupJid: string): number => {
            const record = this.signal.senderKeyManager.rotateSenderKey(groupJid)
            return record.keyId
        },

        /**
         * Announces the sender key of a group to its members again.
         *
         * The devices that already know the sender key are not told about it
         * a second time, which keeps the stanza small. After this call every
         * device of the group receives the distribution with the next
         * message — the way to repair a member that never got the sender key.
         *
         * @param groupJid The group.
         */
        redistributeSenderKey: (groupJid: string): void => {
            this.signal.senderKeyManager.forgetDistributions(groupJid)
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
            this.emit(LavaClient.CALL, {
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

        /**
         * The plaintext is kept for a while: a peer that cannot decrypt the
         * message asks for it to be sent again, and the answer needs the
         * original plaintext.
         */
        this.outboundMessages.set(id, {
            to,
            plaintext,
            type: attrs.typeAttr,
            isGroup: isGroupJid(to),
            ...(attrs.mediatype ? { mediatype: attrs.mediatype } : {}),
            sentAtMs: Date.now(),
        })

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
        /**
         * A group either names its members by phone number or by their
         * linked identity. The mode decides which address the sender uses
         * for itself, which address the members are reached with, and it
         * travels in the `addressing_mode` attribute of the stanza: a group
         * message that leaves it out is not delivered.
         */
        const members = await this.queryGroupParticipants(groupJid)
        if (members.length === 0) {
            throw new Error(`client: no members known for ${groupJid}`)
        }
        const addressingMode = resolveGroupAddressingMode(members)
        const senderJid = this.signal.senderKeyManager.resolveSenderAddress(addressingMode)

        const devices = await this.resolveGroupDevices(groupJid)
        if (devices.length === 0) {
            throw new Error(`client: no devices known for ${groupJid}`)
        }

        const group = this.signal.encryptForGroup(groupJid, plaintext, senderJid)
        const distribution = group.distributionMessage
        if (!distribution) throw new Error('client: no sender key distribution was produced')

        /**
         * The distribution travels to the participants as a pairwise payload:
         * the receiver decodes it as a `Message` and picks the distribution
         * out of the `senderKeyDistributionMessage` field.
         */
        const distributionPayload = prepareSenderKeyDistributionPayload(
            groupJid,
            distribution,
        )

        /**
         * Only the devices that do not know the sender key yet need the
         * distribution. Sending it to every device of every member again
         * would multiply the size of the stanza for nothing.
         */
        const senderKeyId = group.senderKeyId ?? 0
        const pendingAddresses = this.signal.senderKeyManager
            .filterParticipantsNeedingDistribution(
                groupJid,
                senderKeyId,
                devices.map((device) => parseSignalAddressFromJid(device.jid)),
            )
        const pendingJids = new Set(
            pendingAddresses.map((address) => `${address.user}|${address.server}|${address.device}`),
        )

        const participants: EncryptedParticipant[] = []
        const distributed: JidParts[] = []
        for (const device of devices) {
            const address = parseSignalAddressFromJid(device.jid)
            const key = `${address.user}|${address.server}|${address.device}`
            if (!pendingJids.has(key)) continue
            await this.ensureSignalSession(device.jid)
            const encrypted = this.signal.encryptForDevice(device.jid, distributionPayload)
            participants.push({
                jid: device.jid,
                encType: encrypted.encType,
                ciphertext: encrypted.ciphertext,
            })
            distributed.push(address)
        }
        this.signal.senderKeyManager.markSenderKeyDistributed(
            groupJid,
            senderKeyId,
            distributed,
        )

        /**
         * The participant hash covers the devices the message is fanned out
         * to, plus the sender itself. The local device is not part of the
         * fanout: it reads its own copy out of the sender key it holds.
         */
        const phashTargets: string[] = this.groupFanoutDevices(groupJid, devices)
        if (senderJid) phashTargets.push(senderJid)

        this.send(
            buildGroupSenderKeyMessageNode(
                {
                    to: groupJid,
                    type: attrs.typeAttr,
                    id,
                    phash: computePhashV2(phashTargets),
                    addressingMode,
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
        const entries = await this.queryDeviceLists(participants.map((p) => p.jid))
        const out: DeviceEntry[] = []
        for (const entry of entries) out.push(...entry.devices)
        return out
    }

    /**
     * Returns the devices a group message is fanned out to.
     *
     * The local device is left out: it reads its own copy of the message out
     * of the sender key it holds, so a copy for itself would be a waste.
     *
     * @param groupJid The group.
     * @param devices The devices of every member.
     */
    private groupFanoutDevices(groupJid: string, devices: readonly DeviceEntry[]): string[] {
        const local = new Set<string>()
        const meJid = this.credentials?.meJid
        const meLid = this.credentials?.meLid
        if (meJid) local.add(this.normalizeDeviceJid(meJid))
        if (meLid) local.add(this.normalizeDeviceJid(meLid))

        const out: string[] = []
        for (const device of devices) {
            if (local.has(this.normalizeDeviceJid(device.jid))) continue
            out.push(device.jid)
        }
        return out
    }

    /**
     * Normalizes a device address to the `user:device@server` form.
     *
     * @param jid The address.
     */
    private normalizeDeviceJid(jid: string): string {
        const address = parseSignalAddressFromJid(jid)
        const server = address.server ?? HOST_DOMAIN
        return address.device === 0
            ? `${address.user}@${server}`
            : `${address.user}:${address.device}@${server}`
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
     * The group server answers a `w:g2` query with the metadata of the group,
     * the member list included. The members are addressed by their linked
     * identity (LID) when the group uses that addressing mode, and by their
     * phone number otherwise.
     *
     * The answer is cached: the group server refuses a client that asks for
     * the member list of the same group over and over.
     *
     * @param groupJid The group.
     * @param refresh Whether the cached answer may be ignored.
     */
    private async queryGroupParticipants(
        groupJid: string,
        refresh = false,
    ): Promise<GroupParticipant[]> {
        if (!refresh) {
            const cached = this.groupParticipants.get(groupJid)
            if (cached) return cached.participants
        }
        const response = await this.query(buildGetGroupMetadataIq(groupJid))
        assertIqResult(response, 'group participants')
        const participants = parseGroupParticipants(response)
        /**
         * The very same answer holds the settings of the group as well, so
         * the whole metadata is cached: a later read of the metadata does
         * not have to ask the server again.
         */
        let metadata: GroupMetadata = { jid: groupJid, participants }
        try {
            metadata = parseGroupMetadata(response)
        } catch {
            // The answer held no group node; the member list is what matters.
        }
        this.groupParticipants.set(groupJid, metadata)
        this.persistGroupMetadata()
        return participants
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
        /**
         * The server answers with *every* device of the user, not only the one
         * that was asked for, and the answer is not ordered by device id. The
         * bundle of the requested device therefore has to be picked
         * explicitly: taking the first entry hands the identity key of a
         * different device to the session, and every later message of that
         * device fails to decrypt.
         */
        const bundle = selectPreKeyBundle(results[0]?.devices ?? [], deviceJid)
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
            this.emitError(error)
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
                LavaClient.ERROR,
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

/**
 * The old name of {@link LavaClient}.
 *
 * @deprecated Use {@link LavaClient} instead.
 */
export { LavaClient as WaClient }

/**
 * The old name of {@link LavaClientOptions}.
 *
 * @deprecated Use {@link LavaClientOptions} instead.
 */
export type { LavaClientOptions as WaClientOptions }
