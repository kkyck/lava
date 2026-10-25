/**
 * Lava — an ultra-lightweight, zero-dependency WhatsApp library.
 *
 * The library talks to WhatsApp's own protocol directly: the WAP (mobile) API
 * and the WhatsApp Web API, the Signal double ratchet, the Noise handshake
 * and the binary node codec. Nothing is delegated to a third-party runtime,
 * so the only dependency is Node.js itself.
 *
 * ```ts
 * import { LavaClient } from 'lava'
 *
 * const client = new LavaClient({ transport: 'mobile' })
 * client.on('message', (m) => console.log(m.jid, m.text))
 * await client.connect()
 * await client.message.send('6281234567890@s.whatsapp.net', 'Hello')
 * ```
 *
 * @module lava
 */

// ── Client ──────────────────────────────────────────────────────────────────

export {
    LavaClient,
    WaClient,
    type WaCallEvent,
    type LavaClientOptions,
    type WaClientOptions,
    type WaConnectionState,
    type WaInboundMessage,
    type WaMediaMessageOptions,
    type WaMessageAck,
    type WaReceipt,
    type WaSessionInfo,
    type WaTransport,
    type WaTransportFactory,
    type WaTransportMode,
} from './client.js'

// ── Logging ─────────────────────────────────────────────────────────────────

export {
    WA_LOG_LEVELS,
    childLogger,
    createConsoleLogger,
    createSilentLogger,
    type ConsoleLoggerOptions,
    type WaLogLevel,
    type WaLogRecord,
    type WaLogger,
} from './logger.js'

// ── Credentials ─────────────────────────────────────────────────────────────

export {
    FileCredentialStore,
    MemoryCredentialStore,
    fromBase64,
    toBase64,
    type CredentialSnapshot,
    type CredentialStore,
    type StoredKeyPair,
} from './auth/credentials.js'

// ── Registration (mobile primary) ───────────────────────────────────────────

export {
    LavaRegistration,
    buildRegistrationForm,
    computeRegistrationToken,
    encryptRegistrationPayload,
    newRegistrationRequestId,
    parsePhoneNumber,
    toBase64Url,
    toUrlHex,
    type LavaCodeMethod,
    type LavaCodeRequest,
    type LavaCountryMeta,
    type LavaNumberStatus,
    type LavaRegistrationDevice,
    type LavaRegistrationIdentity,
    type LavaRegistrationOptions,
    type LavaRegistrationPlatform,
    type LavaRegistrationResult,
    type LavaRegistrationSession,
} from './auth/registration.js'

export {
    CROCKFORD_ALPHABET,
    PBKDF2_ITERATIONS,
    completeCompanionFinish,
    createCompanionHello,
    encodeBytesToCrockford,
    normalizeCustomPairingCode,
    type CompanionFinish,
    type CompanionFinishInput,
    type CompanionHello,
    type CompanionHelloOptions,
} from './auth/pairing.js'

// ── Protocol ────────────────────────────────────────────────────────────────

export {
    WA_ADDRESSING_MODES,
    WA_CALL_NODE_ATTRS,
    WA_CALL_PAYLOAD_TAGS,
    WA_CHATSTATE_MEDIA,
    WA_DEFAULTS,
    WA_ENC_CIPHERTEXT_TYPES,
    WA_ENC_MEDIA_TYPES,
    WA_IQ_TYPES,
    WA_MESSAGE_TAGS,
    WA_MESSAGE_TYPES,
    WA_NODE_TAGS,
    WA_NOTIFICATION_TYPES,
    WA_PRESENCE_TYPES,
    WA_PRIVACY_VALUES,
    WA_STANZA_MSG_TYPES,
    WA_XMLNS,
} from './protocol/constants.js'

export {
    BROADCAST_SERVER,
    GROUP_SERVER,
    HOST_DOMAIN,
    HOSTED_LID_SERVER,
    HOSTED_SERVER,
    LID_SERVER,
    NEWSLETTER_SERVER,
    buildDeviceJid,
    getLoginIdentity,
    isBroadcastJid,
    isGroupJid,
    isLidJid,
    isNewsletterJid,
    isOwnAccountJid,
    isUserJid,
    normalizeRecipientJid,
    parsePhoneJid,
    splitJid,
    toUserJid,
} from './protocol/jid.js'

export {
    EDIT_ATTRS,
    PROTOCOL_MESSAGE_TYPE,
    buildContactContent,
    buildLocationContent,
    buildPollContent,
    buildReactionContent,
    buildRevokeContent,
    buildTextContent,
    getContentType,
    reactionGroupingKey,
    resolveOutboundMessageAttrs,
    unwrapMessage,
    type MessageContent,
    type MessageKey,
    type OutboundMessageAttrs,
    type PollOption,
    type TextMessageOptions,
} from './protocol/message.js'

export { computePhashV2 } from './protocol/phash.js'

export {
    buildAudioContent,
    buildDocumentContent,
    buildImageContent,
    buildMediaContent,
    buildStickerContent,
    buildVideoContent,
    resolveMediaPayload,
    type MediaMessageOptions,
    type MediaPayload,
    type WaMediaType,
} from './protocol/media.js'

// ── Media ────────────────────────────────────────────────────────────────────

export {
    MEDIA_HKDF_INFO,
    MEDIA_KEY_LENGTH,
    decryptMedia,
    deriveMediaKeys,
    encryptMedia,
    encryptedMediaLength,
    getMediaHkdfInfo,
    type DecryptedMedia,
    type EncryptedMedia,
    type MediaKeys,
} from './media/crypto.js'

export {
    DEFAULT_MEDIA_HOSTS,
    MEDIA_TIMEOUT_MS,
    MEDIA_UPLOAD_PATHS,
    MediaConnectionCache,
    buildMediaConnIq,
    buildMediaUploadUrl,
    defaultMediaHttpHandler,
    downloadMedia,
    generateMediaId,
    hostSupportsType,
    isMediaConnExpired,
    mediaConnNeedsRefresh,
    parseMediaConnResponse,
    selectMediaFallbackHost,
    selectMediaHost,
    uploadMedia,
    type MediaHttpHandler,
    type MediaHttpRequest,
    type MediaHttpResponse,
    type MediaTransferOptions,
    type WaMediaConn,
    type WaMediaHost,
    type WaMediaUpload,
} from './media/transfer.js'

// ── App state ────────────────────────────────────────────────────────────────

export {
    APP_STATE_COLLECTIONS,
    APP_STATE_COLLECTION_STATES,
    APP_STATE_DEFAULT_COLLECTIONS,
    APP_STATE_ERROR_CODES,
    APP_STATE_KEY_TYPES,
    APP_STATE_KDF_INFO,
    APP_STATE_LT_HASH_SIZE,
    APP_STATE_VALUE_MAC_LENGTH,
} from './appstate/constants.js'

export {
    AppStateCrypto,
    type AppStateDecryptedMutation,
    type AppStateDerivedKeys,
    type AppStateEncryptedMutation,
    type AppStateOperation,
} from './appstate/crypto.js'

export {
    buildSyncKeyId,
    generateSyncKey,
    pickActiveSyncKey,
    syncKeyDeviceId,
    syncKeyEpoch,
    type AppStateSyncKey,
} from './appstate/keys.js'

export {
    AppStateStore,
    emptyCollectionState,
    type AppStateCollectionState,
    type AppStateStoreSnapshot,
} from './appstate/store.js'

export {
    AppStateMissingKeyError,
    AppStateSyncClient,
    parseCollectionState,
    type AppStateAppliedMutation,
    type AppStateCollectionPayload,
    type AppStateCollectionResult,
    type AppStateExternalBlob,
    type AppStatePatch,
    type AppStatePendingMutation,
    type AppStateSnapshot,
    type AppStateSyncOptions,
    type AppStateSyncResult,
} from './appstate/sync.js'

// ── Messages ────────────────────────────────────────────────────────────────

export {
    collectGroupCiphertext,
    collectInboundEncryptions,
    decodeMessageBody,
    encodeMessageBody,
    extractSenderKeyDistribution,
    prepareOutboundPlaintext,
    resolveContentType,
    resolveInboundMessageKey,
    stripInboundPadding,
    summarizeMessageBody,
    type InboundEncryption,
    type InboundMessageKey,
    type SenderKeyDistribution,
} from './message/codec.js'

// ── Signal ──────────────────────────────────────────────────────────────────

export {
    SIGNAL_UPLOAD_PREKEYS_COUNT,
    buildMissingPreKeysFetchIq,
    buildPreKeyUploadIq,
    buildSignedPreKeyRotateIq,
    parseMissingPreKeysResponse,
} from './signal/api.js'

export {
    SignalKeyStore,
    generatePreKeyId,
    generatePreKeyPair,
    generateRegistrationId,
    generateRegistrationInfo,
    generateSignedPreKey,
    MAX_RETAINED_PRE_KEYS,
    type PreKeyRecord,
    type RegistrationInfo,
    type SignalKeyStoreSnapshot,
    type SignedPreKeyRecord,
} from './signal/keys.js'

export {
    buildDigestIq,
    computeKeyBundleHash,
    parseDigestResponse,
    validateKeyBundleDigest,
    SIGNAL_DIGEST_HASH_LENGTH,
    type DigestMismatchReason,
    type DigestValidation,
    type SignalDigest,
} from './signal/digest.js'

export {
    SignalSessionManager,
    type DecryptedFromPeer,
    type EncryptedForPeer,
    type PreKeyFetcher,
    type RemoteKeyBundle,
    type SignalSessionManagerOptions,
} from './signal/manager.js'

export {
    deserializeIdentity,
    deserializeInitialExchangeInfo,
    deserializeMessageKey,
    deserializeRecvChain,
    deserializeSendChain,
    deserializeSenderKeyMessageKey,
    deserializeSenderKeyRecord,
    deserializeSignalSession,
    serializeIdentity,
    serializeInitialExchangeInfo,
    serializeMessageKey,
    serializeRecvChain,
    serializeSendChain,
    serializeSenderKeyMessageKey,
    serializeSenderKeyRecord,
    serializeSignalSession,
    type SerializedInitialExchangeInfo,
    type SerializedMessageKey,
    type SerializedRecvChain,
    type SerializedSendChain,
    type SerializedSenderKeyMessageKey,
    type SerializedSenderKeyRecord,
    type SerializedSenderKeyState,
    type SerializedSignalIdentity,
    type SerializedSignalSession,
} from './signal/persistence.js'

export {
    SenderKeyChain,
    SenderKeyManager,
    deriveSenderKeyMessageKey,
    type GroupEncryptionResult,
    type SenderKeyDerivation,
    type SenderKeyMessageKey,
    type SenderKeyRecord,
} from './signal/group.js'

export {
    DeviceListStore,
    buildDeviceListUsyncIq,
    parseDeviceListResponse,
    type DeviceEntry,
    type DeviceListEntry,
} from './signal/device-list.js'

export {
    ADV_PREFIX_ACCOUNT_KEY_INDEX,
    ADV_PREFIX_ACCOUNT_SIGNATURE,
    ADV_PREFIX_DEVICE_SIGNATURE,
    ADV_PREFIX_HOSTED_ACCOUNT_KEY_INDEX,
    ADV_PREFIX_HOSTED_ACCOUNT_SIGNATURE,
    ADV_PREFIX_HOSTED_DEVICE_SIGNATURE,
    ADVEncryptionType,
    buildAdvSignedIdentityResponse,
    computeAdvIdentityHmac,
    generateDeviceSignature,
    parseAdvSignedIdentity,
    parseAdvSignedIdentityHmac,
    readAdvDeviceType,
    readAdvKeyIndex,
    verifyDeviceIdentityAccountSignature,
} from './signal/attestation.js'

// ── Transports ──────────────────────────────────────────────────────────────

export {
    MobileTransport,
    DEFAULT_MOBILE_HOST,
    DEFAULT_MOBILE_PORT,
    DEFAULT_MOBILE_TCP_URL,
    type MobileTransportConfig,
} from './transport/mobile.js'

export {
    WebTransport,
    DEFAULT_WEB_SOCKET_URL,
    type WebTransportConfig,
} from './transport/web.js'

export {
    DEFAULT_ANDROID_PROFILE,
    DEFAULT_ANDROID_VERSION,
    DEFAULT_IOS_PROFILE,
    DEFAULT_WEB_VERSION,
    buildDeviceProps,
    buildLoginPayload,
    buildMobileLoginPayload,
    buildMobileRegistrationPayload,
    buildRegistrationPayload,
    intToBytes,
    parseAppVersion,
    type AppVersion,
    type CommonPayloadConfig,
    type DeviceProfile,
    type MobileLoginPayloadConfig,
    type MobileRegistrationPayloadConfig,
    type WebLoginPayloadConfig,
    type WebRegistrationPayloadConfig,
} from './transport/client-payload.js'

export type { BinaryNode } from './transport/binary/types.js'

export {
    decodeBinaryNode,
    encodeBinaryNode,
} from './transport/binary/codec.js'

// ── Node builders ───────────────────────────────────────────────────────────

export {
    buildAckNode,
    buildIqErrorNode,
    buildIqResultNode,
    buildNotificationAckNode,
    buildReceiptNode,
    buildRetryReceiptNode,
} from './transport/node/builders/global.js'

export {
    WA_COMPANION_PLATFORM_ID,
    WA_SIGNALING,
    buildCompanionFinishRequestNode,
    buildCompanionHelloRequestNode,
    buildGetCountryCodeRequestNode,
    buildPairDeviceSignResultNode,
} from './transport/node/builders/pairing.js'

export {
    buildDirectMessageFanoutNode,
    buildGroupSenderKeyMessageNode,
    type EncryptedParticipant,
} from './transport/node/builders/message.js'

// ── QR ──────────────────────────────────────────────────────────────────────

export {
    encodeQr,
    qrToSvg,
    qrToTerminal,
    type QrEncodeOptions,
    type QrMatrix,
    type QrSvgOptions,
    type QrTerminalOptions,
} from './qr/qrcode.js'

export {
    DEFAULT_CLIENT_VERSION,
    base64Decode,
    base64Encode,
    buildWhatsAppQrPayload,
    parseWhatsAppQrPayload,
    type WhatsAppQrParams,
} from './qr/whatsapp.js'

// ── Crypto primitives ───────────────────────────────────────────────────────

export {
    aesCbcDecrypt,
    aesCbcEncrypt,
    aesCtrDecrypt,
    aesCtrEncrypt,
    aesGcmDecrypt,
    aesGcmEncrypt,
    concat,
    equalBytes,
    fromHex,
    generateX25519KeyPair,
    hkdf,
    hkdfSplit,
    hmacSha256,
    md5,
    randomBytesOf,
    sha256,
    toHex,
    utf8,
    x25519,
    type X25519KeyPair,
} from './crypto/primitives.js'

export {
    NOISE_IK_NAME,
    NOISE_XX_FALLBACK_NAME,
    NOISE_XX_NAME,
    NoiseHandshake,
    NoiseTransport,
    ROOT_CA_PUBLIC_KEY_HEX,
    ROOT_CA_SERIAL,
    WA_PROTO_HEADER,
    sharedSecret,
    type NoiseSession,
} from './crypto/noise.js'

export { xeddsaSign, xeddsaVerify } from './crypto/curve25519.js'

// ── Protobuf ────────────────────────────────────────────────────────────────

export {
    decode,
    encode,
    defineMessage,
    getMessage,
    schemaStats,
    type FieldDescriptor,
    type MessageDescriptor,
    type SchemaStats,
} from './proto/codec.js'

// ── Utilities ───────────────────────────────────────────────────────────────

export {
    generateMessageId,
    generateMobileMessageId,
    generateRandomId,
    generateWebMessageId,
    type MessageIdFormat,
} from './util/message-id.js'

export {
    base64UrlDecode,
    base64UrlEncode,
    base64UrlEncodePadded,
} from './util/base64.js'
