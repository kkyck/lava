/**
 * Message content construction.
 *
 * WhatsApp messages are protobuf `Message` values. Only one payload field is
 * set at a time (`conversation`, `extendedTextMessage`, `imageMessage`, …) and
 * the stanza attributes (`type`, `mediatype`, `edit`, …) are derived from it.
 */

import {
    WA_ENC_MEDIA_TYPES,
    WA_STANZA_MSG_TYPES,
} from './constants.js'

/** A protobuf `Message` value under construction. */
export type MessageContent = Record<string, unknown>

/** Identifies a specific message, used as a reply/reaction target. */
export interface MessageKey {
    /** The chat the message belongs to. */
    remoteJid: string
    /** Whether the message was sent by this account. */
    fromMe: boolean
    /** The message id. */
    id: string
    /** The sender of the message (group participants). */
    participant?: string
}

/** `ProtocolMessage` types. */
export const PROTOCOL_MESSAGE_TYPE = Object.freeze({
    REVOKE: 0,
    EPHEMERAL_SETTING: 3,
    HISTORY_SYNC_NOTIFICATION: 4,
    APP_STATE_SYNC_KEY_SHARE: 5,
    APP_STATE_SYNC_KEY_REQUEST: 6,
    MSG_FANOUT_BACKFILL_REQUEST: 7,
    INITIAL_SECURITY_NOTIFICATION_SETTING_SYNC: 8,
    APP_STATE_FATAL_EXCEPTION_NOTIFICATION: 9,
    SHARE_PHONE_NUMBER: 10,
    MESSAGE_EDIT: 14,
    PEER_DATA_OPERATION_REQUEST_MESSAGE: 16,
    PEER_DATA_OPERATION_REQUEST_RESPONSE_MESSAGE: 17,
    REQUEST_WELCOME_MESSAGE: 18,
    BOT_FEEDBACK_MESSAGE: 19,
    MEDIA_NOTIFY_MESSAGE: 20,
    CLOUD_API_THREAD_CONTROL_NOTIFICATION: 21,
    LID_MIGRATION_MAPPING_SYNC: 22,
    BOT_FEEDBACK_MESSAGE_2: 25,
    REPORT_MESSAGE: 26,
} as const)

/** The message types whose name ends in `Message` and therefore carry a payload. */
const CONTENT_SUFFIXED_KEYS = new Set([
    'conversation',
    'messageHistoryBundle',
    'messageHistoryNotice',
])

/**
 * Returns the content-type key of a message.
 *
 * `senderKeyDistributionMessage` is skipped so group messages report their
 * real payload type rather than the piggy-backed sender key.
 *
 * @param message The message content.
 */
export function getContentType(message: MessageContent | undefined): string | undefined {
    if (!message) return undefined
    for (const key of Object.keys(message)) {
        const value = message[key]
        if (value === null || value === undefined) continue
        if (key === 'senderKeyDistributionMessage') continue
        if (CONTENT_SUFFIXED_KEYS.has(key) || key.includes('Message')) return key
    }
    return undefined
}

/**
 * Unwraps the envelope messages (`ephemeralMessage`, `viewOnceMessage`, …).
 *
 * @param message The message to unwrap.
 */
export function unwrapMessage(message: MessageContent): MessageContent {
    let current = message
    for (;;) {
        const inner =
            (current.ephemeralMessage as MessageContent | undefined)?.message ??
            (current.groupMentionedMessage as MessageContent | undefined)?.message ??
            (current.deviceSentMessage as MessageContent | undefined)?.message ??
            (current.viewOnceMessage as MessageContent | undefined)?.message ??
            (current.viewOnceMessageV2 as MessageContent | undefined)?.message ??
            (current.documentWithCaptionMessage as MessageContent | undefined)?.message
        if (!inner) return current
        current = inner as MessageContent
    }
}

/** Options for building a text message. */
export interface TextMessageOptions {
    /** The message being replied to. */
    quoted?: MessageKey
    /** A link preview to attach. */
    linkPreview?: {
        /** The canonical URL. */
        url: string
        /** The preview title. */
        title?: string
        /** The preview description. */
        description?: string
        /** The thumbnail bytes. */
        jpegThumbnail?: Uint8Array
    }
    /** The quoted message's author. */
    mentionedJid?: string[]
}

/**
 * Builds a plain-text message.
 *
 * A short message with no metadata uses the `conversation` field; anything
 * carrying a quote, a preview or mentions uses `extendedTextMessage`.
 *
 * @param text The message text.
 * @param options Optional context.
 */
export function buildTextContent(
    text: string,
    options: TextMessageOptions = {},
): MessageContent {
    const contextInfo = buildContextInfo(options)
    const hasPreview = options.linkPreview !== undefined
    const hasMentions = (options.mentionedJid?.length ?? 0) > 0

    if (!contextInfo && !hasPreview && !hasMentions) {
        return { conversation: text }
    }

    const extended: Record<string, unknown> = { text }
    if (contextInfo) extended.contextInfo = contextInfo
    if (options.linkPreview) {
        extended.matchedText = options.linkPreview.url
        if (options.linkPreview.title !== undefined) extended.title = options.linkPreview.title
        if (options.linkPreview.description !== undefined) {
            extended.description = options.linkPreview.description
        }
        if (options.linkPreview.jpegThumbnail !== undefined) {
            extended.jpegThumbnail = options.linkPreview.jpegThumbnail
        }
    }
    return { extendedTextMessage: extended }
}

/**
 * Builds the `ContextInfo` sub-message.
 *
 * @param options The context options.
 */
function buildContextInfo(options: TextMessageOptions): Record<string, unknown> | undefined {
    const contextInfo: Record<string, unknown> = {}
    if (options.quoted) {
        contextInfo.messageSecret = randomMessageSecret()
        contextInfo.messageAddOnDurationInSecs = 0
        contextInfo.quotedMessage = { key: options.quoted }
    }
    if (options.mentionedJid && options.mentionedJid.length > 0) {
        contextInfo.mentionedJid = options.mentionedJid
    }
    return Object.keys(contextInfo).length > 0 ? contextInfo : undefined
}

/** Generates the random "message secret" that ties a quote to its reply. */
function randomMessageSecret(): Uint8Array {
    const secret = new Uint8Array(32)
    crypto.getRandomValues(secret)
    return secret
}

/**
 * Builds a reaction message.
 *
 * @param target The message being reacted to.
 * @param emoji The reaction emoji; an empty string removes the reaction.
 */
export function buildReactionContent(target: MessageKey, emoji: string): MessageContent {
    return {
        reactionMessage: {
            key: target,
            text: emoji,
            groupingKey: reactionGroupingKey(target),
            senderTimestampMs: Date.now(),
        },
    }
}

/**
 * Computes the grouping key that identifies a reaction's target.
 *
 * @param target The reacted-to message.
 */
export function reactionGroupingKey(target: MessageKey): string {
    return `${target.remoteJid}|${target.participant ?? ''}|${target.id}`
}

/**
 * Builds a revoke ("delete for everyone") message.
 *
 * @param target The message to revoke.
 */
export function buildRevokeContent(target: MessageKey): MessageContent {
    return {
        protocolMessage: {
            key: target,
            type: PROTOCOL_MESSAGE_TYPE.REVOKE,
        },
    }
}

/**
 * Builds a location message.
 *
 * @param location The location payload.
 */
export function buildLocationContent(location: {
    latitude: number
    longitude: number
    name?: string
    address?: string
    url?: string
    isLive?: boolean
    accuracyInMeters?: number
    comment?: string
}): MessageContent {
    const message: Record<string, unknown> = {
        degreesLatitude: location.latitude,
        degreesLongitude: location.longitude,
    }
    if (location.name !== undefined) message.name = location.name
    if (location.address !== undefined) message.address = location.address
    if (location.url !== undefined) message.url = location.url
    if (location.isLive !== undefined) message.isLive = location.isLive
    if (location.accuracyInMeters !== undefined) {
        message.accuracyInMeters = location.accuracyInMeters
    }
    if (location.comment !== undefined) message.comment = location.comment
    return { locationMessage: message }
}

/**
 * Builds a contact (vCard) message.
 *
 * @param contact The contact payload.
 */
export function buildContactContent(contact: {
    displayName: string
    vcard: string
}): MessageContent {
    return {
        contactMessage: {
            displayName: contact.displayName,
            vcard: contact.vcard,
        },
    }
}

/** A poll option. */
export interface PollOption {
    /** The option name. */
    name: string
}

/**
 * Builds a poll creation message.
 *
 * The option names are sent in clear text inside an `Option` message, exactly
 * as the official clients do; poll *votes* are the part that is encrypted.
 *
 * @param poll The poll payload.
 */
export function buildPollContent(poll: {
    name: string
    options: PollOption[]
    selectableOptionsCount?: number
    allowAddOption?: boolean
    hideParticipantName?: boolean
}): MessageContent {
    if (poll.options.length === 0) {
        throw new Error('poll message requires at least one option')
    }
    const body: Record<string, unknown> = {
        name: poll.name,
        options: poll.options.map((option) => ({ optionName: option.name })),
        selectableOptionsCount: poll.selectableOptionsCount ?? 1,
    }
    if (poll.allowAddOption === true) body.allowAddOption = true
    if (poll.hideParticipantName === true) body.hideParticipantName = true
    return { pollCreationMessageV3: body }
}

/** Attributes derived from a message body. */
export interface OutboundMessageAttrs {
    /** The `type` attribute of the `<message>` stanza. */
    typeAttr: string
    /** The `mediatype` attribute, when the message carries media. */
    mediatype?: string
    /** The `edit` attribute, when the message revokes or edits another. */
    edit?: string
    /** The `decrypt-fail` attribute, when the body must stay hidden. */
    decryptFail?: string
    /** Additional `<meta>` attributes. */
    metaAttrs?: Record<string, string>
}

/** Edit attribute values. */
export const EDIT_ATTRS = Object.freeze({
    MESSAGE_EDIT: '1',
    PIN_IN_CHAT: '2',
    NEWSLETTER_EDIT: '3',
    SENDER_REVOKE: '7',
    ADMIN_REVOKE: '8',
} as const)

/**
 * Derives every outbound stanza attribute from the message body.
 *
 * @param message The message body.
 */
export function resolveOutboundMessageAttrs(message: MessageContent): OutboundMessageAttrs {
    const unwrapped = unwrapMessage(message)
    const result: OutboundMessageAttrs = {
        typeAttr: resolveMessageTypeAttr(unwrapped),
    }
    const mediatype = resolveEncMediaType(unwrapped)
    if (mediatype !== undefined) result.mediatype = mediatype
    const edit = resolveEditAttr(unwrapped)
    if (edit !== undefined) result.edit = edit
    const decryptFail = resolveDecryptFailAttr(unwrapped)
    if (decryptFail !== undefined) result.decryptFail = decryptFail
    const metaAttrs = resolveMetaAttrs(message, unwrapped)
    if (metaAttrs) result.metaAttrs = metaAttrs
    return result
}

/**
 * Resolves the `type` attribute of the `<message>` stanza.
 *
 * @param message The unwrapped message body.
 */
export function resolveMessageTypeAttr(message: MessageContent): string {
    if (message.reactionMessage) return WA_STANZA_MSG_TYPES.REACTION
    if (
        message.pollCreationMessage ||
        message.pollCreationMessageV2 ||
        message.pollCreationMessageV3 ||
        message.pollUpdateMessage
    ) {
        return WA_STANZA_MSG_TYPES.POLL
    }
    const extended = message.extendedTextMessage as Record<string, unknown> | undefined
    if (extended?.matchedText && String(extended.matchedText).trim() !== '') {
        return WA_STANZA_MSG_TYPES.MEDIA
    }
    if (
        message.conversation !== undefined ||
        (extended && !extended.matchedText) ||
        message.protocolMessage ||
        message.interactiveMessage ||
        message.keepInChatMessage ||
        message.editedMessage ||
        message.pinInChatMessage
    ) {
        return WA_STANZA_MSG_TYPES.TEXT
    }
    return WA_STANZA_MSG_TYPES.MEDIA
}

/**
 * Resolves the `mediatype` attribute of the `<enc>` node.
 *
 * @param message The unwrapped message body.
 */
export function resolveEncMediaType(message: MessageContent): string | undefined {
    if (message.imageMessage) return WA_ENC_MEDIA_TYPES.IMAGE
    if (message.stickerMessage) return WA_ENC_MEDIA_TYPES.STICKER
    if (message.stickerPackMessage) return WA_ENC_MEDIA_TYPES.STICKER_PACK
    if (message.locationMessage) {
        const location = message.locationMessage as Record<string, unknown>
        return location.isLive === true
            ? WA_ENC_MEDIA_TYPES.LIVE_LOCATION
            : WA_ENC_MEDIA_TYPES.LOCATION
    }
    if (message.contactMessage) return WA_ENC_MEDIA_TYPES.VCARD
    if (message.contactsArrayMessage) return WA_ENC_MEDIA_TYPES.CONTACT_ARRAY
    if (message.documentMessage) return WA_ENC_MEDIA_TYPES.DOCUMENT
    if (message.audioMessage) {
        const audio = message.audioMessage as Record<string, unknown>
        return audio.ptt === true ? WA_ENC_MEDIA_TYPES.PTT : WA_ENC_MEDIA_TYPES.AUDIO
    }
    if (message.videoMessage) {
        const video = message.videoMessage as Record<string, unknown>
        return video.gifPlayback === true ? WA_ENC_MEDIA_TYPES.GIF : WA_ENC_MEDIA_TYPES.VIDEO
    }
    if (message.ptvMessage) return WA_ENC_MEDIA_TYPES.PTV
    if (message.buttonsMessage) return WA_ENC_MEDIA_TYPES.BUTTON
    if (message.buttonsResponseMessage) return WA_ENC_MEDIA_TYPES.BUTTON_RESPONSE
    if (message.listMessage) return WA_ENC_MEDIA_TYPES.LIST
    if (message.listResponseMessage) return WA_ENC_MEDIA_TYPES.LIST_RESPONSE
    if (message.orderMessage) return WA_ENC_MEDIA_TYPES.ORDER
    if (message.productMessage) return WA_ENC_MEDIA_TYPES.PRODUCT
    if (message.groupInviteMessage) return WA_ENC_MEDIA_TYPES.URL
    if (message.interactiveResponseMessage) return WA_ENC_MEDIA_TYPES.NATIVE_FLOW_RESPONSE
    if (message.messageHistoryBundle) return WA_ENC_MEDIA_TYPES.GROUP_HISTORY
    const extended = message.extendedTextMessage as Record<string, unknown> | undefined
    if (extended?.matchedText && String(extended.matchedText).trim() !== '') {
        return WA_ENC_MEDIA_TYPES.URL
    }
    return undefined
}

/**
 * Resolves the `edit` attribute of the `<message>` stanza.
 *
 * @param message The unwrapped message body.
 */
export function resolveEditAttr(message: MessageContent): string | undefined {
    const protocol = message.protocolMessage as Record<string, unknown> | undefined
    if (protocol) {
        const type = protocol.type as number
        if (type === PROTOCOL_MESSAGE_TYPE.REVOKE) {
            const key = protocol.key as Record<string, unknown> | undefined
            return key?.fromMe === false ? EDIT_ATTRS.ADMIN_REVOKE : EDIT_ATTRS.SENDER_REVOKE
        }
        if (type === PROTOCOL_MESSAGE_TYPE.MESSAGE_EDIT) return EDIT_ATTRS.MESSAGE_EDIT
        return undefined
    }
    if (message.editedMessage) return EDIT_ATTRS.MESSAGE_EDIT
    if (message.pinInChatMessage) return EDIT_ATTRS.PIN_IN_CHAT
    if (message.reactionMessage) {
        const reaction = message.reactionMessage as Record<string, unknown>
        return reaction.text === '' ? EDIT_ATTRS.SENDER_REVOKE : undefined
    }
    return undefined
}

/**
 * Resolves the `decrypt-fail` attribute of the `<message>` stanza.
 *
 * @param message The unwrapped message body.
 */
export function resolveDecryptFailAttr(message: MessageContent): string | undefined {
    if (
        message.reactionMessage ||
        message.pollUpdateMessage ||
        message.keepInChatMessage ||
        message.editedMessage ||
        message.pinInChatMessage ||
        message.messageHistoryNotice
    ) {
        return 'hide'
    }
    const protocol = message.protocolMessage as Record<string, unknown> | undefined
    if (protocol) {
        const type = protocol.type as number
        if (
            type === PROTOCOL_MESSAGE_TYPE.EPHEMERAL_SETTING ||
            type === PROTOCOL_MESSAGE_TYPE.REQUEST_WELCOME_MESSAGE
        ) {
            return 'hide'
        }
    }
    return undefined
}

/**
 * Resolves the `<meta>` attributes of the `<message>` stanza.
 *
 * @param message The full message (envelope included).
 * @param unwrapped The unwrapped message body.
 */
export function resolveMetaAttrs(
    message: MessageContent,
    unwrapped: MessageContent,
): Record<string, string> | undefined {
    const attrs: Record<string, string> = {}
    if (
        unwrapped.pollCreationMessage ||
        unwrapped.pollCreationMessageV2 ||
        unwrapped.pollCreationMessageV3
    ) {
        attrs.polltype = 'creation'
    } else if (unwrapped.pollUpdateMessage) {
        attrs.polltype = 'vote'
    }
    if (message.viewOnceMessage || message.viewOnceMessageV2) {
        attrs.view_once = 'true'
    }
    return Object.keys(attrs).length > 0 ? attrs : undefined
}
