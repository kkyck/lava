/**
 * The message codec.
 *
 * Converts between the protobuf `Message` body that WhatsApp uses on the
 * wire and the JavaScript objects the rest of the library works with.
 *
 * Two things happen here:
 *
 * - **Outbound**: a message body is encoded to protobuf, a *message secret*
 *   is attached, and the result is padded with 1-16 random bytes before it is
 *   handed to Signal.
 * - **Inbound**: the decrypted plaintext is unpadded and decoded back into a
 *   message body, from which the message key, the sender-key distribution
 *   and the content type are derived.
 */

import { decode, encode } from '../proto/codec.js'
import type { BinaryNode } from '../transport/binary/types.js'
import { findNodeChild, getNodeChildren, getNodeChildrenByTag } from '../transport/node/helpers.js'
import { isBroadcastJid, isGroupJid, isOwnAccountJid, toUserJid } from '../protocol/jid.js'
import type { MessageContent, MessageKey } from '../protocol/message.js'
import { getContentType, unwrapMessage } from '../protocol/message.js'
import { unpadPkcs7, writeRandomPadMax16 } from './padding.js'
import { ensureMessageSecret } from './secret.js'

/**
 * Encodes a message body to the protobuf bytes that go on the wire.
 *
 * @param body The message body.
 */
export function encodeMessageBody(body: MessageContent): Uint8Array {
    return encode('Message', body)
}

/**
 * Decodes protobuf bytes back into a message body.
 *
 * @param bytes The protobuf bytes.
 */
export function decodeMessageBody(bytes: Uint8Array): MessageContent {
    return decode('Message', bytes)
}

/**
 * Prepares an outbound message body for encryption.
 *
 * Attaches a message secret (unless the caller already supplied one) and
 * pads the encoded bytes.
 *
 * @param body The message body.
 * @returns The padded plaintext.
 */
export function prepareOutboundPlaintext(body: MessageContent): Uint8Array {
    const withSecret = ensureMessageSecret(body)
    return writeRandomPadMax16(encodeMessageBody(withSecret))
}

/**
 * Strips the padding from an inbound plaintext.
 *
 * @param plaintext The decrypted plaintext.
 */
export function stripInboundPadding(plaintext: Uint8Array): Uint8Array {
    return unpadPkcs7(plaintext)
}

/** A sender-key distribution carried inside a message body. */
export interface SenderKeyDistribution {
    /** The group the sender key belongs to. */
    groupId: string
    /** The distribution message bytes. */
    payload: Uint8Array
}

/**
 * Extracts the sender-key distribution message from a body.
 *
 * Group messages piggy-back the distribution message that lets the receiver
 * decrypt the group ciphertext.
 *
 * @param body The message body.
 */
export function extractSenderKeyDistribution(
    body: MessageContent,
): SenderKeyDistribution | null {
    const direct = pickDistribution(body.senderKeyDistributionMessage)
    if (direct) return direct
    const fast = pickDistribution(body.fastRatchetKeySenderKeyDistributionMessage)
    if (fast) return fast
    const nested = body.deviceSentMessage as MessageContent | undefined
    if (nested?.message) {
        return extractSenderKeyDistribution(nested.message as MessageContent)
    }
    return null
}

/**
 * Extracts a distribution from a single distribution sub-message.
 *
 * @param value The sub-message.
 */
function pickDistribution(value: unknown): SenderKeyDistribution | null {
    if (!value || typeof value !== 'object') return null
    const record = value as Record<string, unknown>
    const groupId = record.groupId
    const payload = record.axolotlSenderKeyDistributionMessage
    if (typeof groupId !== 'string' || groupId === '') return null
    if (!payload) return null
    return { groupId, payload: payload as Uint8Array }
}

/**
 * A message key resolved from an inbound stanza.
 */
export interface InboundMessageKey extends MessageKey {
    /** The chat the message belongs to. */
    remoteJid: string
    /** Whether the message was sent by this account. */
    fromMe: boolean
    /** The message id. */
    id: string
    /** The sender of the message (group participants). */
    participant?: string
    /** Whether the chat is a group. */
    isGroup: boolean
    /** Whether the chat is a broadcast list. */
    isBroadcast: boolean
    /** The sender's device id. */
    senderDevice: number
    /** The sender's push name, when the server reported one. */
    pushName?: string
}

/**
 * Resolves the message key of an inbound `<message>` stanza.
 *
 * The stanza attributes describe the chat, the id and the push name; the
 * sender's device address is supplied by the caller, because it comes from
 * the `<to jid="…">` entry the payload was encrypted for.
 *
 * @param node The `<message>` stanza.
 * @param senderDeviceJid The device JID the payload was addressed to.
 * @param meJid The account's own JID, when it is known.
 * @param meLid The account's own LID, when it is known.
 */
export function resolveInboundMessageKey(
    node: BinaryNode,
    senderDeviceJid: string | undefined,
    meJid: string | undefined,
    meLid?: string | undefined,
): InboundMessageKey {
    const attrs = node.attrs
    const rawFrom = attrs.from
    const fromUserJid = rawFrom ? toUserJid(rawFrom) : undefined
    const isGroup = fromUserJid ? isGroupJid(fromUserJid) : false
    const isBroadcast = fromUserJid ? isBroadcastJid(fromUserJid) : false

    const senderUserJid = senderDeviceJid ? toUserJid(senderDeviceJid) : undefined
    const fromMe =
        senderUserJid !== undefined
            ? isOwnAccountJid(senderUserJid, meJid, meLid)
            : false

    const remoteJid = fromUserJid ?? ''
    const key: InboundMessageKey = {
        remoteJid,
        fromMe,
        id: attrs.id ?? '',
        isGroup,
        isBroadcast,
        senderDevice: parseDeviceId(senderDeviceJid),
    }
    const participant = attrs.participant
    if (participant) key.participant = toUserJid(participant)
    const notify = attrs.notify
    if (notify) key.pushName = notify
    return key
}

/**
 * Extracts the device id from a device JID.
 *
 * @param deviceJid The device JID.
 */
function parseDeviceId(deviceJid: string | undefined): number {
    if (!deviceJid) return 0
    const colon = deviceJid.indexOf(':')
    if (colon < 0) return 0
    const at = deviceJid.indexOf('@', colon)
    const slice = at > colon ? deviceJid.slice(colon + 1, at) : deviceJid.slice(colon + 1)
    const value = Number.parseInt(slice, 10)
    return Number.isSafeInteger(value) ? value : 0
}

/**
 * An encrypted payload carried by an inbound `<message>` stanza.
 */
export interface InboundEncryption {
    /** The `<enc type>` attribute: `msg`, `pkmsg` or `skmsg`. */
    encType: string
    /** The ciphertext. */
    ciphertext: Uint8Array
    /**
     * The device the payload was addressed to.
     *
     * Only set for the fan-out shape
     * (`<participants><to jid><enc/></to></participants>`), which the server
     * only sends back for retry receipts and peer-to-peer messages.
     */
    deviceJid?: string
}

/**
 * Collects the encrypted payloads of an inbound `<message>` stanza.
 *
 * The official clients deliver a message as a **top-level** `<enc>` child:
 *
 * ```xml
 * <message from="…" participant="…">
 *   <enc v="2" type="msg|pkmsg|skmsg">…</enc>
 * </message>
 * ```
 *
 * The per-device fan-out (`<participants><to jid><enc/></to></participants>`)
 * is the *outbound* shape; the server sends it back only in a couple of
 * special cases (retry receipts and peer-to-peer messages), so it is
 * accepted as a fallback.
 *
 * @param node The `<message>` stanza.
 */
export function collectInboundEncryptions(node: BinaryNode): InboundEncryption[] {
    const out: InboundEncryption[] = []

    // The official shape: one or more top-level `<enc>` children.
    for (const child of getNodeChildren(node)) {
        if (child.tag !== 'enc') continue
        const ciphertext = child.content
        if (!(ciphertext instanceof Uint8Array)) continue
        out.push({ encType: child.attrs.type ?? 'msg', ciphertext })
    }
    if (out.length > 0) return out

    // The fan-out shape the server sometimes echoes back.
    const participants = findNodeChild(node, 'participants')
    if (!participants) return out
    for (const to of getNodeChildrenByTag(participants, 'to')) {
        const jid = to.attrs.jid
        if (!jid) continue
        const enc = findNodeChild(to, 'enc')
        if (!enc) continue
        const ciphertext = enc.content
        if (!(ciphertext instanceof Uint8Array)) continue
        out.push({
            encType: enc.attrs.type ?? 'msg',
            ciphertext,
            deviceJid: jid,
        })
    }
    return out
}

/**
 * Extracts the group ciphertext of an inbound group message.
 *
 * @param node The `<message>` stanza.
 */
export function collectGroupCiphertext(
    node: BinaryNode,
): { encType: string; ciphertext: Uint8Array } | null {
    for (const encryption of collectInboundEncryptions(node)) {
        if (encryption.encType === 'skmsg') {
            return { encType: encryption.encType, ciphertext: encryption.ciphertext }
        }
    }
    return null
}

/**
 * Derives the content type of a decoded body.
 *
 * @param body The message body.
 */
export function resolveContentType(body: MessageContent): string | undefined {
    return getContentType(unwrapMessage(body))
}

/**
 * Builds the plain, user-facing view of a decoded message body.
 *
 * @param body The message body.
 */
export function summarizeMessageBody(body: MessageContent): {
    type: string | undefined
    text?: string
    quotedId?: string
    reaction?: string
    revoked?: boolean
} {
    const unwrapped = unwrapMessage(body)
    const type = getContentType(unwrapped)
    const summary: {
        type: string | undefined
        text?: string
        quotedId?: string
        reaction?: string
        revoked?: boolean
    } = { type }

    if (typeof unwrapped.conversation === 'string') {
        summary.text = unwrapped.conversation
    }
    const extended = unwrapped.extendedTextMessage as Record<string, unknown> | undefined
    if (typeof extended?.text === 'string') summary.text = extended.text

    const contextInfo = extended?.contextInfo as Record<string, unknown> | undefined
    const quoted = contextInfo?.quotedMessage as Record<string, unknown> | undefined
    const quotedKey = quoted?.key as Record<string, unknown> | undefined
    if (typeof quotedKey?.id === 'string') summary.quotedId = quotedKey.id

    const reaction = unwrapped.reactionMessage as Record<string, unknown> | undefined
    if (reaction) summary.reaction = String(reaction.text ?? '')

    const protocol = unwrapped.protocolMessage as Record<string, unknown> | undefined
    if (protocol?.type === 0) summary.revoked = true

    return summary
}
