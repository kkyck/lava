/**
 * Message stanza builders.
 *
 * A WhatsApp message is a `<message>` node whose children carry the
 * encrypted payloads:
 *
 * ```xml
 * <message to="…" type="text" id="…">
 *   <participants>
 *     <to jid="…"><enc v="2" type="pkmsg">…</enc></to>
 *   </participants>
 * </message>
 * ```
 *
 * Direct chats fan the ciphertext out to every device of the recipient;
 * group chats carry the sender-key ciphertext in a top-level `<enc>` and
 * piggy-back the sender-key distribution message on the per-device
 * `<to>` entries.
 */

import { WA_MESSAGE_TAGS, WA_MESSAGE_TYPES } from '../../../protocol/constants.js'
import type { BinaryNode } from '../../binary/types.js'
import { WA_NODE_TAGS } from '../../../protocol/constants.js'

/** One encrypted payload addressed to one device. */
export interface EncryptedParticipant {
    /** The device JID the payload is addressed to. */
    jid: string
    /** The `<enc type>` value: `msg`, `pkmsg` or `skmsg`. */
    encType: string
    /** The ciphertext. */
    ciphertext: Uint8Array
    /**
     * The retry counter of the payload.
     *
     * A payload that is sent again after a retry request carries the number
     * of the attempt, so the peer can tell the copies apart.
     */
    count?: number
}

/** Options shared by the message builders. */
export interface MessageNodeOptions {
    /** The recipient JID. */
    to: string
    /** The stanza `type` attribute. */
    type: string
    /** The stanza `id` attribute. */
    id?: string
    /** The participant hash for group and broadcast fanouts. */
    phash?: string
    /**
     * The addressing mode of the group.
     *
     * A group either names its members by phone number or by their linked
     * identity. The attribute tells the server how the addresses of the
     * stanza have to be read, so a group message that leaves it out is not
     * delivered to the members.
     */
    addressingMode?: 'lid' | 'pn'
    /** The `edit` attribute. */
    edit?: string
    /** The `mediatype` attribute. */
    mediatype?: string
    /** The `decrypt-fail` attribute. */
    decryptFail?: string
    /**
     * The `participant` attribute.
     *
     * For a group message that is addressed to a single participant — the
     * answer to a retry request — it names the participant the message is
     * for, so that the server delivers it to that participant alone.
     */
    participant?: string
    /** Extra stanza attributes. */
    additionalAttributes?: Record<string, string>
}

/**
 * Builds the attributes of an `<enc>` node.
 *
 * @param encType The ciphertext kind.
 * @param mediatype The media type, when the message carries media.
 * @param retryCount The retry counter.
 * @param decryptFail The `decrypt-fail` attribute.
 */
export function buildEncAttrs(
    encType: string,
    mediatype?: string,
    retryCount?: number,
    decryptFail?: string,
): Record<string, string> {
    const attrs: Record<string, string> = {
        v: WA_MESSAGE_TYPES.ENC_VERSION,
        type: encType,
    }
    if (mediatype) attrs.mediatype = mediatype
    if (retryCount !== undefined && retryCount > 0) attrs.count = String(Math.trunc(retryCount))
    if (decryptFail) attrs['decrypt-fail'] = decryptFail
    return attrs
}

/**
 * Builds the attributes of a `<message>` node.
 *
 * @param options The message options.
 */
function buildMessageAttrs(options: MessageNodeOptions): Record<string, string> {
    const attrs: Record<string, string> = {
        to: options.to,
        type: options.type,
    }
    if (options.id) attrs.id = options.id
    if (options.edit) attrs.edit = options.edit
    if (options.phash) attrs.phash = options.phash
    if (options.addressingMode) attrs.addressing_mode = options.addressingMode
    if (options.participant) attrs.participant = options.participant
    if (options.additionalAttributes) Object.assign(attrs, options.additionalAttributes)
    return attrs
}

/**
 * Builds the `<to>` entries of a `<participants>` list.
 *
 * @param participants The encrypted payloads.
 * @param mediatype The media type.
 * @param decryptFail The `decrypt-fail` attribute.
 */
export function buildEncryptedToNodes(
    participants: readonly EncryptedParticipant[],
    mediatype?: string,
    decryptFail?: string,
): BinaryNode[] {
    return participants.map((participant) => {
        if (!participant.encType || participant.ciphertext.length === 0) {
            throw new Error(`invalid encrypted participant payload for ${participant.jid}`)
        }
        return {
            tag: 'to',
            attrs: { jid: participant.jid },
            content: [
                {
                    tag: WA_MESSAGE_TAGS.ENC,
                    attrs: buildEncAttrs(
                        participant.encType,
                        mediatype,
                        participant.count,
                        decryptFail,
                    ),
                    content: participant.ciphertext,
                },
            ],
        }
    })
}

/**
 * Builds a direct-chat fanout message.
 *
 * @param options The message options.
 * @param participants The encrypted payloads, one per recipient device.
 */
export function buildDirectMessageFanoutNode(
    options: MessageNodeOptions,
    participants: readonly EncryptedParticipant[],
): BinaryNode {
    if (participants.length === 0) {
        throw new Error('direct message fanout requires at least one participant')
    }
    return {
        tag: WA_MESSAGE_TAGS.MESSAGE,
        attrs: buildMessageAttrs(options),
        content: [
            {
                tag: WA_NODE_TAGS.PARTICIPANTS,
                attrs: {},
                content: buildEncryptedToNodes(participants, options.mediatype, options.decryptFail),
            },
        ],
    }
}

/**
 * Builds a group message.
 *
 * @param options The message options.
 * @param participants The sender-key distribution payloads, one per device.
 * @param groupCiphertext The sender-key ciphertext of the message body.
 */
export function buildGroupSenderKeyMessageNode(
    options: MessageNodeOptions,
    participants: readonly EncryptedParticipant[],
    groupCiphertext: Uint8Array,
): BinaryNode {
    const content: BinaryNode[] = []
    if (participants.length > 0) {
        content.push({
            tag: WA_NODE_TAGS.PARTICIPANTS,
            attrs: {},
            content: buildEncryptedToNodes(participants, options.mediatype, options.decryptFail),
        })
    }
    content.push({
        tag: WA_MESSAGE_TAGS.ENC,
        attrs: buildEncAttrs('skmsg', options.mediatype, undefined, options.decryptFail),
        content: groupCiphertext,
    })
    return {
        tag: WA_MESSAGE_TAGS.MESSAGE,
        attrs: buildMessageAttrs(options),
        content,
    }
}

/**
 * Builds a retry stanza for a message that could not be delivered.
 *
 * The stanza carries the message again, this time encrypted for the device
 * that asked for it. The `count` attribute of the `<enc>` node tells the
 * peer how often the message was already sent.
 *
 * A group message is addressed to the group but names the device that
 * asked for the retry in its `participant` attribute, so that only that
 * device receives the copy.
 *
 * @param options The message options.
 * @param encType The ciphertext kind.
 * @param ciphertext The ciphertext.
 * @param retryCount The retry counter.
 * @param requesterJid The device that asked for the retry.
 */
export function buildRetryMessageNode(
    options: MessageNodeOptions,
    encType: string,
    ciphertext: Uint8Array,
    retryCount: number,
    requesterJid?: string,
): BinaryNode {
    const attrs: Record<string, string> = {
        to: options.to,
        type: options.type,
        id: options.id ?? '',
    }
    if (requesterJid) attrs.participant = requesterJid
    return {
        tag: WA_MESSAGE_TAGS.MESSAGE,
        attrs,
        content: [
            {
                tag: WA_MESSAGE_TAGS.ENC,
                attrs: buildEncAttrs(encType, options.mediatype, retryCount, options.decryptFail),
                content: ciphertext,
            },
        ],
    }
}

/**
 * Builds a retry stanza for a group message that could not be delivered.
 *
 * @param options The message options.
 * @param encType The ciphertext kind.
 * @param ciphertext The ciphertext.
 * @param retryCount The retry counter.
 * @param requesterJid The device that asked for the retry.
 */
export function buildGroupRetryMessageNode(
    options: MessageNodeOptions,
    encType: string,
    ciphertext: Uint8Array,
    retryCount: number,
    requesterJid: string,
): BinaryNode {
    return buildRetryMessageNode(options, encType, ciphertext, retryCount, requesterJid)
}
