/**
 * Global stanza builders: acknowledgements, receipts and IQ responses.
 *
 * These are the stanzas every client has to answer, and the server is strict
 * about their shape: a missing `class` on an `<ack>` or a missing `id` on a
 * `<receipt>` makes the client look broken.
 */

import {
    WA_DEFAULTS,
    WA_IQ_TYPES,
    WA_MESSAGE_TAGS,
    WA_MESSAGE_TYPES,
    WA_NODE_TAGS,
} from '../../../protocol/constants.js'
import type { BinaryNode } from '../../binary/types.js'

/**
 * Builds an `<ack>` stanza for a message.
 *
 * @param id The id of the acknowledged stanza.
 * @param to The recipient of the acknowledgement.
 * @param options Extra attributes.
 */
export function buildAckNode(
    id: string,
    to: string,
    options: {
        /** The `type` attribute, usually the stanza type being acknowledged. */
        type?: string
        /** The `participant` attribute, for group traffic. */
        participant?: string
        /** The `error` attribute, for a negative acknowledgement. */
        error?: number | string
        /** The `class` attribute; a message by default. */
        class?: string
    } = {},
): BinaryNode {
    const attrs: Record<string, string> = {
        id,
        to,
        class: options.class ?? WA_MESSAGE_TYPES.ACK_CLASS_MESSAGE,
    }
    if (options.type) attrs.type = options.type
    if (options.participant) attrs.participant = options.participant
    if (options.error !== undefined) attrs.error = String(options.error)
    return { tag: WA_MESSAGE_TAGS.ACK, attrs }
}

/**
 * Builds an `<ack>` stanza for a notification.
 *
 * @param id The id of the acknowledged notification.
 * @param to The recipient of the acknowledgement.
 * @param type The notification type.
 * @param participant The participant, when the notification is group traffic.
 */
export function buildNotificationAckNode(
    id: string | undefined,
    to: string,
    type: string,
    participant?: string,
): BinaryNode {
    const attrs: Record<string, string> = {
        to,
        class: WA_NODE_TAGS.NOTIFICATION,
        type,
    }
    if (id) attrs.id = id
    if (participant) attrs.participant = participant
    return { tag: WA_MESSAGE_TAGS.ACK, attrs }
}

/**
 * Builds a `<receipt>` stanza.
 *
 * @param id The id of the acknowledged message.
 * @param to The recipient of the receipt.
 * @param type The receipt type (`delivery`, `read`, `read-self`, …).
 * @param options Extra attributes.
 */
export function buildReceiptNode(
    id: string,
    to: string,
    type: string,
    options: {
        /** The `participant` attribute, for group traffic. */
        participant?: string
        /** The `recipient` attribute. */
        recipient?: string
        /** The `category` attribute (`peer`, `participant`, …). */
        category?: string
        /** The `from` attribute. */
        from?: string
        /** The `t` attribute (Unix timestamp). */
        t?: string
        /**
         * The children of the receipt.
         *
         * A call is answered with a receipt that carries the call payload
         * back, so the peer can tell that its offer was received.
         */
        content?: BinaryNode[]
    } = {},
): BinaryNode {
    const attrs: Record<string, string> = { id, to }
    if (type) attrs.type = type
    if (options.participant) attrs.participant = options.participant
    if (options.recipient) attrs.recipient = options.recipient
    if (options.category) attrs.category = options.category
    if (options.from) attrs.from = options.from
    if (options.t) attrs.t = options.t
    return {
        tag: WA_MESSAGE_TAGS.RECEIPT,
        attrs,
        ...(options.content && options.content.length > 0
            ? { content: options.content }
            : {}),
    }
}

/**
 * Builds a `<receipt type="retry">` stanza asking the peer to resend a
 * message.
 *
 * @param id The id of the message to retry.
 * @param to The peer to ask.
 * @param count The retry counter.
 * @param options Extra attributes.
 */
export function buildRetryReceiptNode(
    id: string,
    to: string,
    count: number,
    options: {
        /** The `participant` attribute. */
        participant?: string
        /** The `category` attribute. */
        category?: string
        /** The `t` attribute. */
        t?: string
    } = {},
): BinaryNode {
    const attrs: Record<string, string> = {
        id,
        to,
        type: WA_MESSAGE_TYPES.RECEIPT_TYPE_RETRY,
    }
    if (options.participant) attrs.participant = options.participant
    if (options.category) attrs.category = options.category
    const retryAttrs: Record<string, string> = {
        count: String(count > 0 ? Math.trunc(count) : 1),
        id,
    }
    if (options.t) retryAttrs.t = options.t
    return {
        tag: WA_MESSAGE_TAGS.RECEIPT,
        attrs,
        content: [{ tag: 'retry', attrs: retryAttrs }],
    }
}

/**
 * Builds the successful response to an inbound IQ.
 *
 * @param request The inbound IQ stanza.
 */
export function buildIqResultNode(request: BinaryNode): BinaryNode {
    return {
        tag: WA_NODE_TAGS.IQ,
        attrs: {
            ...(request.attrs.id ? { id: request.attrs.id } : {}),
            to: request.attrs.from ?? WA_DEFAULTS.HOST_DOMAIN,
            type: WA_IQ_TYPES.RESULT,
        },
    }
}

/**
 * Builds the error response to an inbound IQ.
 *
 * @param request The inbound IQ stanza.
 * @param error The error code and text.
 */
export function buildIqErrorNode(
    request: BinaryNode,
    error: { code: number | string; text: string },
): BinaryNode {
    return {
        tag: WA_NODE_TAGS.IQ,
        attrs: {
            ...(request.attrs.id ? { id: request.attrs.id } : {}),
            to: request.attrs.from ?? WA_DEFAULTS.HOST_DOMAIN,
            type: WA_IQ_TYPES.ERROR,
        },
        content: [
            {
                tag: WA_NODE_TAGS.ERROR,
                attrs: { code: String(error.code), text: error.text },
            },
        ],
    }
}
