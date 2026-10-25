/**
 * Retry receipts.
 *
 * A peer that receives a message it cannot decrypt answers with a
 * `<receipt type="retry">` stanza:
 *
 * ```xml
 * <receipt type="retry" from="…" participant="…@lid">
 *   <retry id="…" count="1" v="1" t="17…"/>
 *   <registration>…</registration>
 *   <keys>…</keys>
 * </receipt>
 * ```
 *
 * The receipt names the message that could not be read (`retry.id`), how
 * often it was already asked for (`retry.count`) and — usually — the
 * registration id of the peer. The optional `<keys>` child carries the
 * pre-key bundle of the peer, so the sender can talk to it again without
 * asking the server for the bundle.
 *
 * The receipt is the only way a sender learns that a message did not
 * arrive: the server accepts the message, delivers it and stays silent.
 */

import { WA_MESSAGE_TAGS, WA_MESSAGE_TYPES, WA_NODE_TAGS } from './constants.js'
import type { BinaryNode } from '../transport/binary/types.js'
import { decodeNodeContentBytes, findNodeChildrenByTags } from '../transport/node/helpers.js'
import { parseSignalKeyBundleFromNode } from '../signal/api.js'
import type { ParsedKeyBundle } from '../signal/api.js'

/** The length of the registration id carried by a retry receipt. */
export const RETRY_REGISTRATION_ID_LENGTH = 4

/** The kinds of retry request a peer can send. */
export type RetryRequestType =
    | typeof WA_MESSAGE_TYPES.RECEIPT_TYPE_RETRY
    | typeof WA_MESSAGE_TYPES.RECEIPT_TYPE_ENC_REKEY_RETRY

/** A retry request sent by a peer that could not decrypt a message. */
export interface RetryRequest {
    /** The kind of the request. */
    type: RetryRequestType
    /** The id of the receipt stanza itself. */
    stanzaId: string
    /** The address the request comes from. */
    from: string
    /** The participant that asked for the retry, for group traffic. */
    participant?: string
    /** The recipient the message was addressed to. */
    recipient?: string
    /** The id of the message that could not be decrypted. */
    originalMsgId: string
    /** How often the message was already asked for. */
    retryCount: number
    /** The registration id of the peer. */
    regId?: number
    /** The pre-key bundle of the peer, when it sent one. */
    keyBundle?: ParsedKeyBundle
}

/**
 * Reads a big-endian unsigned integer from bytes.
 *
 * @param bytes The bytes.
 * @param length The number of bytes.
 */
function readUint(bytes: Uint8Array, length: number): number {
    let value = 0
    for (let i = 0; i < length; i += 1) {
        value = value * 256 + (bytes[i] ?? 0)
    }
    return value
}

/**
 * Parses a `<receipt>` stanza into a retry request.
 *
 * Returns `null` when the stanza is not a retry receipt — the other
 * receipt types (`delivery`, `read`, …) say nothing about decryption.
 *
 * @param node The stanza.
 */
export function parseRetryReceipt(node: BinaryNode): RetryRequest | null {
    if (node.tag !== WA_MESSAGE_TAGS.RECEIPT) return null

    const type = node.attrs.type
    if (
        type !== WA_MESSAGE_TYPES.RECEIPT_TYPE_RETRY &&
        type !== WA_MESSAGE_TYPES.RECEIPT_TYPE_ENC_REKEY_RETRY
    ) {
        return null
    }

    const stanzaId = node.attrs.id
    const from = node.attrs.from
    if (!stanzaId || !from) return null

    const [retryNode, registrationNode, keysNode] = findNodeChildrenByTags(node, [
        WA_NODE_TAGS.RETRY,
        WA_NODE_TAGS.REGISTRATION,
        WA_NODE_TAGS.KEYS,
    ])
    if (!retryNode) return null

    const originalMsgId = retryNode.attrs.id
    if (!originalMsgId) return null

    const retryCount = Number.parseInt(retryNode.attrs.count ?? '', 10)
    const request: RetryRequest = {
        type,
        stanzaId,
        from,
        ...(node.attrs.participant ? { participant: node.attrs.participant } : {}),
        ...(node.attrs.recipient ? { recipient: node.attrs.recipient } : {}),
        originalMsgId,
        retryCount: Number.isSafeInteger(retryCount) && retryCount > 0 ? retryCount : 0,
    }

    if (registrationNode) {
        const bytes = decodeNodeContentBytes(
            registrationNode.content,
            'retry.registration',
        )
        if (bytes.length === RETRY_REGISTRATION_ID_LENGTH) {
            request.regId = readUint(bytes, RETRY_REGISTRATION_ID_LENGTH)
        }
    }

    if (keysNode) {
        try {
            request.keyBundle = parseSignalKeyBundleFromNode(keysNode, 'retry.keys')
        } catch {
            // A malformed key bundle is not fatal: the sender can ask the
            // server for the bundle instead.
        }
    }

    return request
}
