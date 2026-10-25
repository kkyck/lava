/**
 * The WhatsApp call protocol.
 *
 * Two shapes of a call travel over the wire:
 *
 * 1. The **classic** one: a `<call>` stanza with a payload child that names
 *    what happened — an `<offer>`, an `<accept>`, a `<reject>` or a
 *    `<terminate>`. This is the shape WhatsApp Web speaks, and it is the
 *    one Lava's own `client.call` API produces.
 * 2. The **modern** one: an ordinary message whose body carries a `call`
 *    field. The body names the call through a serialised `CallKey`, which
 *    holds the id of the call, the chat it takes place in and whether this
 *    device is the one that called.
 *
 * Both are read here, so that a caller is announced the same way no matter
 * which one the peer used.
 */

import { ProtoReader } from '../proto/codec.js'
import {
    WA_CALL_CHILD_TAGS,
    WA_CALL_NODE_ATTRS,
    WA_CALL_PAYLOAD_TAGS,
} from './constants.js'
import type { BinaryNode } from '../transport/binary/types.js'
import { findNodeChild, getFirstNodeChild } from '../transport/node/helpers.js'

/** The payload a call stanza carries. */
export type WaCallPayloadTag = (typeof WA_CALL_PAYLOAD_TAGS)[keyof typeof WA_CALL_PAYLOAD_TAGS]

/** The payloads a call stanza is known to carry. */
const CALL_PAYLOAD_TAGS: ReadonlySet<string> = new Set<string>(Object.values(WA_CALL_PAYLOAD_TAGS))

/**
 * The payloads that are answered with a receipt that carries the payload.
 *
 * The peer waits for the receipt before it considers the call delivered, so
 * an offer, an accept, a reject and a re-key are answered that way. Every
 * other payload is answered with a plain acknowledgement.
 */
export const WA_CALL_RECEIPT_PAYLOADS: ReadonlySet<string> = new Set([
    WA_CALL_PAYLOAD_TAGS.OFFER,
    WA_CALL_PAYLOAD_TAGS.ACCEPT,
    WA_CALL_PAYLOAD_TAGS.REJECT,
    WA_CALL_PAYLOAD_TAGS.ENC_REKEY,
])

/**
 * How a payload shows up in the call event.
 *
 * The payloads that carry no transition of their own — a transport update, a
 * mute, a video state — are not announced: they say nothing about the state
 * of the call.
 */
export const WA_CALL_STATUS: Readonly<
    Record<string, 'offer' | 'accept' | 'reject' | 'terminate'>
> = Object.freeze({
    [WA_CALL_PAYLOAD_TAGS.OFFER]: 'offer',
    [WA_CALL_PAYLOAD_TAGS.OFFER_NOTICE]: 'offer',
    [WA_CALL_PAYLOAD_TAGS.ACCEPT]: 'accept',
    [WA_CALL_PAYLOAD_TAGS.PREACCEPT]: 'accept',
    [WA_CALL_PAYLOAD_TAGS.REJECT]: 'reject',
    [WA_CALL_PAYLOAD_TAGS.TERMINATE]: 'terminate',
})

/** A participant of a group call. */
export interface WaCallParticipant {
    /** The JID of the participant. */
    jid: string
    /** The phone-number address of the participant, when the server named one. */
    userPnJid?: string
    /** The username of the participant, when the server named one. */
    username?: string
    /** The name the guest goes by, when the server named one. */
    guestName?: string
}

/** An inbound call. */
export interface WaInboundCall {
    /** What happened to the call. */
    type: WaCallPayloadTag | 'unknown'
    /** The tag of the payload child, even when it is not a known one. */
    payloadTag?: string
    /** The id of the call. */
    callId?: string
    /** The JID of the peer that created the call. */
    creator?: string
    /** The group the call takes place in. */
    groupJid?: string
    /** The LID address of the sender, when the server named one. */
    senderLid?: string
    /** The phone-number address of the caller, when the server named one. */
    callerPn?: string
    /** The username of the caller, when the server named one. */
    callerUsername?: string
    /** The country code of the caller, when the server named one. */
    callerCountryCode?: string
    /** The name the caller goes by, when the server named one. */
    callerPushName?: string
    /** The platform of the peer. */
    peerPlatform?: string
    /** The app version of the peer. */
    peerAppVersion?: string
    /** Whether the call carries video. */
    video: boolean
    /** The timestamp of the stanza, in seconds. */
    timestamp?: number
    /** The timestamp of the end of the call, in seconds. */
    endTimestamp?: number
    /** The reason the call was silenced, when the server named one. */
    silenceReason?: string
    /** The participants of a group call. */
    participants?: WaCallParticipant[]
}

/**
 * Reads the participants of a group call.
 *
 * @param node The `group_info` child.
 */
function parseGroupParticipants(node: BinaryNode): WaCallParticipant[] {
    const participants: WaCallParticipant[] = []
    const content = node.content
    if (!Array.isArray(content)) return participants
    for (const child of content) {
        const jid = child.attrs.jid
        if (!jid) continue
        participants.push({
            jid,
            ...(child.attrs[WA_CALL_NODE_ATTRS.USER_PN] !== undefined
                ? { userPnJid: child.attrs[WA_CALL_NODE_ATTRS.USER_PN] }
                : {}),
            ...(child.attrs[WA_CALL_NODE_ATTRS.USERNAME] !== undefined
                ? { username: child.attrs[WA_CALL_NODE_ATTRS.USERNAME] }
                : {}),
            ...(child.attrs[WA_CALL_NODE_ATTRS.GUEST_NAME] !== undefined
                ? { guestName: child.attrs[WA_CALL_NODE_ATTRS.GUEST_NAME] }
                : {}),
        })
    }
    return participants
}

/**
 * Reads a classic `<call>` stanza.
 *
 * @param node The stanza.
 * @returns What the stanza says about the call.
 */
export function parseCallNode(node: BinaryNode): WaInboundCall {
    const payload = getFirstNodeChild(node)
    if (!payload) {
        return { type: 'unknown', video: false }
    }
    const timestamp = parseOptionalInt(node.attrs.t)
    const endTimestamp = parseOptionalInt(node.attrs.e)
    const groupInfo = findNodeChild(payload, WA_CALL_CHILD_TAGS.GROUP_INFO)
    const silence = findNodeChild(payload, WA_CALL_CHILD_TAGS.SILENCE)
    const participants = groupInfo ? parseGroupParticipants(groupInfo) : []
    return {
        type: CALL_PAYLOAD_TAGS.has(payload.tag)
            ? (payload.tag as WaCallPayloadTag)
            : 'unknown',
        payloadTag: payload.tag,
        ...(payload.attrs[WA_CALL_NODE_ATTRS.CALL_ID] !== undefined
            ? { callId: payload.attrs[WA_CALL_NODE_ATTRS.CALL_ID] }
            : {}),
        ...(payload.attrs[WA_CALL_NODE_ATTRS.CALL_CREATOR] !== undefined
            ? { creator: payload.attrs[WA_CALL_NODE_ATTRS.CALL_CREATOR] }
            : {}),
        ...(node.attrs[WA_CALL_NODE_ATTRS.GROUP_JID] !== undefined
            ? { groupJid: node.attrs[WA_CALL_NODE_ATTRS.GROUP_JID] }
            : {}),
        ...(node.attrs[WA_CALL_NODE_ATTRS.SENDER_LID] !== undefined
            ? { senderLid: node.attrs[WA_CALL_NODE_ATTRS.SENDER_LID] }
            : {}),
        ...(payload.attrs[WA_CALL_NODE_ATTRS.CALLER_PN] !== undefined
            ? { callerPn: payload.attrs[WA_CALL_NODE_ATTRS.CALLER_PN] }
            : {}),
        ...(payload.attrs[WA_CALL_NODE_ATTRS.USERNAME] !== undefined
            ? { callerUsername: payload.attrs[WA_CALL_NODE_ATTRS.USERNAME] }
            : {}),
        ...(payload.attrs[WA_CALL_NODE_ATTRS.CALLER_COUNTRY_CODE] !== undefined
            ? { callerCountryCode: payload.attrs[WA_CALL_NODE_ATTRS.CALLER_COUNTRY_CODE] }
            : {}),
        ...(payload.attrs[WA_CALL_NODE_ATTRS.NOTIFY] !== undefined
            ? { callerPushName: payload.attrs[WA_CALL_NODE_ATTRS.NOTIFY] }
            : {}),
        ...(node.attrs[WA_CALL_NODE_ATTRS.PLATFORM] !== undefined
            ? { peerPlatform: node.attrs[WA_CALL_NODE_ATTRS.PLATFORM] }
            : {}),
        ...(node.attrs[WA_CALL_NODE_ATTRS.VERSION] !== undefined
            ? { peerAppVersion: node.attrs[WA_CALL_NODE_ATTRS.VERSION] }
            : {}),
        video: findNodeChild(payload, WA_CALL_CHILD_TAGS.VIDEO) !== undefined,
        ...(timestamp !== undefined ? { timestamp } : {}),
        ...(endTimestamp !== undefined ? { endTimestamp } : {}),
        ...(silence?.attrs[WA_CALL_NODE_ATTRS.REASON] !== undefined
            ? { silenceReason: silence.attrs[WA_CALL_NODE_ATTRS.REASON] }
            : {}),
        ...(participants.length > 0 ? { participants } : {}),
    }
}

/**
 * Reads the `CallKey` of a modern call message.
 *
 * The key is what names the call inside an ordinary message. Two shapes are
 * seen in the wild:
 *
 * 1. The call id itself, as raw bytes — the shape the classic flow uses.
 * 2. A tiny protobuf of its own: the id of the call (field 1), the chat it
 *    takes place in (field 2) and whether this device called (field 3).
 *
 * The reader accepts both: the protobuf shape is recognised by its tags, and
 * anything else is read as the call id.
 *
 * @param bytes The serialised key.
 * @returns The id of the call, the chat and the direction.
 */
export function parseCallKey(bytes: Uint8Array): {
    id?: string
    chatJid?: string
    fromMe?: boolean
} {
    // The classic flow puts the call id into the key as plain text; the
    // protobuf shape always carries tag bytes, which are not printable.
    const text = new TextDecoder().decode(bytes)
    if (isPrintable(text)) {
        return { id: text }
    }

    const result: { id?: string; chatJid?: string; fromMe?: boolean } = {}
    const reader = new ProtoReader(bytes)
    try {
        while (!reader.done) {
            const { field, wire } = reader.readTag()
            if (wire === 2) {
                const value = reader.readBytes()
                if (field === 1) result.id = bytesToHex(value)
                else if (field === 2) result.chatJid = new TextDecoder().decode(value)
            } else if (wire === 0) {
                const value = reader.readVarint()
                if (field === 3) result.fromMe = value !== 0n
            } else if (wire === 5) {
                reader.readFixed32()
            } else if (wire === 1) {
                reader.readFixed64()
            } else {
                throw new Error('proto: unknown wire type')
            }
        }
    } catch {
        // A key that cannot be read is a key that says nothing; the call is
        // still announced, only without its id.
    }
    return result
}

/**
 * Returns `true` when the text holds nothing but printable characters.
 *
 * @param value The text.
 */
function isPrintable(value: string): boolean {
    return value.length > 0 && !/[\x00-\x1f\x7f]/.test(value)
}

/**
 * Reads an optional integer attribute.
 *
 * @param value The raw attribute.
 * @returns The number, when the attribute holds one.
 */
function parseOptionalInt(value: string | undefined): number | undefined {
    if (value === undefined) return undefined
    const parsed = Number.parseInt(value, 10)
    return Number.isSafeInteger(parsed) ? parsed : undefined
}

/**
 * Formats bytes as hexadecimal.
 *
 * @param value The bytes.
 */
function bytesToHex(value: Uint8Array): string {
    let out = ''
    for (const byte of value) out += byte.toString(16).padStart(2, '0')
    return out
}
