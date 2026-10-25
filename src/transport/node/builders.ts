/**
 * Protocol node builders.
 *
 * Every request the client sends is an XML-ish node; this module builds
 * them. The shapes follow the official clients exactly — the server
 * fingerprints them, so a slightly different stanza is rejected or, worse,
 * silently treated as something else.
 */

import {
    WA_ADDRESSING_MODES,
    WA_DEFAULTS,
    WA_IQ_TYPES,
    WA_NODE_TAGS,
    WA_PRESENCE_TYPES,
    WA_PRIVACY_VALUES,
    WA_XMLNS,
} from '../../protocol/constants.js'
import type { BinaryNode } from '../binary/types.js'
import { buildIqNode } from './query.js'

/* ──────────────────────────────────────────────────────────────────────────
 * Presence
 * ────────────────────────────────────────────────────────────────────────── */

/**
 * Builds a `<presence>` stanza.
 *
 * @param type The presence type (`available`, `unavailable`, …).
 * @param name The push name to publish.
 */
export function buildPresenceNode(type: string, name?: string): BinaryNode {
    const attrs: Record<string, string> = {}
    if (type) attrs.type = type
    if (name) attrs.name = name
    return { tag: WA_NODE_TAGS.PRESENCE, attrs }
}

/**
 * Builds a `<presence type="subscribe">` stanza.
 *
 * @param jid The contact to subscribe to.
 * @param name The optional display name.
 */
export function buildPresenceSubscribeNode(jid: string, name?: string): BinaryNode {
    const attrs: Record<string, string> = {
        type: 'subscribe',
        to: jid,
    }
    if (name !== undefined) attrs.name = name
    return { tag: WA_NODE_TAGS.PRESENCE, attrs }
}

/* ──────────────────────────────────────────────────────────────────────────
 * Chat state
 * ────────────────────────────────────────────────────────────────────────── */

/**
 * Builds a `<chatstate>` stanza.
 *
 * @param to The recipient.
 * @param state The chat state (`composing` or `paused`).
 */
export function buildChatStateNode(to: string, state: 'composing' | 'paused'): BinaryNode {
    return {
        tag: WA_NODE_TAGS.CHATSTATE,
        attrs: { to },
        content: state,
    }
}

/* ──────────────────────────────────────────────────────────────────────────
 * usync
 * ────────────────────────────────────────────────────────────────────────── */

/** The usync contexts. */
export const WA_USYNC_CONTEXTS = Object.freeze({
    INTERACTIVE: 'interactive',
    NOTIFICATION: 'notification',
} as const)

/** The usync modes. */
export const WA_USYNC_MODES = Object.freeze({
    QUERY: 'query',
} as const)

/** The default usync envelope attributes. */
export const WA_USYNC_DEFAULTS = Object.freeze({
    INDEX: '0',
    LAST: 'true',
} as const)

/** A user entry of a usync request. */
export interface UsyncUser {
    /** The user JID. */
    jid?: string
    /** Extra attributes. */
    attrs?: Record<string, string>
    /** Optional children. */
    content?: BinaryNode[]
}

/** Configuration for {@link buildUsyncIq}. */
export interface UsyncIqConfig {
    /** The sync id. */
    sid: string
    /** The users to query. */
    users: UsyncUser[]
    /** The protocol nodes to request. */
    queryProtocolNodes: BinaryNode[]
    /** The host to send the query to. */
    hostDomain?: string
    /** The usync context. */
    context?: string
    /** The usync mode. */
    mode?: string
    /** The pagination index. */
    index?: string
    /** Whether this is the last page. */
    last?: string
}

/**
 * Builds a `usync` IQ.
 *
 * @param config The query configuration.
 */
export function buildUsyncIq(config: UsyncIqConfig): BinaryNode {
    if (config.queryProtocolNodes.length === 0) {
        throw new Error('usync query must include at least one protocol node')
    }
    const users = config.users.map((user) => ({
        tag: WA_NODE_TAGS.USER,
        attrs: {
            ...(user.attrs ?? {}),
            ...(user.jid !== undefined ? { jid: user.jid } : {}),
        },
        ...(user.content !== undefined ? { content: user.content } : {}),
    }))
    return buildIqNode(
        WA_IQ_TYPES.GET,
        config.hostDomain ?? WA_DEFAULTS.HOST_DOMAIN,
        WA_XMLNS.USYNC,
        [
            {
                tag: WA_NODE_TAGS.USYNC,
                attrs: {
                    sid: config.sid,
                    index: config.index ?? WA_USYNC_DEFAULTS.INDEX,
                    last: config.last ?? WA_USYNC_DEFAULTS.LAST,
                    mode: config.mode ?? WA_USYNC_MODES.QUERY,
                    context: config.context ?? WA_USYNC_CONTEXTS.INTERACTIVE,
                },
                content: [
                    {
                        tag: WA_NODE_TAGS.QUERY,
                        attrs: {},
                        content: config.queryProtocolNodes,
                    },
                    {
                        tag: WA_NODE_TAGS.LIST,
                        attrs: {},
                        content: users,
                    },
                ],
            },
        ],
    )
}

/**
 * Builds a device-list usync query.
 *
 * @param jids The users whose device list should be resolved.
 * @param sid The sync id.
 */
export function buildDeviceListUsyncIq(jids: string[], sid: string): BinaryNode {
    return buildUsyncIq({
        sid,
        users: jids.map((jid) => ({ jid })),
        queryProtocolNodes: [{ tag: WA_NODE_TAGS.DEVICES, attrs: { version: '2' } }],
    })
}

/**
 * Builds a profile usync query.
 *
 * @param jids The users to look up.
 * @param sid The sync id.
 */
export function buildProfileUsyncIq(jids: string[], sid: string): BinaryNode {
    return buildUsyncIq({
        sid,
        users: jids.map((jid) => ({ jid })),
        queryProtocolNodes: [
            { tag: WA_NODE_TAGS.CONTACT, attrs: {} },
            { tag: WA_NODE_TAGS.PUSHNAME, attrs: {} },
            { tag: WA_NODE_TAGS.STATUS, attrs: {} },
        ],
    })
}

/* ──────────────────────────────────────────────────────────────────────────
 * Privacy
 * ────────────────────────────────────────────────────────────────────────── */

/** The `privacy` node children. */
export const WA_PRIVACY_TAGS = Object.freeze({
    CATEGORY: 'category',
    LIST: 'list',
    USER: 'user',
    VALUE: 'value',
    NAME: 'name',
} as const)

/** The placeholder used when the client holds no privacy version stamp. */
export const WA_PRIVACY_DHASH_NONE = 'none'

/**
 * Builds a privacy-settings read IQ.
 */
export function buildGetPrivacySettingsIq(): BinaryNode {
    return buildIqNode(WA_IQ_TYPES.GET, WA_DEFAULTS.HOST_DOMAIN, WA_XMLNS.PRIVACY, [
        { tag: WA_NODE_TAGS.PRIVACY, attrs: {} },
    ])
}

/**
 * Builds a privacy-category write IQ.
 *
 * @param category The category (`last`, `online`, `profile`, …).
 * @param value The value (`all`, `contacts`, `none`, …).
 */
export function buildSetPrivacyCategoryIq(category: string, value: string): BinaryNode {
    return buildIqNode(WA_IQ_TYPES.SET, WA_DEFAULTS.HOST_DOMAIN, WA_XMLNS.PRIVACY, [
        {
            tag: WA_NODE_TAGS.PRIVACY,
            attrs: {},
            content: [
                {
                    tag: WA_PRIVACY_TAGS.CATEGORY,
                    attrs: { name: category, value },
                },
            ],
        },
    ])
}

/**
 * Builds a block-list read IQ.
 *
 * @param category The category the list belongs to.
 * @param lidAddressing Whether the account is LID-migrated.
 */
export function buildGetPrivacyDisallowedListIq(
    category: string,
    lidAddressing = false,
): BinaryNode {
    return buildIqNode(WA_IQ_TYPES.GET, WA_DEFAULTS.HOST_DOMAIN, WA_XMLNS.PRIVACY, [
        {
            tag: WA_NODE_TAGS.PRIVACY,
            attrs: lidAddressing ? { addressing_mode: WA_ADDRESSING_MODES.LID } : {},
            content: [
                {
                    tag: WA_PRIVACY_TAGS.LIST,
                    attrs: { name: category, value: WA_PRIVACY_VALUES.CONTACT_BLACKLIST },
                },
            ],
        },
    ])
}

/**
 * Builds a block-list write IQ.
 *
 * @param category The category the list belongs to.
 * @param entries The JIDs to block or unblock.
 * @param dhash The version stamp from the last read/write.
 * @param lidAddressing Whether the account is LID-migrated.
 */
export function buildSetPrivacyDisallowedListIq(
    category: string,
    entries: string[],
    dhash?: string,
    lidAddressing = false,
): BinaryNode {
    const users = entries.map((jid) => ({
        tag: WA_PRIVACY_TAGS.USER,
        attrs: { jid, action: 'add' },
    }))
    return buildIqNode(WA_IQ_TYPES.SET, WA_DEFAULTS.HOST_DOMAIN, WA_XMLNS.PRIVACY, [
        {
            tag: WA_NODE_TAGS.PRIVACY,
            attrs: lidAddressing ? { addressing_mode: WA_ADDRESSING_MODES.LID } : {},
            content: [
                {
                    tag: WA_PRIVACY_TAGS.CATEGORY,
                    attrs: {
                        name: category,
                        value: WA_PRIVACY_VALUES.CONTACT_BLACKLIST,
                        dhash: dhash ?? WA_PRIVACY_DHASH_NONE,
                    },
                    content: users,
                },
            ],
        },
    ])
}

/* ──────────────────────────────────────────────────────────────────────────
 * Profile
 * ────────────────────────────────────────────────────────────────────────── */

/**
 * Builds a profile-picture read IQ.
 *
 * @param targetJid Whose picture to fetch.
 * @param type `preview` or `image`.
 * @param existingId The previously known picture id.
 */
export function buildGetProfilePictureIq(
    targetJid: string,
    type: 'preview' | 'image' = 'preview',
    existingId?: string,
): BinaryNode {
    const pictureAttrs: Record<string, string> = { type, query: 'url' }
    if (existingId) pictureAttrs.id = existingId
    return buildIqNode(
        WA_IQ_TYPES.GET,
        WA_DEFAULTS.HOST_DOMAIN,
        WA_XMLNS.PROFILE_PICTURE,
        [{ tag: WA_NODE_TAGS.PICTURE, attrs: pictureAttrs }],
        { target: targetJid },
    )
}

/**
 * Builds a profile-picture write IQ.
 *
 * @param imageBytes The encoded image.
 */
export function buildSetProfilePictureIq(imageBytes: Uint8Array): BinaryNode {
    return buildIqNode(WA_IQ_TYPES.SET, WA_DEFAULTS.HOST_DOMAIN, WA_XMLNS.PROFILE_PICTURE, [
        { tag: WA_NODE_TAGS.PICTURE, attrs: { type: 'image' }, content: imageBytes },
    ])
}

/**
 * Builds a profile-picture delete IQ.
 */
export function buildDeleteProfilePictureIq(): BinaryNode {
    return buildIqNode(
        WA_IQ_TYPES.SET,
        WA_DEFAULTS.HOST_DOMAIN,
        WA_XMLNS.PROFILE_PICTURE,
        undefined,
    )
}

/**
 * Builds a "set status" IQ.
 *
 * @param text The status text.
 */
export function buildSetStatusIq(text: string): BinaryNode {
    return buildIqNode(WA_IQ_TYPES.SET, WA_DEFAULTS.HOST_DOMAIN, WA_XMLNS.STATUS, [
        { tag: WA_NODE_TAGS.STATUS, attrs: {}, content: text },
    ])
}

/**
 * Builds a "push name" change IQ.
 *
 * @param pushName The new push name.
 */
export function buildSetPushNameIq(pushName: string): BinaryNode {
    return buildIqNode(WA_IQ_TYPES.SET, WA_DEFAULTS.HOST_DOMAIN, WA_XMLNS.PRIVACY, [
        {
            tag: WA_NODE_TAGS.PRIVACY,
            attrs: {},
            content: [
                {
                    tag: 'pushname',
                    attrs: {},
                    content: pushName,
                },
            ],
        },
    ])
}

/**
 * Builds a disappearing-mode write IQ.
 *
 * @param durationSeconds The expiry; `0` disables the timer.
 */
export function buildSetDisappearingModeIq(durationSeconds: number): BinaryNode {
    return buildIqNode(
        WA_IQ_TYPES.SET,
        WA_DEFAULTS.HOST_DOMAIN,
        WA_XMLNS.DISAPPEARING_MODE,
        [
            {
                tag: WA_NODE_TAGS.DISAPPEARING_MODE,
                attrs: { duration: String(durationSeconds) },
            },
        ],
    )
}

/* ──────────────────────────────────────────────────────────────────────────
 * Groups
 * ────────────────────────────────────────────────────────────────────────── */

/**
 * Builds a group-creation IQ.
 *
 * @param subject The group subject.
 * @param participants The initial member JIDs.
 * @param description The optional group description.
 */
export function buildCreateGroupIq(
    subject: string,
    participants: string[],
    description?: string,
): BinaryNode {
    const children: BinaryNode[] = participants.map((jid) => ({
        tag: WA_NODE_TAGS.PARTICIPANT,
        attrs: { jid },
    }))
    if (description) {
        children.push({
            tag: WA_NODE_TAGS.DESCRIPTION,
            attrs: { id: `${Date.now()}` },
            content: [{ tag: WA_NODE_TAGS.BODY, attrs: {}, content: description }],
        })
    }
    return buildIqNode(WA_IQ_TYPES.SET, WA_DEFAULTS.GROUP_SERVER, WA_XMLNS.GROUPS, [
        { tag: 'create', attrs: { subject }, content: children },
    ])
}

/**
 * Builds a participant-change IQ (add/remove/promote/demote).
 *
 * @param groupJid The group.
 * @param action `add`, `remove`, `promote` or `demote`.
 * @param participants The affected members.
 */
export function buildGroupParticipantChangeIq(
    groupJid: string,
    action: 'add' | 'remove' | 'promote' | 'demote',
    participants: string[],
): BinaryNode {
    return buildIqNode(WA_IQ_TYPES.SET, groupJid, WA_XMLNS.GROUPS, [
        {
            tag: action,
            attrs: {},
            content: participants.map((jid) => ({
                tag: WA_NODE_TAGS.PARTICIPANT,
                attrs: { jid },
            })),
        },
    ])
}

/**
 * Builds a group-leave IQ.
 *
 * @param groupJids The groups to leave.
 */
export function buildLeaveGroupIq(groupJids: string[]): BinaryNode {
    return buildIqNode(WA_IQ_TYPES.SET, WA_DEFAULTS.GROUP_SERVER, WA_XMLNS.GROUPS, [
        {
            tag: 'leave',
            attrs: {},
            content: groupJids.map((jid) => ({ tag: WA_NODE_TAGS.GROUP, attrs: { id: jid } })),
        },
    ])
}

/**
 * Builds a group-subject change IQ.
 *
 * @param groupJid The group.
 * @param subject The new subject.
 */
export function buildSetGroupSubjectIq(groupJid: string, subject: string): BinaryNode {
    return buildIqNode(WA_IQ_TYPES.SET, groupJid, WA_XMLNS.GROUPS, [
        { tag: 'subject', attrs: {}, content: subject },
    ])
}

/**
 * Builds a group-description change IQ.
 *
 * @param groupJid The group.
 * @param description The new description.
 */
export function buildSetGroupDescriptionIq(groupJid: string, description: string): BinaryNode {
    return buildIqNode(WA_IQ_TYPES.SET, groupJid, WA_XMLNS.GROUPS, [
        {
            tag: 'description',
            attrs: { id: `${Date.now()}` },
            content: [{ tag: WA_NODE_TAGS.BODY, attrs: {}, content: description }],
        },
    ])
}

/**
 * Builds a group-metadata read IQ.
 *
 * @param groupJid The group.
 */
export function buildGetGroupMetadataIq(groupJid: string): BinaryNode {
    return buildIqNode(WA_IQ_TYPES.GET, groupJid, WA_XMLNS.GROUPS, [
        { tag: 'membership_approval_requests', attrs: {} },
    ])
}

/**
 * Builds a group-ephemeral write IQ.
 *
 * @param groupJid The group.
 * @param expirationSeconds The expiry; `0` disables the timer.
 */
export function buildSetGroupEphemeralIq(groupJid: string, expirationSeconds: number): BinaryNode {
    return buildIqNode(WA_IQ_TYPES.SET, groupJid, WA_XMLNS.GROUPS, [
        { tag: WA_NODE_TAGS.EPHEMERAL, attrs: { expiration: String(expirationSeconds) } },
    ])
}

/**
 * Builds a group-invite read IQ.
 *
 * @param groupJid The group.
 */
export function buildGetGroupInviteIq(groupJid: string): BinaryNode {
    return buildIqNode(WA_IQ_TYPES.GET, groupJid, WA_XMLNS.GROUPS, [
        { tag: 'invite', attrs: {} },
    ])
}

/* ──────────────────────────────────────────────────────────────────────────
 * Calls
 * ────────────────────────────────────────────────────────────────────────── */

/** The media payload of a call offer. */
export interface CallMediaPayload {
    /** The WebRTC session description (SDP). */
    sdp?: string
    /** The ICE candidates, already formatted for the wire. */
    iceCandidates?: string[]
    /** An opaque transport blob, when the media engine produced one. */
    transport?: Uint8Array
}

/**
 * Builds a call-offer stanza.
 *
 * The classic WhatsApp call protocol sends the offer as a `<call>` node with
 * an `<offer>` child:
 *
 * ```xml
 * <call to="…" call-id="…" call-creator="…" t="…">
 *   <offer call-id="…" call-creator="…" t="…">
 *     <video/>              <!-- only for video calls -->
 *     <transport>…</transport>
 *   </offer>
 * </call>
 * ```
 *
 * @param to The callee.
 * @param callId The call id.
 * @param creator The caller's JID.
 * @param options Video/media options.
 */
export function buildCallOfferNode(
    to: string,
    callId: string,
    creator: string,
    options: { video?: boolean; media?: CallMediaPayload; timestamp?: number } = {},
): BinaryNode {
    const timestamp = options.timestamp ?? Math.floor(Date.now() / 1000)
    const offerChildren: BinaryNode[] = []
    if (options.video === true) {
        offerChildren.push({ tag: 'video', attrs: {} })
    }
    if (options.media?.transport) {
        offerChildren.push({ tag: 'transport', attrs: {}, content: options.media.transport })
    }
    if (options.media?.sdp !== undefined) {
        offerChildren.push({ tag: 'sdp', attrs: {}, content: options.media.sdp })
    }
    return {
        tag: WA_NODE_TAGS.CALL,
        attrs: {
            to,
            'call-id': callId,
            'call-creator': creator,
            t: String(timestamp),
            'call-type': options.video === true ? 'video' : 'audio',
        },
        content: [
            {
                tag: 'offer',
                attrs: {
                    'call-id': callId,
                    'call-creator': creator,
                    t: String(timestamp),
                },
                ...(offerChildren.length > 0 ? { content: offerChildren } : {}),
            },
        ],
    }
}

/**
 * Builds a call-accept stanza.
 *
 * @param to The peer to answer.
 * @param callId The call id.
 * @param creator The caller's JID.
 * @param options Video/media options.
 */
export function buildCallAcceptNode(
    to: string,
    callId: string,
    creator: string,
    options: { video?: boolean; media?: CallMediaPayload; timestamp?: number } = {},
): BinaryNode {
    const timestamp = options.timestamp ?? Math.floor(Date.now() / 1000)
    const acceptChildren: BinaryNode[] = []
    if (options.video === true) {
        acceptChildren.push({ tag: 'video', attrs: {} })
    }
    if (options.media?.transport) {
        acceptChildren.push({ tag: 'transport', attrs: {}, content: options.media.transport })
    }
    if (options.media?.sdp !== undefined) {
        acceptChildren.push({ tag: 'sdp', attrs: {}, content: options.media.sdp })
    }
    return {
        tag: WA_NODE_TAGS.CALL,
        attrs: {
            to,
            'call-id': callId,
            'call-creator': creator,
            t: String(timestamp),
        },
        content: [
            {
                tag: 'accept',
                attrs: {
                    'call-id': callId,
                    'call-creator': creator,
                    t: String(timestamp),
                },
                ...(acceptChildren.length > 0 ? { content: acceptChildren } : {}),
            },
        ],
    }
}

/**
 * Builds a call-reject stanza.
 *
 * @param to The peer.
 * @param callId The call id.
 * @param creator The caller's JID.
 * @param reason The optional rejection reason.
 */
export function buildCallRejectNode(
    to: string,
    callId: string,
    creator: string,
    reason?: string,
): BinaryNode {
    const timestamp = Math.floor(Date.now() / 1000)
    return {
        tag: WA_NODE_TAGS.CALL,
        attrs: {
            to,
            'call-id': callId,
            'call-creator': creator,
            t: String(timestamp),
        },
        content: [
            {
                tag: 'reject',
                attrs: {
                    'call-id': callId,
                    'call-creator': creator,
                    t: String(timestamp),
                    ...(reason !== undefined ? { reason } : {}),
                },
            },
        ],
    }
}

/**
 * Builds a call-terminate stanza.
 *
 * @param to The peer.
 * @param callId The call id.
 * @param creator The caller's JID.
 */
export function buildCallTerminateNode(to: string, callId: string, creator: string): BinaryNode {
    const timestamp = Math.floor(Date.now() / 1000)
    return {
        tag: WA_NODE_TAGS.CALL,
        attrs: {
            to,
            'call-id': callId,
            'call-creator': creator,
            t: String(timestamp),
        },
        content: [
            {
                tag: 'terminate',
                attrs: {
                    'call-id': callId,
                    'call-creator': creator,
                    t: String(timestamp),
                },
            },
        ],
    }
}
