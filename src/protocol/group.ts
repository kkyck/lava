/**
 * Group metadata.
 *
 * The group server answers a `w:g2` query with a `<group>` node that carries
 * everything the client knows about a group: its subject, the settings the
 * owner chose and — most importantly — the list of the members.
 *
 * The member list is what a sender needs: a group message is encrypted with
 * the *sender key* of the sender and delivered to every device of every
 * member, so the devices have to be known before the message can be sent.
 *
 * A group may address its members by phone number or by their *linked
 * identity* (LID). The server reports both: the `jid` attribute holds the
 * address the group is addressed with and the `phone_number` attribute the
 * phone number of the very same member.
 */

import type { BinaryNode } from '../transport/binary/types.js'
import {
    findNodeChild,
    getNodeChildrenByTag,
    getNodeText,
} from '../transport/node/helpers.js'
import { WA_NODE_TAGS } from './constants.js'

/** The role of a group member. */
export type GroupParticipantRole = 'admin' | 'superadmin' | 'regular'

/** A member of a group. */
export interface GroupParticipant {
    /** The address the group addresses the member with. */
    jid: string
    /** The phone number of the member, when the server reports it. */
    phoneJid?: string
    /** The role of the member. */
    role: GroupParticipantRole
    /** When the member joined, in seconds since the epoch. */
    joinTime?: number
    /** The username of the member, when the server reports one. */
    username?: string
}

/** The metadata of a group. */
export interface GroupMetadata {
    /** The group's JID. */
    jid: string
    /** The subject of the group. */
    subject?: string
    /** The description of the group. */
    description?: string
    /** The address of the owner. */
    owner?: string
    /** The phone number of the owner. */
    ownerPhoneNumber?: string
    /** When the group was created, in seconds since the epoch. */
    createdAt?: number
    /** How many members the group has. */
    participantCount?: number
    /** Whether the group is restricted to the members' phone numbers. */
    restrict?: boolean
    /** Whether only the admins may post. */
    announce?: boolean
    /** Whether new members get the history of the group. */
    memberShareGroupHistory?: boolean
    /** The lifetime of the messages, in seconds. */
    ephemeralExpiration?: number
    /** Who may trigger the expiry of the messages. */
    ephemeralTrigger?: number
    /** The members of the group. */
    participants: GroupParticipant[]
}

/**
 * Finds the `<group>` node in a response.
 *
 * The server answers with the group node directly, but a few endpoints wrap
 * it in another node, so the search is recursive.
 *
 * @param node The node to search in.
 */
export function findGroupNode(node: BinaryNode): BinaryNode | undefined {
    if (node.tag === WA_NODE_TAGS.GROUP) return node
    const children = getNodeChildrenByTag(node, WA_NODE_TAGS.GROUP)
    return children[0]
}

/**
 * Parses the member list of a group.
 *
 * @param node The `<group>` node, or a node that holds one.
 */
export function parseGroupParticipants(node: BinaryNode): GroupParticipant[] {
    const target = findGroupNode(node)
    if (!target) return []
    const out: GroupParticipant[] = []
    for (const participant of getNodeChildrenByTag(target, WA_NODE_TAGS.PARTICIPANT)) {
        const jid = participant.attrs.jid
        if (!jid) continue
        const entry: GroupParticipant = {
            jid,
            role: parseParticipantRole(participant.attrs.type),
        }
        const phone = participant.attrs.phone_number
        if (phone) entry.phoneJid = phone
        const joinTime = Number.parseInt(participant.attrs.join_time ?? '', 10)
        if (Number.isSafeInteger(joinTime) && joinTime > 0) entry.joinTime = joinTime
        const username = participant.attrs.username
        if (username) entry.username = username
        out.push(entry)
    }
    return out
}

/**
 * Parses the metadata of a group.
 *
 * @param node The `<group>` node, or a node that holds one.
 */
export function parseGroupMetadata(node: BinaryNode): GroupMetadata {
    const target = findGroupNode(node)
    if (!target) {
        throw new Error(`protocol: expected a <group> node, got <${node.tag}>`)
    }
    const attrs = target.attrs
    const metadata: GroupMetadata = {
        jid: groupJidFromAttrs(attrs.id ?? attrs.jid ?? ''),
        participants: parseGroupParticipants(target),
    }

    if (attrs.subject) metadata.subject = attrs.subject
    if (attrs.creator) metadata.owner = attrs.creator
    if (attrs.creator_pn) metadata.ownerPhoneNumber = attrs.creator_pn

    const descriptionNode = findNodeChild(target, WA_NODE_TAGS.DESCRIPTION)
    if (descriptionNode) {
        const body = findNodeChild(descriptionNode, WA_NODE_TAGS.BODY)
        const text = body ? getNodeText(body) : getNodeText(descriptionNode)
        if (text) metadata.description = text
    }

    const creation = Number.parseInt(attrs.creation ?? '', 10)
    if (Number.isSafeInteger(creation) && creation > 0) metadata.createdAt = creation

    const size = Number.parseInt(attrs.size ?? '', 10)
    if (Number.isSafeInteger(size) && size > 0) metadata.participantCount = size

    if (findNodeChild(target, WA_NODE_TAGS.LOCKED)) metadata.restrict = true
    if (findNodeChild(target, WA_NODE_TAGS.ANNOUNCEMENT)) metadata.announce = true

    const historyNode = findNodeChild(target, 'member_share_group_history_mode')
    if (historyNode) {
        const mode = getNodeText(historyNode)
        metadata.memberShareGroupHistory = mode === 'on' || mode === 'all'
    }

    const ephemeralNode = findNodeChild(target, WA_NODE_TAGS.EPHEMERAL)
    if (ephemeralNode) {
        const expiration = Number.parseInt(ephemeralNode.attrs.expiration ?? '', 10)
        if (Number.isSafeInteger(expiration)) metadata.ephemeralExpiration = expiration
        const trigger = Number.parseInt(ephemeralNode.attrs.trigger ?? '', 10)
        if (Number.isSafeInteger(trigger)) metadata.ephemeralTrigger = trigger
    }

    return metadata
}

/**
 * Reads the role of a member.
 *
 * @param type The `type` attribute of the participant node.
 */
function parseParticipantRole(type: string | undefined): GroupParticipantRole {
    if (type === 'superadmin') return 'superadmin'
    if (type === 'admin') return 'admin'
    return 'regular'
}

/**
 * Builds the JID of a group from the attributes of a `<group>` node.
 *
 * @param id The `id` or `jid` attribute.
 */
function groupJidFromAttrs(id: string): string {
    if (!id) return ''
    if (id.includes('@')) return id
    return `${id}@g.us`
}
