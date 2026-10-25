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

/**
 * The way a group addresses its members.
 *
 * A group either names its members by phone number or by their linked
 * identity (LID). The mode decides which address the sender has to use for
 * itself, which address the members are reached with, and it travels in the
 * `addressing_mode` attribute of every group stanza.
 */
export type GroupAddressingMode = 'lid' | 'pn'

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
 * Resolves the addressing mode of a group from its member list.
 *
 * A group that names at least one of its members by linked identity is a
 * *LID* group: every stanza it carries names its sender and its members by
 * that identity. A group that names all of its members by phone number is a
 * *PN* group.
 *
 * The mode is not cosmetic. The sender key of a group belongs to the address
 * the group uses, and the `addressing_mode` attribute tells the server how
 * the addresses in the stanza have to be read, so a group message that uses
 * the wrong mode is not delivered to the members.
 *
 * @param participants The members of the group.
 */
export function resolveGroupAddressingMode(
    participants: readonly { jid: string }[],
): GroupAddressingMode {
    for (const participant of participants) {
        if (participant.jid.endsWith('@lid')) return 'lid'
    }
    return 'pn'
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

/** The default lifetime of a cached group membership, in milliseconds. */
export const GROUP_METADATA_CACHE_TTL_MS = 5 * 60 * 1000

/** One cached group membership. */
interface GroupMetadataCacheEntry {
    /** The metadata of the group. */
    metadata: GroupMetadata
    /** When the entry was written, in milliseconds since the epoch. */
    updatedAtMs: number
}

/**
 * The cached membership of the groups.
 *
 * The group server is picky about the number of metadata queries it
 * accepts: a client that asks for the member list of the same group over
 * and over is eventually refused with a `403 forbidden`. The membership
 * changes rarely, so the answer is kept for a while.
 */
export class GroupMetadataCache {
    private readonly entries = new Map<string, GroupMetadataCacheEntry>()
    private readonly ttlMs: number

    /**
     * @param options The store options.
     */
    constructor(options: { ttlMs?: number } = {}) {
        this.ttlMs = options.ttlMs ?? GROUP_METADATA_CACHE_TTL_MS
    }

    /**
     * Returns the cached metadata of a group.
     *
     * @param groupJid The group.
     */
    get(groupJid: string): GroupMetadata | undefined {
        const entry = this.entries.get(groupJid)
        if (!entry) return undefined
        if (Date.now() - entry.updatedAtMs > this.ttlMs) {
            this.entries.delete(groupJid)
            return undefined
        }
        return entry.metadata
    }

    /**
     * Stores the metadata of a group.
     *
     * @param groupJid The group.
     * @param metadata The metadata.
     */
    set(groupJid: string, metadata: GroupMetadata): void {
        this.entries.set(groupJid, { metadata, updatedAtMs: Date.now() })
    }

    /**
     * Drops the cached metadata of a group.
     *
     * @param groupJid The group.
     */
    invalidate(groupJid: string): void {
        this.entries.delete(groupJid)
    }

    /** Drops every cached membership. */
    clear(): void {
        this.entries.clear()
    }
}
