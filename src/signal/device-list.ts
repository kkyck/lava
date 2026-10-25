/**
 * The device list.
 *
 * Before a message can be sent, the client has to know every device the
 * recipient runs. WhatsApp exposes that list through a `usync` query with a
 * `<devices version="2">` protocol node:
 *
 * ```xml
 * <iq type="get" xmlns="usync">
 *   <usync sid="…" mode="query" context="interactive">
 *     <query><devices version="2"/></query>
 *     <list><user jid="…"/></list>
 *   </usync>
 * </iq>
 * ```
 *
 * The answer carries one `<device-list>` per user, holding a `<device id="…">`
 * entry per device.
 *
 * The store keeps the result for a while, because the list only changes when
 * the user logs in on a new device.
 */

import { WA_NODE_TAGS } from '../protocol/constants.js'
import { buildDeviceJid, splitJid, toUserJid } from '../protocol/jid.js'
import type { BinaryNode } from '../transport/binary/types.js'
import { findNodeChild, getNodeChildrenByTag } from '../transport/node/helpers.js'
import { buildUsyncIq } from '../transport/node/builders.js'

/** How long a device list stays valid, in milliseconds. */
export const DEVICE_LIST_TTL_MS = 24 * 60 * 60 * 1000

/** A single device of a user. */
export interface DeviceEntry {
    /** The device id (`0` is the primary device). */
    deviceId: number
    /** The full device JID. */
    jid: string
}

/** The cached device list of a user. */
export interface DeviceListEntry {
    /** The user's JID. */
    userJid: string
    /** The user's devices. */
    devices: DeviceEntry[]
    /** When the list was refreshed. */
    updatedAtMs: number
}

/**
 * Builds the `usync` IQ that resolves a user's device list.
 *
 * @param jids The users to resolve.
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
 * Parses the device lists out of a `usync` result.
 *
 * @param result The IQ result.
 * @param requestedUsers The users that were queried.
 */
export function parseDeviceListResponse(
    result: BinaryNode,
    requestedUsers: readonly string[],
): DeviceListEntry[] {
    const usync = findNodeChild(result, WA_NODE_TAGS.USYNC)
    if (!usync) return []
    const list = findNodeChild(usync, WA_NODE_TAGS.LIST)
    if (!list) return []

    const requested = new Set(requestedUsers.map((jid) => toUserJid(jid)))
    const out: DeviceListEntry[] = []
    for (const userNode of getNodeChildrenByTag(list, WA_NODE_TAGS.USER)) {
        const rawJid = userNode.attrs.jid
        if (!rawJid) continue
        let normalized: string
        try {
            normalized = toUserJid(rawJid)
        } catch {
            continue
        }
        if (!requested.has(normalized)) continue

        const devicesNode = findNodeChild(userNode, WA_NODE_TAGS.DEVICES)
        if (!devicesNode) continue
        if (findNodeChild(devicesNode, WA_NODE_TAGS.ERROR)) continue
        const deviceListNode = findNodeChild(devicesNode, 'device-list')
        if (!deviceListNode) continue

        const parsed = splitJid(normalized)
        const rawAt = rawJid.indexOf('@')
        const rawServer =
            rawAt >= 1 && rawAt < rawJid.length - 1 ? rawJid.slice(rawAt + 1) : parsed.server

        const seen = new Set<number>()
        const devices: DeviceEntry[] = []
        for (const deviceNode of getNodeChildrenByTag(deviceListNode, WA_NODE_TAGS.DEVICE)) {
            const deviceId = Number.parseInt(deviceNode.attrs.id ?? '', 10)
            if (!Number.isSafeInteger(deviceId) || deviceId < 0) continue
            if (seen.has(deviceId)) continue
            seen.add(deviceId)
            devices.push({
                deviceId,
                jid: buildDeviceJid(parsed.user, parsed.server, deviceId, { rawServer }),
            })
        }
        out.push({ userJid: normalized, devices, updatedAtMs: Date.now() })
    }
    return out
}

/**
 * An in-memory device-list cache.
 *
 * The cache is deliberately simple: one entry per user, refreshed on demand.
 */
export class DeviceListStore {
    private readonly entries = new Map<string, DeviceListEntry>()
    private readonly ttlMs: number

    /**
     * @param options The store options.
     */
    constructor(options: { ttlMs?: number } = {}) {
        this.ttlMs = options.ttlMs ?? DEVICE_LIST_TTL_MS
    }

    /**
     * Returns the cached devices of a user.
     *
     * @param userJid The user's JID.
     */
    get(userJid: string): DeviceEntry[] | undefined {
        const key = toUserJid(userJid)
        const entry = this.entries.get(key)
        if (!entry) return undefined
        if (Date.now() - entry.updatedAtMs > this.ttlMs) {
            this.entries.delete(key)
            return undefined
        }
        return entry.devices
    }

    /**
     * Stores the devices of a user.
     *
     * @param entry The device list.
     */
    set(entry: DeviceListEntry): void {
        this.entries.set(toUserJid(entry.userJid), entry)
    }

    /**
     * Removes the cached devices of a user.
     *
     * @param userJid The user's JID.
     */
    remove(userJid: string): void {
        this.entries.delete(toUserJid(userJid))
    }

    /** Number of cached users. */
    get size(): number {
        return this.entries.size
    }

    /** Drops every cached entry. */
    clear(): void {
        this.entries.clear()
    }
}
