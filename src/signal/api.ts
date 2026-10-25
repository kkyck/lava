/**
 * Signal key-bundle API.
 *
 * WhatsApp does not use Signal's own protobuf pre-key bundle message. The
 * key material travels in the node protocol instead, inside `<iq>` stanzas
 * with the `encrypt` namespace:
 *
 * ```text
 *   <iq type="set" xmlns="encrypt">
 *     <identity>…</identity>
 *     <registration>…</registration>
 *     <type>…</type>
 *     <list><key><id>…</id><value>…</value></key>…</list>
 *     <skey><id>…</id><value>…</value><signature>…</signature></skey>
 *   </iq>
 * ```
 */

import { WA_IQ_TYPES, WA_NODE_TAGS, WA_XMLNS } from '../protocol/constants.js'
import { HOST_DOMAIN, parseSignalAddressFromJid } from '../protocol/jid.js'
import type { BinaryNode } from '../transport/binary/types.js'
import {
    decodeNodeContentBytes,
    findNodeChild,
    findNodeChildrenByTags,
    getNodeChildrenByTag,
} from '../transport/node/helpers.js'
import { buildIqNode } from '../transport/node/query.js'
import type { PreKeyBundle, SerializedKeyPair } from './session.js'
import type { PreKeyRecord, RegistrationInfo, SignedPreKeyRecord } from './keys.js'

/** The key-bundle type byte WhatsApp uses (`5` = curve25519). */
export const SIGNAL_KEY_BUNDLE_TYPE_BYTES = new Uint8Array([5])

/** Length of the key-bundle type field. */
export const SIGNAL_KEY_BUNDLE_TYPE_LENGTH = 1

/** Length of the registration id field. */
export const SIGNAL_REGISTRATION_ID_LENGTH = 4

/** Length of a key id field. */
export const SIGNAL_KEY_ID_LENGTH = 3

/** Length of a raw (unprefixed) public key. */
export const SIGNAL_KEY_DATA_LENGTH = 32

/** Length of an XEdDSA signature. */
export const SIGNAL_SIGNATURE_LENGTH = 64

/**
 * Number of one-time pre-keys uploaded at once.
 *
 * The official client uploads a full batch of 812 pre-keys in a single
 * `<iq>` (`WAWebUploadPreKeysJob`), and the server keeps handing them out
 * one by one.
 */
export const SIGNAL_UPLOAD_PREKEYS_COUNT = 812

/** How often the signed pre-key is rotated (27 days). */
export const SIGNAL_SIGNED_PREKEY_ROTATION_INTERVAL_MS = 27 * 24 * 60 * 60 * 1000

/**
 * Encodes an integer as a fixed-width big-endian byte string.
 *
 * @param byteLength The width.
 * @param value The value.
 */
export function intToBytes(byteLength: number, value: number): Uint8Array {
    const out = new Uint8Array(byteLength)
    let remaining = value
    for (let i = byteLength - 1; i >= 0; i -= 1) {
        out[i] = remaining & 0xff
        remaining = Math.floor(remaining / 256)
    }
    return out
}

/**
 * Parses a big-endian unsigned integer.
 *
 * @param bytes The encoded bytes.
 * @param field A label used in error messages.
 */
export function parseUint(bytes: Uint8Array, field: string): number {
    if (bytes.length === 1) return bytes[0]!
    if (bytes.length === 2) return (bytes[0]! << 8) | bytes[1]!
    if (bytes.length === 3) return (bytes[0]! << 16) | (bytes[1]! << 8) | bytes[2]!
    if (bytes.length === 4) {
        return (
            bytes[0]! * 0x1000000 + bytes[1]! * 0x10000 + bytes[2]! * 0x100 + bytes[3]!
        )
    }
    throw new Error(`${field} has invalid byte length`)
}

/**
 * Decodes bytes and asserts an exact length.
 *
 * @param content The node content.
 * @param field A label used in error messages.
 * @param expectedLength The required length.
 */
export function decodeExactLength(
    content: BinaryNode['content'],
    field: string,
    expectedLength: number,
): Uint8Array {
    const bytes = decodeNodeContentBytes(content, field)
    if (bytes.byteLength !== expectedLength) {
        throw new Error(`${field} must be ${expectedLength} bytes`)
    }
    return bytes
}

/** Strips the `0x05` prefix from a serialized public key. */
function toRawPubKey(key: Uint8Array): Uint8Array {
    return key.length === 33 ? key.subarray(1) : key
}

/**
 * Builds the `<skey>` node.
 *
 * @param signedPreKey The signed pre-key record.
 */
function buildSignedPreKeyNode(signedPreKey: SignedPreKeyRecord): BinaryNode {
    return {
        tag: WA_NODE_TAGS.SKEY,
        attrs: {},
        content: [
            {
                tag: WA_NODE_TAGS.ID,
                attrs: {},
                content: intToBytes(3, signedPreKey.keyId),
            },
            {
                tag: WA_NODE_TAGS.VALUE,
                attrs: {},
                content: toRawPubKey(signedPreKey.keyPair.pubKey),
            },
            {
                tag: WA_NODE_TAGS.SIGNATURE,
                attrs: {},
                content: signedPreKey.signature,
            },
        ],
    }
}

/**
 * Builds the IQ that uploads this device's pre-keys to the server.
 *
 * @param registrationInfo The registration info.
 * @param signedPreKey The signed pre-key.
 * @param preKeys The one-time pre-keys.
 */
export function buildPreKeyUploadIq(
    registrationInfo: RegistrationInfo,
    signedPreKey: SignedPreKeyRecord,
    preKeys: PreKeyRecord[],
): BinaryNode {
    const children: BinaryNode[] = [
        {
            tag: WA_NODE_TAGS.IDENTITY,
            attrs: {},
            content: toRawPubKey(registrationInfo.identityKeyPair.pubKey),
        },
        {
            tag: WA_NODE_TAGS.REGISTRATION,
            attrs: {},
            content: intToBytes(4, registrationInfo.registrationId),
        },
        {
            tag: WA_NODE_TAGS.TYPE,
            attrs: {},
            content: SIGNAL_KEY_BUNDLE_TYPE_BYTES,
        },
        {
            tag: WA_NODE_TAGS.LIST,
            attrs: {},
            content: preKeys.map((record) => ({
                tag: WA_NODE_TAGS.KEY,
                attrs: {},
                content: [
                    {
                        tag: WA_NODE_TAGS.ID,
                        attrs: {},
                        content: intToBytes(3, record.keyId),
                    },
                    {
                        tag: WA_NODE_TAGS.VALUE,
                        attrs: {},
                        content: toRawPubKey(record.keyPair.pubKey),
                    },
                ],
            })),
        },
        buildSignedPreKeyNode(signedPreKey),
    ]
    return buildIqNode(WA_IQ_TYPES.SET, HOST_DOMAIN, WA_XMLNS.SIGNAL, children)
}

/**
 * Builds the IQ that rotates the signed pre-key.
 *
 * @param signedPreKey The new signed pre-key.
 */
export function buildSignedPreKeyRotateIq(signedPreKey: SignedPreKeyRecord): BinaryNode {
    return buildIqNode(WA_IQ_TYPES.SET, HOST_DOMAIN, WA_XMLNS.SIGNAL, [
        {
            tag: WA_NODE_TAGS.ROTATE,
            attrs: {},
            content: [buildSignedPreKeyNode(signedPreKey)],
        },
    ])
}

/** A device whose pre-keys are being requested. */
export interface PreKeyTargetDevice {
    /** The device id. */
    deviceId: number
    /** The device's registration id, when known. */
    registrationId?: number
}

/** A user whose pre-keys are being requested. */
export interface PreKeyTarget {
    /** The user's JID. */
    userJid: string
    /** The user's devices. */
    devices: PreKeyTargetDevice[]
    /** Request the identity change reason. */
    reasonIdentity?: boolean
}

/**
 * Builds the IQ that fetches missing pre-key bundles.
 *
 * The `<registration>` element is mandatory: the server silently ignores a
 * `key_fetch` request whose device node has no registration id, so the
 * request never gets an answer. When the registration id of a device is not
 * known yet, zero is sent — the server then answers with the bundle and the
 * real registration id.
 *
 * @param users The users to fetch keys for.
 */
export function buildMissingPreKeysFetchIq(users: PreKeyTarget[]): BinaryNode {
    return buildIqNode(WA_IQ_TYPES.GET, HOST_DOMAIN, WA_XMLNS.SIGNAL, [
        {
            tag: WA_NODE_TAGS.KEY_FETCH,
            attrs: {},
            content: users.map((user) => ({
                tag: WA_NODE_TAGS.USER,
                attrs: {
                    jid: user.userJid,
                    ...(user.reasonIdentity === true ? { reason: 'identity' } : {}),
                },
                content: user.devices.map((device) => ({
                    tag: WA_NODE_TAGS.DEVICE,
                    attrs: { id: String(device.deviceId) },
                    content: [
                        {
                            tag: WA_NODE_TAGS.REGISTRATION,
                            attrs: {},
                            content: intToBytes(4, device.registrationId ?? 0),
                        },
                    ],
                })),
            })),
        },
    ])
}

/** A parsed remote key bundle. */
export interface ParsedKeyBundle {
    /** The remote identity key. */
    identity: Uint8Array
    /** The remote signed pre-key. */
    signedKey: { id: number; publicKey: Uint8Array; signature: Uint8Array }
    /** The remote one-time pre-key, when present. */
    oneTimeKey?: { id: number; publicKey: Uint8Array }
    /** The device identity attestation, when present. */
    deviceIdentity?: Uint8Array
}

/**
 * Parses the shared `<identity><skey><key><device-identity>` shape.
 *
 * @param node The node to parse.
 * @param fieldPrefix A label used in error messages.
 */
export function parseSignalKeyBundleFromNode(
    node: BinaryNode,
    fieldPrefix: string,
): ParsedKeyBundle {
    const [identityNode, signedKeyNode, oneTimeKeyNode, deviceIdentityNode] =
        findNodeChildrenByTags(node, [
            WA_NODE_TAGS.IDENTITY,
            WA_NODE_TAGS.SKEY,
            WA_NODE_TAGS.KEY,
            WA_NODE_TAGS.DEVICE_IDENTITY,
        ])
    if (!identityNode) throw new Error(`${fieldPrefix} missing identity node`)
    if (!signedKeyNode) throw new Error(`${fieldPrefix} missing signed pre-key node`)

    const identity = decodeExactLength(
        identityNode.content,
        `${fieldPrefix}.identity`,
        SIGNAL_KEY_DATA_LENGTH,
    )
    const [signedKeyIdNode, signedKeyValueNode, signedKeySignatureNode] = findNodeChildrenByTags(
        signedKeyNode,
        [WA_NODE_TAGS.ID, WA_NODE_TAGS.VALUE, WA_NODE_TAGS.SIGNATURE],
    )
    if (!signedKeyIdNode || !signedKeyValueNode || !signedKeySignatureNode) {
        throw new Error(`${fieldPrefix} signed pre-key is incomplete`)
    }
    const signedKey = {
        id: parseUint(
            decodeExactLength(
                signedKeyIdNode.content,
                `${fieldPrefix}.skey.id`,
                SIGNAL_KEY_ID_LENGTH,
            ),
            `${fieldPrefix}.skey.id`,
        ),
        publicKey: decodeExactLength(
            signedKeyValueNode.content,
            `${fieldPrefix}.skey.value`,
            SIGNAL_KEY_DATA_LENGTH,
        ),
        signature: decodeExactLength(
            signedKeySignatureNode.content,
            `${fieldPrefix}.skey.signature`,
            SIGNAL_SIGNATURE_LENGTH,
        ),
    }

    let oneTimeKey: ParsedKeyBundle['oneTimeKey']
    if (oneTimeKeyNode) {
        const [oneTimeKeyIdNode, oneTimeKeyValueNode] = findNodeChildrenByTags(oneTimeKeyNode, [
            WA_NODE_TAGS.ID,
            WA_NODE_TAGS.VALUE,
        ])
        if (!oneTimeKeyIdNode || !oneTimeKeyValueNode) {
            throw new Error(`${fieldPrefix} one-time pre-key is incomplete`)
        }
        oneTimeKey = {
            id: parseUint(
                decodeExactLength(
                    oneTimeKeyIdNode.content,
                    `${fieldPrefix}.key.id`,
                    SIGNAL_KEY_ID_LENGTH,
                ),
                `${fieldPrefix}.key.id`,
            ),
            publicKey: decodeExactLength(
                oneTimeKeyValueNode.content,
                `${fieldPrefix}.key.value`,
                SIGNAL_KEY_DATA_LENGTH,
            ),
        }
    }

    const deviceIdentity = deviceIdentityNode
        ? decodeNodeContentBytes(deviceIdentityNode.content, `${fieldPrefix}.device-identity`)
        : undefined

    return { identity, signedKey, oneTimeKey, deviceIdentity }
}

/** A device entry in a pre-key fetch response. */
export interface PreKeyDeviceResult {
    /** The device's JID. */
    deviceJid: string
    /** The device's key bundle. */
    bundle: PreKeyBundle
}

/** The result of a pre-key fetch for one user. */
export interface PreKeyUserResult {
    /** The user's JID. */
    userJid: string
    /** The user's devices, when the fetch succeeded. */
    devices?: PreKeyDeviceResult[]
    /** The error code, when the fetch failed for this user. */
    errorCode?: number
    /** The error text, when the fetch failed for this user. */
    errorText?: string
}

/**
 * Parses a pre-key fetch response.
 *
 * @param node The IQ response.
 * @param requested The users that were requested.
 */
export function parseMissingPreKeysResponse(
    node: BinaryNode,
    requested: PreKeyTarget[],
): PreKeyUserResult[] {
    const listNode = findNodeChild(node, WA_NODE_TAGS.LIST)
    if (!listNode) throw new Error('missing prekeys response missing list node')
    const users = getNodeChildrenByTag(listNode, WA_NODE_TAGS.USER)

    const byJid = new Map<string, PreKeyUserResult>()
    for (const userNode of users) {
        const userJid = userNode.attrs.jid
        if (!userJid) continue
        const errorNode = findNodeChild(userNode, WA_NODE_TAGS.ERROR)
        if (errorNode) {
            const parsedCode = Number.parseInt(errorNode.attrs.code ?? '', 10)
            byJid.set(userJid, {
                userJid,
                errorCode: Number.isSafeInteger(parsedCode) ? parsedCode : undefined,
                errorText: errorNode.attrs.text ?? errorNode.attrs.type ?? 'unknown',
            })
            continue
        }
        byJid.set(userJid, { userJid, devices: parseUserDevices(userNode, userJid) })
    }

    return requested.map((target) => {
        const found = byJid.get(target.userJid)
        if (found) return found
        return { userJid: target.userJid, errorText: 'missing user in key_fetch response' }
    })
}

/**
 * Parses the per-device entries of a user node.
 *
 * @param node The user node.
 * @param userJid The user's JID.
 */
function parseUserDevices(node: BinaryNode, userJid: string): PreKeyDeviceResult[] {
    const atIndex = userJid.indexOf('@')
    const server = atIndex >= 0 ? userJid.slice(atIndex + 1) : HOST_DOMAIN
    const devices = getNodeChildrenByTag(node, WA_NODE_TAGS.DEVICE)
    const out: PreKeyDeviceResult[] = []
    for (const deviceNode of devices) {
        const deviceIdValue = deviceNode.attrs.id
        if (!deviceIdValue) throw new Error('missing prekeys device id is missing')
        const deviceId = Number.parseInt(deviceIdValue, 10)
        if (!Number.isSafeInteger(deviceId) || deviceId < 0) {
            throw new Error(`missing prekeys device id is invalid: ${deviceIdValue}`)
        }
        const registrationNode = findNodeChild(deviceNode, WA_NODE_TAGS.REGISTRATION)
        const regId = registrationNode
            ? parseUint(
                  decodeExactLength(
                      registrationNode.content,
                      'missing prekeys device registration',
                      SIGNAL_REGISTRATION_ID_LENGTH,
                  ),
                  'missing prekeys device registration',
              )
            : 0
        const parsed = parseSignalKeyBundleFromNode(deviceNode, 'missing prekeys device')
        const deviceJid =
            deviceId === 0 ? userJid : `${userJid.slice(0, atIndex)}:${deviceId}@${server}`
        out.push({
            deviceJid,
            bundle: {
                regId,
                identity: parsed.identity,
                signedKey: {
                    id: parsed.signedKey.id,
                    publicKey: parsed.signedKey.publicKey,
                },
                oneTimeKey: parsed.oneTimeKey
                    ? { id: parsed.oneTimeKey.id, publicKey: parsed.oneTimeKey.publicKey }
                    : null,
            },
        })
    }
    return out
}

/**
 * Picks the bundle of one device out of a pre-key answer.
 *
 * The server does not answer a pre-key request with the device that was
 * asked for: it answers with **every** device of the user, and the order of
 * the answer is neither the order of the request nor the device order. A
 * caller that wants one specific device therefore has to select it
 * explicitly — taking the first entry hands the identity key of a *different*
 * device to the session, and every later message of that device fails to
 * decrypt.
 *
 * The devices are matched by user and device id, so a bundle is also found
 * when the answer names the device with a different server (a phone-number
 * address instead of a linked-identity one, for example).
 *
 * @param devices The devices of the answer.
 * @param deviceJid The device whose bundle is wanted.
 * @returns The bundle of that device, or `undefined` when it is not in the
 * answer.
 */
export function selectPreKeyBundle(
    devices: readonly PreKeyDeviceResult[],
    deviceJid: string,
): PreKeyDeviceResult['bundle'] | undefined {
    let targetUser: string | null = null
    let targetDevice = 0
    try {
        const address = parseSignalAddressFromJid(deviceJid)
        targetUser = address.user
        targetDevice = address.device
    } catch {
        targetUser = null
    }

    for (const entry of devices) {
        if (targetUser === null) {
            if (entry.deviceJid === deviceJid) return entry.bundle
            continue
        }
        try {
            const address = parseSignalAddressFromJid(entry.deviceJid)
            if (address.user === targetUser && address.device === targetDevice) {
                return entry.bundle
            }
        } catch {
            // A device JID that cannot be parsed belongs to no device.
        }
    }
    /**
     * The answer names one device only, so there is nothing to confuse it
     * with: the bundle belongs to the device that was asked for, even when
     * the server named it differently.
     */
    if (devices.length === 1) return devices[0]!.bundle
    return undefined
}

/**
 * Converts a parsed bundle into the session-layer bundle type.
 *
 * @param parsed The parsed bundle.
 */
export function toPreKeyBundle(parsed: ParsedKeyBundle): PreKeyBundle {
    return {
        regId: 0,
        identity: parsed.identity,
        signedKey: { id: parsed.signedKey.id, publicKey: parsed.signedKey.publicKey },
        oneTimeKey: parsed.oneTimeKey
            ? { id: parsed.oneTimeKey.id, publicKey: parsed.oneTimeKey.publicKey }
            : null,
    }
}

/** Re-exported for convenience. */
export type { SerializedKeyPair }
