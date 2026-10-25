/**
 * Signal key-digest sync.
 *
 * The server keeps a digest of the key bundle it holds for a device: the
 * identity key, the signed pre-key and the ids of the one-time pre-keys.
 * A client can ask for that digest and compare it with its own state:
 *
 * ```text
 *   <iq type="get" xmlns="encrypt"><digest/></iq>
 * ```
 *
 * The answer carries the same material the server holds plus a SHA-1 hash
 * over it. When the two do not match, the client's pre-keys drifted — a
 * crash in the middle of an upload, for example — and the client repairs
 * the situation by uploading a fresh batch.
 *
 * The official client runs this check after a failed signed pre-key
 * rotation (`WAWebDigestKeyJob`), the mobile clients run it when the
 * server sends an `<notification type="encrypt"><digest/></notification>`
 * stanza.
 */

import { createHash } from 'node:crypto'

import { toRawPublicKey } from '../crypto/primitives.js'
import { WA_IQ_TYPES, WA_NODE_TAGS, WA_XMLNS } from '../protocol/constants.js'
import { HOST_DOMAIN } from '../protocol/jid.js'
import type { BinaryNode } from '../transport/binary/types.js'
import {
    base64Decode,
    decodeNodeContentBytes,
    findNodeChild,
    getNodeChildren,
} from '../transport/node/helpers.js'
import { buildIqNode } from '../transport/node/query.js'
import {
    SIGNAL_KEY_BUNDLE_TYPE_BYTES,
    SIGNAL_KEY_DATA_LENGTH,
    SIGNAL_KEY_ID_LENGTH,
    SIGNAL_REGISTRATION_ID_LENGTH,
    SIGNAL_SIGNATURE_LENGTH,
    decodeExactLength,
    parseUint,
} from './api.js'
import type { PreKeyRecord, RegistrationInfo, SignedPreKeyRecord } from './keys.js'

/** Length of the digest hash (a SHA-1 digest). */
export const SIGNAL_DIGEST_HASH_LENGTH = 20

/** The key bundle the server holds for a device. */
export interface SignalDigest {
    /** The registration id of the device. */
    registrationId: number
    /** The key-bundle type (`5` = curve25519). */
    keyBundleType: number
    /** The raw identity public key. */
    identity: Uint8Array
    /** The signed pre-key. */
    signedKey: {
        /** The pre-key id. */
        id: number
        /** The raw public key. */
        publicKey: Uint8Array
        /** The XEdDSA signature. */
        signature: Uint8Array
    }
    /** The ids of the one-time pre-keys the server holds. */
    preKeyIds: number[]
    /** The SHA-1 hash over the bundle. */
    hash: Uint8Array
}

/**
 * Builds the IQ that asks the server for the key digest of this device.
 */
export function buildDigestIq(): BinaryNode {
    return buildIqNode(WA_IQ_TYPES.GET, HOST_DOMAIN, WA_XMLNS.SIGNAL, [
        {
            tag: WA_NODE_TAGS.DIGEST,
            attrs: {},
        },
    ])
}

/**
 * Parses the digest the server answers with.
 *
 * @param node The `<iq>` response.
 */
export function parseDigestResponse(node: BinaryNode): SignalDigest {
    const digestNode = findNodeChild(node, WA_NODE_TAGS.DIGEST)
    if (!digestNode) throw new Error('signal digest response has no digest node')

    const registrationNode = findNodeChild(digestNode, WA_NODE_TAGS.REGISTRATION)
    const typeNode = findNodeChild(digestNode, WA_NODE_TAGS.TYPE)
    const identityNode = findNodeChild(digestNode, WA_NODE_TAGS.IDENTITY)
    const signedKeyNode = findNodeChild(digestNode, WA_NODE_TAGS.SKEY)
    const listNode = findNodeChild(digestNode, WA_NODE_TAGS.LIST)
    const hashNode = findNodeChild(digestNode, WA_NODE_TAGS.HASH)
    if (
        !registrationNode ||
        !typeNode ||
        !identityNode ||
        !signedKeyNode ||
        !listNode ||
        !hashNode
    ) {
        throw new Error('signal digest response is incomplete')
    }

    const signedKeyIdNode = findNodeChild(signedKeyNode, WA_NODE_TAGS.ID)
    const signedKeyValueNode = findNodeChild(signedKeyNode, WA_NODE_TAGS.VALUE)
    const signedKeySignatureNode = findNodeChild(signedKeyNode, WA_NODE_TAGS.SIGNATURE)
    if (!signedKeyIdNode || !signedKeyValueNode || !signedKeySignatureNode) {
        throw new Error('signal digest response has an incomplete signed pre-key')
    }

    const registrationId = parseUint(
        decodeExactLength(
            registrationNode.content,
            'signal digest registration',
            SIGNAL_REGISTRATION_ID_LENGTH,
        ),
        'signal digest registration',
    )
    const keyBundleType = parseUint(
        decodeExactLength(typeNode.content, 'signal digest type', 1),
        'signal digest type',
    )
    const identity = decodeExactLength(
        identityNode.content,
        'signal digest identity',
        SIGNAL_KEY_DATA_LENGTH,
    )
    const signedKeyId = parseUint(
        decodeExactLength(
            signedKeyIdNode.content,
            'signal digest skey.id',
            SIGNAL_KEY_ID_LENGTH,
        ),
        'signal digest skey.id',
    )
    const signedKeyPublicKey = decodeExactLength(
        signedKeyValueNode.content,
        'signal digest skey.value',
        SIGNAL_KEY_DATA_LENGTH,
    )
    const signedKeySignature = decodeExactLength(
        signedKeySignatureNode.content,
        'signal digest skey.signature',
        SIGNAL_SIGNATURE_LENGTH,
    )

    const preKeyIds: number[] = []
    for (const [index, child] of getNodeChildren(listNode).entries()) {
        preKeyIds.push(
            parseUint(
                decodeExactLength(
                    child.content,
                    `signal digest list[${index}]`,
                    SIGNAL_KEY_ID_LENGTH,
                ),
                `signal digest list[${index}]`,
            ),
        )
    }

    const hash = decodeDigestHash(hashNode.content)

    return {
        registrationId,
        keyBundleType,
        identity,
        signedKey: {
            id: signedKeyId,
            publicKey: signedKeyPublicKey,
            signature: signedKeySignature,
        },
        preKeyIds,
        hash,
    }
}

/**
 * Decodes the digest hash.
 *
 * The server sends the hash as raw bytes, but some deployments base64
 * encode it — both forms are accepted.
 *
 * @param content The node content.
 */
function decodeDigestHash(
    content: string | Uint8Array | BinaryNode[] | null | undefined,
): Uint8Array {
    if (typeof content === 'string') {
        const decoded = base64Decode(content)
        if (decoded) return decoded
    }
    return decodeNodeContentBytes(content, 'signal digest hash')
}

/**
 * Computes the hash the server stores for a key bundle.
 *
 * The hash covers the identity key, the signed pre-key (public key and
 * signature) and the public keys of the one-time pre-keys, in that order.
 *
 * @param registration The registration info.
 * @param signedPreKey The signed pre-key.
 * @param preKeys The one-time pre-keys the server holds.
 */
export function computeKeyBundleHash(
    registration: RegistrationInfo,
    signedPreKey: SignedPreKeyRecord,
    preKeys: PreKeyRecord[],
): Uint8Array {
    const hash = createHash('sha1')
    hash.update(toRawPublicKey(registration.identityKeyPair.pubKey))
    hash.update(toRawPublicKey(signedPreKey.keyPair.pubKey))
    hash.update(signedPreKey.signature)
    for (const record of preKeys) {
        hash.update(toRawPublicKey(record.keyPair.pubKey))
    }
    return new Uint8Array(hash.digest())
}

/** Compares two byte strings without leaking their contents. */
function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
    if (left.length !== right.length) return false
    let diff = 0
    for (let i = 0; i < left.length; i += 1) diff |= left[i]! ^ right[i]!
    return diff === 0
}

/** Why a key bundle does not match the server's digest. */
export type DigestMismatchReason =
    | 'ok'
    | 'unsupported_key_bundle_type'
    | 'registration_mismatch'
    | 'identity_mismatch'
    | 'signed_prekey_mismatch'
    | 'missing_local_prekey'
    | 'missing_local_state'
    | 'missing_remote_digest'
    | 'invalid_response'
    | 'hash_mismatch'

/** The result of a digest validation. */
export interface DigestValidation {
    /** Whether the local state matches the server's digest. */
    valid: boolean
    /** The reason for a mismatch. */
    reason: DigestMismatchReason
    /** How many one-time pre-keys the server holds. */
    preKeyCount: number
    /** Whether the client should upload a fresh batch of pre-keys. */
    shouldReupload: boolean
}

/**
 * Validates the local key bundle against the digest the server holds.
 *
 * @param digest The digest the server answered with.
 * @param registration The local registration info.
 * @param signedPreKey The local signed pre-key.
 * @param lookupPreKey Looks a one-time pre-key up by id.
 */
export function validateKeyBundleDigest(
    digest: SignalDigest,
    registration: RegistrationInfo,
    signedPreKey: SignedPreKeyRecord,
    lookupPreKey: (id: number) => PreKeyRecord | undefined,
): DigestValidation {
    const preKeyCount = digest.preKeyIds.length
    const fail = (reason: DigestMismatchReason, shouldReupload = true): DigestValidation => ({
        valid: false,
        reason,
        preKeyCount,
        shouldReupload,
    })

    if (digest.keyBundleType !== SIGNAL_KEY_BUNDLE_TYPE_BYTES[0]) {
        return fail('unsupported_key_bundle_type', false)
    }
    if (digest.registrationId !== registration.registrationId) {
        return fail('registration_mismatch')
    }
    if (!bytesEqual(toRawPublicKey(registration.identityKeyPair.pubKey), digest.identity)) {
        return fail('identity_mismatch')
    }
    if (
        digest.signedKey.id !== signedPreKey.keyId ||
        !bytesEqual(toRawPublicKey(signedPreKey.keyPair.pubKey), digest.signedKey.publicKey) ||
        !bytesEqual(signedPreKey.signature, digest.signedKey.signature)
    ) {
        return fail('signed_prekey_mismatch')
    }

    const preKeys: PreKeyRecord[] = []
    for (const id of digest.preKeyIds) {
        const record = lookupPreKey(id)
        if (!record) return fail('missing_local_prekey')
        preKeys.push(record)
    }

    const localHash = computeKeyBundleHash(registration, signedPreKey, preKeys)
    if (!bytesEqual(localHash.subarray(0, digest.hash.length), digest.hash)) {
        return fail('hash_mismatch')
    }

    return {
        valid: true,
        reason: 'ok',
        preKeyCount,
        shouldReupload: false,
    }
}
