/**
 * Device attestation (ADV).
 *
 * When a companion device pairs with a primary device, the primary signs a
 * *device identity* that binds the companion to the account. The signature
 * travels through the server inside an `ADVSignedDeviceIdentityHMAC`, sealed
 * with a secret both sides derived during the pairing handshake.
 *
 * The companion therefore has to:
 *
 * 1. verify the HMAC over the signed identity,
 * 2. verify the primary's *account* signature over the device details,
 * 3. produce its own *device* signature, proving it holds the identity
 *    private key the server registered for it.
 */

import { concat, hmacSha256, equalBytes } from '../crypto/primitives.js'
import { xeddsaSign, xeddsaVerify } from '../crypto/curve25519.js'
import { decode, encode } from '../proto/codec.js'

/** The domain separator of the account signature. */
export const ADV_PREFIX_ACCOUNT_SIGNATURE = new Uint8Array([0x02, 0x00, 0x01])

/** The domain separator of the hosted account signature. */
export const ADV_PREFIX_HOSTED_ACCOUNT_SIGNATURE = new Uint8Array([0x02, 0x00, 0x02])

/** The domain separator of the device signature. */
export const ADV_PREFIX_DEVICE_SIGNATURE = new Uint8Array([0x02, 0x00, 0x03])

/** The domain separator of the hosted device signature. */
export const ADV_PREFIX_HOSTED_DEVICE_SIGNATURE = new Uint8Array([0x02, 0x00, 0x04])

/** The domain separator of the hosted account key index. */
export const ADV_PREFIX_HOSTED_ACCOUNT_KEY_INDEX = new Uint8Array([0x02, 0x00, 0x05])

/** The domain separator of the account key index. */
export const ADV_PREFIX_ACCOUNT_KEY_INDEX = new Uint8Array([0x02, 0x00, 0x06])

/** The ADV encryption types. */
export const ADVEncryptionType = Object.freeze({
    /** End-to-end encrypted. */
    E2EE: 0,
    /** Hosted (server-side) account. */
    HOSTED: 1,
} as const)

/** The parsed `ADVSignedDeviceIdentityHMAC` payload. */
export interface ParsedAdvSignedIdentityHmac {
    /** The signed identity bytes. */
    details: Uint8Array
    /** The HMAC over the details. */
    hmac: Uint8Array
    /** The account type. */
    accountType: number
}

/**
 * Parses the `ADVSignedDeviceIdentityHMAC` blob the server sends in the
 * `<pair-success>` stanza.
 *
 * @param bytes The blob.
 */
export function parseAdvSignedIdentityHmac(bytes: Uint8Array): ParsedAdvSignedIdentityHmac {
    const parsed = decode('ADVSignedDeviceIdentityHMAC', bytes)
    const details = parsed.details as Uint8Array | undefined
    const hmac = parsed.hmac as Uint8Array | undefined
    if (!details || !hmac) {
        throw new Error('adv: signed identity hmac is missing details/hmac')
    }
    return {
        details,
        hmac,
        accountType: (parsed.accountType as number | undefined) ?? ADVEncryptionType.E2EE,
    }
}

/** The parsed `ADVSignedDeviceIdentity` payload. */
export interface ParsedAdvSignedIdentity {
    /** The `ADVDeviceIdentity` bytes. */
    details: Uint8Array
    /** The primary's account signature key. */
    accountSignatureKey: Uint8Array
    /** The primary's account signature. */
    accountSignature: Uint8Array
    /** The companion's device signature. */
    deviceSignature?: Uint8Array
}

/**
 * Parses the `ADVSignedDeviceIdentity` blob.
 *
 * @param bytes The blob.
 */
export function parseAdvSignedIdentity(bytes: Uint8Array): ParsedAdvSignedIdentity {
    const parsed = decode('ADVSignedDeviceIdentity', bytes)
    const details = parsed.details as Uint8Array | undefined
    const accountSignatureKey = parsed.accountSignatureKey as Uint8Array | undefined
    const accountSignature = parsed.accountSignature as Uint8Array | undefined
    if (!details || !accountSignatureKey || !accountSignature) {
        throw new Error('adv: signed identity is missing details/signatures')
    }
    const deviceSignature = parsed.deviceSignature as Uint8Array | undefined
    return {
        details,
        accountSignatureKey,
        accountSignature,
        ...(deviceSignature ? { deviceSignature } : {}),
    }
}

/**
 * Computes the HMAC over the signed identity details.
 *
 * @param secretKey The ADV secret shared with the primary.
 * @param details The signed identity details.
 * @param hosted Whether the account is hosted.
 */
export function computeAdvIdentityHmac(
    secretKey: Uint8Array,
    details: Uint8Array,
    hosted = false,
): Uint8Array {
    const input = hosted ? concat(ADV_PREFIX_HOSTED_ACCOUNT_SIGNATURE, details) : details
    return hmacSha256(secretKey, input)
}

/**
 * Verifies the primary's account signature over the device details.
 *
 * @param details The `ADVDeviceIdentity` bytes.
 * @param accountSignature The primary's signature.
 * @param identityPublicKey The companion's identity public key.
 * @param accountSignatureKey The primary's account signature key.
 * @param hosted Whether the account is hosted.
 */
export function verifyDeviceIdentityAccountSignature(
    details: Uint8Array,
    accountSignature: Uint8Array,
    identityPublicKey: Uint8Array,
    accountSignatureKey: Uint8Array,
    hosted = false,
): boolean {
    const prefix = hosted ? ADV_PREFIX_HOSTED_ACCOUNT_SIGNATURE : ADV_PREFIX_ACCOUNT_SIGNATURE
    const message = concat(prefix, details, identityPublicKey)
    return xeddsaVerify(stripKeyPrefix(accountSignatureKey), message, accountSignature)
}

/**
 * Produces the companion's device signature.
 *
 * @param details The `ADVDeviceIdentity` bytes.
 * @param identityKeyPair The companion's identity key pair.
 * @param accountSignatureKey The primary's account signature key.
 * @param hosted Whether the account is hosted.
 */
export function generateDeviceSignature(
    details: Uint8Array,
    identityKeyPair: { pubKey: Uint8Array; privKey: Uint8Array },
    accountSignatureKey: Uint8Array,
    hosted = false,
): Uint8Array {
    const prefix = hosted ? ADV_PREFIX_HOSTED_DEVICE_SIGNATURE : ADV_PREFIX_DEVICE_SIGNATURE
    const message = concat(prefix, details, identityKeyPair.pubKey, accountSignatureKey)
    return xeddsaSign(identityKeyPair.privKey, message)
}

/**
 * Builds the `ADVSignedDeviceIdentity` the companion sends back.
 *
 * @param signed The parsed signed identity.
 * @param deviceSignature The companion's device signature.
 */
export function buildAdvSignedIdentityResponse(
    signed: ParsedAdvSignedIdentity,
    deviceSignature: Uint8Array,
): Uint8Array {
    return encode('ADVSignedDeviceIdentity', {
        details: signed.details,
        accountSignatureKey: signed.accountSignatureKey,
        accountSignature: signed.accountSignature,
        deviceSignature,
    })
}

/**
 * Reads the key index out of the `ADVDeviceIdentity` details.
 *
 * @param details The `ADVDeviceIdentity` bytes.
 */
export function readAdvKeyIndex(details: Uint8Array): number {
    const parsed = decode('ADVDeviceIdentity', details)
    return (parsed.keyIndex as number | undefined) ?? 0
}

/**
 * Reads the device type out of the `ADVDeviceIdentity` details.
 *
 * @param details The `ADVDeviceIdentity` bytes.
 */
export function readAdvDeviceType(details: Uint8Array): number {
    const parsed = decode('ADVDeviceIdentity', details)
    return (parsed.deviceType as number | undefined) ?? ADVEncryptionType.E2EE
}

/**
 * Compares two byte strings in constant time.
 *
 * @param a The first string.
 * @param b The second string.
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false
    let diff = 0
    for (let i = 0; i < a.length; i += 1) diff |= a[i]! ^ b[i]!
    return diff === 0
}

/**
 * Strips the `0x05` prefix from a serialized public key.
 *
 * @param key The key.
 */
function stripKeyPrefix(key: Uint8Array): Uint8Array {
    return key.length === 33 ? key.subarray(1) : key
}

/** Re-exported for convenience. */
export { equalBytes }
