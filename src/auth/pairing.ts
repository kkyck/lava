/**
 * Device pairing.
 *
 * WhatsApp lets a companion device (this library) attach to a primary device
 * (the phone) in two ways:
 *
 * - **QR** — the phone scans a QR code, which carries a short-lived
 *   reference the server hands out. The reference is exchanged for the
 *   phone's identity key over the encrypted channel.
 * - **Pairing code** — the phone shows an eight-character code that the
 *   user types into the companion. The code is the key that unwraps the
 *   phone's ephemeral public key, so both sides end up with the same
 *   symmetric key without any extra round trip.
 *
 * Both flows converge on the same key bundle:
 *
 * ```text
 *   companionEphemeral ⊗ phoneEphemeral   → bundle encryption key
 *   companionIdentity  ⊗ phoneIdentity     → shared identity secret
 *   bundleSecret                                → ADV secret
 * ```
 */

import {
    aesCtrDecrypt,
    aesCtrEncrypt,
    aesGcmEncrypt,
    concat,
    hkdf,
    pbkdf2Sha256,
    randomBytesOf,
    utf8,
    x25519,
    x25519PublicFromPrivate,
} from '../crypto/primitives.js'

/** The Crockford base32 alphabet WhatsApp uses for pairing codes. */
export const CROCKFORD_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTVWXYZ'

/** The number of PBKDF2 iterations used to stretch a pairing code. */
export const PBKDF2_ITERATIONS = 2 << 16

/** The length of the AES key derived from a pairing code. */
export const PAIRING_AES_KEY_BYTES = 32

/** The HKDF info string for the pairing key bundle. */
export const WA_PAIRING_KDF_INFO_LINK_CODE_BUNDLE = utf8(
    'link_code_pairing_key_bundle_encryption_key',
)

/** The HKDF info string for the ADV secret. */
export const WA_PAIRING_KDF_INFO_ADV_SECRET = utf8('adv_secret')

/**
 * Encodes bytes into a Crockford base32 string.
 *
 * @param bytes The bytes to encode.
 */
export function encodeBytesToCrockford(bytes: Uint8Array): string {
    let bitCount = 0
    let value = 0
    let out = ''
    for (let i = 0; i < bytes.length; i += 1) {
        value = (value << 8) | bytes[i]!
        bitCount += 8
        while (bitCount >= 5) {
            out += CROCKFORD_ALPHABET[(value >>> (bitCount - 5)) & 31]
            bitCount -= 5
        }
    }
    if (bitCount > 0) out += CROCKFORD_ALPHABET[(value << (5 - bitCount)) & 31]
    return out
}

/**
 * Normalises a user-supplied pairing code.
 *
 * Dashes are stripped, the code is upper-cased and every character is checked
 * against the Crockford alphabet.
 *
 * @param input The code as typed by the user.
 */
export function normalizeCustomPairingCode(input: string): string {
    const stripped = input.replace(/-/g, '').toUpperCase()
    if (stripped.length !== 8) {
        throw new Error(`custom pairing code must be 8 characters, got ${stripped.length}`)
    }
    for (let i = 0; i < stripped.length; i += 1) {
        if (CROCKFORD_ALPHABET.indexOf(stripped[i]!) < 0) {
            throw new Error(
                `custom pairing code contains invalid character "${stripped[i]}" (allowed: ${CROCKFORD_ALPHABET})`,
            )
        }
    }
    return stripped
}

/** The result of creating a companion hello. */
export interface CompanionHello {
    /** The pairing code the user has to type on the phone. */
    pairingCode: string
    /** The companion's ephemeral key pair. */
    companionEphemeralPrivateKey: Uint8Array
    /** The companion's ephemeral public key. */
    companionEphemeralPublicKey: Uint8Array
    /** The wrapped companion ephemeral key: `salt ‖ counter ‖ ciphertext`. */
    wrappedCompanionEphemeralPub: Uint8Array
}

/** Options for {@link createCompanionHello}. */
export interface CompanionHelloOptions {
    /** A user-chosen pairing code; a random one is generated when omitted. */
    customCode?: string
}

/**
 * Creates the companion's half of the pairing handshake.
 *
 * The ephemeral public key is encrypted with a key derived from the pairing
 * code, so only a device that knows the code can unwrap it.
 *
 * @param options Optional custom pairing code.
 */
export async function createCompanionHello(
    options: CompanionHelloOptions = {},
): Promise<CompanionHello> {
    const normalizedCustomCode =
        options.customCode !== undefined ? normalizeCustomPairingCode(options.customCode) : null

    const companionEphemeralPrivateKey = randomBytesOf(32)
    const companionEphemeralPublicKey = x25519PublicFromPrivate(companionEphemeralPrivateKey)
    const salt = randomBytesOf(32)
    const counter = randomBytesOf(16)
    const codeBytes = normalizedCustomCode !== null ? null : randomBytesOf(5)

    const pairingCode = normalizedCustomCode ?? encodeBytesToCrockford(codeBytes!)
    const cipherKey = pbkdf2Sha256(
        utf8(pairingCode),
        salt,
        PBKDF2_ITERATIONS,
        PAIRING_AES_KEY_BYTES,
    )
    const encrypted = aesCtrEncrypt(cipherKey, counter, companionEphemeralPublicKey)

    return {
        pairingCode,
        companionEphemeralPrivateKey,
        companionEphemeralPublicKey,
        wrappedCompanionEphemeralPub: concat(salt, counter, encrypted),
    }
}

/** The inputs for {@link completeCompanionFinish}. */
export interface CompanionFinishInput {
    /** The pairing code the user typed. */
    pairingCode: string
    /** The companion's ephemeral private key. */
    companionEphemeralPrivateKey: Uint8Array
    /** The companion's Signal identity key pair. */
    identityKeyPair: { pubKey: Uint8Array; privKey: Uint8Array }
    /** The phone's ephemeral public key, as wrapped by the server. */
    wrappedPrimaryEphemeralPub: Uint8Array
    /** The phone's Signal identity public key. */
    primaryIdentityPub: Uint8Array
}

/** The result of finishing the pairing handshake. */
export interface CompanionFinish {
    /** The wrapped key bundle sent to the server. */
    wrappedKeyBundle: Uint8Array
    /** The companion's identity public key. */
    companionIdentityPublic: Uint8Array
    /** The ADV secret derived from the shared material. */
    advSecret: Uint8Array
}

/**
 * Completes the pairing handshake.
 *
 * The server hands back the phone's ephemeral public key, wrapped with a key
 * derived from the pairing code. Unwrapping it yields the shared secret the
 * whole session is built on.
 *
 * @param input The pairing inputs.
 */
export async function completeCompanionFinish(
    input: CompanionFinishInput,
): Promise<CompanionFinish> {
    if (input.wrappedPrimaryEphemeralPub.length <= 48) {
        throw new Error('invalid wrapped primary payload')
    }

    const pairingCipherKey = pbkdf2Sha256(
        utf8(input.pairingCode),
        input.wrappedPrimaryEphemeralPub.subarray(0, 32),
        PBKDF2_ITERATIONS,
        PAIRING_AES_KEY_BYTES,
    )
    const primaryEphemeralPub = aesCtrDecrypt(
        pairingCipherKey,
        input.wrappedPrimaryEphemeralPub.subarray(32, 48),
        input.wrappedPrimaryEphemeralPub.subarray(48),
    )
    if (primaryEphemeralPub.length === 0) {
        throw new Error('empty primary ephemeral public key')
    }

    const sharedEphemeral = x25519(input.companionEphemeralPrivateKey, primaryEphemeralPub)
    const sharedIdentity = x25519(input.identityKeyPair.privKey, input.primaryIdentityPub)
    const bundleSalt = randomBytesOf(32)
    const bundleSecret = randomBytesOf(32)
    const bundleIv = randomBytesOf(12)

    const bundleEncryptionKey = hkdf(
        sharedEphemeral,
        bundleSalt,
        WA_PAIRING_KDF_INFO_LINK_CODE_BUNDLE,
        32,
    )
    const plaintextBundle = concat(
        input.identityKeyPair.pubKey,
        input.primaryIdentityPub,
        bundleSecret,
    )
    const encryptedBundle = aesGcmEncrypt(bundleEncryptionKey, bundleIv, plaintextBundle)

    const advMaterial = concat(sharedEphemeral, sharedIdentity, bundleSecret)
    const advSecret = hkdf(advMaterial, null, WA_PAIRING_KDF_INFO_ADV_SECRET, 32)

    return {
        wrappedKeyBundle: concat(bundleSalt, bundleIv, encryptedBundle),
        companionIdentityPublic: input.identityKeyPair.pubKey,
        advSecret,
    }
}
