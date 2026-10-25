/**
 * Noise protocol handshake used by the WhatsApp transports.
 *
 * WhatsApp uses a **modified** Noise XX / IK handshake:
 *
 * - The protocol name is the 32-byte string `Noise_XX_25519_AESGCM_SHA256`
 *   padded with four NUL bytes. Because it is exactly 32 bytes it is used
 *   verbatim as the initial handshake hash instead of being hashed first
 *   (the "no name hash" optimisation).
 * - The prologue is the 4-byte `WA` protocol header (`57 41 06 03`), which
 *   binds the handshake to the WA protocol version.
 * - The cipher suite is AES-256-GCM with HKDF-SHA256.
 *
 * The handshake messages themselves are protobuf `HandshakeMessage` values:
 *
 * ```text
 * client → server   HandshakeMessage{ clientHello: { ephemeral, static?, payload? } }
 * server → client   HandshakeMessage{ serverHello: { ephemeral, static, payload } }
 * client → server   HandshakeMessage{ clientFinish: { static, payload } }
 * ```
 *
 * The implementation below is a direct, minimal transcription of the Noise
 * specification's XX and IK patterns rather than a generic Noise library, so
 * the library stays dependency-free and allocation-light.
 */

import {
    aesGcmDecrypt,
    aesGcmEncrypt,
    concat,
    equalBytes,
    GCM_NONCE_LENGTH,
    hkdfSplit,
    sha256,
    writeNonceCounter,
    x25519,
    type X25519KeyPair,
} from './primitives.js'

/** Protocol name for a full (XX) handshake. */
export const NOISE_XX_NAME = new Uint8Array([
    0x4e, 0x6f, 0x69, 0x73, 0x65, 0x5f, 0x58, 0x58, 0x5f, 0x32, 0x35, 0x35, 0x31, 0x39, 0x5f, 0x41,
    0x45, 0x53, 0x47, 0x43, 0x4d, 0x5f, 0x53, 0x48, 0x41, 0x32, 0x35, 0x36, 0x00, 0x00, 0x00, 0x00,
])

/** Protocol name for a resumed (IK) handshake. */
export const NOISE_IK_NAME = new Uint8Array([
    0x4e, 0x6f, 0x69, 0x73, 0x65, 0x5f, 0x49, 0x4b, 0x5f, 0x32, 0x35, 0x35, 0x31, 0x39, 0x5f, 0x41,
    0x45, 0x53, 0x47, 0x43, 0x4d, 0x5f, 0x53, 0x48, 0x41, 0x32, 0x35, 0x36, 0x00, 0x00, 0x00, 0x00,
])

/** Protocol name used when an IK resume must fall back to a full handshake. */
export const NOISE_XX_FALLBACK_NAME = new Uint8Array([
    0x4e, 0x6f, 0x69, 0x73, 0x65, 0x5f, 0x58, 0x58, 0x66, 0x61, 0x6c, 0x6c, 0x62, 0x61, 0x63, 0x6b,
    0x5f, 0x32, 0x35, 0x35, 0x31, 0x39, 0x5f, 0x41, 0x45, 0x53, 0x47, 0x43, 0x4d, 0x5f, 0x53,
    0x48, 0x41, 0x32, 0x35, 0x36,
])

/** The WA protocol header used as the Noise prologue: `"WA"` + version 6.3. */
export const WA_PROTO_HEADER = new Uint8Array([0x57, 0x41, 0x06, 0x03])

/** Serial number of the production WhatsApp root certificate authority. */
export const ROOT_CA_SERIAL = 0

/** Public key of the production WhatsApp root certificate authority. */
export const ROOT_CA_PUBLIC_KEY_HEX =
    '142375574d0a587166aae71ebe516437c4a28b73e3695c6ce1f7f9545da8ee6b'

/** A completed Noise transport session. */
export interface NoiseSession {
    /** Encrypts a plaintext frame. */
    encrypt(plaintext: Uint8Array): Uint8Array
    /** Decrypts a ciphertext frame. */
    decrypt(ciphertext: Uint8Array): Uint8Array
}

/**
 * Mutable handshake state.
 *
 * Mirrors the Noise `SymmetricState` object: it tracks the running handshake
 * hash (`h`), the chaining key (`ck`) and the current cipher key (`k`).
 */
export class NoiseHandshake {
    private readonly nonceScratch = new Uint8Array(GCM_NONCE_LENGTH)
    private handshakeHash: Uint8Array = new Uint8Array(0)
    private chainingKey: Uint8Array = new Uint8Array(0)
    private cipherKey: Uint8Array | null = null
    private nonce = 0

    /**
     * Initialises the handshake state.
     *
     * @param protocolName Noise protocol name (32 bytes, used verbatim).
     * @param prologue Prologue bytes mixed into the handshake hash.
     */
    start(protocolName: Uint8Array, prologue: Uint8Array): void {
        const hashInput = protocolName.length === 32 ? protocolName : sha256(protocolName)
        this.handshakeHash = hashInput
        this.chainingKey = hashInput
        this.cipherKey = this.handshakeHash
        this.authenticate(prologue)
    }

    /** Mixes `data` into the handshake hash. */
    authenticate(data: Uint8Array): void {
        this.handshakeHash = sha256(this.handshakeHash, data)
    }

    /**
     * Performs a `MixKey` operation: re-derives the chaining key and the
     * encryption key from `keyMaterial`.
     */
    mixIntoKey(keyMaterial: Uint8Array): void {
        this.nonce = 0
        const [nextChainingKey, nextCipherKey] = hkdfSplit(
            keyMaterial,
            this.chainingKey,
            new Uint8Array(0),
        )
        this.chainingKey = nextChainingKey
        this.cipherKey = nextCipherKey
    }

    /** Encrypts `plaintext` with the current cipher key. */
    encrypt(plaintext: Uint8Array): Uint8Array {
        if (!this.cipherKey) {
            throw new Error('noise: cipher key is not initialised')
        }
        writeNonceCounter(this.nonceScratch, this.nonce++)
        const ciphertext = aesGcmEncrypt(this.cipherKey, this.nonceScratch, plaintext, this.handshakeHash)
        this.authenticate(ciphertext)
        return ciphertext
    }

    /** Decrypts `ciphertext` with the current cipher key. */
    decrypt(ciphertext: Uint8Array): Uint8Array {
        if (!this.cipherKey) {
            throw new Error('noise: cipher key is not initialised')
        }
        writeNonceCounter(this.nonceScratch, this.nonce++)
        const plaintext = aesGcmDecrypt(this.cipherKey, this.nonceScratch, ciphertext, this.handshakeHash)
        this.authenticate(ciphertext)
        return plaintext
    }

    /** Derives the final transport keys and clears handshake material. */
    finish(): NoiseSession {
        const [writeKey, readKey] = hkdfSplit(new Uint8Array(0), this.chainingKey, new Uint8Array(0))
        // Wipe handshake secrets as soon as the transport keys exist.
        this.handshakeHash = new Uint8Array(0)
        this.chainingKey = new Uint8Array(0)
        this.cipherKey = null
        this.nonce = 0
        return new NoiseTransport(writeKey, readKey)
    }
}

/**
 * A finished Noise transport.
 *
 * Each direction has its own key and its own 32-bit nonce counter, matching
 * the Noise specification's split transport cipher.
 */
export class NoiseTransport implements NoiseSession {
    private readonly writeNonce = new Uint8Array(GCM_NONCE_LENGTH)
    private readonly readNonce = new Uint8Array(GCM_NONCE_LENGTH)
    private writeCounter = 0
    private readCounter = 0

    constructor(
        private readonly writeKey: Uint8Array,
        private readonly readKey: Uint8Array,
    ) {}

    encrypt(plaintext: Uint8Array): Uint8Array {
        writeNonceCounter(this.writeNonce, this.writeCounter++)
        return aesGcmEncrypt(this.writeKey, this.writeNonce, plaintext)
    }

    decrypt(ciphertext: Uint8Array): Uint8Array {
        writeNonceCounter(this.readNonce, this.readCounter++)
        return aesGcmDecrypt(this.readKey, this.readNonce, ciphertext)
    }
}

/**
 * Verifies that a server static key matches the leaf certificate key.
 */
export function staticKeyMatches(serverStatic: Uint8Array, certificateKey: Uint8Array): boolean {
    return equalBytes(serverStatic, certificateKey)
}

/**
 * Computes an X25519 shared secret between our private key and a peer key.
 *
 * Exposed here so the handshake driver can mix keys without reaching into
 * the crypto module directly.
 */
export function sharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
    return x25519(privateKey, publicKey)
}

/**
 * A key pair used by the handshake driver.
 */
export type NoiseKeyPair = X25519KeyPair
