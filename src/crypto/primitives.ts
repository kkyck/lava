/**
 * Cryptographic primitives.
 *
 * Everything here is built on Node's native `node:crypto` so the library ships
 * with **zero runtime dependencies**. Node 22 exposes every primitive the
 * WhatsApp stack needs: X25519 ECDH, AES-256-GCM/CBC, HKDF-SHA256, HMAC and
 * SHA-2.
 *
 * Design notes
 * ------------
 * - All binary inputs/outputs are `Uint8Array`. We avoid `Buffer` because
 *   `Buffer` is a `Uint8Array` subclass with pooled memory that keeps large
 *   slabs alive; plain `Uint8Array` keeps GC pressure predictable.
 * - Functions that consume secrets accept `Uint8Array` and never copy it
 *   unless the algorithm requires it.
 */

import {
    createCipheriv,
    createDecipheriv,
    createHash,
    createHmac,
    createPrivateKey,
    createPublicKey,
    diffieHellman,
    generateKeyPairSync,
    hkdfSync,
    pbkdf2Sync,
    randomBytes,
    timingSafeEqual,
    type KeyObject,
} from 'node:crypto'

/** An empty, immutable byte buffer. */
export const EMPTY = new Uint8Array(0)

/** Number of bytes in an AES-256 key. */
export const KEY_LENGTH = 32

/** Number of bytes in an AES-GCM authentication tag. */
export const GCM_TAG_LENGTH = 16

/** Number of bytes in the GCM nonce used by the Noise handshake. */
export const GCM_NONCE_LENGTH = 12

/** Number of bytes in an X25519 public or private key. */
export const X25519_KEY_LENGTH = 32

const textEncoder = new TextEncoder()

/** Encodes a string as UTF-8 bytes. */
export function utf8(value: string): Uint8Array {
    return textEncoder.encode(value)
}

/** Decodes UTF-8 bytes into a string. */
export function fromUtf8(value: Uint8Array): string {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength).toString('utf8')
}

/**
 * Concatenates byte arrays into a single freshly allocated buffer.
 *
 * @param parts Buffers to join. `undefined`/`null` entries are skipped.
 */
export function concat(...parts: (Uint8Array | undefined | null)[]): Uint8Array {
    let total = 0
    for (const part of parts) {
        if (part) total += part.length
    }
    if (total === 0) return EMPTY
    const out = new Uint8Array(total)
    let offset = 0
    for (const part of parts) {
        if (!part || part.length === 0) continue
        out.set(part, offset)
        offset += part.length
    }
    return out
}

/** Copies `value` into a new buffer with `length` bytes. */
export function copyBytes(value: Uint8Array, length = value.length): Uint8Array {
    const out = new Uint8Array(length)
    out.set(value.subarray(0, Math.min(length, value.length)))
    return out
}

/** Returns a hexadecimal string for `value`. */
export function toHex(value: Uint8Array): string {
    let out = ''
    for (let i = 0; i < value.length; i++) {
        out += value[i]!.toString(16).padStart(2, '0')
    }
    return out
}

/** Parses a hexadecimal string into bytes. */
export function fromHex(value: string): Uint8Array {
    const clean = value.trim()
    if (clean.length % 2 !== 0) {
        throw new Error('hex string must have an even length')
    }
    const out = new Uint8Array(clean.length / 2)
    for (let i = 0; i < out.length; i++) {
        const byte = Number.parseInt(clean.substr(i * 2, 2), 16)
        if (Number.isNaN(byte)) {
            throw new Error('invalid hex string')
        }
        out[i] = byte
    }
    return out
}

/**
 * Constant-time comparison of two byte arrays.
 *
 * Returns `false` immediately when the lengths differ — length is not secret
 * for the values we compare here (MAC tags are fixed length, keys are fixed
 * length), and an early exit avoids pointless work.
 */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false
    if (a.length === 0) return true
    return timingSafeEqual(a, b)
}

/** Computes SHA-256 over one or more buffers. */
export function sha256(...parts: Uint8Array[]): Uint8Array {
    const hash = createHash('sha256')
    for (const part of parts) hash.update(part)
    return new Uint8Array(hash.digest())
}

/** Computes SHA-512 over one or more buffers. */
export function sha512(...parts: Uint8Array[]): Uint8Array {
    const hash = createHash('sha512')
    for (const part of parts) hash.update(part)
    return new Uint8Array(hash.digest())
}

/** Computes MD5 over one or more buffers (WhatsApp uses it for build hashes). */
export function md5(...parts: Uint8Array[]): Uint8Array {
    const hash = createHash('md5')
    for (const part of parts) hash.update(part)
    return new Uint8Array(hash.digest())
}

/** Computes an HMAC-SHA256 tag. */
export function hmacSha256(key: Uint8Array, ...parts: Uint8Array[]): Uint8Array {
    const mac = createHmac('sha256', key)
    for (const part of parts) mac.update(part)
    return new Uint8Array(mac.digest())
}

/** Computes an HMAC-SHA512 tag (used by XEdDSA). */
export function hmacSha512(key: Uint8Array, ...parts: Uint8Array[]): Uint8Array {
    const mac = createHmac('sha512', key)
    for (const part of parts) mac.update(part)
    return new Uint8Array(mac.digest())
}

/**
 * HKDF-SHA256 (RFC 5869).
 *
 * @param ikm Input keying material.
 * @param salt Optional salt; empty when omitted.
 * @param info Context/application-specific info.
 * @param length Output length in bytes.
 */
export function hkdf(
    ikm: Uint8Array,
    salt: Uint8Array | null,
    info: Uint8Array,
    length: number,
): Uint8Array {
    if (length <= 0 || length > 255 * 32) {
        throw new Error('hkdf: invalid output length')
    }
    const out = hkdfSync('sha256', ikm, salt ?? EMPTY, info, length)
    return new Uint8Array(out)
}

/**
 * HKDF-SHA256 producing 64 bytes split into two 32-byte halves.
 *
 * The WhatsApp/Signal key schedule uses this pattern extensively: the first
 * half continues the chaining key, the second half becomes the next cipher
 * key.
 */
export function hkdfSplit(
    ikm: Uint8Array,
    salt: Uint8Array | null,
    info: Uint8Array,
): [Uint8Array, Uint8Array] {
    const out = hkdf(ikm, salt, info, 64)
    return [out.subarray(0, 32), out.subarray(32, 64)]
}

/**
 * AES-256-GCM encryption. The 16-byte auth tag is appended to the ciphertext.
 *
 * @param key 32-byte key.
 * @param nonce 12-byte nonce.
 * @param plaintext Data to encrypt.
 * @param aad Optional additional authenticated data.
 */
export function aesGcmEncrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
    aad?: Uint8Array,
): Uint8Array {
    if (key.length !== KEY_LENGTH) throw new Error('aesGcmEncrypt: invalid key length')
    if (nonce.length !== GCM_NONCE_LENGTH) throw new Error('aesGcmEncrypt: invalid nonce length')
    const cipher = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: GCM_TAG_LENGTH })
    if (aad && aad.length) cipher.setAAD(aad)
    const body = cipher.update(plaintext)
    const final = cipher.final()
    const tag = cipher.getAuthTag()
    return concat(body, final, new Uint8Array(tag))
}

/**
 * AES-256-GCM decryption. The ciphertext must include the trailing tag.
 *
 * @throws When the authentication tag does not verify.
 */
export function aesGcmDecrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    ciphertext: Uint8Array,
    aad?: Uint8Array,
): Uint8Array {
    if (key.length !== KEY_LENGTH) throw new Error('aesGcmDecrypt: invalid key length')
    if (nonce.length !== GCM_NONCE_LENGTH) throw new Error('aesGcmDecrypt: invalid nonce length')
    if (ciphertext.length < GCM_TAG_LENGTH) {
        throw new Error('aesGcmDecrypt: ciphertext is too short')
    }
    const body = ciphertext.subarray(0, ciphertext.length - GCM_TAG_LENGTH)
    const tag = ciphertext.subarray(ciphertext.length - GCM_TAG_LENGTH)
    const decipher = createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: GCM_TAG_LENGTH })
    if (aad && aad.length) decipher.setAAD(aad)
    // The auth tag has to be set *before* `final()`, otherwise the
    // authentication check never runs and every ciphertext would "verify".
    decipher.setAuthTag(tag)
    const plain = decipher.update(body)
    const final = decipher.final()
    return concat(plain, final)
}

/**
 * AES-256-CBC encryption with PKCS#7 padding.
 *
 * @param key 32-byte key.
 * @param iv 16-byte initialisation vector.
 */
export function aesCbcEncrypt(key: Uint8Array, iv: Uint8Array, plaintext: Uint8Array): Uint8Array {
    if (key.length !== KEY_LENGTH) throw new Error('aesCbcEncrypt: invalid key length')
    if (iv.length !== 16) throw new Error('aesCbcEncrypt: invalid iv length')
    const cipher = createCipheriv('aes-256-cbc', key, iv)
    cipher.setAutoPadding(true)
    return concat(cipher.update(plaintext), cipher.final())
}

/**
 * AES-256-CBC decryption with PKCS#7 padding removal.
 *
 * @throws When the padding is invalid (which also covers a wrong key).
 */
export function aesCbcDecrypt(key: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    if (key.length !== KEY_LENGTH) throw new Error('aesCbcDecrypt: invalid key length')
    if (iv.length !== 16) throw new Error('aesCbcDecrypt: invalid iv length')
    const decipher = createDecipheriv('aes-256-cbc', key, iv)
    decipher.setAutoPadding(true)
    return concat(decipher.update(ciphertext), decipher.final())
}

/**
 * AES-256-CTR encryption.
 *
 * CTR is a stream cipher mode, so encryption and decryption are the same
 * operation. The counter block is the full 16-byte IV.
 *
 * @param key 32-byte key.
 * @param iv 16-byte initialisation vector (the counter block).
 * @param plaintext Data to encrypt.
 */
export function aesCtrEncrypt(
    key: Uint8Array,
    iv: Uint8Array,
    plaintext: Uint8Array,
): Uint8Array {
    if (key.length !== KEY_LENGTH) throw new Error('aesCtrEncrypt: invalid key length')
    if (iv.length !== 16) throw new Error('aesCtrEncrypt: invalid iv length')
    const cipher = createCipheriv('aes-256-ctr', key, iv)
    cipher.setAutoPadding(false)
    return concat(cipher.update(plaintext), cipher.final())
}

/**
 * AES-256-CTR decryption.
 *
 * @param key 32-byte key.
 * @param iv 16-byte initialisation vector (the counter block).
 * @param ciphertext Data to decrypt.
 */
export function aesCtrDecrypt(
    key: Uint8Array,
    iv: Uint8Array,
    ciphertext: Uint8Array,
): Uint8Array {
    if (key.length !== KEY_LENGTH) throw new Error('aesCtrDecrypt: invalid key length')
    if (iv.length !== 16) throw new Error('aesCtrDecrypt: invalid iv length')
    const decipher = createDecipheriv('aes-256-ctr', key, iv)
    decipher.setAutoPadding(false)
    return concat(decipher.update(ciphertext), decipher.final())
}

/**
 * PBKDF2-HMAC-SHA256.
 *
 * @param password The password bytes.
 * @param salt The salt.
 * @param iterations The iteration count.
 * @param length The derived key length in bytes.
 */
export function pbkdf2Sha256(
    password: Uint8Array,
    salt: Uint8Array,
    iterations: number,
    length: number,
): Uint8Array {
    if (!Number.isSafeInteger(iterations) || iterations <= 0) {
        throw new Error('pbkdf2Sha256: invalid iteration count')
    }
    if (!Number.isSafeInteger(length) || length <= 0) {
        throw new Error('pbkdf2Sha256: invalid output length')
    }
    return new Uint8Array(pbkdf2Sync(password, salt, iterations, length, 'sha256'))
}

/** Fills `target` with cryptographically secure random bytes. */
export function randomFill(target: Uint8Array): Uint8Array {
    randomBytes(target.length).copy(target)
    return target
}

/** Returns `length` cryptographically secure random bytes. */
export function randomBytesOf(length: number): Uint8Array {
    return new Uint8Array(randomBytes(length))
}

/** Returns a random 32-bit integer in `[0, max)`. */
export function randomInt(max: number): number {
    if (max <= 0) throw new Error('randomInt: max must be positive')
    // Rejection sampling keeps the distribution uniform for non-power-of-two max.
    const limit = Math.floor(0x1_0000_0000 / max) * max
    for (;;) {
        const value = randomBytes(4).readUInt32BE(0)
        if (value < limit) return value % max
    }
}

/** An X25519 key pair. */
export interface X25519KeyPair {
    /** 32-byte public key. */
    publicKey: Uint8Array
    /** 32-byte private key. */
    privateKey: Uint8Array
}

/**
 * Generates an X25519 key pair.
 *
 * Node's `generateKeyPairSync` returns DER/SPKI key objects; we convert them to
 * raw 32-byte keys so they can be stored and compared cheaply.
 */
export function generateX25519KeyPair(): X25519KeyPair {
    const { publicKey, privateKey } = generateKeyPairSync('x25519')
    return {
        publicKey: exportRawPublic(publicKey),
        privateKey: exportRawPrivate(privateKey),
    }
}

/**
 * Computes the X25519 shared secret.
 *
 * @param privateKey 32-byte private key.
 * @param publicKey 32-byte public key.
 */
export function x25519(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
    const priv = importRawPrivate(privateKey)
    const pub = importRawPublic(publicKey)
    return new Uint8Array(diffieHellman({ privateKey: priv, publicKey: pub }))
}

/**
 * Derives the X25519 public key for a private key.
 */
export function x25519PublicFromPrivate(privateKey: Uint8Array): Uint8Array {
    return exportRawPublic(createPublicKey(importRawPrivate(privateKey)))
}

/**
 * Converts a 33-byte "serialized" Signal public key (0x05 prefix) into the raw
 * 32-byte X25519 form.
 */
export function fromSerializedPublicKey(value: Uint8Array): Uint8Array {
    if (value.length === 32) return value
    if (value.length === 33 && value[0] === 5) return value.subarray(1)
    throw new Error('invalid serialized public key')
}

/**
 * Converts a raw 32-byte X25519 public key into the 33-byte serialized form
 * expected by the Signal protocol (0x05 prefix).
 */
export function toSerializedPublicKey(value: Uint8Array): Uint8Array {
    if (value.length === 33) {
        if (value[0] !== 5) throw new Error('invalid serialized public key prefix')
        return value
    }
    if (value.length !== 32) throw new Error('invalid public key length')
    const out = new Uint8Array(33)
    out[0] = 5
    out.set(value, 1)
    return out
}

/**
 * Prefixes content with a Signal version byte: `(v << 4) | v`.
 */
export function prependVersion(content: Uint8Array, version: number): Uint8Array {
    const out = new Uint8Array(content.length + 1)
    out[0] = ((version << 4) | version) & 0xff
    out.set(content, 1)
    return out
}

/**
 * Writes a 32-bit big-endian counter into the last four bytes of a 12-byte
 * GCM nonce, leaving the first eight bytes untouched.
 */
export function writeNonceCounter(target: Uint8Array, counter: number): Uint8Array {
    if (target.length < GCM_NONCE_LENGTH) {
        throw new Error('nonce buffer must be at least 12 bytes')
    }
    if (counter > 0xffff_ffff) {
        throw new Error('nonce counter overflow')
    }
    target[8] = (counter >>> 24) & 0xff
    target[9] = (counter >>> 16) & 0xff
    target[10] = (counter >>> 8) & 0xff
    target[11] = counter & 0xff
    return target
}

// ─── Internal key-object helpers ──────────────────────────────────────────────

/** Extracts the raw 32-byte public key from a Node `KeyObject`. */
function exportRawPublic(key: KeyObject): Uint8Array {
    const der = key.export({ type: 'spki', format: 'der' }) as Buffer
    // SPKI for X25519 is 44 bytes; the raw key is the trailing 32.
    return new Uint8Array(der.subarray(der.length - 32))
}

/** Extracts the raw 32-byte private key from a Node `KeyObject`. */
function exportRawPrivate(key: KeyObject): Uint8Array {
    const der = key.export({ type: 'pkcs8', format: 'der' }) as Buffer
    // PKCS#8 for X25519 is 48 bytes; the raw key is the trailing 32.
    return new Uint8Array(der.subarray(der.length - 32))
}

/**
 * DER prefix of a SubjectPublicKeyInfo structure holding an X25519 key
 * (RFC 8410): `SEQUENCE { SEQUENCE { OID 1.3.101.110 }, BIT STRING }`.
 */
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex')

/**
 * DER prefix of a PKCS#8 structure holding an X25519 private key
 * (RFC 8410): `SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.110 }, OCTET STRING }`.
 */
const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex')

/** Builds a Node `KeyObject` from a raw 32-byte X25519 public key. */
function importRawPublic(key: Uint8Array): KeyObject {
    if (key.length !== X25519_KEY_LENGTH) {
        throw new Error('invalid X25519 public key length')
    }
    const der = Buffer.concat([X25519_SPKI_PREFIX, Buffer.from(key)])
    return createPublicKey({ key: der, format: 'der', type: 'spki' })
}

/** Builds a Node `KeyObject` from a raw 32-byte X25519 private key. */
function importRawPrivate(key: Uint8Array): KeyObject {
    if (key.length !== X25519_KEY_LENGTH) {
        throw new Error('invalid X25519 private key length')
    }
    const der = Buffer.concat([X25519_PKCS8_PREFIX, Buffer.from(key)])
    return createPrivateKey({ key: der, format: 'der', type: 'pkcs8' })
}
