/**
 * Curve25519 / Ed25519 arithmetic implemented in pure JavaScript.
 *
 * Why not use `node:crypto`?
 * --------------------------
 * Node can do X25519 (Montgomery) ECDH natively, but the WhatsApp/Signal
 * stack also needs **XEdDSA**: a signature scheme that signs with an X25519
 * key pair. XEdDSA is not "Ed25519 with a different key" — it requires
 *
 * - the Edwards conversion of the Montgomery public key,
 * - a specific private-key clamping,
 * - a 64-byte random suffix mixed into the nonce derivation, and
 * - the sign bit of the Edwards public key smuggled into the top bit of the
 *   signature's `s` half.
 *
 * None of that is reachable through Node's Ed25519 API, so this module
 * implements the small slice of curve arithmetic that is missing:
 *
 * - field arithmetic in GF(2^255 - 19) backed by `BigInt`,
 * - twisted Edwards point arithmetic in extended coordinates
 *   (X : Y : Z : T), which needs only one modular inversion per encoding and
 *   avoids the per-addition inversions of the affine representation,
 * - point compression/decompression with canonical-encoding checks, and
 * - the XEdDSA sign/verify wrappers themselves.
 *
 * The implementation is deliberately self-contained: it only depends on
 * `node:crypto` through `primitives.ts` (SHA-512 and a CSPRNG).
 *
 * Reference: the Signal "XEdDSA" specification and RFC 8032 (Ed25519).
 */

import { randomBytesOf, sha512 } from './primitives.js'

/** The field prime `p = 2^255 - 19`. */
const P = (1n << 255n) - 19n

/**
 * The order of the prime-order subgroup,
 * `L = 2^252 + 27742317777372353535851937790883648493`.
 *
 * Scalars (nonces and `s` values) live in this group.
 */
const L = (1n << 252n) + 27742317777372353535851937790883648493n

/** The Ed25519 curve constant `d = -121665 / 121666 (mod p)`. */
const D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n

/** `2 * d (mod p)`, used by the extended-coordinate addition formula. */
const D2 = 16295367250680780974490674513165176452449235426866156013048779062215315747161n

/**
 * A square root of `-1` modulo `p`, i.e. `2^((p-1)/4) (mod p)`.
 *
 * Needed to recover `x` from `y` during point decompression, because
 * `p = 5 (mod 8)` and therefore every square has two roots.
 */
const SQRT_MINUS_ONE =
    19681161376707505956807079304988542015446066515923890162744021073123829784752n

/** `x` coordinate of the Ed25519 base point. */
const BASE_X = 15112221349535400772501151409588531511454012693041857206046113283949847762202n

/** `y` coordinate of the Ed25519 base point. */
const BASE_Y = 46316835694926478169428394003475163141307993866256225615783033603165251855960n

/** Length of a Curve25519 key or encoding in bytes. */
const KEY_LENGTH = 32

/** Length of an XEdDSA / Ed25519 signature in bytes. */
const SIGNATURE_LENGTH = 64

/**
 * The XEdDSA nonce prefix: `0xFE` followed by 31 bytes of `0xFF`.
 *
 * It domain-separates the nonce hash from every other SHA-512 use in the
 * protocol.
 */
const SIGNATURE_RANDOM_PREFIX = new Uint8Array([
    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
])

// ─── Byte helpers ─────────────────────────────────────────────────────────────

/** Interprets `bytes` as a little-endian unsigned integer. */
function bytesToBigIntLE(bytes: Uint8Array): bigint {
    let out = 0n
    for (let i = bytes.length - 1; i >= 0; i -= 1) {
        out = (out << 8n) | BigInt(bytes[i]!)
    }
    return out
}

/** Encodes `value` as a little-endian byte string of `length` bytes. */
function bigIntToBytesLE(value: bigint, length: number): Uint8Array {
    const out = new Uint8Array(length)
    let current = value
    for (let i = 0; i < length; i += 1) {
        out[i] = Number(current & 0xffn)
        current >>= 8n
    }
    return out
}

// ─── Field arithmetic ─────────────────────────────────────────────────────────

/** Reduces `value` into `[0, p)`. */
function feMod(value: bigint): bigint {
    const remainder = value % P
    return remainder >= 0n ? remainder : remainder + P
}

/** Field addition. */
function feAdd(a: bigint, b: bigint): bigint {
    return feMod(a + b)
}

/** Field subtraction. */
function feSub(a: bigint, b: bigint): bigint {
    return feMod(a - b)
}

/** Field multiplication. */
function feMul(a: bigint, b: bigint): bigint {
    return feMod(a * b)
}

/** Field negation. */
function feNeg(a: bigint): bigint {
    return a === 0n ? 0n : P - a
}

/** Field squaring. */
function feSqr(a: bigint): bigint {
    return feMod(a * a)
}

/**
 * Field exponentiation (`base^exponent mod p`) using square-and-multiply.
 *
 * @param base Base element.
 * @param exponent Non-negative exponent.
 */
function fePow(base: bigint, exponent: bigint): bigint {
    let result = 1n
    let factor = feMod(base)
    let remaining = exponent
    while (remaining > 0n) {
        if ((remaining & 1n) === 1n) result = feMod(result * factor)
        factor = feMod(factor * factor)
        remaining >>= 1n
    }
    return result
}

/**
 * Field inversion (`a^-1 mod p`).
 *
 * Fermat's little theorem is used (`a^(p-2)`), which is constant time with
 * respect to the secret exponent and cheap enough for our call volume: the
 * function is invoked a handful of times per signature.
 */
function feInv(a: bigint): bigint {
    return fePow(a, P - 2n)
}

/**
 * Computes a square root of `value` modulo `p`.
 *
 * `p = 5 (mod 8)`, so the candidate root is
 * `value^((p+3)/8)`; it is correct for half of the inputs and needs to be
 * multiplied by `sqrt(-1)` for the other half. `null` is returned when
 * `value` is not a quadratic residue.
 */
function feSqrt(value: bigint): bigint | null {
    if (value === 0n) return 0n
    const exponent = (P + 3n) / 8n
    let candidate = fePow(value, exponent)
    if (feSqr(candidate) !== value) {
        candidate = feMul(candidate, SQRT_MINUS_ONE)
        if (feSqr(candidate) !== value) return null
    }
    return candidate
}

// ─── Point arithmetic ─────────────────────────────────────────────────────────

/**
 * A point of the twisted Edwards curve in extended coordinates.
 *
 * The affine coordinates are `x = X/Z` and `y = Y/Z`; `T = XY/Z` is kept
 * around so that addition needs a single multiplication chain instead of
 * four.
 */
interface EdwardsPoint {
    /** Projective x coordinate. */
    x: bigint
    /** Projective y coordinate. */
    y: bigint
    /** Projective z coordinate. */
    z: bigint
    /** Projective `x*y` coordinate. */
    t: bigint
}

/** The neutral element `(0, 1)`. */
const IDENTITY: EdwardsPoint = { x: 0n, y: 1n, z: 1n, t: 0n }

/** The Ed25519 base point `B`. */
const BASE_POINT: EdwardsPoint = {
    x: BASE_X,
    y: BASE_Y,
    z: 1n,
    t: feMod(BASE_X * BASE_Y),
}

/**
 * Adds two points in extended coordinates.
 *
 * Uses the standard "add-2008-hwcd-3" formulas for `a = -1`, which are
 * complete for every pair of points on the curve.
 */
function pointAdd(a: EdwardsPoint, b: EdwardsPoint): EdwardsPoint {
    const aa = feMul(feSub(a.y, a.x), feSub(b.y, b.x))
    const bb = feMul(feAdd(a.y, a.x), feAdd(b.y, b.x))
    const cc = feMul(feMul(a.t, D2), b.t)
    const dd = feMul(feMul(a.z, 2n), b.z)
    const ee = feSub(bb, aa)
    const ff = feSub(dd, cc)
    const gg = feAdd(dd, cc)
    const hh = feAdd(bb, aa)
    return {
        x: feMul(ee, ff),
        y: feMul(gg, hh),
        z: feMul(ff, gg),
        t: feMul(ee, hh),
    }
}

/** Doubles a point in extended coordinates ("dbl-2008-hwcd"). */
function pointDouble(point: EdwardsPoint): EdwardsPoint {
    const aa = feSqr(point.x)
    const bb = feSqr(point.y)
    const cc = feMul(2n, feSqr(point.z))
    const dd = feNeg(aa)
    const ee = feSub(feSub(feSqr(feAdd(point.x, point.y)), aa), bb)
    const gg = feAdd(dd, bb)
    const ff = feSub(gg, cc)
    const hh = feSub(dd, bb)
    return {
        x: feMul(ee, ff),
        y: feMul(gg, hh),
        z: feMul(ff, gg),
        t: feMul(ee, hh),
    }
}

/** Negates a point (mirrors it across the x axis). */
function pointNegate(point: EdwardsPoint): EdwardsPoint {
    return {
        x: feNeg(point.x),
        y: point.y,
        z: point.z,
        t: feNeg(point.t),
    }
}

/**
 * Multiplies a point by a scalar using a 4-bit fixed window.
 *
 * The window table holds the first 16 multiples of `point`, which keeps the
 * number of expensive additions low while only doubling the amount of work
 * per scalar multiplication.
 */
function pointScalarMult(point: EdwardsPoint, scalar: bigint): EdwardsPoint {
    let base = point
    let value = scalar
    if (value < 0n) {
        value = -value
        base = pointNegate(base)
    }
    if (value === 0n) return IDENTITY

    // table[i] = (i + 1) * point
    const table: EdwardsPoint[] = new Array(16)
    table[0] = base
    for (let i = 1; i < 16; i += 1) {
        table[i] = pointAdd(table[i - 1]!, base)
    }

    let result = IDENTITY
    let started = false
    for (let shift = 252; shift >= 0; shift -= 4) {
        if (started) {
            result = pointDouble(pointDouble(pointDouble(pointDouble(result))))
        }
        const digit = Number((value >> BigInt(shift)) & 0xfn)
        if (digit !== 0) {
            result = started ? pointAdd(result, table[digit - 1]!) : table[digit - 1]!
            started = true
        }
    }
    return result
}

/**
 * Computes `pointA * scalarA + pointB * scalarB` with a joint 4-bit window.
 *
 * Shamir's trick: both scalars are consumed in the same loop, so the shared
 * doublings are paid only once. This is what the signature verification
 * needs (`[s]B - [h]A`), and it is roughly a third cheaper than two
 * independent scalar multiplications.
 */
function pointDoubleScalarMult(
    pointA: EdwardsPoint,
    scalarA: bigint,
    pointB: EdwardsPoint,
    scalarB: bigint,
): EdwardsPoint {
    const valueA = scalarA < 0n ? -scalarA : scalarA
    const valueB = scalarB < 0n ? -scalarB : scalarB
    const baseA = scalarA < 0n ? pointNegate(pointA) : pointA
    const baseB = scalarB < 0n ? pointNegate(pointB) : pointB

    const tableA: EdwardsPoint[] = new Array(16)
    tableA[0] = baseA
    for (let i = 1; i < 16; i += 1) {
        tableA[i] = pointAdd(tableA[i - 1]!, baseA)
    }
    const tableB: EdwardsPoint[] = new Array(16)
    tableB[0] = baseB
    for (let i = 1; i < 16; i += 1) {
        tableB[i] = pointAdd(tableB[i - 1]!, baseB)
    }

    let result = IDENTITY
    let started = false
    for (let shift = 252; shift >= 0; shift -= 4) {
        if (started) {
            result = pointDouble(pointDouble(pointDouble(pointDouble(result))))
        }
        const digitA = Number((valueA >> BigInt(shift)) & 0xfn)
        const digitB = Number((valueB >> BigInt(shift)) & 0xfn)
        if (digitA !== 0 || digitB !== 0) {
            if (digitA !== 0) {
                result = started ? pointAdd(result, tableA[digitA - 1]!) : tableA[digitA - 1]!
                started = true
            }
            if (digitB !== 0) {
                result = started ? pointAdd(result, tableB[digitB - 1]!) : tableB[digitB - 1]!
                started = true
            }
        }
    }
    return result
}

/**
 * Multiplies the base point `B` by `scalar`.
 *
 * Identical to {@link pointScalarMult} with the base point, but kept as a
 * separate entry point so that call sites read clearly.
 */
function pointScalarMultBase(scalar: bigint): EdwardsPoint {
    return pointScalarMult(BASE_POINT, scalar)
}

/** Converts an extended point into its affine `(x, y)` representation. */
function pointToAffine(point: EdwardsPoint): { x: bigint; y: bigint } {
    const invZ = feInv(point.z)
    return {
        x: feMul(point.x, invZ),
        y: feMul(point.y, invZ),
    }
}

/**
 * Encodes a point in the 32-byte compressed Ed25519 format.
 *
 * The `y` coordinate occupies the low 255 bits; the sign of `x` is stored in
 * the top bit of the last byte.
 */
function pointEncode(point: EdwardsPoint): Uint8Array {
    const affine = pointToAffine(point)
    const out = bigIntToBytesLE(affine.y, KEY_LENGTH)
    out[31] = (out[31]! & 0x7f) | (Number(affine.x & 1n) << 7)
    return out
}

/**
 * Decodes a compressed Ed25519 point.
 *
 * Non-canonical encodings are rejected: `y` must be smaller than `p`, and a
 * zero `x` coordinate may not carry the sign bit.
 *
 * @returns The decoded point, or `null` when the encoding is invalid.
 */
function pointDecode(encoded: Uint8Array): EdwardsPoint | null {
    if (encoded.length !== KEY_LENGTH) return null
    const bytes = new Uint8Array(encoded)
    const signBit = (bytes[31]! & 0x80) !== 0
    bytes[31] = bytes[31]! & 0x7f

    const y = bytesToBigIntLE(bytes)
    // Canonical encodings require y < p.
    if (y >= P) return null

    const y2 = feSqr(y)
    const u = feSub(y2, 1n)
    const v = feAdd(feMul(D, y2), 1n)

    // x = sqrt(u / v); the curve equation is x^2 = u/v.
    const x = feSqrt(feMul(u, feInv(v)))
    if (x === null) return null

    let signedX = x
    if ((x & 1n) !== (signBit ? 1n : 0n)) {
        signedX = feNeg(x)
    }
    // x = 0 has a single encoding; the sign bit must therefore be zero.
    if (signedX === 0n && signBit) return null

    return { x: signedX, y, z: 1n, t: feMod(signedX * y) }
}

/**
 * Compares two points for equality.
 *
 * The comparison is done in projective coordinates (`X1*Z2 == X2*Z1` and
 * `Y1*Z2 == Y2*Z1`), which avoids two modular inversions.
 */
function pointEquals(a: EdwardsPoint, b: EdwardsPoint): boolean {
    const x1z2 = feMul(a.x, b.z)
    const x2z1 = feMul(b.x, a.z)
    if (x1z2 !== x2z1) return false
    const y1z2 = feMul(a.y, b.z)
    const y2z1 = feMul(b.y, a.z)
    return y1z2 === y2z1
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Converts a Montgomery (X25519) public key into its Edwards counterpart.
 *
 * The birational map between the two curve models is
 * `y = (u - 1) / (u + 1) (mod p)`. The Montgomery representation does not
 * carry the sign of the Edwards `x` coordinate, so the caller has to supply
 * it:
 *
 * - during **verification** the sign bit is taken from the top bit of the
 *   signature's `s` half (that is where the signer put it), and
 * - when no sign bit is given, the top bit of the *input* key is used, which
 *   is the convention for keys that were produced by storing the Edwards
 *   sign alongside the Montgomery `u` coordinate.
 *
 * @param curvePublicKey 32-byte X25519 public key.
 * @param signBit Optional sign bit (`0x80` or `0`) of the Edwards x coordinate.
 *
 * @throws When the key has the wrong length or encodes the low-order point
 *         `p - 1`, which has no meaningful Edwards image.
 */
export function montgomeryToEdwardsPublic(
    curvePublicKey: Uint8Array,
    signBit?: number,
): Uint8Array {
    if (curvePublicKey.length !== KEY_LENGTH) {
        throw new Error('invalid curve25519 public key length')
    }

    // Bit 255 of an X25519 public key is not part of the u coordinate.
    const u = bytesToBigIntLE(curvePublicKey) & ((1n << 255n) - 1n)
    if (u === P - 1n) {
        throw new Error('invalid curve25519 low-order public key')
    }

    const numerator = feMod(u - 1n)
    const denominator = feMod(u + 1n)
    const y = feMul(numerator, feInv(denominator))

    const effectiveSign = signBit === undefined ? curvePublicKey[31]! & 0x80 : signBit & 0x80
    const out = bigIntToBytesLE(y, KEY_LENGTH)
    out[31] = (out[31]! & 0x7f) | effectiveSign
    return out
}

/**
 * Applies the standard Curve25519 clamping to a *copy* of `privateKey`.
 *
 * The copy matters: the caller's key material must not be modified as a side
 * effect of signing.
 */
function clampPrivateKey(privateKey: Uint8Array): Uint8Array {
    const out = new Uint8Array(privateKey)
    out[0] = out[0]! & 248
    out[31] = out[31]! & 127
    out[31] = out[31]! | 64
    return out
}

/**
 * Signs `message` with an X25519 private key using the XEdDSA construction.
 *
 * The produced signature is the usual 64-byte Ed25519 shape (`R || s`) with
 * one twist: the top bit of `s` carries the sign of the Edwards public key
 * instead of being part of the scalar.
 *
 * @param privateKey 32-byte X25519 private key (the raw scalar, unclamped).
 * @param message The bytes to sign.
 *
 * @returns A 64-byte signature.
 */
export function xeddsaSign(privateKey: Uint8Array, message: Uint8Array): Uint8Array {
    if (privateKey.length !== KEY_LENGTH) {
        throw new Error('invalid curve25519 private key length')
    }

    const clamped = clampPrivateKey(privateKey)
    const scalar = bytesToBigIntLE(clamped)

    // A = a * B, compressed.
    const publicKey = pointEncode(pointScalarMultBase(scalar))

    // r = H(0xFE || 0xFF * 31 || a || M || random) mod L
    const randomSuffix = randomBytesOf(64)
    const nonceHash = sha512(
        SIGNATURE_RANDOM_PREFIX,
        clamped,
        message,
        randomSuffix,
    )
    const r = feModGroup(bytesToBigIntLE(nonceHash))

    // R = r * B, compressed.
    const encodedR = pointEncode(pointScalarMultBase(r))

    // h = H(R || A || M) mod L
    const challengeHash = sha512(encodedR, publicKey, message)
    const h = feModGroup(bytesToBigIntLE(challengeHash))

    // s = (r + h * a) mod L
    const s = feModGroup(r + h * scalar)

    const encodedS = bigIntToBytesLE(s, KEY_LENGTH)
    encodedS[31] = (encodedS[31]! & 0x7f) | (publicKey[31]! & 0x80)

    const signature = new Uint8Array(SIGNATURE_LENGTH)
    signature.set(encodedR, 0)
    signature.set(encodedS, KEY_LENGTH)
    return signature
}

/**
 * Verifies an XEdDSA signature.
 *
 * @param curvePublicKey 32-byte X25519 public key of the signer.
 * @param message The signed bytes.
 * @param signature A 64-byte signature produced by {@link xeddsaSign}.
 *
 * @returns `true` when the signature is valid, `false` otherwise. Malformed
 *          input never throws; it simply fails to verify.
 */
export function xeddsaVerify(
    curvePublicKey: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array,
): boolean {
    if (signature.length !== SIGNATURE_LENGTH) return false
    // Bits 5 and 6 of the last byte must be zero: the scalar is smaller than
    // L < 2^253 and bit 7 is reserved for the public key sign.
    if ((signature[63]! & 0x60) !== 0) return false

    const signBit = signature[63]! & 0x80
    const encodedS = new Uint8Array(signature.subarray(KEY_LENGTH, SIGNATURE_LENGTH))
    encodedS[31] = encodedS[31]! & 0x7f
    const s = bytesToBigIntLE(encodedS)
    // Canonical scalars are strictly smaller than L.
    if (s >= L) return false

    let edwardsPublicKey: Uint8Array
    try {
        edwardsPublicKey = montgomeryToEdwardsPublic(curvePublicKey, signBit)
    } catch {
        return false
    }

    const publicKeyPoint = pointDecode(edwardsPublicKey)
    if (!publicKeyPoint) return false

    const encodedR = signature.subarray(0, KEY_LENGTH)
    const rPoint = pointDecode(encodedR)
    if (!rPoint) return false

    const challengeHash = sha512(encodedR, edwardsPublicKey, message)
    const h = feModGroup(bytesToBigIntLE(challengeHash))

    // [s]B = R + [h]A  <=>  [s]B - [h]A = R
    const left = pointDoubleScalarMult(BASE_POINT, s, publicKeyPoint, -h)
    return pointEquals(left, rPoint)
}

/**
 * Reduces a value into the prime-order subgroup `[0, L)`.
 */
function feModGroup(value: bigint): bigint {
    const remainder = value % L
    return remainder >= 0n ? remainder : remainder + L
}
