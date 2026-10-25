/**
 * A minimal, dependency-free QR Code encoder (ISO/IEC 18004).
 *
 * Features
 * --------
 * - Byte mode only: the payload is encoded as its UTF-8 byte representation.
 * - Versions 1-40 and all four error-correction levels (`L`, `M`, `Q`, `H`).
 * - All eight data mask patterns with the standard penalty scoring used to
 *   pick the "best" mask.
 * - Reed-Solomon error correction over GF(256) with the QR generator
 *   polynomial, block interleaving, format information (BCH 15,5) and version
 *   information (BCH 18,6).
 *
 * The symbol layout follows the reference implementation (libqrencode and the
 * `qrcode` JavaScript port that descends from it) so that the produced module
 * grid is identical to what other well-known encoders emit.
 *
 * Everything is plain TypeScript on top of `TextEncoder`; no `Buffer` and no
 * third-party packages are used.
 */

/** The four error-correction levels defined by the specification. */
export type QrErrorCorrectionLevel = 'L' | 'M' | 'Q' | 'H'

/** A rendered QR Code symbol, without the quiet zone. */
export interface QrMatrix {
    /** Number of modules per side. */
    size: number
    /** The module grid; `true` means a dark module. */
    modules: boolean[][]
    /** Error correction level used. */
    errorCorrectionLevel: QrErrorCorrectionLevel
    /** The mask pattern applied. */
    mask: number
}

/** Options accepted by {@link encodeQr}. */
export interface QrEncodeOptions {
    /** Error correction level; defaults to 'L'. */
    errorCorrectionLevel?: QrErrorCorrectionLevel
    /** Minimum QR version (1-40); defaults to 1. */
    minVersion?: number
    /** Maximum QR version (1-40); defaults to 40. */
    maxVersion?: number
    /** Forced mask pattern (0-7); when omitted the best mask is chosen. */
    mask?: number
}

/** Options accepted by {@link qrToSvg}. */
export interface QrSvgOptions {
    /** Size of a single module in user units; defaults to 8. */
    moduleSize?: number
    /** Quiet zone width in modules; defaults to 4. */
    margin?: number
    /** Colour of the dark modules; defaults to `#000000`. */
    dark?: string
    /** Colour of the light modules (background); defaults to `#ffffff`. */
    light?: string
}

/** Options accepted by {@link qrToTerminal}. */
export interface QrTerminalOptions {
    /** Use half-block characters for double vertical density; defaults to true. */
    halfBlocks?: boolean
}

// ─── Tables ───────────────────────────────────────────────────────────────────

/** Index of each error-correction level inside the flat per-version tables. */
const ECL_INDEX: Readonly<Record<QrErrorCorrectionLevel, number>> = { L: 0, M: 1, Q: 2, H: 3 }

/**
 * Format-information "level" bits for `L`, `M`, `Q` and `H`
 * (ISO/IEC 18004, table 12).
 */
const ECL_FORMAT_BITS: readonly number[] = [1, 0, 3, 2]

/** Total number of codewords (data + error correction) per version, 1-40. */
const TOTAL_CODEWORDS: readonly number[] = [
    26, 44, 70, 100, 134, 172, 196, 242, 292, 346,
    404, 466, 532, 581, 655, 733, 815, 901, 991, 1085,
    1156, 1258, 1364, 1474, 1588, 1706, 1828, 1921, 2051, 2185,
    2323, 2465, 2611, 2761, 2876, 3034, 3196, 3362, 3532, 3706,
]

/**
 * Number of error-correction blocks per version and level.
 *
 * Flattened as `(version - 1) * 4 + level` with the levels in `L, M, Q, H`
 * order.
 */
const EC_BLOCKS: readonly number[] = [
    1, 1, 1, 1,
    1, 1, 1, 1,
    1, 1, 2, 2,
    1, 2, 2, 4,
    1, 2, 4, 4,
    2, 4, 4, 4,
    2, 4, 6, 5,
    2, 4, 6, 6,
    2, 5, 8, 8,
    4, 5, 8, 8,
    4, 5, 8, 11,
    4, 8, 10, 11,
    4, 9, 12, 16,
    4, 9, 16, 16,
    6, 10, 12, 18,
    6, 10, 17, 16,
    6, 11, 16, 19,
    6, 13, 18, 21,
    7, 14, 21, 25,
    8, 16, 20, 25,
    8, 17, 23, 25,
    9, 17, 23, 34,
    9, 18, 25, 30,
    10, 20, 27, 32,
    12, 21, 29, 35,
    12, 23, 34, 37,
    12, 25, 34, 40,
    13, 26, 35, 42,
    14, 28, 38, 45,
    15, 29, 40, 48,
    16, 31, 43, 51,
    17, 33, 45, 54,
    18, 35, 48, 57,
    19, 37, 51, 60,
    19, 38, 53, 63,
    20, 40, 56, 66,
    21, 43, 59, 70,
    22, 45, 62, 74,
    24, 47, 65, 77,
    25, 49, 68, 81,
]

/**
 * Total number of error-correction codewords per version and level.
 *
 * Flattened as `(version - 1) * 4 + level` with the levels in `L, M, Q, H`
 * order.
 */
const EC_CODEWORDS: readonly number[] = [
    7, 10, 13, 17,
    10, 16, 22, 28,
    15, 26, 36, 44,
    20, 36, 52, 64,
    26, 48, 72, 88,
    36, 64, 96, 112,
    40, 72, 108, 130,
    48, 88, 132, 156,
    60, 110, 160, 192,
    72, 130, 192, 224,
    80, 150, 224, 264,
    96, 176, 260, 308,
    104, 198, 288, 352,
    120, 216, 320, 384,
    132, 240, 360, 432,
    144, 280, 408, 480,
    168, 308, 448, 532,
    180, 338, 504, 588,
    196, 364, 546, 650,
    224, 416, 600, 700,
    224, 442, 644, 750,
    252, 476, 690, 816,
    270, 504, 750, 900,
    300, 560, 810, 960,
    312, 588, 870, 1050,
    336, 644, 952, 1110,
    360, 700, 1020, 1200,
    390, 728, 1050, 1260,
    420, 784, 1140, 1350,
    450, 812, 1200, 1440,
    480, 868, 1290, 1530,
    510, 924, 1350, 1620,
    540, 980, 1440, 1710,
    570, 1036, 1530, 1800,
    570, 1064, 1590, 1890,
    600, 1120, 1680, 1980,
    630, 1204, 1770, 2100,
    660, 1260, 1860, 2220,
    720, 1316, 1950, 2310,
    750, 1372, 2040, 2430,
]

/** Generator polynomial for the format information, BCH(15,5). */
const FORMAT_GENERATOR = (1 << 10) | (1 << 8) | (1 << 5) | (1 << 4) | (1 << 2) | (1 << 1) | (1 << 0)

/** Mask applied to the format information so that it is never all zeroes. */
const FORMAT_MASK = (1 << 14) | (1 << 12) | (1 << 10) | (1 << 4) | (1 << 1)

/** Generator polynomial for the version information, BCH(18,6). */
const VERSION_GENERATOR =
    (1 << 12) | (1 << 11) | (1 << 10) | (1 << 9) | (1 << 8) | (1 << 5) | (1 << 2) | (1 << 0)

/** Penalty weights used when scoring the mask patterns. */
const PENALTY_N1 = 3
/** @see PENALTY_N1 */
const PENALTY_N2 = 3
/** @see PENALTY_N1 */
const PENALTY_N3 = 40
/** @see PENALTY_N1 */
const PENALTY_N4 = 10

/** Byte mode indicator (0100). */
const MODE_BYTE = 0b0100

// ─── Galois field helpers ─────────────────────────────────────────────────────

/** Anti-log table for GF(256) with the QR primitive polynomial 0x11D. */
const GF_EXP = new Uint8Array(512)
/** Log table for GF(256) with the QR primitive polynomial 0x11D. */
const GF_LOG = new Uint8Array(256)

;(function initGaloisTables(): void {
    let x = 1
    for (let i = 0; i < 255; i++) {
        GF_EXP[i] = x
        GF_LOG[x] = i
        x <<= 1
        if (x & 0x100) x ^= 0x11d
    }
    for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255]!
})()

/**
 * Multiplies two field elements of GF(256).
 *
 * @param a First factor.
 * @param b Second factor.
 */
function gfMul(a: number, b: number): number {
    if (a === 0 || b === 0) return 0
    return GF_EXP[GF_LOG[a]! + GF_LOG[b]!]!
}

/**
 * Computes the Reed-Solomon generator polynomial of the given degree.
 *
 * The polynomial is returned as coefficients in descending order, so
 * `poly[0]` is the leading coefficient (always 1).
 *
 * @param degree Number of error-correction codewords.
 */
function generatorPolynomial(degree: number): Uint8Array {
    let poly = new Uint8Array([1])
    for (let i = 0; i < degree; i++) {
        const next = new Uint8Array(poly.length + 1)
        for (let j = 0; j < poly.length; j++) {
            next[j] = (next[j]! ^ poly[j]!) as number
            next[j + 1] = (next[j + 1]! ^ gfMul(poly[j]!, GF_EXP[i]!)) as number
        }
        poly = next
    }
    return poly
}

/**
 * Computes the Reed-Solomon error-correction codewords for one data block.
 *
 * @param data The data codewords of the block.
 * @param ecCount Number of error-correction codewords to produce.
 */
function reedSolomonEncode(data: Uint8Array, ecCount: number): Uint8Array {
    const generator = generatorPolynomial(ecCount)
    const remainder = new Uint8Array(data.length + ecCount)
    remainder.set(data)

    for (let i = 0; i < data.length; i++) {
        const factor = remainder[i]!
        if (factor === 0) continue
        for (let j = 0; j < generator.length; j++) {
            remainder[i + j] = remainder[i + j]! ^ gfMul(generator[j]!, factor)
        }
    }

    return remainder.subarray(data.length)
}

// ─── Bit buffer ───────────────────────────────────────────────────────────────

/** A most-significant-bit-first bit buffer used to build the data codewords. */
class BitBuffer {
    /** Raw bytes, most significant bit first. */
    private readonly bytes: number[] = []
    /** Number of bits written so far. */
    private bitLength = 0

    /** Appends the lowest `length` bits of `value`, most significant first. */
    put(value: number, length: number): void {
        for (let i = length - 1; i >= 0; i--) this.putBit((value >>> i) & 1)
    }

    /** Appends a single bit. */
    putBit(bit: number): void {
        const byteIndex = this.bitLength >>> 3
        if (byteIndex >= this.bytes.length) this.bytes.push(0)
        if (bit) this.bytes[byteIndex] = this.bytes[byteIndex]! | (0x80 >>> (this.bitLength & 7))
        this.bitLength++
    }

    /** Number of bits currently held. */
    get lengthInBits(): number {
        return this.bitLength
    }

    /** Copies the buffer into a `Uint8Array`. */
    toBytes(): Uint8Array {
        return Uint8Array.from(this.bytes)
    }
}

// ─── Data encoding ────────────────────────────────────────────────────────────

/**
 * Returns the width of the character count indicator for byte mode.
 *
 * @param version The QR version (1-40).
 */
function charCountBits(version: number): number {
    return version < 10 ? 8 : 16
}

/**
 * Returns the number of data codewords available for a version/level pair.
 *
 * @param version The QR version (1-40).
 * @param level The error-correction level.
 */
function dataCapacityBits(version: number, level: QrErrorCorrectionLevel): number {
    const total = TOTAL_CODEWORDS[version - 1]!
    const ec = EC_CODEWORDS[(version - 1) * 4 + ECL_INDEX[level]]!
    return (total - ec) * 8
}

/**
 * Returns the smallest version that can hold `byteLength` bytes in byte mode.
 *
 * @param byteLength Number of payload bytes.
 * @param level The error-correction level.
 * @param minVersion Lowest version that may be used.
 * @param maxVersion Highest version that may be used.
 */
function chooseVersion(
    byteLength: number,
    level: QrErrorCorrectionLevel,
    minVersion: number,
    maxVersion: number,
): number {
    for (let version = minVersion; version <= maxVersion; version++) {
        const needed = 4 + charCountBits(version) + byteLength * 8
        if (needed <= dataCapacityBits(version, level)) return version
    }
    throw new Error(`qrcode: data does not fit into a version ${minVersion}-${maxVersion} QR code`)
}

/**
 * Builds the final codeword stream (data + error correction, interleaved).
 *
 * @param version The QR version (1-40).
 * @param level The error-correction level.
 * @param bytes The payload bytes.
 */
function buildCodewords(version: number, level: QrErrorCorrectionLevel, bytes: Uint8Array): Uint8Array {
    const levelIndex = ECL_INDEX[level]
    const capacity = dataCapacityBits(version, level)

    const buffer = new BitBuffer()
    buffer.put(MODE_BYTE, 4)
    buffer.put(bytes.length, charCountBits(version))
    for (let i = 0; i < bytes.length; i++) buffer.put(bytes[i]!, 8)

    // Terminator: up to four zero bits, but only when they still fit.
    if (buffer.lengthInBits + 4 <= capacity) buffer.put(0, 4)

    // Pad to a byte boundary.
    while (buffer.lengthInBits % 8 !== 0) buffer.putBit(0)

    // Fill the rest with the alternating pad codewords 0xEC / 0x11.
    let padIndex = 0
    while (buffer.lengthInBits < capacity) {
        buffer.put(padIndex % 2 === 0 ? 0xec : 0x11, 8)
        padIndex++
    }

    const data = buffer.toBytes()

    // Split the data codewords into blocks and compute their error correction.
    const totalCodewords = TOTAL_CODEWORDS[version - 1]!
    const totalEcCodewords = EC_CODEWORDS[(version - 1) * 4 + levelIndex]!
    const totalDataCodewords = totalCodewords - totalEcCodewords
    const blockCount = EC_BLOCKS[(version - 1) * 4 + levelIndex]!

    const blocksInGroup2 = totalCodewords % blockCount
    const blocksInGroup1 = blockCount - blocksInGroup2
    const codewordsPerBlock = Math.floor(totalCodewords / blockCount)
    const dataPerBlock1 = Math.floor(totalDataCodewords / blockCount)
    const dataPerBlock2 = dataPerBlock1 + 1
    const ecPerBlock = codewordsPerBlock - dataPerBlock1

    const dataBlocks: Uint8Array[] = []
    const ecBlocks: Uint8Array[] = []
    let offset = 0
    for (let block = 0; block < blockCount; block++) {
        const size = block < blocksInGroup1 ? dataPerBlock1 : dataPerBlock2
        const chunk = data.slice(offset, offset + size)
        offset += size
        dataBlocks.push(chunk)
        ecBlocks.push(reedSolomonEncode(chunk, ecPerBlock))
    }

    // Interleave: data codewords first, then the error-correction codewords.
    const output = new Uint8Array(totalCodewords)
    let cursor = 0
    const maxDataSize = Math.max(dataPerBlock1, dataPerBlock2)
    for (let i = 0; i < maxDataSize; i++) {
        for (let block = 0; block < blockCount; block++) {
            const chunk = dataBlocks[block]!
            if (i < chunk.length) output[cursor++] = chunk[i]!
        }
    }
    for (let i = 0; i < ecPerBlock; i++) {
        for (let block = 0; block < blockCount; block++) {
            output[cursor++] = ecBlocks[block]![i]!
        }
    }

    return output
}

// ─── Matrix construction ──────────────────────────────────────────────────────

/**
 * Returns the centre coordinates of the alignment patterns for a version.
 *
 * @param version The QR version (1-40).
 */
function alignmentCoordinates(version: number): number[] {
    if (version === 1) return []
    const size = version * 4 + 17
    const count = Math.floor(version / 7) + 2
    const interval = size === 145 ? 26 : Math.ceil((size - 13) / (2 * count - 2)) * 2
    const positions: number[] = [size - 7]
    for (let i = 1; i < count - 1; i++) positions[i] = positions[i - 1]! - interval
    positions.push(6)
    return positions.reverse()
}

/**
 * Computes the 15-bit format information for an error-correction level/mask
 * pair.
 *
 * @param level The error-correction level.
 * @param mask The mask pattern (0-7).
 */
function formatInformation(level: QrErrorCorrectionLevel, mask: number): number {
    const data = (ECL_FORMAT_BITS[ECL_INDEX[level]]! << 3) | mask
    let remainder = data << 10
    for (;;) {
        const degree = bitLength(remainder) - bitLength(FORMAT_GENERATOR)
        if (degree < 0) break
        remainder ^= FORMAT_GENERATOR << degree
    }
    return ((data << 10) | remainder) ^ FORMAT_MASK
}

/**
 * Computes the 18-bit version information for versions 7 and above.
 *
 * @param version The QR version (7-40).
 */
function versionInformation(version: number): number {
    let remainder = version << 12
    for (;;) {
        const degree = bitLength(remainder) - bitLength(VERSION_GENERATOR)
        if (degree < 0) break
        remainder ^= VERSION_GENERATOR << degree
    }
    return (version << 12) | remainder
}

/**
 * Returns the number of bits required to represent `value`.
 *
 * @param value The value to measure.
 */
function bitLength(value: number): number {
    let length = 0
    let rest = value
    while (rest !== 0) {
        length++
        rest >>>= 1
    }
    return length
}

/**
 * Mutable symbol buffer used while the matrix is assembled.
 */
interface SymbolBuilder {
    /** Module values, `true` means dark. */
    modules: boolean[][]
    /** Marks function-pattern modules that must not be masked. */
    reserved: boolean[][]
}

/**
 * Draws the three finder patterns together with their separators.
 *
 * @param symbol The symbol under construction.
 */
function setupFinderPatterns(symbol: SymbolBuilder): void {
    const size = symbol.modules.length
    const origins: readonly (readonly [number, number])[] = [
        [0, 0],
        [0, size - 7],
        [size - 7, 0],
    ]

    for (const [row0, col0] of origins) {
        for (let r = -1; r <= 7; r++) {
            const row = row0 + r
            if (row < 0 || row >= size) continue
            for (let c = -1; c <= 7; c++) {
                const col = col0 + c
                if (col < 0 || col >= size) continue
                const dark =
                    (r >= 0 && r <= 6 && (c === 0 || c === 6)) ||
                    (c >= 0 && c <= 6 && (r === 0 || r === 6)) ||
                    (r >= 2 && r <= 4 && c >= 2 && c <= 4)
                symbol.modules[row]![col] = dark
                symbol.reserved[row]![col] = true
            }
        }
    }
}

/**
 * Draws the horizontal and vertical timing patterns.
 *
 * @param symbol The symbol under construction.
 */
function setupTimingPatterns(symbol: SymbolBuilder): void {
    const size = symbol.modules.length
    for (let i = 8; i < size - 8; i++) {
        const dark = i % 2 === 0
        symbol.modules[i]![6] = dark
        symbol.reserved[i]![6] = true
        symbol.modules[6]![i] = dark
        symbol.reserved[6]![i] = true
    }
}

/**
 * Draws the alignment patterns of a version.
 *
 * @param symbol The symbol under construction.
 * @param version The QR version (1-40).
 */
function setupAlignmentPatterns(symbol: SymbolBuilder, version: number): void {
    const positions = alignmentCoordinates(version)
    for (const row of positions) {
        for (const col of positions) {
            // The three positions that overlap a finder pattern are skipped.
            const isCorner =
                (row === 6 && col === 6) ||
                (row === 6 && col === positions[positions.length - 1]!) ||
                (row === positions[positions.length - 1]! && col === 6)
            if (isCorner) continue
            for (let r = -2; r <= 2; r++) {
                for (let c = -2; c <= 2; c++) {
                    const dark = r === -2 || r === 2 || c === -2 || c === 2 || (r === 0 && c === 0)
                    symbol.modules[row + r]![col + c] = dark
                    symbol.reserved[row + r]![col + c] = true
                }
            }
        }
    }
}

/**
 * Writes the 15-bit format information (both copies) and the dark module.
 *
 * @param symbol The symbol under construction.
 * @param level The error-correction level.
 * @param mask The mask pattern (0-7).
 */
function setupFormatInformation(symbol: SymbolBuilder, level: QrErrorCorrectionLevel, mask: number): void {
    const size = symbol.modules.length
    const bits = formatInformation(level, mask)

    for (let i = 0; i < 15; i++) {
        const dark = ((bits >>> i) & 1) === 1

        // Vertical copy, running down the left hand side and the bottom.
        let row: number
        if (i < 6) row = i
        else if (i < 8) row = i + 1
        else row = size - 15 + i
        symbol.modules[row]![8] = dark
        symbol.reserved[row]![8] = true

        // Horizontal copy, running along the top row and the right hand side.
        let col: number
        if (i < 8) col = size - i - 1
        else if (i < 9) col = 15 - i - 1 + 1
        else col = 15 - i - 1
        symbol.modules[8]![col] = dark
        symbol.reserved[8]![col] = true
    }

    // The always-dark module below the top-left finder pattern.
    symbol.modules[size - 8]![8] = true
    symbol.reserved[size - 8]![8] = true
}

/**
 * Writes the 18-bit version information (versions 7 and above).
 *
 * @param symbol The symbol under construction.
 * @param version The QR version (7-40).
 */
function setupVersionInformation(symbol: SymbolBuilder, version: number): void {
    const size = symbol.modules.length
    const bits = versionInformation(version)

    for (let i = 0; i < 18; i++) {
        const row = Math.floor(i / 3)
        const col = (i % 3) + size - 8 - 3
        const dark = ((bits >>> i) & 1) === 1

        symbol.modules[row]![col] = dark
        symbol.reserved[row]![col] = true
        symbol.modules[col]![row] = dark
        symbol.reserved[col]![row] = true
    }
}

/**
 * Writes the codeword stream into the data region of the symbol.
 *
 * @param symbol The symbol under construction.
 * @param codewords The interleaved codeword stream.
 */
function setupData(symbol: SymbolBuilder, codewords: Uint8Array): void {
    const size = symbol.modules.length
    let direction = -1
    let row = size - 1
    let bitIndex = 7
    let byteIndex = 0

    for (let col = size - 1; col > 0; col -= 2) {
        // Column 6 is the vertical timing pattern and is skipped entirely.
        if (col === 6) col--

        for (;;) {
            for (let c = 0; c < 2; c++) {
                const target = col - c
                if (symbol.reserved[row]![target]) continue
                let dark = false
                if (byteIndex < codewords.length) {
                    dark = ((codewords[byteIndex]! >>> bitIndex) & 1) === 1
                }
                symbol.modules[row]![target] = dark
                bitIndex--
                if (bitIndex === -1) {
                    byteIndex++
                    bitIndex = 7
                }
            }

            row += direction
            if (row < 0 || row >= size) {
                row -= direction
                direction = -direction
                break
            }
        }
    }
}

// ─── Masking ──────────────────────────────────────────────────────────────────

/**
 * Returns the mask value for a module.
 *
 * @param pattern The mask pattern (0-7).
 * @param row The module row.
 * @param col The module column.
 */
function maskValue(pattern: number, row: number, col: number): boolean {
    switch (pattern) {
        case 0:
            return (row + col) % 2 === 0
        case 1:
            return row % 2 === 0
        case 2:
            return col % 3 === 0
        case 3:
            return (row + col) % 3 === 0
        case 4:
            return (Math.floor(row / 2) + Math.floor(col / 3)) % 2 === 0
        case 5:
            return ((row * col) % 2) + ((row * col) % 3) === 0
        case 6:
            return (((row * col) % 2) + ((row * col) % 3)) % 2 === 0
        default:
            return (((row * col) % 3) + ((row + col) % 2)) % 2 === 0
    }
}

/**
 * Applies (or un-applies) a mask pattern to the data region.
 *
 * Masking is an exclusive-or, so applying the same pattern twice restores the
 * original modules.
 *
 * @param symbol The symbol under construction.
 * @param pattern The mask pattern (0-7).
 */
function applyMask(symbol: SymbolBuilder, pattern: number): void {
    const size = symbol.modules.length
    for (let row = 0; row < size; row++) {
        for (let col = 0; col < size; col++) {
            if (symbol.reserved[row]![col]) continue
            if (maskValue(pattern, row, col)) {
                symbol.modules[row]![col] = !symbol.modules[row]![col]
            }
        }
    }
}

/**
 * Penalty N1: runs of five or more modules of the same colour.
 *
 * @param symbol The symbol to score.
 */
function penaltyN1(symbol: SymbolBuilder): number {
    const size = symbol.modules.length
    let points = 0

    for (let row = 0; row < size; row++) {
        let sameCountCol = 0
        let sameCountRow = 0
        let lastCol: boolean | null = null
        let lastRow: boolean | null = null

        for (let col = 0; col < size; col++) {
            const module = symbol.modules[row]![col]!
            if (module === lastCol) {
                sameCountCol++
            } else {
                if (sameCountCol >= 5) points += PENALTY_N1 + (sameCountCol - 5)
                lastCol = module
                sameCountCol = 1
            }

            const other = symbol.modules[col]![row]!
            if (other === lastRow) {
                sameCountRow++
            } else {
                if (sameCountRow >= 5) points += PENALTY_N1 + (sameCountRow - 5)
                lastRow = other
                sameCountRow = 1
            }
        }

        if (sameCountCol >= 5) points += PENALTY_N1 + (sameCountCol - 5)
        if (sameCountRow >= 5) points += PENALTY_N1 + (sameCountRow - 5)
    }

    return points
}

/**
 * Penalty N2: blocks of 2x2 modules of the same colour.
 *
 * @param symbol The symbol to score.
 */
function penaltyN2(symbol: SymbolBuilder): number {
    const size = symbol.modules.length
    let points = 0

    for (let row = 0; row < size - 1; row++) {
        for (let col = 0; col < size - 1; col++) {
            const sum =
                (symbol.modules[row]![col]! ? 1 : 0) +
                (symbol.modules[row]![col + 1]! ? 1 : 0) +
                (symbol.modules[row + 1]![col]! ? 1 : 0) +
                (symbol.modules[row + 1]![col + 1]! ? 1 : 0)
            if (sum === 0 || sum === 4) points++
        }
    }

    return points * PENALTY_N2
}

/**
 * Penalty N3: the 1:1:3:1:1 finder-like pattern.
 *
 * @param symbol The symbol to score.
 */
function penaltyN3(symbol: SymbolBuilder): number {
    const size = symbol.modules.length
    let points = 0

    for (let row = 0; row < size; row++) {
        let bitsCol = 0
        let bitsRow = 0
        for (let col = 0; col < size; col++) {
            bitsCol = ((bitsCol << 1) & 0x7ff) | (symbol.modules[row]![col]! ? 1 : 0)
            if (col >= 10 && (bitsCol === 0x5d0 || bitsCol === 0x05d)) points++

            bitsRow = ((bitsRow << 1) & 0x7ff) | (symbol.modules[col]![row]! ? 1 : 0)
            if (col >= 10 && (bitsRow === 0x5d0 || bitsRow === 0x05d)) points++
        }
    }

    return points * PENALTY_N3
}

/**
 * Penalty N4: deviation of the dark module ratio from 50%.
 *
 * @param symbol The symbol to score.
 */
function penaltyN4(symbol: SymbolBuilder): number {
    const size = symbol.modules.length
    let darkCount = 0
    for (let row = 0; row < size; row++) {
        for (let col = 0; col < size; col++) {
            if (symbol.modules[row]![col]) darkCount++
        }
    }

    const modulesCount = size * size
    const k = Math.abs(Math.ceil((darkCount * 100) / modulesCount / 5) - 10)
    return k * PENALTY_N4
}

/**
 * Scores a symbol with all four penalty rules.
 *
 * @param symbol The symbol to score.
 */
function penaltyScore(symbol: SymbolBuilder): number {
    return penaltyN1(symbol) + penaltyN2(symbol) + penaltyN3(symbol) + penaltyN4(symbol)
}

/**
 * Picks the mask pattern with the lowest penalty score.
 *
 * @param symbol The symbol to score.
 * @param level The error-correction level.
 */
function bestMask(symbol: SymbolBuilder, level: QrErrorCorrectionLevel): number {
    let best = 0
    let lowest = Number.POSITIVE_INFINITY

    for (let pattern = 0; pattern < 8; pattern++) {
        setupFormatInformation(symbol, level, pattern)
        applyMask(symbol, pattern)
        const score = penaltyScore(symbol)
        applyMask(symbol, pattern)

        if (score < lowest) {
            lowest = score
            best = pattern
        }
    }

    return best
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Encodes `text` (UTF-8, byte mode) into a QR matrix.
 *
 * The smallest version that can hold the payload is selected automatically
 * unless `minVersion`/`maxVersion` restrict the range.
 *
 * @param text The payload to encode.
 * @param options Encoding options.
 */
export function encodeQr(text: string, options?: QrEncodeOptions): QrMatrix {
    const level: QrErrorCorrectionLevel = options?.errorCorrectionLevel ?? 'L'
    if (!(level in ECL_INDEX)) throw new Error(`qrcode: unknown error correction level "${level}"`)

    const minVersion = options?.minVersion ?? 1
    const maxVersion = options?.maxVersion ?? 40
    if (!Number.isInteger(minVersion) || minVersion < 1 || minVersion > 40) {
        throw new Error('qrcode: minVersion must be an integer between 1 and 40')
    }
    if (!Number.isInteger(maxVersion) || maxVersion < 1 || maxVersion > 40) {
        throw new Error('qrcode: maxVersion must be an integer between 1 and 40')
    }
    if (minVersion > maxVersion) throw new Error('qrcode: minVersion must not exceed maxVersion')

    let forcedMask: number | undefined
    if (options?.mask !== undefined) {
        if (!Number.isInteger(options.mask) || options.mask < 0 || options.mask > 7) {
            throw new Error('qrcode: mask must be an integer between 0 and 7')
        }
        forcedMask = options.mask
    }

    const bytes = new TextEncoder().encode(text)
    const version = chooseVersion(bytes.length, level, minVersion, maxVersion)
    const codewords = buildCodewords(version, level, bytes)

    const size = version * 4 + 17
    const modules: boolean[][] = []
    const reserved: boolean[][] = []
    for (let row = 0; row < size; row++) {
        modules.push(new Array<boolean>(size).fill(false))
        reserved.push(new Array<boolean>(size).fill(false))
    }
    const symbol: SymbolBuilder = { modules, reserved }

    setupFinderPatterns(symbol)
    setupTimingPatterns(symbol)
    setupAlignmentPatterns(symbol, version)
    // Reserve the format information area before the data is written so that
    // the data placement skips it.
    setupFormatInformation(symbol, level, 0)
    if (version >= 7) setupVersionInformation(symbol, version)
    setupData(symbol, codewords)

    const mask = forcedMask ?? bestMask(symbol, level)
    applyMask(symbol, mask)
    setupFormatInformation(symbol, level, mask)

    return { size, modules, errorCorrectionLevel: level, mask }
}

/**
 * Renders a matrix as an SVG string.
 *
 * The result is a standalone SVG document with a light background rectangle
 * and a single path holding all dark modules.
 *
 * @param matrix The matrix to render.
 * @param options Rendering options.
 */
export function qrToSvg(matrix: QrMatrix, options?: QrSvgOptions): string {
    const moduleSize = options?.moduleSize ?? 8
    const margin = options?.margin ?? 4
    const dark = options?.dark ?? '#000000'
    const light = options?.light ?? '#ffffff'

    if (!(moduleSize > 0)) throw new Error('qrcode: moduleSize must be positive')
    if (!(margin >= 0)) throw new Error('qrcode: margin must not be negative')

    const size = matrix.size
    const total = size + margin * 2
    const dimension = total * moduleSize

    // Build a path with one horizontal run per dark module group.
    let path = ''
    for (let row = 0; row < size; row++) {
        let col = 0
        while (col < size) {
            if (!matrix.modules[row]![col]) {
                col++
                continue
            }
            let end = col + 1
            while (end < size && matrix.modules[row]![end]) end++
            const x = (col + margin) * moduleSize
            const y = (row + margin) * moduleSize
            const width = (end - col) * moduleSize
            path += `M${x} ${y}h${width}v${moduleSize}h-${width}z`
            col = end
        }
    }

    return (
        `<svg xmlns="http://www.w3.org/2000/svg" width="${dimension}" height="${dimension}" ` +
        `viewBox="0 0 ${dimension} ${dimension}" shape-rendering="crispEdges">` +
        `<rect width="${dimension}" height="${dimension}" fill="${light}"/>` +
        `<path d="${path}" fill="${dark}"/></svg>`
    )
}

/**
 * Renders a matrix as text suitable for a terminal.
 *
 * With `halfBlocks` enabled every character cell covers two module rows, so
 * the symbol keeps a roughly square aspect ratio in a terminal. Otherwise
 * each module is drawn as two full blocks.
 *
 * @param matrix The matrix to render.
 * @param options Rendering options.
 */
export function qrToTerminal(matrix: QrMatrix, options?: QrTerminalOptions): string {
    const halfBlocks = options?.halfBlocks ?? true
    const margin = 4
    const size = matrix.size
    const total = size + margin * 2

    /** Reads a module, treating the quiet zone as light. */
    const moduleAt = (row: number, col: number): boolean => {
        const y = row - margin
        const x = col - margin
        if (y < 0 || y >= size || x < 0 || x >= size) return false
        return matrix.modules[y]![x]!
    }

    const lines: string[] = []

    if (halfBlocks) {
        for (let top = 0; top < total; top += 2) {
            let line = ''
            for (let col = 0; col < total; col++) {
                const upper = moduleAt(top, col)
                const lower = moduleAt(top + 1, col)
                if (upper && lower) line += '█'
                else if (upper) line += '▀'
                else if (lower) line += '▄'
                else line += ' '
            }
            lines.push(line)
        }
    } else {
        for (let row = 0; row < total; row++) {
            let line = ''
            for (let col = 0; col < total; col++) {
                line += moduleAt(row, col) ? '██' : '  '
            }
            lines.push(line)
        }
    }

    return lines.join('\n')
}
