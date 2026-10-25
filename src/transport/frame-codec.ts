/**
 * WhatsApp frame codec.
 *
 * Frames on the wire are length-prefixed with a **3-byte big-endian**
 * length. The very first frame additionally carries a *prefix* (the Noise
 * protocol header) that is transmitted **outside** of the length prefix:
 *
 * ```
 * +---------------+----------------+-----------------+-------------------+
 * | prefix (4 B)  | len (3 bytes)  | payload         | ... next frame ... |
 * +---------------+----------------+-----------------+-------------------+
 * ```
 *
 * The prefix is only sent once per connection. Every subsequent frame is
 * simply `len(3) || payload`.
 */

import { EMPTY, concat } from '../crypto/primitives.js'

/** Maximum frame length allowed by the protocol (2^24 - 1). */
export const WA_MAX_FRAME_LENGTH = (1 << 24) - 1

/** Reads a 3-byte big-endian length from a header. */
function frameLength(header: Uint8Array): number {
    return (header[0]! << 16) | (header[1]! << 8) | header[2]!
}

/**
 * Encodes and decodes WhatsApp length-prefixed frames.
 *
 * The decoder is incremental: feed it arbitrary chunks and it yields whole
 * frames. It keeps only the incomplete tail of a chunk, so memory use stays
 * proportional to the largest single frame rather than the total stream.
 */
export class FrameCodec {
    private readonly tailScratch = new Uint8Array(4096)
    private buffered: Uint8Array = EMPTY
    private bufferedLength = 0
    private introSent = false

    /**
     * @param introFrame Optional prefix sent once before the first frame
     *   (the Noise protocol header).
     * @param maxFrameLength Largest frame accepted.
     */
    constructor(
        private readonly introFrame: Uint8Array | null = null,
        private readonly maxFrameLength: number = WA_MAX_FRAME_LENGTH,
    ) {
        if (!Number.isSafeInteger(maxFrameLength) || maxFrameLength <= 0) {
            throw new Error('maxFrameLength must be a positive safe integer')
        }
        if (maxFrameLength >= 1 << 24) {
            throw new Error('maxFrameLength must be lower than the protocol limit (16777216)')
        }
    }

    /** Throws when a frame exceeds the configured maximum. */
    private assertFrameLength(length: number): void {
        if (length <= this.maxFrameLength) return
        throw new Error(
            `incoming frame is too large: ${length} bytes (max allowed: ${this.maxFrameLength})`,
        )
    }

    /** Appends `chunk` to the internal buffer. */
    private appendBuffered(chunk: Uint8Array): void {
        if (chunk.length === 0) return
        if (this.bufferedLength === 0) {
            this.buffered = chunk
        } else {
            const nextLength = this.bufferedLength + chunk.length
            if (this.buffered.length < nextLength) {
                const nextBuffered = new Uint8Array(Math.max(nextLength, this.bufferedLength * 2))
                nextBuffered.set(this.buffered.subarray(0, this.bufferedLength))
                this.buffered = nextBuffered
            }
            this.buffered.set(chunk, this.bufferedLength)
        }
        this.bufferedLength += chunk.length
    }

    /**
     * Encodes a frame for transmission.
     *
     * The first call prepends the intro frame outside of the length prefix.
     */
    encodeFrame(frame: Uint8Array): Uint8Array {
        if (frame.length > this.maxFrameLength) {
            throw new Error(
                `frame is too large: ${frame.length} bytes (max allowed: ${this.maxFrameLength})`,
            )
        }
        if (!this.introSent && this.introFrame && this.introFrame.length > 0) {
            this.introSent = true
            const headerOffset = this.introFrame.length
            const out = new Uint8Array(headerOffset + 3 + frame.length)
            out.set(this.introFrame, 0)
            out[headerOffset] = (frame.length >> 16) & 0xff
            out[headerOffset + 1] = (frame.length >> 8) & 0xff
            out[headerOffset + 2] = frame.length & 0xff
            out.set(frame, headerOffset + 3)
            return out
        }
        this.introSent = true
        const out = new Uint8Array(3 + frame.length)
        out[0] = (frame.length >> 16) & 0xff
        out[1] = (frame.length >> 8) & 0xff
        out[2] = frame.length & 0xff
        out.set(frame, 3)
        return out
    }

    /**
     * Feeds a chunk of wire data and returns any complete frames.
     *
     * @param chunk Bytes received from the socket.
     */
    pushWireChunk(chunk: Uint8Array): Uint8Array[] {
        if (chunk.length === 0) return []
        const frames: Uint8Array[] = []
        let chunkOffset = 0

        if (this.bufferedLength > 0) {
            if (this.bufferedLength < 3) {
                // We only have part of the length header.
                const missingHeaderBytes = 3 - this.bufferedLength
                if (chunk.length < missingHeaderBytes) {
                    this.appendBuffered(chunk)
                    return frames
                }
                this.appendBuffered(chunk.subarray(0, missingHeaderBytes))
                const length = frameLength(this.buffered)
                this.assertFrameLength(length)
                const remainingAfterHeader = chunk.length - missingHeaderBytes
                if (remainingAfterHeader < length) {
                    this.appendBuffered(chunk.subarray(missingHeaderBytes))
                    return frames
                }
                frames.push(chunk.subarray(missingHeaderBytes, missingHeaderBytes + length))
                chunkOffset = missingHeaderBytes + length
            } else {
                const length = frameLength(this.buffered)
                this.assertFrameLength(length)
                const bufferedPayloadLength = this.bufferedLength - 3
                const missingPayloadBytes = length - bufferedPayloadLength
                if (missingPayloadBytes > chunk.length) {
                    this.appendBuffered(chunk)
                    return frames
                }
                if (missingPayloadBytes === 0) {
                    frames.push(this.buffered.slice(3, 3 + length))
                } else if (bufferedPayloadLength === 0) {
                    frames.push(chunk.subarray(0, missingPayloadBytes))
                } else {
                    const frame = new Uint8Array(length)
                    frame.set(this.buffered.subarray(3, this.bufferedLength))
                    frame.set(chunk.subarray(0, missingPayloadBytes), bufferedPayloadLength)
                    frames.push(frame)
                }
                chunkOffset = missingPayloadBytes
            }
            this.buffered = EMPTY
            this.bufferedLength = 0
        }

        const remainingChunk = chunk.subarray(chunkOffset)
        let offset = 0
        while (remainingChunk.length - offset >= 3) {
            const header = remainingChunk.subarray(offset, offset + 3)
            const length = frameLength(header)
            this.assertFrameLength(length)
            if (remainingChunk.length - offset - 3 < length) break
            const start = offset + 3
            const end = start + length
            frames.push(remainingChunk.subarray(start, end))
            offset = end
        }

        const restLength = remainingChunk.length - offset
        if (restLength === 0) {
            this.buffered = EMPTY
        } else if (restLength <= this.tailScratch.length) {
            this.tailScratch.set(remainingChunk.subarray(offset))
            this.buffered = this.tailScratch
        } else {
            this.buffered = new Uint8Array(remainingChunk.subarray(offset))
        }
        this.bufferedLength = restLength
        return frames
    }
}

/**
 * Builds the routing-info prefix used by the mobile transport.
 *
 * The prefix is `"ED"` followed by a version byte, a 3-byte big-endian
 * length and the routing info itself.
 */
export function buildRoutingInfoPrefix(routingInfo: Uint8Array): Uint8Array {
    const prefix = new Uint8Array(7 + routingInfo.length)
    prefix[0] = 0x45 // 'E'
    prefix[1] = 0x44 // 'D'
    prefix[2] = 0x00
    prefix[3] = 0x01
    prefix[4] = (routingInfo.length >> 16) & 0xff
    prefix[5] = (routingInfo.length >> 8) & 0xff
    prefix[6] = routingInfo.length & 0xff
    prefix.set(routingInfo, 7)
    return prefix
}

/** Convenience helper: prefixes `payload` with `header`. */
export function withPrefix(header: Uint8Array, payload: Uint8Array): Uint8Array {
    return concat(header, payload)
}
