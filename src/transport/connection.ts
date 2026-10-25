/**
 * The transport connection.
 *
 * A connection owns the Noise session and turns the byte stream into
 * protocol nodes (and back). It is deliberately transport agnostic: the
 * socket lives in the transport ({@link ./web.ts} or {@link ./mobile.ts}),
 * which forwards inbound bytes here and provides the wire writer.
 *
 * ```text
 *   node  →  encodeBinaryNodeStanza → Noise.encrypt → length prefix → socket
 *   socket →  length prefix → Noise.decrypt → decodeBinaryNodeStanza → node
 * ```
 */

import { decodeBinaryNodeStanza, encodeBinaryNodeStanza } from './binary/codec.js'
import type { BinaryNode } from './binary/types.js'
import { IqDispatcher } from './node/query.js'
import { NoiseSessionDriver, type NoiseSessionConfig } from './noise-session.js'
import type { TransportHandlers } from './types.js'

/** Configuration for a {@link Connection}. */
export interface ConnectionConfig {
    /** The Noise handshake configuration. */
    noise: Omit<NoiseSessionConfig, 'sendWire'>
    /** Writes an encoded frame to the wire. */
    sendWire: (frame: Uint8Array) => void
    /** Tears the wire down. */
    closeWire: () => void
    /** Timeout for the Noise handshake, in milliseconds. */
    handshakeTimeoutMs?: number
    /** Timeout for an IQ request/response round trip, in milliseconds. */
    iqTimeoutMs?: number
    /** Event handlers. */
    handlers?: TransportHandlers
}

/** A transport connection. */
export class Connection {
    private readonly noiseConfig: Omit<NoiseSessionConfig, 'sendWire'>
    private readonly sendWire: (frame: Uint8Array) => void
    private readonly closeWire: () => void
    private readonly handlers: TransportHandlers
    private readonly iq = new IqDispatcher()
    private driver: NoiseSessionDriver | null = null
    private closed = false
    private closeError: Error | null = null
    private serverStaticKey: Uint8Array | null = null
    /** Serialises frame processing so stanzas are handled in arrival order. */
    private queue: Promise<void> = Promise.resolve()

    /**
     * @param config The connection configuration.
     */
    constructor(config: ConnectionConfig) {
        this.noiseConfig = config.noise
        this.sendWire = config.sendWire
        this.closeWire = config.closeWire
        this.handlers = config.handlers ?? {}
    }

    /** The cached server static key, usable for an IK resume. */
    getServerStaticKey(): Uint8Array | null {
        return this.serverStaticKey
    }

    /** Whether the connection has been closed. */
    get isClosed(): boolean {
        return this.closed
    }

    /**
     * Runs the Noise handshake.
     *
     * @param timeoutMs Handshake timeout.
     */
    async start(timeoutMs = 10000): Promise<{ serverStaticKey: Uint8Array }> {
        const driver = new NoiseSessionDriver({
            ...this.noiseConfig,
            sendWire: (frame) => this.sendWire(frame),
        })
        this.driver = driver

        let timer: NodeJS.Timeout | undefined
        const timeout = new Promise<never>((_, reject) => {
            timer = setTimeout(() => {
                reject(new Error(`noise handshake timed out after ${timeoutMs}ms`))
            }, timeoutMs)
            timer.unref?.()
        })
        try {
            const result = await Promise.race([driver.start(), timeout])
            this.serverStaticKey = result.serverStaticKey
            return { serverStaticKey: result.serverStaticKey }
        } finally {
            if (timer) clearTimeout(timer)
        }
    }

    /**
     * Sends a node to the peer.
     *
     * @param node The node to send.
     */
    send(node: BinaryNode): void {
        if (this.closed) {
            throw new Error('connection is closed')
        }
        if (!this.driver) {
            throw new Error('connection handshake has not completed')
        }
        const payload = encodeBinaryNodeStanza(node)
        this.sendWire(this.driver.encodeFrame(payload))
    }

    /**
     * Sends an IQ stanza and waits for the matching response.
     *
     * @param node The IQ node; an `id` attribute is added automatically.
     * @param timeoutMs Response timeout.
     */
    async query(node: BinaryNode, timeoutMs = 15000): Promise<BinaryNode> {
        const id = this.iq.nextId()
        const tagged: BinaryNode = { ...node, attrs: { ...node.attrs, id } }
        const response = this.iq.expect(id, timeoutMs)
        this.send(tagged)
        return response
    }

    /**
     * Feeds a raw inbound node into the IQ dispatcher.
     *
     * @param node The inbound node.
     */
    handleNode(node: BinaryNode): void {
        if (node.tag === 'iq') {
            const id = node.attrs.id
            if (id && this.iq.settle(id, node)) return
        }
        this.handlers.onNode?.(node)
    }

    /**
     * Handles inbound socket data.
     *
     * Frames are processed strictly in order: the work is chained onto an
     * internal promise so a slow (decompressing) stanza cannot overtake the
     * frames that follow it.
     *
     * @param chunk Bytes received from the socket.
     */
    handleData(chunk: Uint8Array): void {
        this.queue = this.queue.then(() => this.processChunk(chunk))
        this.queue.catch(() => {
            // The rejection is surfaced through `onError`; this handler only
            // exists so the chain never becomes an unhandled rejection.
        })
    }

    /**
     * Decodes and dispatches every frame contained in a chunk.
     *
     * @param chunk Bytes received from the socket.
     */
    private async processChunk(chunk: Uint8Array): Promise<void> {
        if (!this.driver) return
        let payloads: Uint8Array[]
        try {
            payloads = this.driver.pushWireChunk(chunk)
        } catch (error) {
            this.handlers.onError?.(error instanceof Error ? error : new Error(String(error)))
            return
        }
        for (const payload of payloads) {
            let node: BinaryNode
            try {
                node = await decodeBinaryNodeStanza(payload)
            } catch (error) {
                this.handlers.onError?.(
                    error instanceof Error ? error : new Error(String(error)),
                )
                continue
            }
            this.handleNode(node)
        }
    }

    /**
     * Handles the socket closing.
     *
     * @param error The reason the connection ended.
     */
    handleClose(error?: Error): void {
        if (this.closed) return
        this.closed = true
        this.closeError = error ?? new Error('connection closed')
        this.iq.failAll(this.closeError)
        this.driver?.onSocketClosed(this.closeError)
        this.handlers.onClose?.(this.closeError)
    }

    /** Closes the connection. */
    close(): void {
        if (this.closed) return
        this.closed = true
        this.iq.failAll(new Error('connection closed'))
        this.closeWire()
    }
}
