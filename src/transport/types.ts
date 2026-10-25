/**
 * Transport abstractions.
 */

import type { BinaryNode } from './binary/types.js'

export type { BinaryNode }

/**
 * The minimal socket surface the connection layer needs.
 *
 * Both the WebSocket (web transport) and the raw TCP socket (mobile
 * transport) implement this, so the protocol logic above them is shared.
 */
export interface RawSocket {
    /** Writes bytes to the wire. */
    write(data: Uint8Array): void
    /** Closes the socket. */
    close(): void
    /** Registers the data handler. */
    onData(handler: (chunk: Uint8Array) => void): void
    /** Registers the close handler. */
    onClose(handler: (error?: Error) => void): void
}

/** Events emitted by a transport connection. */
export interface TransportHandlers {
    /** Called for every inbound protocol node. */
    onNode?: (node: BinaryNode) => void
    /** Called when the connection closes. */
    onClose?: (error?: Error) => void
    /** Called on a transport-level error that does not close the connection. */
    onError?: (error: Error) => void
}

/** The transport mode a client runs in. */
export type TransportMode = 'mobile' | 'web'
