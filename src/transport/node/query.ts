/**
 * IQ request/response handling.
 *
 * WhatsApp's request/response mechanism is an XML-ish `<iq>` stanza. The
 * client assigns an id, sends the stanza and waits for a response carrying
 * the same id.
 */

import type { BinaryNode } from '../binary/types.js'
import { WA_IQ_TYPES, WA_NODE_TAGS } from './constants.js'
import { findNodeChild } from './helpers.js'

/** Builds an IQ stanza. */
export interface IqOptions {
    /** Additional attributes. */
    attrs?: Record<string, string>
    /** Children of the stanza. */
    content?: BinaryNode[]
}

/**
 * Builds an `<iq>` stanza.
 *
 * @param type `get` or `set`.
 * @param to Recipient JID.
 * @param xmlns Namespace.
 * @param content Child nodes.
 * @param attrs Extra attributes.
 */
export function buildIqNode(
    type: 'get' | 'set',
    to: string,
    xmlns: string,
    content?: BinaryNode[],
    attrs: Record<string, string> = {},
): BinaryNode {
    const node: BinaryNode = {
        tag: WA_NODE_TAGS.IQ,
        attrs: { ...attrs, to, type, xmlns },
    }
    if (content !== undefined) node.content = content
    return node
}

/** A parsed IQ error. */
export interface IqError {
    /** The raw error code. */
    code: string
    /** The human readable error text. */
    text: string
    /** The numeric error code when parseable. */
    numericCode?: number
}

/**
 * Reads the error envelope from an IQ stanza.
 *
 * @param node The IQ node.
 */
export function parseIqError(node: BinaryNode): IqError {
    const errorNode = findNodeChild(node, WA_NODE_TAGS.ERROR)
    const code = errorNode?.attrs.code ?? node.attrs.type ?? 'unknown'
    const text = errorNode?.attrs.text ?? errorNode?.attrs.type ?? 'unknown'
    const numericCode = Number.parseInt(code, 10)
    return {
        code,
        text,
        ...(Number.isSafeInteger(numericCode) ? { numericCode } : {}),
    }
}

/**
 * Throws when the node is not a successful IQ result.
 *
 * @param node The IQ node.
 * @param context Label used in the error message.
 */
export function assertIqResult(node: BinaryNode, context: string): void {
    if (node.tag !== WA_NODE_TAGS.IQ) {
        throw new Error(`${context} returned a non-iq node (${node.tag})`)
    }
    if (node.attrs.type === WA_IQ_TYPES.RESULT) return
    const error = parseIqError(node)
    throw new Error(`${context} iq failed (${error.code}: ${error.text})`)
}

/**
 * A pending IQ request.
 */
interface PendingRequest {
    resolve: (node: BinaryNode) => void
    reject: (error: Error) => void
    timer: NodeJS.Timeout
}

/**
 * Correlates outgoing IQ stanzas with their responses.
 *
 * The dispatcher owns one instance and feeds every inbound node into it.
 */
export class IqDispatcher {
    private readonly pending = new Map<string, PendingRequest>()
    private counter = 0

    /**
     * Generates a unique stanza id.
     */
    nextId(): string {
        this.counter = (this.counter + 1) % 0xffffffff
        return `wa-${this.counter.toString(16)}-${Date.now().toString(16)}`
    }

    /**
     * Registers a pending request.
     *
     * @param id The stanza id.
     * @param timeoutMs How long to wait for the response.
     */
    expect(id: string, timeoutMs: number): Promise<BinaryNode> {
        return new Promise<BinaryNode>((resolve, reject) => {
            const timer = setTimeout(() => {
                this.pending.delete(id)
                reject(new Error(`iq request timed out after ${timeoutMs}ms (id ${id})`))
            }, timeoutMs)
            timer.unref?.()
            this.pending.set(id, { resolve, reject, timer })
        })
    }

    /**
     * Resolves a pending request.
     *
     * @param id The stanza id.
     * @param node The response node.
     * @returns `true` when a pending request was found.
     */
    settle(id: string, node: BinaryNode): boolean {
        const request = this.pending.get(id)
        if (!request) return false
        this.pending.delete(id)
        clearTimeout(request.timer)
        request.resolve(node)
        return true
    }

    /**
     * Rejects a pending request.
     *
     * @param id The stanza id.
     * @param error The failure.
     */
    fail(id: string, error: Error): boolean {
        const request = this.pending.get(id)
        if (!request) return false
        this.pending.delete(id)
        clearTimeout(request.timer)
        request.reject(error)
        return true
    }

    /** Rejects every pending request, e.g. when the socket closes. */
    failAll(error: Error): void {
        for (const [id, request] of this.pending) {
            clearTimeout(request.timer)
            request.reject(error)
            this.pending.delete(id)
        }
    }

    /** Number of outstanding requests. */
    get pendingCount(): number {
        return this.pending.size
    }
}
