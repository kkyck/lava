/**
 * Helpers for working with WhatsApp protocol nodes.
 */

import type { BinaryNode } from '../binary/types.js'

/** An empty, frozen child list to avoid allocating on every lookup. */
const EMPTY_NODE_CHILDREN: readonly BinaryNode[] = Object.freeze([])

/**
 * Returns the children of a node.
 *
 * @param node The node to inspect.
 */
export function getNodeChildren(node: BinaryNode): readonly BinaryNode[] {
    return Array.isArray(node.content) ? node.content : EMPTY_NODE_CHILDREN
}

/**
 * Finds the first child with the given tag.
 *
 * @param node The parent node.
 * @param tag The tag to look for.
 */
export function findNodeChild(node: BinaryNode, tag: string): BinaryNode | undefined {
    const content = node.content
    if (!Array.isArray(content)) return undefined
    for (let i = 0; i < content.length; i++) {
        if (content[i]!.tag === tag) return content[i]
    }
    return undefined
}

/**
 * Returns the first child of a node.
 *
 * @param node The parent node.
 */
export function getFirstNodeChild(node: BinaryNode): BinaryNode | undefined {
    const content = node.content
    if (!Array.isArray(content)) return undefined
    return content[0]
}

/**
 * Returns every child with the given tag.
 *
 * @param node The parent node.
 * @param tag The tag to look for.
 */
export function getNodeChildrenByTag(node: BinaryNode, tag: string): BinaryNode[] {
    const content = node.content
    if (!Array.isArray(content)) return []
    const out: BinaryNode[] = []
    for (let i = 0; i < content.length; i++) {
        if (content[i]!.tag === tag) out.push(content[i]!)
    }
    return out
}

/**
 * Returns the first child for each of the given tags.
 *
 * @param node The parent node.
 * @param tags The tags to look for, in order.
 */
export function findNodeChildrenByTags(
    node: BinaryNode,
    tags: readonly string[],
): (BinaryNode | undefined)[] {
    const content = node.content
    if (!Array.isArray(content)) return tags.map(() => undefined)
    const out: (BinaryNode | undefined)[] = []
    for (const tag of tags) {
        let found: BinaryNode | undefined
        for (let i = 0; i < content.length; i++) {
            if (content[i]!.tag === tag) {
                found = content[i]!
                break
            }
        }
        out.push(found)
    }
    return out
}

/**
 * Decodes a node's content as raw bytes.
 *
 * Node content arrives either as raw bytes or as a base64-encoded string,
 * depending on the sender and the transport.
 *
 * @param content The node content.
 * @param field A label used in error messages.
 */
export function decodeNodeContentBytes(
    content: string | Uint8Array | BinaryNode[] | null | undefined,
    field: string,
): Uint8Array {
    if (content instanceof Uint8Array) return content
    if (typeof content === 'string') {
        const decoded = base64Decode(content)
        if (!decoded) throw new Error(`${field} is not valid base64`)
        return decoded
    }
    throw new Error(`${field} has no binary content`)
}

/**
 * Decodes a node's content as UTF-8 text.
 *
 * @param content The node content.
 * @param field A label used in error messages.
 */
export function decodeNodeContentUtf8(
    content: string | Uint8Array | BinaryNode[] | null | undefined,
    field: string,
): string {
    if (typeof content === 'string') return content
    if (content instanceof Uint8Array) return new TextDecoder().decode(content)
    throw new Error(`${field} has no text content`)
}

/**
 * Decodes standard base64 into bytes.
 *
 * @param value The base64 text.
 * @returns The decoded bytes, or `undefined` when the input is not base64.
 */
export function base64Decode(value: string): Uint8Array | undefined {
    try {
        const binary = atob(value)
        const out = new Uint8Array(binary.length)
        for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i)
        return out
    } catch {
        return undefined
    }
}

/**
 * Returns the text content of a node.
 *
 * @param node The node to read.
 */
export function getNodeText(node: BinaryNode): string {
    const content = node.content
    if (typeof content === 'string') return content
    if (content instanceof Uint8Array) {
        return new TextDecoder().decode(content)
    }
    return ''
}

/**
 * Returns the binary content of a node.
 *
 * @param node The node to read.
 */
export function getNodeBytes(node: BinaryNode): Uint8Array {
    const content = node.content
    if (content instanceof Uint8Array) return content
    if (typeof content === 'string') return new TextEncoder().encode(content)
    return new Uint8Array(0)
}

/**
 * Reads an attribute as a number.
 *
 * @param node The node to read.
 * @param name The attribute name.
 */
export function getAttrNumber(node: BinaryNode, name: string): number | undefined {
    const raw = node.attrs[name]
    if (raw === undefined) return undefined
    const value = Number.parseInt(raw, 10)
    return Number.isFinite(value) ? value : undefined
}

/**
 * Reads an attribute as a boolean (`"true"` / `"1"`).
 *
 * @param node The node to read.
 * @param name The attribute name.
 */
export function getAttrBoolean(node: BinaryNode, name: string): boolean | undefined {
    const raw = node.attrs[name]
    if (raw === undefined) return undefined
    return raw === 'true' || raw === '1'
}

/**
 * Renders a node as human-readable XML.
 *
 * Useful for debugging; not used on the hot path.
 *
 * @param node The node to render.
 */
export function formatNodeAsXml(node: BinaryNode): string {
    const indent = '    '
    const render = (current: BinaryNode, depth: number): string => {
        const pad = indent.repeat(depth)
        const keys = Object.keys(current.attrs)
        let attrs = ''
        for (const key of keys) {
            attrs += ` ${key}='${escapeXml(current.attrs[key]!)}'`
        }
        const content = current.content
        if (content === undefined || content === null) {
            return `${pad}<${current.tag}${attrs}/>`
        }
        if (typeof content === 'string') {
            return `${pad}<${current.tag}${attrs}>${escapeXml(content)}</${current.tag}>`
        }
        if (content instanceof Uint8Array) {
            return `${pad}<${current.tag}${attrs}>${toBase64(content)}</${current.tag}>`
        }
        if (content.length === 0) {
            return `${pad}<${current.tag}${attrs}/>`
        }
        const children = content
            .map((child) => `\n${render(child, depth + 1)}`)
            .join('')
        return `${pad}<${current.tag}${attrs}>${children}\n${pad}</${current.tag}>`
    }
    return render(node, 0)
}

/** Escapes XML special characters. */
function escapeXml(value: string): string {
    let out = ''
    let last = 0
    for (let i = 0; i < value.length; i++) {
        let escaped: string | undefined
        switch (value.charCodeAt(i)) {
            case 38:
                escaped = '&amp;'
                break
            case 60:
                escaped = '&lt;'
                break
            case 62:
                escaped = '&gt;'
                break
            case 34:
                escaped = '&quot;'
                break
            case 39:
                escaped = '&apos;'
                break
        }
        if (escaped) {
            out += value.slice(last, i) + escaped
            last = i + 1
        }
    }
    return last === 0 ? value : out + value.slice(last)
}

/** Base64-encodes bytes without Node's `Buffer`. */
function toBase64(bytes: Uint8Array): string {
    let binary = ''
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]!)
    return btoa(binary)
}
