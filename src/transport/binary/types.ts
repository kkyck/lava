/**
 * The binary node representation used by the WhatsApp node protocol.
 *
 * A node has a tag, a set of attributes and optional content. The content is
 * either text, raw bytes or a list of child nodes.
 */

/** A protocol node. */
export interface BinaryNode {
    /** The node tag, e.g. `iq` or `message`. */
    tag: string
    /** The node attributes. */
    attrs: Record<string, string>
    /** The node content. */
    content?: string | Uint8Array | BinaryNode[] | null
}

/**
 * Returns `true` when the node's content is a list of child nodes.
 *
 * @param node The node to test.
 */
export function isNodeList(
    node: BinaryNode,
): node is BinaryNode & { content: BinaryNode[] } {
    return Array.isArray(node.content)
}
