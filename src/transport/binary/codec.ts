/**
 * The binary-node codec: the WhatsApp node protocol's wire format.
 */

export { encodeBinaryNode, encodeBinaryNodeStanza } from './encoder.js'
export { decodeBinaryNode, decodeBinaryNodeStanza } from './decoder.js'
export type { BinaryNode } from './types.js'
export { isNodeList } from './types.js'
