/**
 * Builders for the passive-mode stanzas.
 *
 * A client tells the server in which mode it runs: `active` means that it
 * is connected and receives messages right away, `passive` means that it
 * only polls. A device that never says anything is treated as a passive
 * one, and the server may hold its messages back.
 */

import { WA_DEFAULTS, WA_IQ_TYPES, WA_XMLNS } from '../../../protocol/constants.js'
import { buildIqNode } from '../query.js'
import type { BinaryNode } from '../../binary/types.js'

/**
 * Builds the `<iq>` that switches the client into the given passive mode.
 *
 * @param mode The mode, e.g. `active` or `passive`.
 */
export function buildPassiveModeIqNode(mode: string): BinaryNode {
    return buildIqNode(WA_IQ_TYPES.SET, WA_DEFAULTS.HOST_DOMAIN, WA_XMLNS.PASSIVE, [
        { tag: mode, attrs: {} },
    ])
}
