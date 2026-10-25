/**
 * The `<failure/>` stanza of the server.
 *
 * When the server refuses a session it does not answer the pending request:
 * it sends a `<failure/>` stanza with a numeric reason and closes the
 * socket.
 *
 * ```xml
 * <failure reason="401" location="cco" code="401" message="…"/>
 * ```
 *
 * The reason decides what the client does with the session. A reason that
 * ends the session for good means that the stored credentials are worthless
 * and the device has to pair again; a reason that only interrupts the
 * connection keeps them, so the client may connect again.
 */

import type { BinaryNode } from '../transport/binary/types.js'

/** The reasons the server reports in a `<failure/>` stanza. */
export const WA_FAILURE_REASONS = Object.freeze({
    /** The session is not authorized any more. */
    NOT_AUTHORIZED: 401,
    /** The account is locked. */
    LOCKED: 403,
    /** The account is banned. */
    BANNED: 406,
    /** The client version is too old for the server. */
    CLIENT_TOO_OLD: 405,
    /** The client announced a build the server does not know. */
    BAD_USER_AGENT: 409,
    /** The service is unavailable. */
    SERVICE_UNAVAILABLE: 503,
})

/**
 * The reasons that end the session for good.
 *
 * The credentials of a session the server refuses with one of these reasons
 * are worthless: the device has to pair again, so they are removed.
 */
export const WA_LOGOUT_FAILURE_REASONS: ReadonlySet<number> = new Set([
    WA_FAILURE_REASONS.NOT_AUTHORIZED,
    WA_FAILURE_REASONS.LOCKED,
    WA_FAILURE_REASONS.BANNED,
])

/**
 * The reasons that only interrupt the connection.
 *
 * The credentials stay valid, so the client may connect again.
 */
export const WA_DISCONNECT_FAILURE_REASONS: ReadonlySet<number> = new Set([
    WA_FAILURE_REASONS.CLIENT_TOO_OLD,
    WA_FAILURE_REASONS.BAD_USER_AGENT,
    WA_FAILURE_REASONS.SERVICE_UNAVAILABLE,
])

/** A `<failure/>` stanza, as handed to the `failure` event. */
export interface WaFailure {
    /** The reason the server gave. */
    reason?: number
    /** The error code of the failure. */
    code?: number
    /** The human readable message of the failure. */
    message?: string
    /** The address of the documentation of the failure. */
    url?: string
    /** The server location that reported the failure. */
    location?: string
    /** Whether the session is over and the device has to pair again. */
    logout: boolean
    /** Whether the connection may be re-established. */
    disconnect: boolean
}

/**
 * Reads the numeric attribute of a node.
 *
 * @param value The attribute value.
 * @returns The number, or `undefined` when the value is not a number.
 */
function parseOptionalInt(value: string | undefined): number | undefined {
    if (value === undefined) return undefined
    const parsed = Number.parseInt(value, 10)
    return Number.isFinite(parsed) ? parsed : undefined
}

/**
 * Reads a `<failure/>` stanza.
 *
 * @param node The stanza.
 * @returns What the stanza says about the session.
 */
export function parseFailureNode(node: BinaryNode): WaFailure {
    const reason = parseOptionalInt(node.attrs.reason)
    const code = parseOptionalInt(node.attrs.code)
    return {
        ...(reason !== undefined ? { reason } : {}),
        ...(code !== undefined ? { code } : {}),
        ...(node.attrs.message ? { message: node.attrs.message } : {}),
        ...(node.attrs.url ? { url: node.attrs.url } : {}),
        ...(node.attrs.location ? { location: node.attrs.location } : {}),
        logout: reason !== undefined && WA_LOGOUT_FAILURE_REASONS.has(reason),
        disconnect: reason !== undefined && WA_DISCONNECT_FAILURE_REASONS.has(reason),
    }
}
