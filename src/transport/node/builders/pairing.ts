/**
 * Pairing stanza builders.
 *
 * A companion device (this library) attaches to a primary device (the phone)
 * through the `md` namespace. The handshake has three stages:
 *
 * 1. `companion_hello` — the companion sends its wrapped ephemeral key; the
 *    server answers with the pairing reference and, later, with the phone's
 *    wrapped ephemeral key.
 * 2. `get_country_code` — optional; used to derive the country of the
 *    phone number.
 * 3. `companion_finish` — the companion sends the wrapped key bundle and
 *    the server answers with `<pair-success>`.
 */

import { WA_DEFAULTS, WA_IQ_TYPES, WA_NODE_TAGS, WA_XMLNS } from '../../../protocol/constants.js'
import type { BinaryNode } from '../../binary/types.js'

/** The pairing stages of the `md` namespace. */
export const WA_SIGNALING = Object.freeze({
    LINK_CODE_STAGE_COMPANION_HELLO: 'companion_hello',
    LINK_CODE_STAGE_GET_COUNTRY_CODE: 'get_country_code',
    LINK_CODE_STAGE_COMPANION_FINISH: 'companion_finish',
    LINK_CODE_STAGE_REFRESH_CODE: 'refresh_code',
    LINK_CODE_STAGE_PRIMARY_HELLO: 'primary_hello',
    COMPANION_REG_REFRESH_NOTIFICATION: 'companion_reg_refresh',
} as const)

/**
 * The companion platform identifiers the server accepts.
 *
 * These are the *client types* of the linking protocol, not the platform
 * types of the device props: the official client sends the type of the
 * program that links (a browser, the desktop app), as a one-character
 * string.
 */
export const WA_COMPANION_PLATFORM_ID = Object.freeze({
    /** An unknown client. */
    UNKNOWN: '0',
    /** Google Chrome. */
    CHROME: '1',
    /** Microsoft Edge. */
    EDGE: '2',
    /** Mozilla Firefox. */
    FIREFOX: '3',
    /** Internet Explorer. */
    IE: '4',
    /** Opera. */
    OPERA: '5',
    /** Apple Safari. */
    SAFARI: '6',
    /** The desktop app (Electron). */
    ELECTRON: '7',
    /** The Windows app. */
    UWP: '8',
    /** Any other web client. */
    OTHER_WEB_CLIENT: '9',
} as const)

/**
 * The name the phone shows for the client that links.
 *
 * The server checks the display name against the browsers it knows and
 * answers a hello it does not recognise with `400 bad-request`. The desktop
 * app is not part of that list — only the browsers are — so a companion
 * device announces itself as a browser.
 */
export const WA_COMPANION_PLATFORM_DISPLAY = 'Chrome'

/**
 * Builds the `companion_hello` IQ.
 *
 * @param args The hello arguments.
 */
export function buildCompanionHelloRequestNode(args: {
    /** The phone number JID of the primary device. */
    phoneJid: string
    /** The companion's wrapped ephemeral public key. */
    wrappedCompanionEphemeralPub: Uint8Array
    /** The companion's server-auth key public key. */
    companionServerAuthKeyPub: Uint8Array
    /** The companion platform id — the client type, e.g. `7` for the desktop app. */
    companionPlatformId: string
    /** The companion platform display name, e.g. `Desktop (Windows)`. */
    companionPlatformDisplay: string
    /** Whether the phone should show a push notification. */
    shouldShowPushNotification?: boolean
}): BinaryNode {
    return {
        tag: WA_NODE_TAGS.IQ,
        attrs: {
            to: WA_DEFAULTS.HOST_DOMAIN,
            type: WA_IQ_TYPES.SET,
            xmlns: WA_XMLNS.MD,
        },
        content: [
            {
                tag: WA_NODE_TAGS.LINK_CODE_COMPANION_REG,
                attrs: {
                    jid: args.phoneJid,
                    stage: WA_SIGNALING.LINK_CODE_STAGE_COMPANION_HELLO,
                    should_show_push_notification:
                        args.shouldShowPushNotification === true ? 'true' : 'false',
                },
                content: [
                    {
                        tag: WA_NODE_TAGS.LINK_CODE_PAIRING_WRAPPED_COMPANION_EPHEMERAL_PUB,
                        attrs: {},
                        content: args.wrappedCompanionEphemeralPub,
                    },
                    {
                        tag: WA_NODE_TAGS.COMPANION_SERVER_AUTH_KEY_PUB,
                        attrs: {},
                        content: args.companionServerAuthKeyPub,
                    },
                    {
                        tag: 'companion_platform_id',
                        attrs: {},
                        content: args.companionPlatformId,
                    },
                    {
                        tag: 'companion_platform_display',
                        attrs: {},
                        content: args.companionPlatformDisplay,
                    },
                    {
                        tag: 'link_code_pairing_nonce',
                        attrs: {},
                        // The nonce is a single zero byte, not an empty
                        // payload: the server drops a hello that carries none.
                        content: new Uint8Array([0]),
                    },
                ],
            },
        ],
    }
}

/**
 * Builds the `get_country_code` IQ.
 */
export function buildGetCountryCodeRequestNode(): BinaryNode {
    return {
        tag: WA_NODE_TAGS.IQ,
        attrs: {
            to: WA_DEFAULTS.HOST_DOMAIN,
            type: WA_IQ_TYPES.GET,
            xmlns: WA_XMLNS.MD,
        },
        content: [
            {
                tag: WA_NODE_TAGS.LINK_CODE_COMPANION_REG,
                attrs: { stage: WA_SIGNALING.LINK_CODE_STAGE_GET_COUNTRY_CODE },
            },
        ],
    }
}

/**
 * Builds the `companion_finish` IQ.
 *
 * @param args The finish arguments.
 */
export function buildCompanionFinishRequestNode(args: {
    /** The phone number JID of the primary device. */
    phoneJid: string
    /** The wrapped key bundle. */
    wrappedKeyBundle: Uint8Array
    /** The companion's identity public key. */
    companionIdentityPublic: Uint8Array
    /** The pairing reference handed out by the server. */
    ref: string
}): BinaryNode {
    return {
        tag: WA_NODE_TAGS.IQ,
        attrs: {
            to: WA_DEFAULTS.HOST_DOMAIN,
            type: WA_IQ_TYPES.SET,
            xmlns: WA_XMLNS.MD,
        },
        content: [
            {
                tag: WA_NODE_TAGS.LINK_CODE_COMPANION_REG,
                attrs: {
                    jid: args.phoneJid,
                    stage: WA_SIGNALING.LINK_CODE_STAGE_COMPANION_FINISH,
                },
                content: [
                    {
                        tag: WA_NODE_TAGS.LINK_CODE_PAIRING_WRAPPED_KEY_BUNDLE,
                        attrs: {},
                        content: args.wrappedKeyBundle,
                    },
                    {
                        tag: WA_NODE_TAGS.COMPANION_IDENTITY_PUBLIC,
                        attrs: {},
                        content: args.companionIdentityPublic,
                    },
                    {
                        tag: WA_NODE_TAGS.LINK_CODE_PAIRING_REF,
                        attrs: {},
                        content: args.ref,
                    },
                ],
            },
        ],
    }
}

/**
 * Builds the `<pair-device-sign>` IQ result that answers the server's
 * `<pair-success>` stanza.
 *
 * @param deviceIdentity The signed device identity.
 * @param keyIndex The index of the signing key.
 * @param id The id of the `<pair-success>` request, so the server can match
 * the answer to its request.
 * @param to The recipient of the answer — the host that sent the request.
 */
export function buildPairDeviceSignResultNode(
    deviceIdentity: Uint8Array,
    keyIndex = 0,
    id?: string,
    to: string = WA_DEFAULTS.HOST_DOMAIN,
): BinaryNode {
    return {
        tag: WA_NODE_TAGS.IQ,
        attrs: {
            to,
            type: WA_IQ_TYPES.RESULT,
            ...(id ? { id } : {}),
        },
        content: [
            {
                tag: 'pair-device-sign',
                attrs: {},
                content: [
                    {
                        tag: WA_NODE_TAGS.DEVICE_IDENTITY,
                        attrs: { 'key-index': String(keyIndex) },
                        content: deviceIdentity,
                    },
                ],
            },
        ],
    }
}
